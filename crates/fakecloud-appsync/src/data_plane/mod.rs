//! AppSync's GraphQL data plane: `POST /graphql` on
//! `<apiId>.appsync-api.<region>.amazonaws.com` and the realtime WebSocket on
//! `<apiId>.appsync-realtime-api.<region>.amazonaws.com/graphql`.
//!
//! Scope, stated rather than faked: requests authenticate with `AWS_IAM`,
//! `API_KEY` or `AMAZON_COGNITO_USER_POOLS` (tokens are checked against the
//! pool's signing key, issuer, expiry and the provider's `appIdClientRegex`;
//! SigV4 signatures are not recomputed, as everywhere in fakecloud). Fields are
//! authorized by AppSync's directive rules (`@aws_iam`,
//! `@aws_cognito_user_pools`, `@aws_api_key`). Resolvers run when they are
//! `UNIT` `APPSYNC_JS` resolvers on a `NONE` data source; any other resolver
//! answers its field with an `UnsupportedOperation` error naming what it uses.
//! A field with no resolver resolves to `null` at the root and to its parent's
//! property below it. Mutation results reach subscriptions whose field lists the
//! mutation in `@aws_subscribe` and whose filter passes them.

pub mod filter;
pub mod js;
pub mod realtime;

use std::collections::{BTreeMap, HashMap};

use fakecloud_cognito::SharedCognitoState;
use graphql_parser::query as q;
use graphql_parser::schema as s;
use serde_json::{json, Map, Value};

use js::{run_handler, HandlerRun, Outcome};

type Document = q::Document<'static, String>;
pub(crate) type QueryField = q::Field<'static, String>;
pub(crate) type Fragment = q::FragmentDefinition<'static, String>;
type SelectionSet = q::SelectionSet<'static, String>;

const AUTH_DIRECTIVES: &[&str] = &[
    "aws_iam",
    "aws_cognito_user_pools",
    "aws_api_key",
    "aws_oidc",
    "aws_lambda",
];

/// How a caller authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Iam,
    UserPools,
    ApiKey,
}

impl AuthMode {
    fn wire(self) -> &'static str {
        match self {
            Self::Iam => "AWS_IAM",
            Self::UserPools => "AMAZON_COGNITO_USER_POOLS",
            Self::ApiKey => "API_KEY",
        }
    }

    fn directive(self) -> &'static str {
        match self {
            Self::Iam => "aws_iam",
            Self::UserPools => "aws_cognito_user_pools",
            Self::ApiKey => "aws_api_key",
        }
    }

    /// `util.authType()`.
    pub fn util_name(self) -> &'static str {
        match self {
            Self::Iam => "IAM Authorization",
            Self::UserPools => "User Pool Authorization",
            Self::ApiKey => "API Key Authorization",
        }
    }
}

/// An authenticated caller and its resolver `ctx.identity`.
#[derive(Debug, Clone)]
pub struct Caller {
    pub mode: AuthMode,
    pub identity: Value,
}

/// What a request presents for authentication.
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    pub authorization: Option<String>,
    pub api_key: Option<String>,
    pub account_id: String,
    pub access_key_id: Option<String>,
    pub source_ip: Option<String>,
}

/// One API as the data plane reads it, copied out of the service state.
#[derive(Debug, Clone)]
pub struct ApiSnapshot {
    pub api_id: String,
    pub api: Value,
    pub schema: String,
    pub resolvers: BTreeMap<String, Value>,
    pub data_sources: BTreeMap<String, Value>,
    pub api_keys: BTreeMap<String, Value>,
}

/// The API `api_id`, from whichever account owns it.
pub fn snapshot(state: &crate::SharedAppSyncState, api_id: &str) -> Option<ApiSnapshot> {
    let accounts = state.read();
    let found = accounts.iter().find_map(|(_, data)| {
        let api = data.graphql_apis.get(api_id)?;
        Some(ApiSnapshot {
            api_id: api_id.to_string(),
            api: api.clone(),
            schema: data
                .schemas
                .get(api_id)
                .map(|schema| schema.definition.clone())
                .unwrap_or_default(),
            resolvers: data.resolvers.get(api_id).cloned().unwrap_or_default(),
            data_sources: data.data_sources.get(api_id).cloned().unwrap_or_default(),
            api_keys: data.api_keys.get(api_id).cloned().unwrap_or_default(),
        })
    });
    found
}

/// The API id a data-plane host names: `<apiId>.appsync-api.<region>...` or
/// `<apiId>.appsync-realtime-api.<region>...`, with or without a port.
pub fn api_id_of_host(host: &str, realtime: bool) -> Option<String> {
    let host = host.split(':').next()?;
    let mut labels = host.split('.');
    let api_id = labels.next()?;
    let endpoint = labels.next()?;
    let wanted = if realtime {
        "appsync-realtime-api"
    } else {
        "appsync-api"
    };
    (endpoint == wanted && !api_id.is_empty()).then(|| api_id.to_string())
}

fn providers(api: &Value) -> Vec<(String, Value)> {
    let mut found = vec![(
        api.get("authenticationType")
            .and_then(Value::as_str)
            .unwrap_or("API_KEY")
            .to_string(),
        api.get("userPoolConfig").cloned().unwrap_or(Value::Null),
    )];
    if let Some(extra) = api
        .get("additionalAuthenticationProviders")
        .and_then(Value::as_array)
    {
        for provider in extra {
            if let Some(kind) = provider.get("authenticationType").and_then(Value::as_str) {
                found.push((
                    kind.to_string(),
                    provider
                        .get("userPoolConfig")
                        .cloned()
                        .unwrap_or(Value::Null),
                ));
            }
        }
    }
    found
}

/// Authenticate `credentials` against the API's providers; the error is the
/// `UnauthorizedException` message of a 401.
pub fn authenticate(
    snapshot: &ApiSnapshot,
    cognito: Option<&SharedCognitoState>,
    credentials: &Credentials,
) -> Result<Caller, String> {
    let providers = providers(&snapshot.api);
    let offers = |mode: AuthMode| providers.iter().any(|(kind, _)| kind == mode.wire());
    let source_ip = json!([credentials.source_ip.clone().unwrap_or_default()]);
    let authorization = credentials.authorization.as_deref().map(str::trim);

    if let Some(header) = authorization.filter(|h| h.starts_with("AWS4-HMAC-SHA256")) {
        if !offers(AuthMode::Iam) {
            return Err("You are not authorized to make this call.".to_string());
        }
        let _ = header;
        return Ok(Caller {
            mode: AuthMode::Iam,
            identity: json!({
                "accountId": credentials.account_id,
                "cognitoIdentityAuthProvider": null,
                "cognitoIdentityAuthType": null,
                "cognitoIdentityId": null,
                "cognitoIdentityPoolId": null,
                "sourceIp": source_ip,
                "username": credentials.access_key_id,
                "userArn": null,
            }),
        });
    }
    if let Some(key) = credentials.api_key.as_deref() {
        if offers(AuthMode::ApiKey) {
            let now = chrono::Utc::now().timestamp();
            let valid = snapshot.api_keys.values().any(|stored| {
                stored.get("id").and_then(Value::as_str) == Some(key)
                    && stored
                        .get("expires")
                        .and_then(Value::as_i64)
                        .is_none_or(|expires| expires > now)
            });
            if valid {
                return Ok(Caller {
                    mode: AuthMode::ApiKey,
                    identity: Value::Null,
                });
            }
        }
        return Err("You are not authorized to make this call.".to_string());
    }
    let Some(token) = authorization.filter(|h| !h.is_empty()) else {
        return Err("Valid authorization header not provided.".to_string());
    };
    let token = token.strip_prefix("Bearer ").unwrap_or(token);
    let mut last = "You are not authorized to make this call.".to_string();
    for (kind, config) in &providers {
        if kind != AuthMode::UserPools.wire() {
            continue;
        }
        match verify_user_pool_token(token, config, cognito) {
            Ok(claims) => {
                return Ok(Caller {
                    mode: AuthMode::UserPools,
                    identity: json!({
                        "sub": claims.get("sub").cloned().unwrap_or(Value::Null),
                        "issuer": claims.get("iss").cloned().unwrap_or(Value::Null),
                        "username": claims
                            .get("cognito:username")
                            .or_else(|| claims.get("username"))
                            .cloned()
                            .unwrap_or(Value::Null),
                        "claims": claims.clone(),
                        "sourceIp": source_ip,
                        "defaultAuthStrategy": "ALLOW",
                        "groups": claims.get("cognito:groups").cloned().unwrap_or(Value::Null),
                    }),
                })
            }
            Err(message) => last = message,
        }
    }
    Err(last)
}

fn verify_user_pool_token(
    token: &str,
    config: &Value,
    cognito: Option<&SharedCognitoState>,
) -> Result<Value, String> {
    let refused = || "You are not authorized to make this call.".to_string();
    let pool_id = config
        .get("userPoolId")
        .and_then(Value::as_str)
        .ok_or_else(refused)?;
    let region = config
        .get("awsRegion")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| pool_id.split('_').next().map(str::to_string))
        .ok_or_else(refused)?;
    let pem = cognito
        .and_then(|state| {
            let accounts = state.read();
            let pem = accounts
                .iter()
                .find_map(|(_, account)| account.user_pools.get(pool_id)?.signing_key_pem.clone());
            pem
        })
        .ok_or_else(refused)?;
    let (_, claims) = fakecloud_cognito::jwt::verify_rs256(token, &pem).map_err(|_| refused())?;
    let issuer = format!("https://cognito-idp.{region}.amazonaws.com/{pool_id}");
    if claims.get("iss").and_then(Value::as_str) != Some(issuer.as_str()) {
        return Err(refused());
    }
    if claims
        .get("exp")
        .and_then(Value::as_i64)
        .is_none_or(|exp| exp <= chrono::Utc::now().timestamp())
    {
        return Err("Token has expired.".to_string());
    }
    let client = match claims.get("token_use").and_then(Value::as_str) {
        Some("id") => claims.get("aud").and_then(Value::as_str),
        Some("access") => claims.get("client_id").and_then(Value::as_str),
        _ => None,
    }
    .ok_or_else(refused)?;
    if let Some(pattern) = config.get("appIdClientRegex").and_then(Value::as_str) {
        let admitted = regex::Regex::new(pattern)
            .map(|re| re.is_match(client))
            .unwrap_or(false);
        if !admitted {
            return Err(refused());
        }
    }
    Ok(claims)
}

/// The parts of a schema the data plane needs.
#[derive(Debug, Default)]
pub(crate) struct Schema {
    query: String,
    mutation: String,
    subscription: String,
    types: HashMap<String, TypeInfo>,
}

#[derive(Debug, Default)]
struct TypeInfo {
    auth: Vec<String>,
    fields: HashMap<String, FieldInfo>,
}

#[derive(Debug, Default)]
struct FieldInfo {
    auth: Vec<String>,
    subscribe_to: Vec<String>,
    type_name: String,
}

fn named_type(ty: &s::Type<'static, String>) -> String {
    match ty {
        s::Type::NamedType(name) => name.clone(),
        s::Type::ListType(inner) | s::Type::NonNullType(inner) => named_type(inner),
    }
}

fn auth_directives(directives: &[s::Directive<'static, String>]) -> Vec<String> {
    directives
        .iter()
        .filter(|d| AUTH_DIRECTIVES.contains(&d.name.as_str()))
        .map(|d| d.name.clone())
        .collect()
}

impl Schema {
    pub(crate) fn parse(sdl: &str) -> Result<Self, String> {
        let document = s::parse_schema::<String>(sdl)
            .map_err(|e| e.to_string())?
            .into_static();
        let mut schema = Schema {
            query: "Query".into(),
            mutation: "Mutation".into(),
            subscription: "Subscription".into(),
            types: HashMap::new(),
        };
        for definition in document.definitions {
            match definition {
                s::Definition::SchemaDefinition(roots) => {
                    if let Some(name) = roots.query {
                        schema.query = name;
                    }
                    if let Some(name) = roots.mutation {
                        schema.mutation = name;
                    }
                    if let Some(name) = roots.subscription {
                        schema.subscription = name;
                    }
                }
                s::Definition::TypeDefinition(s::TypeDefinition::Object(object)) => {
                    let mut info = TypeInfo {
                        auth: auth_directives(&object.directives),
                        fields: HashMap::new(),
                    };
                    for field in object.fields {
                        let subscribe_to = field
                            .directives
                            .iter()
                            .filter(|d| d.name == "aws_subscribe")
                            .flat_map(|d| d.arguments.iter())
                            .filter(|(name, _)| name == "mutations")
                            .flat_map(|(_, value)| match value {
                                q::Value::List(items) => items
                                    .iter()
                                    .filter_map(|item| match item {
                                        q::Value::String(name) => Some(name.clone()),
                                        _ => None,
                                    })
                                    .collect::<Vec<_>>(),
                                _ => Vec::new(),
                            })
                            .collect();
                        info.fields.insert(
                            field.name.clone(),
                            FieldInfo {
                                auth: auth_directives(&field.directives),
                                subscribe_to,
                                type_name: named_type(&field.field_type),
                            },
                        );
                    }
                    schema.types.insert(object.name.clone(), info);
                }
                _ => {}
            }
        }
        Ok(schema)
    }

    /// AppSync's rule: a field's own auth directives decide; without any, its
    /// type's decide; without either, only the API's default mode is allowed.
    fn allows(&self, default_mode: &str, type_name: &str, field: &str, mode: AuthMode) -> bool {
        let Some(info) = self.types.get(type_name) else {
            return mode.wire() == default_mode;
        };
        let field_auth = info
            .fields
            .get(field)
            .map(|f| f.auth.as_slice())
            .unwrap_or(&[]);
        let rules = if !field_auth.is_empty() {
            field_auth
        } else {
            info.auth.as_slice()
        };
        if rules.is_empty() {
            mode.wire() == default_mode
        } else {
            rules.iter().any(|rule| rule == mode.directive())
        }
    }

    fn field_type(&self, type_name: &str, field: &str) -> Option<&str> {
        self.types
            .get(type_name)?
            .fields
            .get(field)
            .map(|f| f.type_name.as_str())
    }

    pub(crate) fn subscribes_to(&self, field: &str) -> Vec<String> {
        self.types
            .get(&self.subscription)
            .and_then(|t| t.fields.get(field))
            .map(|f| f.subscribe_to.clone())
            .unwrap_or_default()
    }
}

/// A mutation result to deliver to subscriptions.
#[derive(Debug, Clone)]
pub struct Published {
    pub field: String,
    pub value: Value,
}

/// The response document of one request and what it asks the realtime side to do.
#[derive(Debug, Clone)]
pub struct Execution {
    pub response: Value,
    pub published: Vec<Published>,
    pub invalidations: Vec<Value>,
}

struct Request<'a> {
    snapshot: &'a ApiSnapshot,
    schema: &'a Schema,
    caller: &'a Caller,
    variables: &'a Map<String, Value>,
    fragments: &'a [Fragment],
    errors: Vec<Value>,
    invalidations: Vec<Value>,
}

fn location(position: graphql_parser::Pos) -> Value {
    json!([{ "line": position.line, "column": position.column, "sourceName": null }])
}

fn error(
    path: &[Value],
    position: graphql_parser::Pos,
    message: &str,
    error_type: Option<&str>,
) -> Value {
    json!({
        "path": path,
        "data": null,
        "errorType": error_type,
        "errorInfo": null,
        "locations": location(position),
        "message": message,
    })
}

fn default_mode(snapshot: &ApiSnapshot) -> String {
    snapshot
        .api
        .get("authenticationType")
        .and_then(Value::as_str)
        .unwrap_or("API_KEY")
        .to_string()
}

fn value_of(value: &q::Value<'static, String>, variables: &Map<String, Value>) -> Value {
    match value {
        q::Value::Variable(name) => variables.get(name).cloned().unwrap_or(Value::Null),
        q::Value::Int(number) => number.as_i64().map(Value::from).unwrap_or(Value::Null),
        q::Value::Float(number) => json!(number),
        q::Value::String(text) => json!(text),
        q::Value::Boolean(flag) => json!(flag),
        q::Value::Null => Value::Null,
        q::Value::Enum(name) => json!(name),
        q::Value::List(items) => {
            Value::Array(items.iter().map(|i| value_of(i, variables)).collect())
        }
        q::Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(k, v)| (k.clone(), value_of(v, variables)))
                .collect(),
        ),
    }
}

fn arguments(field: &QueryField, variables: &Map<String, Value>) -> Value {
    Value::Object(
        field
            .arguments
            .iter()
            .map(|(name, value)| (name.clone(), value_of(value, variables)))
            .collect(),
    )
}

/// The fields a selection set selects on `type_name`, fragments expanded.
fn fields_of<'f>(
    selection: &'f SelectionSet,
    type_name: &str,
    fragments: &'f [Fragment],
) -> Vec<&'f QueryField> {
    let mut found = Vec::new();
    for item in &selection.items {
        match item {
            q::Selection::Field(field) => found.push(field),
            q::Selection::InlineFragment(inline) => {
                let applies = match &inline.type_condition {
                    Some(q::TypeCondition::On(name)) => name == type_name,
                    None => true,
                };
                if applies {
                    found.extend(fields_of(&inline.selection_set, type_name, fragments));
                }
            }
            q::Selection::FragmentSpread(spread) => {
                if let Some(fragment) = fragments.iter().find(|f| f.name == spread.fragment_name) {
                    let q::TypeCondition::On(name) = &fragment.type_condition;
                    if name == type_name {
                        found.extend(fields_of(&fragment.selection_set, type_name, fragments));
                    }
                }
            }
        }
    }
    found
}

fn response_key(field: &QueryField) -> String {
    field.alias.clone().unwrap_or_else(|| field.name.clone())
}

impl Request<'_> {
    /// Shape `value` (of `type_name`) to `selection`, authorizing each field.
    fn project(
        &mut self,
        value: &Value,
        type_name: &str,
        selection: &SelectionSet,
        path: &[Value],
    ) -> Value {
        match value {
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .enumerate()
                    .map(|(i, item)| {
                        let mut at = path.to_vec();
                        at.push(json!(i));
                        self.project(item, type_name, selection, &at)
                    })
                    .collect(),
            ),
            Value::Object(object) if !selection.items.is_empty() => {
                let mut out = Map::new();
                let default = default_mode(self.snapshot);
                for field in fields_of(selection, type_name, self.fragments) {
                    let key = response_key(field);
                    let mut at = path.to_vec();
                    at.push(json!(key));
                    if field.name == "__typename" {
                        out.insert(key, json!(type_name));
                        continue;
                    }
                    if !self
                        .schema
                        .allows(&default, type_name, &field.name, self.caller.mode)
                    {
                        self.errors.push(error(
                            &at,
                            field.position,
                            &format!(
                                "Not Authorized to access {} on type {type_name}",
                                field.name
                            ),
                            Some("Unauthorized"),
                        ));
                        out.insert(key, Value::Null);
                        continue;
                    }
                    let child_type = self
                        .schema
                        .field_type(type_name, &field.name)
                        .unwrap_or_default()
                        .to_string();
                    let child = object.get(&field.name).cloned().unwrap_or(Value::Null);
                    out.insert(
                        key,
                        self.project(&child, &child_type, &field.selection_set, &at),
                    );
                }
                Value::Object(out)
            }
            other => other.clone(),
        }
    }

    fn handler(&mut self, code: &str, name: &str, ctx: &Value, path: &[Value]) -> HandlerRun {
        let run = run_handler(code, name, ctx, self.caller.mode.util_name());
        for appended in &run.appended_errors {
            let mut entry = appended.clone();
            if let Some(object) = entry.as_object_mut() {
                object.insert("path".into(), json!(path));
                object.insert("locations".into(), Value::Null);
            }
            self.errors.push(entry);
        }
        self.invalidations.extend(run.invalidations.iter().cloned());
        run
    }

    /// Resolve one root field: authorize it, run its resolver, project the result.
    fn root_field(&mut self, type_name: &str, field: &QueryField) -> (Value, bool) {
        let key = response_key(field);
        let path = vec![json!(key)];
        let unauthorized = |field: &QueryField| {
            error(
                &path,
                field.position,
                &format!(
                    "Not Authorized to access {} on type {type_name}",
                    field.name
                ),
                Some("Unauthorized"),
            )
        };
        if field.name == "__typename" {
            return (json!(type_name), true);
        }
        if !self.schema.allows(
            &default_mode(self.snapshot),
            type_name,
            &field.name,
            self.caller.mode,
        ) {
            self.errors.push(unauthorized(field));
            return (Value::Null, false);
        }
        let Some(resolver) = self
            .snapshot
            .resolvers
            .get(&format!("{type_name}::{}", field.name))
        else {
            return (Value::Null, true);
        };
        let runtime = resolver
            .get("runtime")
            .and_then(|r| r.get("name"))
            .and_then(Value::as_str);
        let kind = resolver
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("UNIT");
        let source_type = resolver
            .get("dataSourceName")
            .and_then(Value::as_str)
            .and_then(|name| self.snapshot.data_sources.get(name))
            .and_then(|source| source.get("type"))
            .and_then(Value::as_str);
        let code = resolver.get("code").and_then(Value::as_str);
        let (Some("APPSYNC_JS"), "UNIT", Some("NONE"), Some(code)) =
            (runtime, kind, source_type, code)
        else {
            self.errors.push(error(
                &path,
                field.position,
                &format!(
                    "fakecloud's AppSync data plane runs UNIT APPSYNC_JS resolvers on NONE data sources; {type_name}.{} is a {kind} resolver with runtime {} on a {} data source",
                    field.name,
                    runtime.unwrap_or("VTL"),
                    source_type.unwrap_or("missing"),
                ),
                Some("UnsupportedOperation"),
            ));
            return (Value::Null, false);
        };
        let code = code.to_string();
        let arguments = arguments(field, self.variables);
        let return_type = self
            .schema
            .field_type(type_name, &field.name)
            .unwrap_or_default()
            .to_string();
        let ctx = json!({
            "arguments": arguments,
            "args": arguments,
            "identity": self.caller.identity,
            "source": null,
            "stash": {},
            "result": null,
            "prev": { "result": null },
            "error": null,
            "info": {
                "fieldName": field.name,
                "parentTypeName": type_name,
                "variables": self.variables,
                "selectionSetList": fields_of(&field.selection_set, &return_type, self.fragments)
                    .iter()
                    .map(|f| f.name.clone())
                    .collect::<Vec<_>>(),
            },
        });
        let request = self.handler(&code, "request", &ctx, &path);
        let value = match request.outcome {
            Outcome::Returned(payload) => {
                let result = payload.get("payload").cloned().unwrap_or(Value::Null);
                let mut ctx = request.context;
                ctx["result"] = result.clone();
                ctx["prev"] = json!({ "result": result });
                let response = self.handler(&code, "response", &ctx, &path);
                match response.outcome {
                    Outcome::Returned(value) | Outcome::EarlyReturn(value) => Ok(value),
                    other => Err(other),
                }
            }
            Outcome::EarlyReturn(value) => Ok(value),
            other => Err(other),
        };
        match value {
            Ok(value) => {
                let projected = self.project(&value, &return_type, &field.selection_set, &path);
                (projected, true)
            }
            Err(Outcome::Error(detail)) => {
                let mut entry = error(
                    &path,
                    field.position,
                    detail.get("message").and_then(Value::as_str).unwrap_or(""),
                    detail.get("errorType").and_then(Value::as_str),
                );
                entry["data"] = detail.get("data").cloned().unwrap_or(Value::Null);
                entry["errorInfo"] = detail.get("errorInfo").cloned().unwrap_or(Value::Null);
                self.errors.push(entry);
                (Value::Null, false)
            }
            Err(Outcome::Unauthorized) => {
                self.errors.push(unauthorized(field));
                (Value::Null, false)
            }
            Err(Outcome::Failed(message)) => {
                self.errors
                    .push(error(&path, field.position, &message, Some("Code")));
                (Value::Null, false)
            }
            Err(Outcome::Returned(_) | Outcome::EarlyReturn(_)) => unreachable!("handled above"),
        }
    }
}

struct Operation {
    kind: OperationKind,
    selection: SelectionSet,
    variables: Map<String, Value>,
    fragments: Vec<Fragment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperationKind {
    Query,
    Mutation,
    Subscription,
}

fn validation_error(message: String) -> Value {
    json!({ "data": null, "errors": [{ "errorType": "ValidationError", "message": message, "locations": [] }] })
}

fn operation(body: &Value) -> Result<Operation, Value> {
    let query = body
        .get("query")
        .and_then(Value::as_str)
        .ok_or_else(|| validation_error("Validation error: the request has no query".into()))?;
    let document: Document = q::parse_query::<String>(query)
        .map_err(|e| validation_error(format!("Validation error of type InvalidSyntax: {e}")))?
        .into_static();
    let wanted = body.get("operationName").and_then(Value::as_str);
    let mut fragments = Vec::new();
    let mut operations = Vec::new();
    for definition in document.definitions {
        match definition {
            q::Definition::Fragment(fragment) => fragments.push(fragment),
            q::Definition::Operation(operation) => operations.push(operation),
        }
    }
    let named = |operation: &q::OperationDefinition<'static, String>| match operation {
        q::OperationDefinition::SelectionSet(_) => None,
        q::OperationDefinition::Query(o) => o.name.clone(),
        q::OperationDefinition::Mutation(o) => o.name.clone(),
        q::OperationDefinition::Subscription(o) => o.name.clone(),
    };
    let chosen = match wanted {
        Some(name) => operations
            .into_iter()
            .find(|o| named(o).as_deref() == Some(name))
            .ok_or_else(|| {
                validation_error(format!(
                    "Validation error: unknown operation named '{name}'"
                ))
            })?,
        None if operations.len() == 1 => operations.remove(0),
        None => return Err(validation_error(
            "Validation error: operationName is required when the document has several operations"
                .into(),
        )),
    };
    let given = body
        .get("variables")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let with_defaults = |definitions: &[q::VariableDefinition<'static, String>]| {
        let mut variables = given.clone();
        for definition in definitions {
            if !variables.contains_key(&definition.name) {
                if let Some(default) = &definition.default_value {
                    variables.insert(definition.name.clone(), value_of(default, &Map::new()));
                }
            }
        }
        variables
    };
    let (kind, selection, variables) = match chosen {
        q::OperationDefinition::SelectionSet(selection) => {
            (OperationKind::Query, selection, given.clone())
        }
        q::OperationDefinition::Query(o) => (
            OperationKind::Query,
            o.selection_set,
            with_defaults(&o.variable_definitions),
        ),
        q::OperationDefinition::Mutation(o) => (
            OperationKind::Mutation,
            o.selection_set,
            with_defaults(&o.variable_definitions),
        ),
        q::OperationDefinition::Subscription(o) => (
            OperationKind::Subscription,
            o.selection_set,
            with_defaults(&o.variable_definitions),
        ),
    };
    Ok(Operation {
        kind,
        selection,
        variables,
        fragments,
    })
}

/// Execute a query or mutation request body (`{query, variables, operationName}`).
pub fn execute(snapshot: &ApiSnapshot, caller: &Caller, body: &Value) -> Execution {
    let done = |response| Execution {
        response,
        published: Vec::new(),
        invalidations: Vec::new(),
    };
    let schema = match Schema::parse(&snapshot.schema) {
        Ok(schema) => schema,
        Err(message) => {
            return done(validation_error(format!(
                "The API's schema could not be parsed: {message}"
            )))
        }
    };
    let operation = match operation(body) {
        Ok(operation) => operation,
        Err(response) => return done(response),
    };
    let type_name = match operation.kind {
        OperationKind::Query => schema.query.clone(),
        OperationKind::Mutation => schema.mutation.clone(),
        OperationKind::Subscription => {
            return done(validation_error(
                "Validation error: subscriptions are served by the realtime endpoint".into(),
            ))
        }
    };
    let mut request = Request {
        snapshot,
        schema: &schema,
        caller,
        variables: &operation.variables,
        fragments: &operation.fragments,
        errors: Vec::new(),
        invalidations: Vec::new(),
    };
    let mut data = Map::new();
    let mut published = Vec::new();
    for field in fields_of(&operation.selection, &type_name, &operation.fragments) {
        let (value, resolved) = request.root_field(&type_name, field);
        if operation.kind == OperationKind::Mutation && resolved && !value.is_null() {
            published.push(Published {
                field: field.name.clone(),
                value: value.clone(),
            });
        }
        data.insert(response_key(field), value);
    }
    let mut response = json!({ "data": data });
    if !request.errors.is_empty() {
        response["errors"] = Value::Array(request.errors);
    }
    Execution {
        response,
        published,
        invalidations: request.invalidations,
    }
}

/// A subscription the realtime side registers: what it listens to, how its
/// deliveries are shaped and which filters it passes.
#[derive(Debug, Clone)]
pub struct Subscription {
    pub field: QueryField,
    pub fragments: Vec<Fragment>,
    pub mutations: Vec<String>,
    pub filter: Option<Value>,
    pub invalidation_filter: Option<Value>,
}

/// Start a subscription from a realtime `start` message's `data`
/// (`{query, variables}`); the error is the `errors` list AppSync answers with.
pub fn subscribe(
    snapshot: &ApiSnapshot,
    caller: &Caller,
    data: &Value,
) -> Result<Subscription, Value> {
    let errors = |message: String, error_type: &str| json!([{ "errorType": error_type, "message": message }]);
    let schema = Schema::parse(&snapshot.schema).map_err(|m| errors(m, "ValidationError"))?;
    let operation = operation(data).map_err(|response| response["errors"].clone())?;
    if operation.kind != OperationKind::Subscription {
        return Err(errors(
            "Validation error: the operation is not a subscription".into(),
            "ValidationError",
        ));
    }
    let type_name = schema.subscription.clone();
    let fields = fields_of(&operation.selection, &type_name, &operation.fragments);
    let [field] = fields.as_slice() else {
        return Err(errors(
            "Validation error: a subscription selects exactly one field".into(),
            "ValidationError",
        ));
    };
    let field = (*field).clone();
    if !schema
        .types
        .get(&type_name)
        .is_some_and(|t| t.fields.contains_key(&field.name))
    {
        return Err(errors(
            format!("Validation error: {type_name} has no field {}", field.name),
            "ValidationError",
        ));
    }
    let mut request = Request {
        snapshot,
        schema: &schema,
        caller,
        variables: &operation.variables,
        fragments: &operation.fragments,
        errors: Vec::new(),
        invalidations: Vec::new(),
    };
    let (_, resolved) = request.root_field(&type_name, &field);
    if !resolved {
        let reported: Vec<Value> = request
            .errors
            .iter()
            .map(|e| json!({ "errorType": e["errorType"], "message": e["message"] }))
            .collect();
        return Err(Value::Array(reported));
    }
    let (filter, invalidation_filter) =
        subscription_filters(snapshot, caller, &type_name, &field, &operation.variables);
    let filter = filter.or_else(|| argument_filter(&field, &operation.variables));
    Ok(Subscription {
        mutations: schema.subscribes_to(&field.name),
        field,
        fragments: operation.fragments,
        filter,
        invalidation_filter,
    })
}

/// The filters the subscription's resolver set, from its `response` handler.
fn subscription_filters(
    snapshot: &ApiSnapshot,
    caller: &Caller,
    type_name: &str,
    field: &QueryField,
    variables: &Map<String, Value>,
) -> (Option<Value>, Option<Value>) {
    let Some(code) = snapshot
        .resolvers
        .get(&format!("{type_name}::{}", field.name))
        .and_then(|r| r.get("code"))
        .and_then(Value::as_str)
    else {
        return (None, None);
    };
    let arguments = arguments(field, variables);
    let ctx = json!({
        "arguments": arguments, "args": arguments, "identity": caller.identity,
        "source": null, "stash": {}, "result": null, "prev": { "result": null }, "error": null,
        "info": { "fieldName": field.name, "parentTypeName": type_name, "variables": variables },
    });
    let run = run_handler(code, "response", &ctx, caller.mode.util_name());
    (run.subscription_filter, run.invalidation_filter)
}

/// Without an enhanced filter, AppSync delivers what equals the subscription's
/// non-null arguments.
fn argument_filter(field: &QueryField, variables: &Map<String, Value>) -> Option<Value> {
    let filters: Vec<Value> = field
        .arguments
        .iter()
        .map(|(name, value)| (name, value_of(value, variables)))
        .filter(|(_, value)| !value.is_null())
        .map(|(name, value)| json!({ "fieldName": name, "operator": "eq", "value": value }))
        .collect();
    (!filters.is_empty()).then(|| json!({ "filterGroup": [{ "filters": filters }] }))
}

/// The `data` payload a subscription receives for a published mutation result,
/// or `None` when it does not listen to that mutation or its filter refuses it.
pub fn delivery(
    snapshot: &ApiSnapshot,
    subscription: &Subscription,
    published: &Published,
    caller: &Caller,
) -> Option<Value> {
    if !subscription.mutations.contains(&published.field) {
        return None;
    }
    if let Some(filter) = &subscription.filter {
        if !filter::passes(filter, &published.value) {
            return None;
        }
    }
    let schema = Schema::parse(&snapshot.schema).ok()?;
    let mut request = Request {
        snapshot,
        schema: &schema,
        caller,
        variables: &Map::new(),
        fragments: &subscription.fragments,
        errors: Vec::new(),
        invalidations: Vec::new(),
    };
    let type_name = schema
        .field_type(&schema.subscription, &subscription.field.name)
        .unwrap_or_default()
        .to_string();
    let key = response_key(&subscription.field);
    let value = request.project(
        &published.value,
        &type_name,
        &subscription.field.selection_set,
        &[json!(key)],
    );
    Some(json!({ "data": { key: value } }))
}

#[cfg(test)]
mod tests;
