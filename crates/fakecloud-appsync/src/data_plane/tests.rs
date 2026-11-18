use super::*;

const SCHEMA: &str = r#"
schema { query: Query mutation: Mutation subscription: Subscription }
type Hint @aws_iam @aws_cognito_user_pools { tenant: String! resource: String! audience: String! subject: ID }
input HintInput { tenant: String! resource: String! audience: String! subject: ID }
type Invalidation @aws_iam { sub: ID! }
type Mutation {
  publishHint(input: HintInput!): Hint @aws_iam
  invalidateUser(sub: ID!): Invalidation @aws_iam
}
type Subscription {
  onTenant: Hint @aws_subscribe(mutations: ["publishHint"]) @aws_cognito_user_pools
  onUser: Hint @aws_subscribe(mutations: ["publishHint"]) @aws_cognito_user_pools
}
type Query { health: String @aws_iam }
"#;

const PUBLISH: &str = r#"
import { util } from '@aws-appsync/utils';
export function request(ctx) {
  if (util.authType() !== 'IAM Authorization') { util.unauthorized(); }
  if (!util.matches('^[a-z0-9][a-z0-9-]{0,39}$', ctx.args.input.tenant)) { util.error('Malformed tenant', 'InvalidHint'); }
  return { payload: ctx.args.input };
}
export function response(ctx) { return ctx.result; }
"#;

const INVALIDATE: &str = r#"
import { util, extensions } from '@aws-appsync/utils';
export function request(ctx) { return { payload: { sub: ctx.args.sub } }; }
export function response(ctx) {
  extensions.invalidateSubscriptions({ subscriptionField: 'onTenant', payload: { sub: ctx.args.sub } });
  return ctx.result;
}
"#;

const ON_TENANT: &str = r#"
import { util, extensions } from '@aws-appsync/utils';
function scope(ctx) {
  if (util.authType() !== 'User Pool Authorization' || ctx.identity.claims.token_use !== 'id') { util.unauthorized(); }
  return { subject: ctx.identity.sub, tenant: ctx.identity.claims['custom:tenant'] };
}
export function request(ctx) { scope(ctx); return { payload: null }; }
export function response(ctx) {
  const admitted = scope(ctx);
  extensions.setSubscriptionFilter(util.transform.toSubscriptionFilter({ tenant: { eq: admitted.tenant }, audience: { eq: 'tenant' } }));
  extensions.setSubscriptionInvalidationFilter(util.transform.toSubscriptionFilter({ sub: { eq: admitted.subject } }));
  return null;
}
"#;

const HEALTH: &str = "export function request() { return { payload: 'ok' }; } export function response(ctx) { return ctx.result; }";

const PUBLISH_QUERY: &str = "mutation P($input: HintInput!) { publishHint(input: $input) { tenant resource audience subject __typename } }";

fn resolver(type_name: &str, field: &str, code: &str) -> (String, Value) {
    (
        format!("{type_name}::{field}"),
        json!({ "typeName": type_name, "fieldName": field, "kind": "UNIT", "dataSourceName": "none",
                "runtime": { "name": "APPSYNC_JS", "runtimeVersion": "1.0.0" }, "code": code }),
    )
}

fn api() -> ApiSnapshot {
    ApiSnapshot {
        api_id: "api1".into(),
        api: json!({
            "apiId": "api1",
            "authenticationType": "AWS_IAM",
            "additionalAuthenticationProviders": [{
                "authenticationType": "AMAZON_COGNITO_USER_POOLS",
                "userPoolConfig": { "userPoolId": "us-east-1_pool", "awsRegion": "us-east-1", "appIdClientRegex": "^client$" }
            }, { "authenticationType": "API_KEY" }]
        }),
        schema: SCHEMA.into(),
        resolvers: [
            resolver("Mutation", "publishHint", PUBLISH),
            resolver("Mutation", "invalidateUser", INVALIDATE),
            resolver("Subscription", "onTenant", ON_TENANT),
            resolver("Query", "health", HEALTH),
        ]
        .into_iter()
        .collect(),
        data_sources: [(
            "none".to_string(),
            json!({ "name": "none", "type": "NONE" }),
        )]
        .into_iter()
        .collect(),
        api_keys: [(
            "k1".to_string(),
            json!({ "id": "da2-key", "expires": 4_102_444_800i64 }),
        )]
        .into_iter()
        .collect(),
    }
}

fn iam() -> Caller {
    Caller {
        mode: AuthMode::Iam,
        identity: json!({ "accountId": "123456789012" }),
    }
}

fn person(tenant: &str, sub: &str) -> Caller {
    Caller {
        mode: AuthMode::UserPools,
        identity: json!({ "sub": sub, "claims": { "token_use": "id", "custom:tenant": tenant, "sub": sub } }),
    }
}

fn hint(tenant: &str, audience: &str) -> Value {
    json!({ "query": PUBLISH_QUERY, "variables": { "input": { "tenant": tenant, "resource": "study", "audience": audience } } })
}

#[test]
fn an_iam_mutation_runs_its_resolver_and_is_published() {
    let run = execute(&api(), &iam(), &hint("acme", "tenant"));
    assert_eq!(
        run.response,
        json!({ "data": { "publishHint": { "tenant": "acme", "resource": "study", "audience": "tenant", "subject": null, "__typename": "Hint" } } })
    );
    assert_eq!(run.published.len(), 1);
    assert_eq!(run.published[0].field, "publishHint");
}

#[test]
fn directive_rules_refuse_the_other_auth_modes() {
    let run = execute(&api(), &person("acme", "s-1"), &hint("acme", "tenant"));
    assert_eq!(run.response["data"]["publishHint"], Value::Null);
    assert_eq!(
        run.response["errors"][0]["errorType"],
        json!("Unauthorized")
    );
    assert_eq!(
        run.response["errors"][0]["message"],
        json!("Not Authorized to access publishHint on type Mutation")
    );
    assert!(run.published.is_empty());
    let key = Caller {
        mode: AuthMode::ApiKey,
        identity: Value::Null,
    };
    assert_eq!(
        execute(&api(), &key, &json!({ "query": "{ health }" })).response["errors"][0]["errorType"],
        json!("Unauthorized")
    );
    assert_eq!(
        execute(&api(), &iam(), &json!({ "query": "{ health }" })).response,
        json!({ "data": { "health": "ok" } })
    );
}

#[test]
fn util_error_becomes_a_graphql_error_with_its_type() {
    let run = execute(&api(), &iam(), &hint("Not Valid", "tenant"));
    assert_eq!(run.response["data"]["publishHint"], Value::Null);
    let error = &run.response["errors"][0];
    assert_eq!(
        (
            error["errorType"].clone(),
            error["message"].clone(),
            error["path"].clone()
        ),
        (
            json!("InvalidHint"),
            json!("Malformed tenant"),
            json!(["publishHint"])
        )
    );
}

#[test]
fn malformed_documents_and_subscriptions_over_http_are_validation_errors() {
    assert_eq!(
        execute(&api(), &iam(), &json!({ "query": "mutation {" })).response["errors"][0]
            ["errorType"],
        json!("ValidationError")
    );
    assert_eq!(
        execute(
            &api(),
            &iam(),
            &json!({ "query": "subscription { onTenant { tenant } }" })
        )
        .response["errors"][0]["errorType"],
        json!("ValidationError")
    );
}

#[test]
fn a_resolver_fakecloud_cannot_run_says_so() {
    let mut snapshot = api();
    snapshot.data_sources.insert(
        "none".into(),
        json!({ "name": "none", "type": "AMAZON_DYNAMODB" }),
    );
    let run = execute(&snapshot, &iam(), &hint("acme", "tenant"));
    assert_eq!(
        run.response["errors"][0]["errorType"],
        json!("UnsupportedOperation")
    );
}

#[test]
fn subscriptions_receive_only_what_their_filter_passes() {
    let snapshot = api();
    let mine = subscribe(
        &snapshot,
        &person("acme", "s-1"),
        &json!({ "query": "subscription { onTenant { tenant resource } }" }),
    )
    .unwrap();
    assert_eq!(mine.mutations, vec!["publishHint".to_string()]);
    let published = |tenant: &str, audience: &str| {
        execute(&snapshot, &iam(), &hint(tenant, audience))
            .published
            .remove(0)
    };
    assert_eq!(
        delivery(
            &snapshot,
            &mine,
            &published("acme", "tenant"),
            &person("acme", "s-1")
        ),
        Some(json!({ "data": { "onTenant": { "tenant": "acme", "resource": "study" } } }))
    );
    assert_eq!(
        delivery(
            &snapshot,
            &mine,
            &published("other", "tenant"),
            &person("acme", "s-1")
        ),
        None
    );
    assert_eq!(
        delivery(
            &snapshot,
            &mine,
            &published("acme", "person"),
            &person("acme", "s-1")
        ),
        None
    );
}

#[test]
fn a_subscription_resolver_can_refuse_the_caller() {
    let access_token = Caller {
        mode: AuthMode::UserPools,
        identity: json!({ "sub": "s-1", "claims": { "token_use": "access", "custom:tenant": "acme" } }),
    };
    let refused = subscribe(
        &api(),
        &access_token,
        &json!({ "query": "subscription { onTenant { tenant } }" }),
    )
    .unwrap_err();
    assert_eq!(refused[0]["errorType"], json!("Unauthorized"));
    let iam_refused = subscribe(
        &api(),
        &iam(),
        &json!({ "query": "subscription { onTenant { tenant } }" }),
    )
    .unwrap_err();
    assert_eq!(iam_refused[0]["errorType"], json!("Unauthorized"));
}

#[test]
fn invalidation_ends_the_matching_subscriptions() {
    let snapshot = api();
    let realtime = realtime::Realtime::new();
    let (sender, mut received) = tokio::sync::mpsc::unbounded_channel();
    let subscription = subscribe(
        &snapshot,
        &person("acme", "s-1"),
        &json!({ "query": "subscription { onTenant { tenant } }" }),
    )
    .unwrap();
    realtime.register_for_test(
        &snapshot.api_id,
        "sub-1",
        person("acme", "s-1"),
        subscription,
        sender,
    );
    realtime.publish(
        &snapshot,
        &execute(&snapshot, &iam(), &hint("acme", "tenant")).published,
    );
    assert_eq!(
        received.try_recv().unwrap(),
        json!({ "id": "sub-1", "type": "data", "payload": { "data": { "onTenant": { "tenant": "acme" } } } })
    );
    let other = execute(
        &snapshot,
        &iam(),
        &json!({ "query": "mutation { invalidateUser(sub: \"s-2\") { sub } }" }),
    );
    realtime.invalidate(&snapshot.api_id, &other.invalidations);
    assert_eq!(realtime.count(&snapshot.api_id), 1);
    let mine = execute(
        &snapshot,
        &iam(),
        &json!({ "query": "mutation { invalidateUser(sub: \"s-1\") { sub } }" }),
    );
    assert_eq!(
        mine.response,
        json!({ "data": { "invalidateUser": { "sub": "s-1" } } })
    );
    realtime.invalidate(&snapshot.api_id, &mine.invalidations);
    assert_eq!(
        received.try_recv().unwrap(),
        json!({ "id": "sub-1", "type": "complete" })
    );
    assert_eq!(realtime.count(&snapshot.api_id), 0);
}

#[test]
fn authentication_follows_the_request_credentials() {
    let snapshot = api();
    let base = Credentials {
        account_id: "123456789012".into(),
        ..Credentials::default()
    };
    assert_eq!(
        authenticate(&snapshot, None, &base).unwrap_err(),
        "Valid authorization header not provided."
    );
    let signed = Credentials {
        authorization: Some("AWS4-HMAC-SHA256 Credential=AKID/...".into()),
        access_key_id: Some("AKID".into()),
        ..base.clone()
    };
    assert_eq!(
        authenticate(&snapshot, None, &signed).unwrap().mode,
        AuthMode::Iam
    );
    let key = Credentials {
        api_key: Some("da2-key".into()),
        ..base.clone()
    };
    assert_eq!(
        authenticate(&snapshot, None, &key).unwrap().mode,
        AuthMode::ApiKey
    );
    let wrong_key = Credentials {
        api_key: Some("da2-other".into()),
        ..base.clone()
    };
    assert!(authenticate(&snapshot, None, &wrong_key).is_err());
    let token = Credentials {
        authorization: Some("eyJ.not.verifiable".into()),
        ..base
    };
    assert!(authenticate(&snapshot, None, &token).is_err());
    assert_eq!(
        api_id_of_host("api1.appsync-api.us-east-1.amazonaws.com:443", false),
        Some("api1".into())
    );
    assert_eq!(
        api_id_of_host("api1.appsync-realtime-api.us-east-1.amazonaws.com", true),
        Some("api1".into())
    );
    assert_eq!(
        api_id_of_host("api1.execute-api.us-east-1.amazonaws.com", false),
        None
    );
}
