//! Runs one `APPSYNC_JS` resolver handler (`request` or `response`) in
//! `boa_engine`, the way AppSync's JS runtime does: the resolver code is an ES
//! module that imports `@aws-appsync/utils`, and the handler is called with the
//! resolver context. The utils module (`appsync_utils.js`) records what the
//! handler asks of AppSync on a host object, which this module reads back.
//!
//! A run is bounded by boa's loop-iteration and recursion limits and happens on
//! the calling thread; callers run it on a blocking thread.

use std::rc::Rc;

use boa_engine::builtins::promise::PromiseState;
use boa_engine::module::MapModuleLoader;
use boa_engine::{js_string, Context, JsValue, Module, Source};
use serde_json::{json, Value};

const UTILS_SOURCE: &str = include_str!("appsync_utils.js");
const UTILS_SPECIFIER: &str = "@aws-appsync/utils";
const LOOP_ITERATION_LIMIT: u64 = 1_000_000;
const RECURSION_LIMIT: usize = 400;

/// How a handler ended.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// It returned `value`.
    Returned(Value),
    /// It called `util.error`: `{message, errorType, data, errorInfo}`.
    Error(Value),
    /// It called `util.unauthorized`.
    Unauthorized,
    /// It called `runtime.earlyReturn(value)`.
    EarlyReturn(Value),
    /// The code failed to load or threw: the message AppSync reports.
    Failed(String),
}

/// One handler run: how it ended, the context as the handler left it (its
/// `stash` carries to the next handler), and what it asked of AppSync.
#[derive(Debug, Clone, PartialEq)]
pub struct HandlerRun {
    pub outcome: Outcome,
    pub context: Value,
    pub appended_errors: Vec<Value>,
    pub subscription_filter: Option<Value>,
    pub invalidation_filter: Option<Value>,
    pub invalidations: Vec<Value>,
}

/// Run `handler` of the resolver `code` with `context`, under `auth_type`
/// (AppSync's `util.authType()` string, e.g. `IAM Authorization`).
pub fn run_handler(code: &str, handler: &str, context: &Value, auth_type: &str) -> HandlerRun {
    let failed = |message: String| HandlerRun {
        outcome: Outcome::Failed(message),
        context: context.clone(),
        appended_errors: Vec::new(),
        subscription_filter: None,
        invalidation_filter: None,
        invalidations: Vec::new(),
    };
    let loader = Rc::new(MapModuleLoader::new());
    let mut js = match Context::builder().module_loader(loader.clone()).build() {
        Ok(js) => js,
        Err(error) => return failed(error.to_string()),
    };
    js.runtime_limits_mut()
        .set_loop_iteration_limit(LOOP_ITERATION_LIMIT);
    js.runtime_limits_mut().set_recursion_limit(RECURSION_LIMIT);

    let host = json!({
        "authType": auth_type,
        "errors": [],
        "subscriptionFilter": null,
        "invalidationFilter": null,
        "invalidations": [],
    });
    let installed = JsValue::from_json(&host, &mut js).and_then(|host| {
        js.global_object()
            .set(js_string!("__appsync"), host, false, &mut js)
            .map(|_| ())
    });
    if let Err(error) = installed {
        return failed(error.to_string());
    }
    let utils = match Module::parse(Source::from_bytes(UTILS_SOURCE.as_bytes()), None, &mut js) {
        Ok(module) => module,
        Err(error) => return failed(error.to_string()),
    };
    loader.insert(UTILS_SPECIFIER, utils);
    let module = match Module::parse(Source::from_bytes(code.as_bytes()), None, &mut js) {
        Ok(module) => module,
        Err(error) => return failed(format!("The code could not be parsed: {error}")),
    };
    let loaded = module.load_link_evaluate(&mut js);
    if let Err(error) = js.run_jobs() {
        return failed(error.to_string());
    }
    match loaded.state() {
        PromiseState::Fulfilled(_) => {}
        PromiseState::Rejected(reason) => {
            return failed(describe(&reason, &mut js));
        }
        PromiseState::Pending => return failed("The code did not finish loading".to_string()),
    }
    let function = match module
        .namespace(&mut js)
        .get(js_string!(handler), &mut js)
        .ok()
        .and_then(|value| value.as_callable())
    {
        Some(function) => function,
        None => return failed(format!("The code exports no {handler} function")),
    };
    let ctx = match JsValue::from_json(context, &mut js) {
        Ok(ctx) => ctx,
        Err(error) => return failed(error.to_string()),
    };
    let called = function.call(&JsValue::undefined(), std::slice::from_ref(&ctx), &mut js);
    let outcome = match called {
        Ok(value) => Outcome::Returned(to_json(&value, &mut js)),
        Err(error)
            if error
                .as_native()
                .is_some_and(|native| native.is_runtime_limit()) =>
        {
            Outcome::Failed("The code exceeded the runtime's execution limits".to_string())
        }
        Err(error) => {
            let thrown = error.to_opaque(&mut js);
            match signal_of(&thrown, &mut js) {
                Some(signal) => match signal.get("kind").and_then(Value::as_str) {
                    Some("error") => Outcome::Error(json!({
                        "message": signal.get("message").cloned().unwrap_or(Value::Null),
                        "errorType": signal.get("errorType").cloned().unwrap_or(Value::Null),
                        "data": signal.get("data").cloned().unwrap_or(Value::Null),
                        "errorInfo": signal.get("errorInfo").cloned().unwrap_or(Value::Null),
                    })),
                    Some("unauthorized") => Outcome::Unauthorized,
                    Some("earlyReturn") => {
                        Outcome::EarlyReturn(signal.get("value").cloned().unwrap_or(Value::Null))
                    }
                    _ => Outcome::Failed(describe(&thrown, &mut js)),
                },
                None => Outcome::Failed(describe(&thrown, &mut js)),
            }
        }
    };
    let host = js
        .global_object()
        .get(js_string!("__appsync"), &mut js)
        .map(|value| to_json(&value, &mut js))
        .unwrap_or(Value::Null);
    let non_null = |key: &str| host.get(key).filter(|value| !value.is_null()).cloned();
    HandlerRun {
        outcome,
        context: to_json(&ctx, &mut js),
        appended_errors: host
            .get("errors")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        subscription_filter: non_null("subscriptionFilter"),
        invalidation_filter: non_null("invalidationFilter"),
        invalidations: host
            .get("invalidations")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    }
}

fn to_json(value: &JsValue, js: &mut Context) -> Value {
    value.to_json(js).ok().flatten().unwrap_or(Value::Null)
}

/// The `__appsync` record the utils module attaches to what it throws.
fn signal_of(thrown: &JsValue, js: &mut Context) -> Option<Value> {
    let object = thrown.as_object()?;
    let signal = object.get(js_string!("__appsync"), js).ok()?;
    if signal.is_undefined() {
        return None;
    }
    Some(to_json(&signal, js))
}

fn describe(thrown: &JsValue, js: &mut Context) -> String {
    if let Some(object) = thrown.as_object() {
        if let Ok(message) = object.get(js_string!("message"), js) {
            if let Some(text) = message.as_string() {
                return text.to_std_string_escaped();
            }
        }
    }
    thrown
        .to_string(js)
        .map(|text| text.to_std_string_escaped())
        .unwrap_or_else(|_| "The code threw".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLISH: &str = r#"
import { util } from '@aws-appsync/utils';
export function request(ctx) {
  if (util.authType() !== 'IAM Authorization') { util.unauthorized(); }
  if (!util.matches('^[a-z0-9]+$', ctx.args.input.tenant)) { util.error('Malformed tenant', 'InvalidHint'); }
  ctx.stash.seen = true;
  return { payload: ctx.args.input };
}
export function response(ctx) { return ctx.result; }
"#;

    const SUBSCRIBE: &str = r#"
import { util, extensions } from '@aws-appsync/utils';
export function request(ctx) { return { payload: null }; }
export function response(ctx) {
  extensions.setSubscriptionFilter(util.transform.toSubscriptionFilter({
    tenant: { eq: ctx.identity.claims['custom:tenant'] },
    audience: { eq: 'tenant' },
  }));
  extensions.setSubscriptionInvalidationFilter(util.transform.toSubscriptionFilter({ sub: { eq: ctx.identity.sub } }));
  extensions.invalidateSubscriptions({ subscriptionField: 'onUser', payload: { sub: 'x' } });
  return null;
}
"#;

    fn context(input: Value) -> Value {
        json!({ "arguments": { "input": input }, "args": { "input": input }, "stash": {}, "identity": null })
    }

    #[test]
    fn request_returns_its_payload_and_keeps_the_stash() {
        let run = run_handler(
            PUBLISH,
            "request",
            &context(json!({ "tenant": "acme" })),
            "IAM Authorization",
        );
        assert_eq!(
            run.outcome,
            Outcome::Returned(json!({ "payload": { "tenant": "acme" } }))
        );
        assert_eq!(run.context["stash"], json!({ "seen": true }));
    }

    #[test]
    fn util_error_and_unauthorized_end_the_handler() {
        let malformed = run_handler(
            PUBLISH,
            "request",
            &context(json!({ "tenant": "Not Valid" })),
            "IAM Authorization",
        );
        assert_eq!(
            malformed.outcome,
            Outcome::Error(
                json!({ "message": "Malformed tenant", "errorType": "InvalidHint", "data": null, "errorInfo": null })
            )
        );
        let refused = run_handler(
            PUBLISH,
            "request",
            &context(json!({ "tenant": "acme" })),
            "User Pool Authorization",
        );
        assert_eq!(refused.outcome, Outcome::Unauthorized);
    }

    #[test]
    fn matches_requires_the_whole_value_to_match() {
        let code = "import { util } from '@aws-appsync/utils'; export function request(ctx) { return [util.matches('[a-z]+', 'abc'), util.matches('[a-z]+', 'abc1')]; }";
        assert_eq!(
            run_handler(code, "request", &json!({}), "IAM Authorization").outcome,
            Outcome::Returned(json!([true, false]))
        );
    }

    #[test]
    fn subscription_filters_and_invalidations_are_recorded() {
        let ctx = json!({ "identity": { "sub": "s-1", "claims": { "custom:tenant": "acme" } }, "stash": {} });
        let run = run_handler(SUBSCRIBE, "response", &ctx, "User Pool Authorization");
        assert_eq!(run.outcome, Outcome::Returned(Value::Null));
        assert_eq!(
            run.subscription_filter,
            Some(json!({ "filterGroup": [{ "filters": [
                { "fieldName": "tenant", "operator": "eq", "value": "acme" },
                { "fieldName": "audience", "operator": "eq", "value": "tenant" }
            ] }] }))
        );
        assert_eq!(
            run.invalidation_filter,
            Some(
                json!({ "filterGroup": [{ "filters": [{ "fieldName": "sub", "operator": "eq", "value": "s-1" }] }] })
            )
        );
        assert_eq!(
            run.invalidations,
            vec![json!({ "subscriptionField": "onUser", "payload": { "sub": "x" } })]
        );
    }

    #[test]
    fn an_or_filter_makes_one_group_per_branch() {
        let code = "import { util } from '@aws-appsync/utils'; export function request() { return util.transform.toSubscriptionFilter({ a: { eq: 1 }, or: [{ b: { eq: 2 } }, { c: { ne: 3 } }] }); }";
        assert_eq!(
            run_handler(code, "request", &json!({}), "IAM Authorization").outcome,
            Outcome::Returned(json!({ "filterGroup": [
                { "filters": [{ "fieldName": "a", "operator": "eq", "value": 1 }, { "fieldName": "b", "operator": "eq", "value": 2 }] },
                { "filters": [{ "fieldName": "a", "operator": "eq", "value": 1 }, { "fieldName": "c", "operator": "ne", "value": 3 }] }
            ] }))
        );
    }

    #[test]
    fn unknown_calls_syntax_errors_and_endless_loops_fail_the_run() {
        let unknown = "import { util } from '@aws-appsync/utils'; export function request() { return util.dynamodb.toMapValues({}); }";
        assert!(matches!(
            run_handler(unknown, "request", &json!({}), "IAM Authorization").outcome,
            Outcome::Failed(_)
        ));
        assert!(matches!(
            run_handler(
                "export function request( {",
                "request",
                &json!({}),
                "IAM Authorization"
            )
            .outcome,
            Outcome::Failed(_)
        ));
        let endless = "export function request() { while (true) {} }";
        assert!(matches!(
            run_handler(endless, "request", &json!({}), "IAM Authorization").outcome,
            Outcome::Failed(_)
        ));
        assert!(matches!(
            run_handler(
                "export const x = 1;",
                "request",
                &json!({}),
                "IAM Authorization"
            )
            .outcome,
            Outcome::Failed(_)
        ));
    }
}
