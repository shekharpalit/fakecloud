//! AppSync enhanced subscription filters: `{filterGroup: [{filters: [...]}]}`.
//! An event passes when any group passes, and a group passes when every one
//! of its filters does. A filter names a field of the event (dots reach into
//! nested objects), an operator and a value.

use serde_json::Value;

/// Whether `event` passes `filter`. A filter with no groups passes everything.
pub fn passes(filter: &Value, event: &Value) -> bool {
    let groups = match filter.get("filterGroup").and_then(Value::as_array) {
        Some(groups) if !groups.is_empty() => groups,
        _ => return true,
    };
    groups.iter().any(|group| {
        group
            .get("filters")
            .and_then(Value::as_array)
            .is_none_or(|filters| filters.iter().all(|f| filter_passes(f, event)))
    })
}

fn field<'a>(event: &'a Value, name: &str) -> Option<&'a Value> {
    name.split('.')
        .try_fold(event, |value, part| value.get(part))
        .filter(|value| !value.is_null())
}

fn filter_passes(filter: &Value, event: &Value) -> bool {
    let Some(name) = filter.get("fieldName").and_then(Value::as_str) else {
        return false;
    };
    let operator = filter.get("operator").and_then(Value::as_str).unwrap_or("");
    let expected = filter.get("value").unwrap_or(&Value::Null);
    let actual = field(event, name);
    match operator {
        "eq" => actual.is_some_and(|a| a == expected),
        "ne" => actual != Some(expected),
        "lt" | "le" | "gt" | "ge" => actual.is_some_and(|a| ordered(a, expected, operator)),
        "contains" => actual.is_some_and(|a| contains(a, expected)),
        "notContains" => !actual.is_some_and(|a| contains(a, expected)),
        "beginsWith" => {
            matches!((actual, expected), (Some(Value::String(a)), Value::String(p)) if a.starts_with(p.as_str()))
        }
        "in" => actual.is_some_and(|a| expected.as_array().is_some_and(|set| set.contains(a))),
        "notIn" => !actual.is_some_and(|a| expected.as_array().is_some_and(|set| set.contains(a))),
        "between" => match (actual, expected.as_array().map(Vec::as_slice)) {
            (Some(a), Some([low, high])) => ordered(a, low, "ge") && ordered(a, high, "le"),
            _ => false,
        },
        "attributeExists" => actual.is_some() == expected.as_bool().unwrap_or(true),
        _ => false,
    }
}

fn ordered(actual: &Value, expected: &Value, operator: &str) -> bool {
    let ordering = match (actual, expected) {
        (Value::Number(a), Value::Number(b)) => a
            .as_f64()
            .zip(b.as_f64())
            .and_then(|(a, b)| a.partial_cmp(&b)),
        (Value::String(a), Value::String(b)) => Some(a.cmp(b)),
        _ => None,
    };
    ordering.is_some_and(|o| match operator {
        "lt" => o.is_lt(),
        "le" => o.is_le(),
        "gt" => o.is_gt(),
        _ => o.is_ge(),
    })
}

fn contains(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::String(a), Value::String(e)) => a.contains(e.as_str()),
        (Value::Array(items), e) => items.contains(e),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn one(field: &str, operator: &str, value: Value) -> Value {
        json!({ "filterGroup": [{ "filters": [{ "fieldName": field, "operator": operator, "value": value }] }] })
    }

    #[test]
    fn groups_are_any_and_filters_are_all() {
        let filter = json!({ "filterGroup": [
            { "filters": [
                { "fieldName": "tenant", "operator": "eq", "value": "acme" },
                { "fieldName": "audience", "operator": "eq", "value": "tenant" }
            ] },
            { "filters": [{ "fieldName": "subject", "operator": "eq", "value": "s-1" }] }
        ] });
        assert!(passes(
            &filter,
            &json!({ "tenant": "acme", "audience": "tenant" })
        ));
        assert!(passes(
            &filter,
            &json!({ "tenant": "other", "subject": "s-1" })
        ));
        assert!(!passes(
            &filter,
            &json!({ "tenant": "acme", "audience": "person" })
        ));
        assert!(passes(&json!({}), &json!({ "anything": 1 })));
    }

    #[test]
    fn operators_compare_as_appsync_does() {
        let event = json!({ "n": 5, "s": "study-7", "tags": ["a", "b"], "nested": { "k": "v" }, "gone": null });
        assert!(passes(&one("n", "between", json!([1, 5])), &event));
        assert!(!passes(&one("n", "gt", json!(5)), &event));
        assert!(passes(&one("s", "beginsWith", json!("study")), &event));
        assert!(passes(&one("tags", "contains", json!("b")), &event));
        assert!(passes(&one("s", "notContains", json!("x")), &event));
        assert!(passes(&one("s", "in", json!(["a", "study-7"])), &event));
        assert!(passes(&one("s", "notIn", json!(["a"])), &event));
        assert!(passes(&one("nested.k", "eq", json!("v")), &event));
        assert!(passes(&one("missing", "ne", json!("x")), &event));
        assert!(passes(
            &one("gone", "attributeExists", json!(false)),
            &event
        ));
        assert!(!passes(&one("s", "unknownOperator", json!("x")), &event));
    }
}
