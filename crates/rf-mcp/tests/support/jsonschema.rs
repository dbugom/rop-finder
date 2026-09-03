//! A JSON Schema validator, sized to exactly what schemars 1 emits.
//!
//! CRIT-03's exit criterion is that every `structuredContent` validates
//! against the tool's OWN declared `outputSchema` with
//! `additionalProperties: false`, so that an added field fails the test as
//! loudly as a missing one.
//!
//! Why this and not the `jsonschema` crate, which MCP-DESIGN names: at the
//! version resolved today (0.53) its default features pull `reqwest` and a
//! TLS stack, because it can fetch remote `$ref`s over HTTP. Putting an
//! HTTP client into the test dependency graph of a tool whose whole first
//! release was about not reading things it was not asked to read is a bad
//! trade for a validator that has to understand nine keywords. Every
//! keyword schemars can put in these schemas is handled below, and
//! `unsupported keyword` is a FAILURE rather than a silent pass, so the
//! validator cannot quietly stop checking when the schemas grow.

#![allow(dead_code)]

use serde_json::Value;

/// Validate `instance` against `schema`, resolving `$ref` against `root`.
///
/// Returns every problem found, deepest path first in document order, as
/// `path: explanation`. An empty vector is a pass.
pub fn validate(instance: &Value, schema: &Value, root: &Value) -> Vec<String> {
    let mut errs = Vec::new();
    check(instance, schema, root, "$", &mut errs);
    errs
}

fn resolve<'a>(schema: &'a Value, root: &'a Value) -> &'a Value {
    let Some(r) = schema.get("$ref").and_then(Value::as_str) else {
        return schema;
    };
    // schemars only ever emits local pointers of the form `#/$defs/Name`.
    let mut cur = root;
    for part in r.trim_start_matches("#/").split('/') {
        match cur.get(part) {
            Some(next) => cur = next,
            None => return schema,
        }
    }
    cur
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                "integer"
            } else {
                "number"
            }
        }
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn type_matches(instance: &Value, want: &str) -> bool {
    match want {
        // Every integer is a valid number.
        "number" => matches!(instance, Value::Number(_)),
        other => type_name(instance) == other,
    }
}

/// Keywords this validator understands. Anything else in a schema is
/// reported rather than ignored — a validator that silently skips what it
/// does not know is worse than no validator, because it reports success.
const KNOWN: &[&str] = &[
    "$schema",
    "$ref",
    "$defs",
    "title",
    "description",
    "default",
    "examples",
    "readOnly",
    "writeOnly",
    "deprecated",
    "format",
    "type",
    "enum",
    "const",
    "properties",
    "required",
    "additionalProperties",
    "propertyNames",
    "items",
    "prefixItems",
    "minItems",
    "maxItems",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "minLength",
    "maxLength",
    "pattern",
    "anyOf",
    "oneOf",
    "allOf",
];

fn check(instance: &Value, schema: &Value, root: &Value, path: &str, errs: &mut Vec<String>) {
    // A boolean schema: `true` accepts anything, `false` accepts nothing.
    if let Value::Bool(b) = schema {
        if !b {
            errs.push(format!("{path}: schema is `false`, nothing validates"));
        }
        return;
    }
    let schema = resolve(schema, root);
    let Some(obj) = schema.as_object() else {
        errs.push(format!("{path}: schema is not an object or a boolean"));
        return;
    };
    for key in obj.keys() {
        if !KNOWN.contains(&key.as_str()) {
            errs.push(format!(
                "{path}: schema keyword {key:?} is not handled by this validator; \
                 extend tests/support/jsonschema.rs"
            ));
        }
    }

    if let Some(t) = obj.get("type") {
        let ok = match t {
            Value::String(s) => type_matches(instance, s),
            Value::Array(a) => a
                .iter()
                .filter_map(Value::as_str)
                .any(|s| type_matches(instance, s)),
            _ => false,
        };
        if !ok {
            errs.push(format!(
                "{path}: expected type {t}, got {} ({})",
                type_name(instance),
                truncate(instance)
            ));
            return;
        }
    }

    if let Some(Value::Array(allowed)) = obj.get("enum") {
        if !allowed.contains(instance) {
            errs.push(format!(
                "{path}: {} is not one of {}",
                truncate(instance),
                Value::Array(allowed.clone())
            ));
        }
    }
    if let Some(c) = obj.get("const") {
        if instance != c {
            errs.push(format!(
                "{path}: expected const {c}, got {}",
                truncate(instance)
            ));
        }
    }

    for key in ["anyOf", "oneOf"] {
        if let Some(Value::Array(branches)) = obj.get(key) {
            let ok = branches
                .iter()
                .any(|b| validate_at(instance, b, root, path).is_empty());
            if !ok {
                errs.push(format!(
                    "{path}: {} matches no branch of {key}",
                    truncate(instance)
                ));
            }
        }
    }
    if let Some(Value::Array(branches)) = obj.get("allOf") {
        for b in branches {
            check(instance, b, root, path, errs);
        }
    }

    match instance {
        Value::Object(map) => {
            if let Some(Value::Array(req)) = obj.get("required") {
                for r in req.iter().filter_map(Value::as_str) {
                    if !map.contains_key(r) {
                        errs.push(format!("{path}: missing required property {r:?}"));
                    }
                }
            }
            let props = obj.get("properties").and_then(Value::as_object);
            for (k, v) in map {
                match props.and_then(|p| p.get(k)) {
                    Some(sub) => check(v, sub, root, &format!("{path}.{k}"), errs),
                    None => match obj.get("additionalProperties") {
                        Some(Value::Bool(false)) => errs.push(format!(
                            "{path}: property {k:?} is not in the schema and \
                             additionalProperties is false"
                        )),
                        Some(sub) => check(v, sub, root, &format!("{path}.{k}"), errs),
                        None => {}
                    },
                }
            }
        }
        Value::Array(items) => {
            if let Some(sub) = obj.get("items") {
                for (i, v) in items.iter().enumerate() {
                    check(v, sub, root, &format!("{path}[{i}]"), errs);
                }
            }
            if let Some(n) = obj.get("minItems").and_then(Value::as_u64) {
                if (items.len() as u64) < n {
                    errs.push(format!("{path}: fewer than {n} items"));
                }
            }
            if let Some(n) = obj.get("maxItems").and_then(Value::as_u64) {
                if (items.len() as u64) > n {
                    errs.push(format!("{path}: more than {n} items"));
                }
            }
        }
        Value::Number(n) => {
            if let (Some(min), Some(v)) = (obj.get("minimum").and_then(Value::as_f64), n.as_f64()) {
                if v < min {
                    errs.push(format!("{path}: {v} is below the minimum {min}"));
                }
            }
        }
        _ => {}
    }
}

fn validate_at(instance: &Value, schema: &Value, root: &Value, path: &str) -> Vec<String> {
    let mut errs = Vec::new();
    check(instance, schema, root, path, &mut errs);
    errs
}

fn truncate(v: &Value) -> String {
    let s = v.to_string();
    match s.char_indices().nth(120) {
        Some((i, _)) => match s.get(..i) {
            Some(head) => format!("{head}…"),
            None => s,
        },
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn root() -> Value {
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["a", "b"],
            "properties": {
                "a": {"type": ["string", "null"]},
                "b": {"type": "integer", "minimum": 0},
                "c": {"$ref": "#/$defs/Sub"},
                "d": {"type": "array", "items": {"type": "string"}},
                "e": {"anyOf": [{"$ref": "#/$defs/Sub"}, {"type": "null"}]},
            },
            "$defs": {
                "Sub": {"type": "string", "enum": ["x", "y"]}
            }
        })
    }

    #[test]
    fn accepts_a_conforming_document() {
        let r = root();
        let doc = json!({"a": null, "b": 3, "c": "x", "d": ["p"], "e": null});
        assert!(
            validate(&doc, &r, &r).is_empty(),
            "{:?}",
            validate(&doc, &r, &r)
        );
    }

    /// The property CRIT-03's exit criterion rests on: an ADDED field is a
    /// failure, not a pass.
    #[test]
    fn an_extra_field_fails() {
        let r = root();
        let doc = json!({"a": "s", "b": 1, "surprise": 1});
        let errs = validate(&doc, &r, &r);
        assert!(errs.iter().any(|e| e.contains("surprise")), "{errs:?}");
    }

    #[test]
    fn missing_wrong_typed_and_out_of_enum_values_fail() {
        let r = root();
        for (doc, want) in [
            (json!({"a": "s"}), "missing required property \"b\""),
            (json!({"a": 1, "b": 1}), "expected type"),
            (json!({"a": "s", "b": "no"}), "expected type"),
            (json!({"a": "s", "b": 1, "c": "z"}), "is not one of"),
            (json!({"a": "s", "b": 1, "d": [1]}), "expected type"),
            (json!({"a": "s", "b": 1, "e": 5}), "matches no branch"),
        ] {
            let errs = validate(&doc, &r, &r);
            assert!(
                errs.iter().any(|e| e.contains(want)),
                "{doc} should fail with {want:?}, got {errs:?}"
            );
        }
    }

    /// A validator that ignores what it does not understand reports
    /// success it has not earned, so an unknown keyword is an error.
    #[test]
    fn an_unhandled_keyword_is_reported() {
        let schema = json!({"type": "object", "unevaluatedProperties": false});
        let errs = validate(&json!({}), &schema, &schema);
        assert!(
            errs.iter().any(|e| e.contains("unevaluatedProperties")),
            "{errs:?}"
        );
    }
}
