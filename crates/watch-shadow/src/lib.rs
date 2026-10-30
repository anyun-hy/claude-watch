#![forbid(unsafe_code)]

use claude_watch_core::tag_policy::{self, Evidence, Mode};
use serde::{de, Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, BufRead, Write};

pub const MAX_FRAME_BYTES: usize = 65_536;
const MAX_ROUTES: usize = 128;
const MAX_HOPS: usize = 16;
type Routes = BTreeMap<String, Option<Vec<String>>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u32,
    request_id: String,
    operation: String,
    evidence: WireEvidence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEvidence {
    observed_chain: Vec<String>,
    required_group: String,
    pinned_node: String,
    matched_rule: Option<String>,
    api: WireApi,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireApi {
    state: String,
    mode: Option<String>,
    #[serde(deserialize_with = "unique_routes")]
    route_chains: Routes,
}

fn unique_routes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Routes, D::Error> {
    struct Visitor;
    impl<'de> de::Visitor<'de> for Visitor {
        type Value = Routes;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a bounded map with unique route names")
        }
        fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Routes, A::Error> {
            let mut routes = Routes::new();
            while let Some((name, chain)) = map.next_entry::<String, Option<Vec<String>>>()? {
                if routes.len() >= MAX_ROUTES || routes.contains_key(&name) {
                    return Err(de::Error::custom("duplicate or excessive route entries"));
                }
                routes.insert(name, chain);
            }
            Ok(routes)
        }
    }
    deserializer.deserialize_map(Visitor)
}

#[derive(Serialize)]
struct PolicyResult {
    state: &'static str,
    code: &'static str,
    detail: &'static str,
}

#[derive(Serialize)]
pub struct Response {
    schema_version: u32,
    mode: &'static str,
    grants_launch_permission: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<PolicyResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
}

fn response(
    id: Option<String>,
    result: Option<PolicyResult>,
    error: Option<&'static str>,
) -> Response {
    Response {
        schema_version: 1,
        mode: "shadow",
        grants_launch_permission: false,
        request_id: id,
        result,
        error,
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c))
}

fn valid_text(value: &str) -> bool {
    value.len() <= 1024 && !value.chars().any(char::is_control)
}

fn valid_chain(chain: &[String]) -> bool {
    chain.len() <= MAX_HOPS && chain.iter().all(|v| valid_text(v))
}

pub fn evaluate_frame(bytes: &[u8]) -> Response {
    if bytes.len() > MAX_FRAME_BYTES {
        return response(None, None, Some("frame_too_large"));
    }
    let Ok(request) = serde_json::from_slice::<Request>(bytes) else {
        // Never echo raw input, credentials, unknown field names or parser messages.
        return response(None, None, Some("invalid_request"));
    };
    if !valid_id(&request.request_id) {
        return response(None, None, Some("invalid_request_id"));
    }
    let id = Some(request.request_id);
    if request.schema_version != 1 {
        return response(id, None, Some("unsupported_schema"));
    }
    if request.operation != "tag_connection_policy" {
        return response(id, None, Some("unsupported_operation"));
    }
    let wire = request.evidence;
    if !valid_chain(&wire.observed_chain)
        || !valid_text(&wire.required_group)
        || !valid_text(&wire.pinned_node)
        || !wire.matched_rule.as_deref().map(valid_text).unwrap_or(true)
        || !valid_text(&wire.api.state)
        || !wire.api.mode.as_deref().map(valid_text).unwrap_or(true)
        || wire.api.route_chains.iter().any(|(name, chain)| {
            !valid_text(name) || !chain.as_deref().map(valid_chain).unwrap_or(true)
        })
    {
        return response(id, None, Some("evidence_limits_exceeded"));
    }
    let input = Evidence {
        api_available: wire.api.state == "available",
        mode: Mode::from_wire(wire.api.mode.as_deref()),
        observed_chain: wire.observed_chain,
        required_group: wire.required_group,
        pinned_node: wire.pinned_node,
        matched_rule: wire.matched_rule,
        route_chains: wire.api.route_chains,
    };
    let decision = tag_policy::evaluate(&input);
    response(
        id,
        Some(PolicyResult {
            state: decision.state.as_str(),
            code: decision.reason.as_str(),
            detail: decision.reason.detail(),
        }),
        None,
    )
}

enum Frame {
    Complete(Vec<u8>),
    TooLarge,
}

/// A line is drained when oversized, but never buffered beyond the frame limit.
fn read_frame<R: BufRead>(reader: &mut R) -> io::Result<Option<Frame>> {
    let mut bytes = Vec::new();
    let mut oversized = false;
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(if oversized {
                Some(Frame::TooLarge)
            } else if bytes.is_empty() {
                None
            } else {
                Some(Frame::Complete(bytes))
            });
        }
        let newline = buffer.iter().position(|&v| v == b'\n');
        let count = newline.unwrap_or(buffer.len());
        if !oversized {
            if count > MAX_FRAME_BYTES - bytes.len() {
                oversized = true;
                bytes.clear();
            } else {
                bytes.extend_from_slice(&buffer[..count]);
            }
        }
        reader.consume(count + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Some(if oversized {
                Frame::TooLarge
            } else {
                Frame::Complete(bytes)
            }));
        }
    }
}

pub fn run<R: BufRead, W: Write>(mut reader: R, mut writer: W) -> io::Result<()> {
    while let Some(frame) = read_frame(&mut reader)? {
        let result = match frame {
            Frame::Complete(bytes) => evaluate_frame(&bytes),
            Frame::TooLarge => response(None, None, Some("frame_too_large")),
        };
        serde_json::to_writer(&mut writer, &result).map_err(io::Error::other)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::io::Cursor;

    fn request() -> Value {
        json!({"schema_version":1,"request_id":"case-1","operation":"tag_connection_policy",
               "evidence":{"observed_chain":["JP-test","GLOBAL"],"required_group":"","pinned_node":"",
                           "matched_rule":null,"api":{"state":"available","mode":"global",
                           "route_chains":{"GLOBAL":["JP-test","GLOBAL"]}}}})
    }
    fn evaluate(value: &Value) -> Value {
        serde_json::to_value(evaluate_frame(&serde_json::to_vec(value).unwrap())).unwrap()
    }

    #[test]
    fn match_has_no_authority() {
        let result = evaluate(&request());
        assert_eq!(result["result"]["state"], "match");
        assert_eq!(result["mode"], "shadow");
        assert_eq!(result["grants_launch_permission"], false);
    }

    #[test]
    fn invalid_versions_operations_and_fields_do_not_produce_decisions() {
        for (field, value, error) in [
            ("schema_version", json!(2), "unsupported_schema"),
            ("operation", json!("launch"), "unsupported_operation"),
            ("apply", json!(true), "invalid_request"),
            ("request_id", json!("bad\nidentifier"), "invalid_request_id"),
        ] {
            let mut input = request();
            input[field] = value;
            let result = evaluate(&input);
            assert_eq!(result["error"], error);
            assert!(result.get("result").is_none());
            assert_eq!(result["grants_launch_permission"], false);
        }
    }

    #[test]
    fn duplicate_keys_and_excessive_evidence_are_rejected() {
        let bytes = serde_json::to_string(&request()).unwrap().replace(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
        );
        assert_eq!(
            serde_json::to_value(evaluate_frame(bytes.as_bytes())).unwrap()["error"],
            "invalid_request"
        );
        let bytes = serde_json::to_string(&request()).unwrap().replace(
            "\"GLOBAL\":[\"JP-test\",\"GLOBAL\"]",
            "\"GLOBAL\":[\"JP-test\",\"GLOBAL\"],\"GLOBAL\":null",
        );
        assert_eq!(
            serde_json::to_value(evaluate_frame(bytes.as_bytes())).unwrap()["error"],
            "invalid_request"
        );
        let mut input = request();
        input["evidence"]["observed_chain"] = json!(vec!["hop"; 17]);
        assert_eq!(evaluate(&input)["error"], "evidence_limits_exceeded");
    }

    #[test]
    fn bad_frames_do_not_contaminate_the_next_request() {
        let mut input = vec![b'x'; MAX_FRAME_BYTES + 1];
        input.push(b'\n');
        input.extend_from_slice(b"invalid-secret-payload\n\xff\n");
        input.extend_from_slice(&serde_json::to_vec(&request()).unwrap());
        let mut output = Vec::new();
        run(Cursor::new(input), &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("invalid-secret-payload"));
        let values: Vec<Value> = text
            .lines()
            .map(|v| serde_json::from_str(v).unwrap())
            .collect();
        assert_eq!(values.len(), 4);
        assert_eq!(values[0]["error"], "frame_too_large");
        assert_eq!(values[1]["error"], "invalid_request");
        assert_eq!(values[2]["error"], "invalid_request");
        assert_eq!(values[3]["result"]["state"], "match");
    }
}
