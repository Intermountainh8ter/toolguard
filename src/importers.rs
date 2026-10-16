//! Importers for real-world tool-spec formats.
//!
//! Two formats cover almost every deployed agent:
//!
//! * **Anthropic**: a JSON array of `{"name", "description", "input_schema"}`
//!   objects, as served from the Claude API's tool-use feature.
//! * **OpenAI functions**: a JSON array of `{"type": "function",
//!   "function": {"name", "description", "parameters"}}` objects, as
//!   served from the OpenAI Chat Completions `tools` parameter.
//!
//! The importer validates the shape (required fields present, names
//! non-empty, no duplicate names) and emits a `Catalog`. Risk tiers are
//! not carried by the real formats, so the caller supplies a tier map
//! `fn(&str) -> RiskTier` (the catalog's job is risk annotation; the
//! importer's job is schema extraction). Unknown names default to
//! `Benign`, which pre-reg §4 then catches as "insufficient dangerous
//! tools" if nothing dangerous was mapped.

use crate::{check_catalog, Catalog, CatalogError, RiskTier, ToolSpec};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImportError {
    #[error("JSON could not be parsed: {0}")]
    MalformedJson(String),
    #[error("tool at index {index} is missing the required field `{field}`")]
    MissingField { index: usize, field: &'static str },
    #[error("tool at index {index} has an empty `name`")]
    EmptyName { index: usize },
    #[error("duplicate tool name `{name}` (indices {first}, {second})")]
    DuplicateName {
        name: String,
        first: usize,
        second: usize,
    },
    #[error("catalog refuses: {0:?}")]
    PreRegRefusal(CatalogError),
}

#[derive(Deserialize)]
struct AnthropicTool {
    name: Option<String>,
    #[allow(dead_code)]
    description: Option<String>,
    input_schema: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct OpenAiEntry {
    #[serde(rename = "type")]
    kind: Option<String>,
    function: Option<OpenAiFn>,
}

#[derive(Deserialize)]
struct OpenAiFn {
    name: Option<String>,
    #[allow(dead_code)]
    description: Option<String>,
    parameters: Option<serde_json::Value>,
}

/// Import an Anthropic-shaped tool array into a Catalog. `tier_map` is
/// looked up by tool name; a missing entry yields RiskTier::Benign.
pub fn import_anthropic(
    name: &str,
    provenance: &str,
    json: &str,
    tier_map: &dyn Fn(&str) -> RiskTier,
) -> Result<Catalog, ImportError> {
    let raw: Vec<AnthropicTool> =
        serde_json::from_str(json).map_err(|e| ImportError::MalformedJson(e.to_string()))?;
    let mut tools: Vec<ToolSpec> = Vec::with_capacity(raw.len());
    let mut seen: Vec<(String, usize)> = Vec::new();
    for (i, t) in raw.into_iter().enumerate() {
        let n = t.name.ok_or(ImportError::MissingField {
            index: i,
            field: "name",
        })?;
        if n.trim().is_empty() {
            return Err(ImportError::EmptyName { index: i });
        }
        if t.input_schema.is_none() {
            return Err(ImportError::MissingField {
                index: i,
                field: "input_schema",
            });
        }
        if let Some((_, first)) = seen.iter().find(|(name, _)| name == &n) {
            return Err(ImportError::DuplicateName {
                name: n,
                first: *first,
                second: i,
            });
        }
        seen.push((n.clone(), i));
        tools.push(ToolSpec {
            tool: n.clone(),
            tier: tier_map(&n),
        });
    }
    let c = Catalog {
        name: name.into(),
        provenance: provenance.into(),
        tools,
    };
    check_catalog(&c).map_err(ImportError::PreRegRefusal)?;
    Ok(c)
}

/// Import an OpenAI-functions-shaped tool array into a Catalog.
pub fn import_openai(
    name: &str,
    provenance: &str,
    json: &str,
    tier_map: &dyn Fn(&str) -> RiskTier,
) -> Result<Catalog, ImportError> {
    let raw: Vec<OpenAiEntry> =
        serde_json::from_str(json).map_err(|e| ImportError::MalformedJson(e.to_string()))?;
    let mut tools: Vec<ToolSpec> = Vec::with_capacity(raw.len());
    let mut seen: Vec<(String, usize)> = Vec::new();
    for (i, entry) in raw.into_iter().enumerate() {
        if entry.kind.as_deref() != Some("function") {
            return Err(ImportError::MissingField {
                index: i,
                field: "type == \"function\"",
            });
        }
        let f = entry.function.ok_or(ImportError::MissingField {
            index: i,
            field: "function",
        })?;
        let n = f.name.ok_or(ImportError::MissingField {
            index: i,
            field: "function.name",
        })?;
        if n.trim().is_empty() {
            return Err(ImportError::EmptyName { index: i });
        }
        if f.parameters.is_none() {
            return Err(ImportError::MissingField {
                index: i,
                field: "function.parameters",
            });
        }
        if let Some((_, first)) = seen.iter().find(|(name, _)| name == &n) {
            return Err(ImportError::DuplicateName {
                name: n,
                first: *first,
                second: i,
            });
        }
        seen.push((n.clone(), i));
        tools.push(ToolSpec {
            tool: n.clone(),
            tier: tier_map(&n),
        });
    }
    let c = Catalog {
        name: name.into(),
        provenance: provenance.into(),
        tools,
    };
    check_catalog(&c).map_err(ImportError::PreRegRefusal)?;
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn danger_everything(_: &str) -> RiskTier {
        RiskTier::Dangerous
    }

    fn mixed_tier(name: &str) -> RiskTier {
        match name {
            "run_shell" | "write_file" | "transfer_funds" => RiskTier::Dangerous,
            "list_dir" | "read_file" => RiskTier::Benign,
            _ => RiskTier::Caution,
        }
    }

    #[test]
    fn imports_a_well_formed_anthropic_catalog() {
        let json = r#"[
            {"name": "run_shell", "description": "run a shell cmd", "input_schema": {"type": "object"}},
            {"name": "write_file", "description": "write a file", "input_schema": {"type": "object"}},
            {"name": "transfer_funds", "description": "move money", "input_schema": {"type": "object"}},
            {"name": "list_dir", "description": "list a dir", "input_schema": {"type": "object"}}
        ]"#;
        let c = import_anthropic("agentA", "test fixture", json, &mixed_tier).expect("ok");
        assert_eq!(c.name, "agentA");
        assert_eq!(c.tools.len(), 4);
        assert_eq!(c.tools[3].tier, RiskTier::Benign);
    }

    #[test]
    fn imports_a_well_formed_openai_catalog() {
        let json = r#"[
            {"type":"function","function":{"name":"run_shell","description":"d","parameters":{}}},
            {"type":"function","function":{"name":"write_file","description":"d","parameters":{}}},
            {"type":"function","function":{"name":"transfer_funds","description":"d","parameters":{}}}
        ]"#;
        let c = import_openai("agentB", "test fixture", json, &mixed_tier).expect("ok");
        assert_eq!(c.name, "agentB");
        assert_eq!(c.tools.len(), 3);
        assert!(c.tools.iter().all(|t| t.tier == RiskTier::Dangerous));
    }

    #[test]
    fn anthropic_missing_input_schema_errors_with_index() {
        let json = r#"[
            {"name": "a", "description": "d", "input_schema": {}},
            {"name": "b", "description": "d", "input_schema": {}},
            {"name": "c", "description": "d"}
        ]"#;
        match import_anthropic("x", "p", json, &danger_everything) {
            Err(ImportError::MissingField { index, field }) => {
                assert_eq!(index, 2);
                assert_eq!(field, "input_schema");
            }
            o => panic!("wrong variant: {o:?}"),
        }
    }

    #[test]
    fn openai_non_function_type_errors() {
        let json = r#"[{"type":"not_a_function","function":{"name":"x","parameters":{}}}]"#;
        match import_openai("x", "p", json, &danger_everything) {
            Err(ImportError::MissingField { index, field }) => {
                assert_eq!(index, 0);
                assert!(field.contains("function"));
            }
            o => panic!("wrong variant: {o:?}"),
        }
    }

    #[test]
    fn duplicate_name_is_rejected() {
        let json = r#"[
            {"name": "run", "description": "d", "input_schema": {}},
            {"name": "run", "description": "d", "input_schema": {}},
            {"name": "x", "description": "d", "input_schema": {}}
        ]"#;
        match import_anthropic("x", "p", json, &danger_everything) {
            Err(ImportError::DuplicateName { name, first, second }) => {
                assert_eq!(name, "run");
                assert_eq!(first, 0);
                assert_eq!(second, 1);
            }
            o => panic!("wrong variant: {o:?}"),
        }
    }

    #[test]
    fn empty_name_rejected_with_index() {
        let json = r#"[
            {"name": "", "description": "d", "input_schema": {}}
        ]"#;
        match import_anthropic("x", "p", json, &danger_everything) {
            Err(ImportError::EmptyName { index }) => assert_eq!(index, 0),
            o => panic!("wrong variant: {o:?}"),
        }
    }

    #[test]
    fn pre_reg_refusal_bubbles_up_as_error() {
        // Only two tools, both Benign: fails §4 "insufficient dangerous".
        let json = r#"[
            {"name": "a", "description": "d", "input_schema": {}},
            {"name": "b", "description": "d", "input_schema": {}}
        ]"#;
        match import_anthropic("x", "p", json, &|_| RiskTier::Benign) {
            Err(ImportError::PreRegRefusal(_)) => {}
            o => panic!("wrong variant: {o:?}"),
        }
    }
}
