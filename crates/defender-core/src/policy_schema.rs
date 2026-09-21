use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "version", content = "config")]
pub enum VersionedPolicyDocument {
    #[serde(rename = "v1")]
    V1(PolicyDocumentV1),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDocumentV1 {
    pub profile: String,
    pub max_input_size_bytes: u64,
    pub max_output_size_bytes: u64,
    pub max_output_expansion_ratio: f64,
    pub blocked_extensions: Vec<String>,
}

impl PolicyDocumentV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_input_size_bytes == 0 {
            return Err("max_input_size_bytes must be > 0".to_string());
        }
        if self.max_output_size_bytes == 0 {
            return Err("max_output_size_bytes must be > 0".to_string());
        }
        if self.max_output_expansion_ratio <= 0.0 {
            return Err("max_output_expansion_ratio must be > 0".to_string());
        }
        if self.profile.is_empty() {
            return Err("profile cannot be empty".to_string());
        }
        Ok(())
    }
}

pub fn migrate_to_latest(input: VersionedPolicyDocument) -> PolicyDocumentV1 {
    match input {
        VersionedPolicyDocument::V1(value) => value,
    }
}

#[cfg(test)]
mod tests {
    use super::{PolicyDocumentV1, VersionedPolicyDocument, migrate_to_latest};

    #[test]
    fn validates_document() {
        let value = PolicyDocumentV1 {
            profile: "strict".to_string(),
            max_input_size_bytes: 1,
            max_output_size_bytes: 1,
            max_output_expansion_ratio: 1.0,
            blocked_extensions: vec!["exe".to_string()],
        };
        assert!(value.validate().is_ok());
    }

    #[test]
    fn migrates_v1() {
        let value = VersionedPolicyDocument::V1(PolicyDocumentV1 {
            profile: "staging".to_string(),
            max_input_size_bytes: 10,
            max_output_size_bytes: 20,
            max_output_expansion_ratio: 2.0,
            blocked_extensions: vec![],
        });
        let migrated = migrate_to_latest(value);
        assert_eq!(migrated.profile, "staging");
    }
}
