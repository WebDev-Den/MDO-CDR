use crate::{
    DefendResult, DefenderError, FileDefender,
    types::{DefenseContext, SourceRole},
};

#[derive(Debug, Clone)]
pub struct ClientDefender {
    core: FileDefender,
}

impl ClientDefender {
    pub fn new(core: FileDefender) -> Self {
        Self { core }
    }

    pub fn defend_upload(
        &self,
        bytes: Vec<u8>,
        file_name: Option<String>,
        tenant_id: Option<String>,
    ) -> Result<DefendResult, DefenderError> {
        self.defend_upload_with_mime(bytes, file_name, tenant_id, None)
    }

    pub fn defend_upload_with_mime(
        &self,
        bytes: Vec<u8>,
        file_name: Option<String>,
        tenant_id: Option<String>,
        declared_mime: Option<String>,
    ) -> Result<DefendResult, DefenderError> {
        let context = DefenseContext {
            source: SourceRole::Outgoing,
            tenant_id,
            declared_mime,
            ..DefenseContext::default()
        };
        self.core.defend_bytes(bytes, file_name, context)
    }
}
