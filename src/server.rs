use std::path::Path;

use crate::{
    DefendResult, DefenderError, FileDefender,
    types::{DefenseContext, SourceRole},
};

#[derive(Debug, Clone)]
pub struct ServerDefender {
    core: FileDefender,
}

impl ServerDefender {
    pub fn new(core: FileDefender) -> Self {
        Self { core }
    }

    pub fn defend_file(
        &self,
        input_path: &Path,
        output_path: &Path,
        tenant_id: Option<String>,
    ) -> Result<DefendResult, DefenderError> {
        self.defend_file_with_mime(input_path, output_path, tenant_id, None)
    }

    pub fn defend_file_with_mime(
        &self,
        input_path: &Path,
        output_path: &Path,
        tenant_id: Option<String>,
        declared_mime: Option<String>,
    ) -> Result<DefendResult, DefenderError> {
        let context = DefenseContext {
            source: SourceRole::Incoming,
            tenant_id,
            declared_mime,
            ..DefenseContext::default()
        };
        self.core.defend_path(input_path, output_path, context)
    }
}
