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
        let context = DefenseContext {
            source: SourceRole::Incoming,
            tenant_id,
            ..DefenseContext::default()
        };
        self.core.defend_path(input_path, output_path, context)
    }
}
