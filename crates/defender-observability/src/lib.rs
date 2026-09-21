#[derive(Debug, Clone)]
pub struct PipelineAuditEvent {
    pub tenant_id: Option<String>,
    pub source: String,
    pub verdict: String,
    pub alert_count: usize,
    pub stage_count: usize,
}

pub trait AuditSink: Send + Sync {
    fn emit(&self, event: &PipelineAuditEvent);
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAuditSink;

impl AuditSink for NoopAuditSink {
    fn emit(&self, _event: &PipelineAuditEvent) {}
}
