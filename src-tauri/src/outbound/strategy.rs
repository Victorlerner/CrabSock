use serde_json::Value;

pub trait OutboundStrategy: Send + Sync {
    fn build_outbounds(&self) -> Value;
}

