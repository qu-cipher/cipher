use crate::engine::singbox::config::{
    dns::DNS,
    endpoint::Endpoint,
    experimental::Experimental,
    inbound::Inbound,
    outbound::Outbound,
    route::Route,
    log::Log
};
use serde::{Deserialize, Serialize};

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct SingBoxConfig {
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<Log>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<DNS>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbounds: Vec<Inbound>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<Outbound>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<Endpoint>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<Route>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Experimental>,
}
