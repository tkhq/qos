use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use qos_core::protocol::msg::ProtocolPhase;
use k8s_openapi::api::core::v1::ResourceRequirements;

#[derive(CustomResource, Serialize, Deserialize, Debug, PartialEq, Clone, JsonSchema)]
#[kube(
    group = "qos.turnkey.com",
    version = "v1alpha1",
    kind = "QosApp",
    plural = "QosApps",
    derive = "PartialEq",
    namespaced
)]
pub struct QosAppSpec {
    pub provisioning_mode: ProvisioningMode,
    pub enclave: EnclaveSpec,
    pub qos_host: QosHostSpec,
    pub app_host: AppHostSpec,
}

pub struct EnclaveBootSpec {
    pub image: String,
    pub unsafe_mode: bool,
    pub app: String,
    pub app_bin: String,
    pub nonce: String,
    pub namespace: String,
}

pub struct EnclaveSpec {
    pub image: String,
    pub eif_path: String,
    pub cid: String,
    pub cpu_count: String,
    pub resources: ResourceRequirements,
    pub command: Option<Vec<String>>,
    pub args: Option<Vec<String>>,
    pub boot: EnclaveBootSpec,
}

pub struct QosHostSpec {
    pub image: String,
    pub resources: ResourceRequirements,
    pub command: Option<Vec<String>>,
    pub args: Option<Vec<String>>,
}

pub struct AppHostSpec {
    pub image: String,
    pub resources: ResourceRequirements,
    pub command: Option<Vec<String>>,
    pub args: Option<Vec<String>>,
}

pub enum ProvisioningMode {
    BootStandard,
    KeyForward,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
pub struct QosAppStatus {
    pub app: String,
    pub enclave_state:  ProtocolPhase,
    pub provisioning_mode: ProvisioningMode,
    pub unsafe_mode: bool,
    pub nonce: String,
    pub namespace: String,
}
