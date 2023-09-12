use kube::client::Client;

use create::crd::QosApp;

pub mod crd;
mod qos;

#[tokio::main]
async fn main() {
    // Create kubernetes client
    let kubernetes_client: Client = Client::try_default()
        .await
        .expect("Expected a valid KUBECONFIG environment variable.");

    // Preparation of resources used by the `kube_runtime::Controller`
    let crd_api: Api<QosApp> = Api::all(kubernetes_client.clone());
    let context: Arc<ContextData> = Arc::new(ContextData::new(kubernetes_client.clone()));
}

// Context injected with each `reconcile` and `on_error` method invocation.
struct ContextData {
    // Kubernetes client to make Kubernetes API requests with. Required for k8s resource management
    client: Client,
}

impl ContextData {
    pub fn new(client: Client) -> Self {
        ContextData{ client }
    }
}

// Action to be taken upan a `QosApp` resource during reconciliation
enum QosAppAction {
    // Create the subresource, this inclused spawning `n` pods of QosApp
    Create,
    // Delete all subresources created in the `Create` phase
    Delete,
    // This `QosApp` resource is in the desired state and requires no actions to be taken
}
