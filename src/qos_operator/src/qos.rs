use k8s_openapi::api:apps:v1::{Deployment, DeploymentSpec};

pub async fn deploy(
    client: Client,
    name: &str,
    namespace: &str,
) -> Result<Deployment, Error> {
    let mut labels: BTreeMap<String, String> = BTreeMap::new();
    labels.insert("app".to_owned(), name.to_owned());

    // Boot Standard Deployment to kickstart process
    let bootStandardDeployment: Deployment = Deployment{
        metadata: ObjectMeta{
            name: Some(name.to_owned())
        }
    }
}
