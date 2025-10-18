pub use oci_client::Reference;

use crate::runner::common::Error;
use oci_client::{
    Client as OciClient,
    client::{ClientConfig, ClientProtocol},
    secrets::RegistryAuth,
};

pub struct Client {
    client: OciClient,
    auth: RegistryAuth,
}

impl Client {
    pub fn new(unencrypted: bool) -> Self {
        let config = ClientConfig {
            protocol: if unencrypted {
                ClientProtocol::Http
            } else {
                ClientProtocol::Https
            },
            ..Default::default()
        };
        Self {
            client: OciClient::new(config),
            auth: RegistryAuth::Anonymous,
        }
    }

    pub async fn fetch(&self, reference: &Reference) -> Result<Vec<u8>, Error> {
        let mut out: Vec<u8> = Vec::new();
        let (manifest, _) = self
            .client
            .pull_image_manifest(reference, &self.auth)
            .await?;
        // per cosign source, sbom attachments should only have one layer
        self.client
            .pull_blob(reference, &manifest.layers[0], &mut out)
            .await?;
        Ok(out)
    }
}
