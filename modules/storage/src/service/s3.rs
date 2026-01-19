use crate::{
    config::S3Config,
    service::{
        StorageBackend, StorageKey, StorageResult, StoreError, compression::Compression,
        temp::TempFile,
    },
};
use anyhow::{Context, anyhow, bail};
use aws_config::AppName;
use aws_sdk_s3::{
    Client,
    config::{
        self, Credentials, Region, SharedHttpClient,
        endpoint::{EndpointFuture, Params, ResolveEndpoint},
    },
    operation::get_object::GetObjectError,
    primitives::FsBuilder,
};
use aws_smithy_http_client::tls::{Provider, TlsContext, TrustStore, rustls_provider::CryptoMode};
use aws_smithy_types::endpoint::Endpoint;
use bytes::Bytes;
use futures::{Stream, TryStreamExt};
use std::{fmt::Debug, io, str::FromStr};
use tokio::{fs, io::AsyncRead};
use tokio_util::io::ReaderStream;
use tracing::instrument;
use urlencoding::encode;

/// Resolver using a provided base url
#[derive(Debug)]
struct StringResolver(Endpoint);

impl From<String> for StringResolver {
    fn from(value: String) -> Self {
        StringResolver(Endpoint::builder().url(value).build())
    }
}

impl ResolveEndpoint for StringResolver {
    fn resolve_endpoint<'a>(&'a self, params: &'a Params) -> EndpointFuture<'a> {
        if let Some(bucket) = params.bucket() {
            let url = format!("{}/{}", self.0.url(), encode(bucket));
            EndpointFuture::ready(Ok(Endpoint::builder().url(url).build()))
        } else {
            EndpointFuture::ready(Ok(self.0.clone()))
        }
    }
}

#[derive(Clone, Debug)]
pub struct S3Backend {
    client: Client,
    bucket: String,
    compression: Compression,
}

impl S3Backend {
    pub async fn new(s3: S3Config, compression: Compression) -> Result<Self, anyhow::Error> {
        let S3Config {
            bucket,
            region,
            access_key,
            secret_key,
            trust_anchors,
            path_style,
        } = s3;

        log::info!("Using S3 bucket '{bucket:?}' in '{region:?}' for doc storage",);

        let name = format!("{}#{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

        // Validate credentials: both must be provided or both must be omitted
        if access_key.is_some() != secret_key.is_some() {
            let missing = if access_key.is_none() {
                "access_key"
            } else {
                "secret_key"
            };
            bail!("S3 {missing} is missing (both credentials must be provided together)");
        }

        // basics

        let config = config::Builder::new()
            .app_name(AppName::new(name)?)
            .force_path_style(path_style);

        // region

        let region = region.ok_or_else(|| anyhow!("region not provided"))?;
        let mut config = if region.starts_with("http://") || region.starts_with("https://") {
            config
                .endpoint_resolver(StringResolver::from(region))
                // we just use any region
                .region(Region::from_static("us-east-1"))
        } else {
            config.region(Region::new(region))
        };

        // credentials

        if let Some((key_id, access_key)) = access_key.zip(secret_key) {
            let credentials = Credentials::new(key_id, access_key, None, None, "config");
            config = config.credentials_provider(credentials);
        }

        // TLS

        let mut trust_store = TrustStore::empty().with_native_roots(true);

        for ta in &trust_anchors {
            let content = fs::read(&ta)
                .await
                .with_context(|| format!("failed reading trust anchor: {ta}"))?;

            trust_store = trust_store.with_pem_certificate(content);
        }

        let http = aws_smithy_http_client::Builder::new()
            .tls_provider(Provider::Rustls(CryptoMode::AwsLc))
            .tls_context(
                TlsContext::builder()
                    .with_trust_store(trust_store)
                    .build()?,
            )
            .build_https();

        let config = config.http_client(SharedHttpClient::new(http));

        // create client

        let client = Client::from_conf(config.build());

        Ok(Self {
            client,
            bucket: bucket.unwrap_or_default(),
            compression,
        })
    }
}

impl StorageBackend for S3Backend {
    type Error = Error;

    #[instrument(skip(self, stream), err(Debug, level=tracing::Level::INFO))]
    async fn store<S>(&self, stream: S) -> Result<StorageResult, StoreError<Self::Error>>
    where
        S: AsyncRead + Unpin + Send,
    {
        let file = TempFile::with_compression(stream, self.compression).await?;
        let result = file.to_result();

        self.client
            .put_object()
            .bucket(&self.bucket)
            .set_content_encoding(match self.compression {
                // `None` is the way to remove the header, for NooBaa, which has problems with this header
                Compression::None => None,
                other => Some(other.to_string()),
            })
            .key(result.key())
            .body(
                FsBuilder::new()
                    .file(file.file().await?)
                    .build()
                    .await
                    .map_err(|err| StoreError::Backend(Error::Bytes(err)))?,
            )
            .send()
            .await
            .map_err(|err| Error::S3(err.into()))?;

        Ok(result)
    }

    async fn retrieve(
        &self,
        StorageKey(key): StorageKey,
    ) -> Result<Option<impl Stream<Item = Result<Bytes, Self::Error>> + use<>>, Self::Error> {
        let req = self.client.get_object().bucket(&self.bucket).key(&key);

        match req.send().await {
            Ok(resp) => {
                let content_encoding = resp.content_encoding().and_then(cleanup);
                log::debug!("Content encoding: {content_encoding:?}");

                let compression = match content_encoding {
                    Some(encoding) => Compression::from_str(&encoding).inspect_err(|_| {
                        log::warn!("Content encoding: '{encoding}' not supported")
                    })?,
                    None => Compression::None,
                };

                Ok(Some(
                    ReaderStream::new(compression.reader(resp.body.into_async_read()))
                        .map_err(Error::Io),
                ))
            }
            Err(err) => match err.into_service_error() {
                GetObjectError::NoSuchKey(_) => Ok(None),
                err => Err(Error::S3(err.into())),
            },
        }
    }

    async fn delete(&self, StorageKey(key): StorageKey) -> Result<(), Self::Error> {
        let req = self.client.delete_object().bucket(&self.bucket).key(&key);
        match req.send().await {
            Ok(_) => Ok(()),
            Err(err) => Err(Error::S3(err.into())),
        }
    }
}

/// Cleanup the encoding header returned by the S3 storage.
///
/// Today, this removes the `aws-chunked` encoding, which should not be present in the metadata, but
/// for ODF it is.
fn cleanup(encoding: &str) -> Option<String> {
    let items = encoding
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !matches!(*s, "aws-chunked"))
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();

    if items.is_empty() {
        None
    } else {
        Some(items.join(", "))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    S3(#[from] aws_sdk_s3::Error),
    #[error(transparent)]
    Bytes(#[from] aws_smithy_types::byte_stream::error::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Parse(#[from] strum::ParseError),
}

impl From<Error> for StoreError<Error> {
    fn from(e: Error) -> Self {
        StoreError::Backend(e)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::service::{
        dispatch::DispatchBackend,
        test::{test_read_not_found, test_store_read_and_delete},
    };
    use rstest::rstest;
    use std::fmt::Write;
    use test_log::test;
    use uuid::Uuid;

    async fn backend(compression: Compression) -> DispatchBackend {
        let bucket: String = Uuid::new_v4()
            .as_bytes()
            .iter()
            .fold(String::new(), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            });

        let backend = S3Backend::new(
            S3Config {
                bucket: Some(bucket),
                region: Some(
                    std::env::var("TEST_S3_REGION")
                        .unwrap_or_else(|_| "http://127.0.0.1:9000".to_string()),
                ),
                access_key: Some(
                    std::env::var("TEST_S3_ACCESS_KEY")
                        .unwrap_or_else(|_| "minioadmin".to_string()),
                ),
                secret_key: Some(
                    std::env::var("TEST_S3_SECRET_KEY")
                        .unwrap_or_else(|_| "minioadmin".to_string()),
                ),
                trust_anchors: vec![],
                path_style: false,
            },
            compression,
        )
        .await
        .unwrap();

        // create the bucket

        backend
            .client
            .create_bucket()
            .bucket(&backend.bucket)
            .send()
            .await
            .unwrap();

        backend.into()
    }

    #[test(tokio::test)]
    #[rstest]
    #[case(Compression::None)]
    #[case(Compression::Zstd)]
    #[cfg_attr(not(feature = "_test-s3"), ignore = "requires minio or s3")]
    async fn store_read_and_delete(#[case] compression: Compression) {
        let backend = backend(compression).await;

        test_store_read_and_delete(backend).await
    }

    /// Ensure retrieving the information that the file does not exist works.
    #[test(tokio::test)]
    #[cfg_attr(not(feature = "_test-s3"), ignore = "requires minio or s3")]
    async fn read_not_found() {
        let backend = backend(Compression::None).await;
        test_read_not_found(backend).await;
    }

    #[test]
    fn cleanup() {
        assert_eq!(super::cleanup(""), None);
        assert_eq!(super::cleanup("none").as_deref(), Some("none"));
        assert_eq!(super::cleanup("aws-chunked"), None);
        assert_eq!(super::cleanup("aws-chunked, none").as_deref(), Some("none"));
        assert_eq!(
            super::cleanup("foo, aws-chunked, bar").as_deref(),
            Some("foo, bar")
        );
    }

    #[test(tokio::test)]
    async fn partial_credentials_validation() {
        // Providing only access_key should fail
        let result = S3Backend::new(
            S3Config {
                bucket: Some("test-bucket".to_string()),
                region: Some("us-east-1".to_string()),
                access_key: Some("test-key".to_string()),
                secret_key: None,
                trust_anchors: vec![],
                path_style: false,
            },
            Compression::None,
        )
        .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("secret_key is missing"));

        // Providing only secret_key should fail
        let result = S3Backend::new(
            S3Config {
                bucket: Some("test-bucket".to_string()),
                region: Some("us-east-1".to_string()),
                access_key: None,
                secret_key: Some("test-secret".to_string()),
                trust_anchors: vec![],
                path_style: false,
            },
            Compression::None,
        )
        .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("access_key is missing"));
    }
}
