use crate::{
    config::S3Config,
    service::{
        DeleteManyError, StorageBackend, StorageKey, StorageResult, StoreError,
        compression::Compression, temp::TempFile,
    },
};
use anyhow::{Context, anyhow, bail};
use aws_config::{AppName, BehaviorVersion};
use aws_sdk_s3::{
    Client,
    config::{
        self, Credentials, Region, SharedHttpClient,
        endpoint::{EndpointFuture, Params, ResolveEndpoint},
    },
    operation::get_object::GetObjectError,
    primitives::FsBuilder,
    types::{Delete, ObjectIdentifier},
};
use aws_smithy_http_client::tls::{Provider, TlsContext, TrustStore, rustls_provider::CryptoMode};
use aws_smithy_types::{byte_stream::error::Error as ByteStreamError, endpoint::Endpoint};
use bytes::Bytes;
use futures::{Stream, TryStreamExt};
use std::{fmt::Debug, io, str::FromStr};
use tokio::{fs, io::AsyncRead};
use tokio_util::io::ReaderStream;
use tracing::instrument;
use trustify_common::aws::aws_credentials_configured;
use urlencoding::encode;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
enum S3CredentialError {
    #[error("S3 secret_key is missing (both credentials must be provided together)")]
    SecretKeyMissing,
    #[error("S3 access_key is missing (both credentials must be provided together)")]
    AccessKeyMissing,
}

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
        match (access_key.is_some(), secret_key.is_some()) {
            (true, true) | (false, false) => {}
            (true, false) => bail!(S3CredentialError::SecretKeyMissing),
            (false, true) => bail!(S3CredentialError::AccessKeyMissing),
        }

        // basics

        let config = config::Builder::new()
            .app_name(AppName::new(name)?)
            .force_path_style(path_style);

        // region

        let region = region.ok_or_else(|| anyhow!("region not provided"))?;
        let config = if region.starts_with("http://") || region.starts_with("https://") {
            config
                .endpoint_resolver(StringResolver::from(region))
                // we just use any region
                .region(Region::from_static("us-east-1"))
        } else {
            config.region(Region::new(region))
        };

        let config = configure_credentials(config, access_key, secret_key).await;

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

/// Configure the credentials for the S3 client.
///
/// Two mutually exclusive credential sources are supported:
///
/// 1. Static credentials — an explicit access-key / secret-key pair. These are
///    supplied directly (`--s3-access-key` / `--s3-secret-key`) or injected by
///    the OpenShift Cloud Credential Operator (CCO) in `mint` / `passthrough` /
///    `default` mode (as `TRUSTD_S3_ACCESS_KEY` / `TRUSTD_S3_SECRET_KEY`).
///
/// 2. The AWS default credential provider chain — used when no static keys are
///    provided. This engages the SDK's built-in providers, including the
///    Web Identity Token provider used by CCO `manual` (STS) mode. In that mode
///    no static keys are set; credentials are instead derived from
///    `AWS_ROLE_ARN` + `AWS_WEB_IDENTITY_TOKEN_FILE` (and/or
///    `AWS_SHARED_CREDENTIALS_FILE`) by performing `AssumeRoleWithWebIdentity`,
///    yielding short-lived credentials that the SDK refreshes automatically.
///
/// Note: `aws_sdk_s3::config::Builder` does *not* wire up any credential chain
/// by itself — unlike a client built from `aws_config::defaults(..)`. Without
/// the fallback below, omitting the static keys would leave the client with no
/// credentials provider at all and token-based (STS) auth would never happen.
async fn configure_credentials(
    config: config::Builder,
    access_key: Option<String>,
    secret_key: Option<String>,
) -> config::Builder {
    match access_key.zip(secret_key) {
        Some((key_id, access_key)) => {
            let credentials = Credentials::new(key_id, access_key, None, None, "config");
            config.credentials_provider(credentials)
        }
        // No static keys: only engage the AWS default credential provider chain when the
        // environment actually points at an AWS credential source (e.g. CCO manual/STS
        // mode sets `AWS_ROLE_ARN` + `AWS_WEB_IDENTITY_TOKEN_FILE`, or an EC2 deployment
        // opts into IMDS with `TRUSTD_AWS_USE_IMDS=true`). Loading the chain otherwise just
        // costs time and resolves to nothing, so skip AWS entirely — the client is left
        // without a credentials provider, matching a non-AWS backend.
        None if aws_credentials_configured() => {
            let shared = aws_config::defaults(BehaviorVersion::latest()).load().await;
            match shared.credentials_provider() {
                Some(provider) => config.credentials_provider(provider),
                None => config,
            }
        }
        None => {
            log::info!(
                "No S3 static credentials and no AWS credential environment detected; not engaging the AWS credential provider chain"
            );
            config
        }
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

    async fn delete_many(&self, keys: &[StorageKey]) -> Result<(), DeleteManyError<Self::Error>> {
        if keys.is_empty() {
            return Ok(());
        }

        // From official AWS S3 SDK examples
        //
        // Push into a mut vector to use `?` early return errors while building object keys.
        let mut delete_object_ids: Vec<ObjectIdentifier> = vec![];
        for StorageKey(key) in keys {
            let obj_id = ObjectIdentifier::builder()
                .key(key)
                .build()
                .map_err(|err| DeleteManyError::Generic(Error::S3(err.into())))?;
            delete_object_ids.push(obj_id);
        }

        self.client
            .delete_objects()
            .bucket(&self.bucket)
            .delete(
                Delete::builder()
                    .set_objects(Some(delete_object_ids))
                    .build()
                    .map_err(|err| DeleteManyError::Generic(Error::S3(err.into())))?,
            )
            .send()
            .await
            .map_err(|err| DeleteManyError::Generic(Error::S3(err.into())))?;
        Ok(())
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
    Bytes(#[from] ByteStreamError),
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
        test::{test_read_not_found, test_store_read_and_delete, test_store_read_and_delete_rng},
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
    #[case::none(Compression::None)]
    #[case::zstd(Compression::Zstd)]
    #[cfg_attr(not(feature = "_test-s3"), ignore = "requires minio or s3")]
    async fn store_read_and_delete(#[case] compression: Compression) {
        let backend = backend(compression).await;

        test_store_read_and_delete(backend).await
    }

    #[test(tokio::test)]
    #[rstest]
    #[case::none(Compression::None)]
    #[case::zstd(Compression::Zstd)]
    #[cfg_attr(not(feature = "_test-s3"), ignore = "requires minio or s3")]
    async fn store_read_and_delete_rng(#[case] compression: Compression) {
        let backend = backend(compression).await;

        test_store_read_and_delete_rng(backend).await;

        log::info!("test finished: {compression}");
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
        let err = result.unwrap_err();
        assert_eq!(
            err.downcast_ref::<super::S3CredentialError>(),
            Some(&super::S3CredentialError::SecretKeyMissing)
        );

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
        let err = result.unwrap_err();
        assert_eq!(
            err.downcast_ref::<super::S3CredentialError>(),
            Some(&super::S3CredentialError::AccessKeyMissing)
        );
    }

    /// With no static credentials, construction must still succeed. When the AWS
    /// credential environment is present the backend engages the default provider chain
    /// (which powers CCO `manual`/STS token auth); when it is absent the backend simply
    /// skips AWS. Either way, construction does not fail — the chain, when used, is
    /// resolved lazily on the first request.
    #[test(tokio::test)]
    async fn no_static_credentials_uses_default_chain() {
        let result = S3Backend::new(
            S3Config {
                bucket: Some("test-bucket".to_string()),
                region: Some("us-east-1".to_string()),
                access_key: None,
                secret_key: None,
                trust_anchors: vec![],
                path_style: false,
            },
            Compression::None,
        )
        .await;
        assert!(result.is_ok());
    }
}
