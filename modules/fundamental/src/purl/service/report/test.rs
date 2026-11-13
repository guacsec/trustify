use super::{ProviderIdentity, ReportContext, ReportError, context, source::RecoveryLimits};
use crate::purl::service::{PurlService, StatusInfo};
use bytes::Bytes;
use futures_util::{
    Stream, StreamExt, TryStreamExt,
    stream::{self, BoxStream},
};
use rstest::rstest;
use sea_orm::{EntityTrait, TryIntoModel};
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    io,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};
use test_context::test_context;
use tokio::io::AsyncRead;
use tracing::{Instrument, Subscriber, instrument::WithSubscriber, span};
use tracing_subscriber::{
    Layer,
    layer::{Context, SubscriberExt},
    registry::LookupSpan,
};
use trustify_common::{cpe::Cpe, purl::Purl};
use trustify_entity::{
    advisory, cpe, sbom, source_document, version_range, version_scheme::VersionScheme,
};
use trustify_module_storage::service::{
    Compression, RetrieveEncodedResult, StorageBackend, StorageContent, StorageKey, StorageResult,
    StoreError,
};
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

/// Builds a source with stable metadata and one arbitrary ingested component tree.
fn cdx(component: Value) -> Value {
    json!({"bomFormat":"CycloneDX","specVersion":"1.4","version":1,
        "serialNumber":"urn:uuid:00000000-0000-0000-0000-744620000001",
        "metadata":{"component":{"type":"application","name":"recovery-test","version":"1.0","bom-ref":"root"}},
        "components":[component]})
}

/// A component supplier is independent of the namespace/name encoded in its PURL.
fn library() -> Value {
    json!({"type":"library","name":"lib","version":"1.0.0","bom-ref":"lib",
        "purl":"pkg:maven/com.example/lib@1.0.0","supplier":{"name":"Red Hat"}})
}

/// Execute recovery through the same module interface used by the report, without ingestion writes.
async fn recover(ctx: &TrustifyContext, document: Value) -> anyhow::Result<(Uuid, ReportContext)> {
    let id = Uuid::parse_str(&ctx.ingest_json(document).await?.id)?;
    let before = sbom::Entity::find_by_id(id).one(&ctx.db).await?.unwrap();
    let source_before = source_document::Entity::find_by_id(before.source_document_id)
        .one(&ctx.db)
        .await?
        .unwrap();
    let rows = PurlService::fetch_sbom_purl_rows(&[id], &ctx.db).await?;
    let result =
        ReportContext::load(&rows, &HashMap::new(), &ctx.storage.clone().into(), &ctx.db).await?;
    assert_eq!(
        sbom::Entity::find_by_id(id).one(&ctx.db).await?.unwrap(),
        before
    );
    assert_eq!(
        source_document::Entity::find_by_id(before.source_document_id)
            .one(&ctx.db)
            .await?
            .unwrap(),
        source_before
    );
    Ok((id, result))
}

/// Captures real recovery spans without replacing the database or object-storage operations.
#[derive(Clone, Default)]
struct RecoverySpans(Arc<Mutex<Vec<RecoverySpan>>>);

struct RecoverySpan {
    target: &'static str,
    name: &'static str,
    parent: Option<&'static str>,
    fields: Vec<&'static str>,
}

impl<S> Layer<S> for RecoverySpans
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, context: Context<'_, S>) {
        let metadata = attrs.metadata();
        if metadata
            .target()
            .starts_with("trustify_module_fundamental::purl::service::report")
        {
            let current = context.span(id).unwrap();
            self.0.lock().unwrap().push(RecoverySpan {
                target: metadata.target(),
                name: metadata.name(),
                parent: current.parent().map(|parent| parent.metadata().name()),
                fields: metadata.fields().iter().map(|field| field.name()).collect(),
            });
        }
    }
}

/// Recovery I/O remains attributable to its request without recording source or storage arguments.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn recovery_io_is_traced_without_arguments(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given a real stored SBOM and a subscriber scoped to one recovery request.
    let id = Uuid::parse_str(&ctx.ingest_json(cdx(library())).await?.id)?;
    let rows = PurlService::fetch_sbom_purl_rows(&[id], &ctx.db).await?;
    let spans = RecoverySpans::default();
    let subscriber = tracing_subscriber::registry().with(spans.clone());

    // When the same recovery interface used by report generation reads its inputs.
    let result = async {
        ReportContext::load(&rows, &HashMap::new(), &ctx.storage.clone().into(), &ctx.db)
            .instrument(tracing::info_span!("report_request"))
            .await
    }
    .with_subscriber(subscriber)
    .await?;

    // Then the provider and nested I/O spans are preserved, without document payloads or arguments.
    assert_eq!(
        result.key(id, "lib").provider.as_deref(),
        Some("https://www.redhat.com")
    );
    let spans = spans.0.lock().unwrap();
    for (target, name, parent) in [
        (
            "trustify_module_fundamental::purl::service::report",
            "load",
            "report_request",
        ),
        (
            "trustify_module_fundamental::purl::service::report",
            "load_sources",
            "load",
        ),
        (
            "trustify_module_fundamental::purl::service::report::source",
            "load_parsed",
            "load_sources",
        ),
        (
            "trustify_module_fundamental::purl::service::report::context",
            "load",
            "load",
        ),
    ] {
        let matching = spans
            .iter()
            .filter(|span| span.target == target && span.name == name)
            .collect::<Vec<_>>();
        assert_eq!(
            matching.len(),
            1,
            "missing or duplicate I/O span {target}::{name}"
        );
        assert_eq!(matching[0].parent, Some(parent));
        assert!(
            matching[0].fields.is_empty(),
            "I/O arguments must not be captured"
        );
    }
    Ok(())
}

/// A stable ref or a unique anonymous identity both recover an existing component's provider.
#[test_context(TrustifyContext)]
#[rstest]
#[case::explicit(Some("lib"))]
#[case::explicit_uuid(Some("00000000-0000-0000-0000-744620000010"))]
#[case::anonymous(None)]
#[test_log::test(actix_web::test)]
async fn recover_existing_cdx_component(
    ctx: &TrustifyContext,
    #[case] reference: Option<&str>,
) -> anyhow::Result<()> {
    // Given a source ingested with either a source ref or a generated historical node ID.
    let mut component = library();
    component["bom-ref"] = json!(reference);
    let (id, result) = recover(ctx, cdx(component)).await?;
    // When inspecting the original node's recovered canonical provider.
    let rows = PurlService::fetch_sbom_purl_rows(&[id], &ctx.db).await?;
    // Then no manual re-ingestion or source-order assumption was necessary.
    assert_eq!(rows.len(), 1);
    assert_eq!(
        result.key(id, &rows[0].node_id).provider.as_deref(),
        Some("https://www.redhat.com")
    );
    Ok(())
}

/// Nested and pedigree components follow the same traversal paths as release ingestion.
#[test_context(TrustifyContext)]
#[rstest]
#[case::nested(json!({"type":"library","name":"outer","components":[library()]}))]
#[case::ancestor(json!({"type":"library","name":"outer","pedigree":{"ancestors":[library()]}}))]
#[case::variant(json!({"type":"library","name":"outer","pedigree":{"variants":[library()]}}))]
#[test_log::test(actix_web::test)]
async fn recover_cdx_traversal(
    ctx: &TrustifyContext,
    #[case] component: Value,
) -> anyhow::Result<()> {
    // Given the same reportable package in each supported component location.
    let (id, result) = recover(ctx, cdx(component)).await?;
    // When looking up its exact source ref.
    let key = result.key(id, "lib");
    // Then its supplier is recovered rather than inherited from the unrelated outer component.
    assert_eq!(key.provider.as_deref(), Some("https://www.redhat.com"));
    Ok(())
}

/// Confirmed absence permits product inheritance; explicit empty or unresolved suppliers do not.
#[test_context(TrustifyContext)]
#[rstest]
#[case::absent(json!(null),Some("https://www.redhat.com"))]
#[case::empty(json!({}),None)]
#[case::unknown(json!({"name":"Unknown"}),None)]
#[case::url(json!({"url":["https://vendor.example/"]}),Some("https://vendor.example"))]
#[test_log::test(actix_web::test)]
async fn recover_supplier_presence(
    ctx: &TrustifyContext,
    #[case] supplier: Value,
    #[case] expected: Option<&str>,
) -> anyhow::Result<()> {
    // Given a describing component with a known supplier and an independently attributed library.
    let mut component = library();
    component["supplier"] = supplier;
    let mut doc = cdx(component);
    doc["metadata"]["component"]["supplier"] = json!({"name":"Red Hat"});
    let (id, result) = recover(ctx, doc).await?;
    // When deriving the library's provider with canonical component-first precedence.
    let provider = result.key(id, "lib").provider;
    // Then absent and explicitly unresolved identities have different behavior.
    assert_eq!(provider.as_deref(), expected);
    Ok(())
}

/// Unique explicit refs keep duplicate PURLs' different providers independent.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn recover_duplicate_purls(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given two source refs sharing a PURL but naming different providers.
    let mut doc = cdx(library());
    let mut second = library();
    second["bom-ref"] = json!("second");
    second["supplier"] = json!({"name":"SUSE"});
    doc["components"].as_array_mut().unwrap().push(second);
    let (id, result) = recover(ctx, doc).await?;
    // When resolving providers by node, not by a PURL-only index.
    let providers = [
        result.key(id, "lib").provider,
        result.key(id, "second").provider,
    ];
    // Then both shipped canonical aliases are retained independently.
    assert_eq!(
        providers,
        [
            Some("https://www.redhat.com".into()),
            Some("https://www.suse.com".into())
        ]
    );
    Ok(())
}

/// A describing file's ignored supplier must not become the product provider of other packages.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn recover_nonpackage_describing_supplier(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given a library with no supplier and a describing file carrying an unpersisted supplier.
    let mut component = library();
    component["supplier"] = Value::Null;
    let mut doc = cdx(component);
    doc["metadata"]["component"]["type"] = json!("file");
    doc["metadata"]["component"]["supplier"] = json!({"name":"Red Hat"});
    // When recovering the same package-supplier evidence used by main's ProviderSnapshot.
    let (id, result) = recover(ctx, doc).await?;
    // Then the file's source field cannot invent a provider for the library.
    assert_eq!(result.key(id, "lib").provider, None);
    Ok(())
}

/// Local CPE identity can disambiguate otherwise identical anonymous historical components.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn recover_anonymous_cpe_identity(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given anonymous components with the same names/PURLs, but distinct retained CPEs and suppliers.
    let mut first = library();
    first["bom-ref"] = Value::Null;
    first["cpe"] = json!("cpe:/a:example:product:1.0");
    let mut second = first.clone();
    second["cpe"] = json!("cpe:/a:example:product:2.0");
    second["supplier"] = json!({"name":"SUSE"});
    let mut doc = cdx(first);
    doc["components"].as_array_mut().unwrap().push(second);
    let (id, result) = recover(ctx, doc).await?;
    // When each random node ID is matched using its own retained references.
    let providers = result
        .suppliers
        .iter()
        .filter(|((sbom, _), _)| *sbom == id)
        .map(|(_, identity)| identity.as_ref().unwrap().resolve().provider.unwrap())
        .collect::<BTreeSet<_>>();
    // Then recovery succeeds without an unsafe array-order heuristic.
    assert_eq!(
        providers,
        BTreeSet::from([
            "https://www.redhat.com".into(),
            "https://www.suse.com".into()
        ])
    );
    Ok(())
}

/// SPDXIDs retain exact component attribution; NONE and NOASSERTION are confirmed supplier absence.
#[test_context(TrustifyContext)]
#[rstest]
#[case::named("Organization: Red Hat", Some("https://www.redhat.com"))]
#[case::none("NONE", None)]
#[case::noassertion("NOASSERTION", None)]
#[test_log::test(actix_web::test)]
async fn recover_spdx_supplier(
    ctx: &TrustifyContext,
    #[case] supplier: &str,
    #[case] expected: Option<&str>,
) -> anyhow::Result<()> {
    // Given an existing SPDX package with a stable ID, including its sentinel supplier values.
    let doc = json!({"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT",
        "name":"recovery-spdx","documentNamespace":"https://example.org/spdx/recovery",
        "creationInfo":{"creators":["Tool: test"],"created":"2024-01-15T00:00:00Z"},
        "packages":[{"SPDXID":"SPDXRef-lib","name":"lib","versionInfo":"1.0.0","downloadLocation":"NOASSERTION",
            "filesAnalyzed":false,"licenseConcluded":"NOASSERTION","licenseDeclared":"NOASSERTION","copyrightText":"NOASSERTION","supplier":supplier,
            "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:maven/com.example/lib@1.0.0"}]}]});
    let (id, result) = recover(ctx, doc).await?;
    // When the report reuses the original SPDXID rather than guessing from a package version.
    let provider = result.key(id, "SPDXRef-lib").provider;
    // Then sentinel values are not treated as explicitly unresolved organizations.
    assert_eq!(provider.as_deref(), expected);
    Ok(())
}

/// Scripted storage faults are external-input adapters, not assertions about a mock's call count.
enum InputStorage {
    Interrupted,
    Pending,
    Bytes(Vec<u8>),
}

impl StorageBackend for InputStorage {
    type Error = io::Error;
    async fn store<S>(&self, _stream: S) -> Result<StorageResult, StoreError<Self::Error>>
    where
        S: AsyncRead + Unpin + Send,
    {
        Err(StoreError::Backend(io::Error::other(
            "read-only test input",
        )))
    }
    async fn retrieve(
        &self,
        _key: StorageKey,
    ) -> Result<Option<impl Stream<Item = Result<Bytes, Self::Error>> + Send + use<>>, Self::Error>
    {
        let stream: BoxStream<'static, Result<Bytes, io::Error>> = match self {
            Self::Interrupted => stream::iter([
                Ok(Bytes::from_static(b"{")),
                Err(io::Error::other("interrupted source")),
            ])
            .boxed(),
            Self::Pending => stream::pending().boxed(),
            Self::Bytes(bytes) => stream::iter([Ok(Bytes::copy_from_slice(bytes))]).boxed(),
        };
        Ok(Some(stream))
    }
    async fn retrieve_encoded(
        &self,
        key: StorageKey,
        _accepted: &[Compression],
    ) -> RetrieveEncodedResult<
        impl Stream<Item = Result<Bytes, Self::Error>> + Send + use<>,
        Self::Error,
    > {
        // Scripted inputs are always identity-encoded, regardless of what the caller accepts.
        Ok(self.retrieve(key).await?.map(|stream| StorageContent {
            compression: Compression::None,
            stream,
        }))
    }
    async fn delete(&self, _key: StorageKey) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[rstest]
#[case::identity(&[])]
#[case::zstd(&[Compression::Zstd])]
#[test_log::test(tokio::test)]
async fn input_storage_retrieve_encoded(#[case] accepted: &[Compression]) -> anyhow::Result<()> {
    let storage = InputStorage::Bytes(b"scripted input".to_vec());
    let content = storage
        .retrieve_encoded(StorageKey::from_sha256(&"0".repeat(64)), accepted)
        .await?
        .unwrap();
    assert_eq!(content.compression, Compression::None);
    let chunks = content.stream.try_collect::<Vec<_>>().await?;
    assert_eq!(chunks.concat(), b"scripted input");
    Ok(())
}

/// A stream failure after successful chunks cannot produce confirmed supplier absence.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn recovery_stream_error(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given source metadata for an existing SBOM and an interrupted storage stream.
    let id = Uuid::parse_str(&ctx.ingest_json(cdx(library())).await?.id)?;
    let rows = PurlService::fetch_sbom_purl_rows(&[id], &ctx.db).await?;
    // When recovery reads a prefix before the backend reports an I/O error.
    let result = ReportContext::load_with_limits(
        &rows,
        &HashMap::new(),
        &InputStorage::Interrupted,
        &ctx.db,
        RecoveryLimits::default(),
    )
    .await;
    // Then no partial provider cache is returned.
    assert!(matches!(result, Err(ReportError::Source { .. })));
    Ok(())
}

/// The total recovery deadline also covers streams that never yield another chunk.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn recovery_deadline(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given a source whose storage response remains pending.
    let id = Uuid::parse_str(&ctx.ingest_json(cdx(library())).await?.id)?;
    let rows = PurlService::fetch_sbom_purl_rows(&[id], &ctx.db).await?;
    let limits = RecoveryLimits {
        duration: Duration::from_millis(30),
        ..RecoveryLimits::default()
    };
    // When the request's recovery budget elapses.
    let result = ReportContext::load_with_limits(
        &rows,
        &HashMap::new(),
        &InputStorage::Pending,
        &ctx.db,
        limits,
    )
    .await;
    // Then timeout is explicit instead of waiting indefinitely or guessing the supplier.
    assert!(matches!(
        result,
        Err(ReportError::Limit {
            reason: "source recovery deadline",
            ..
        })
    ));
    Ok(())
}

/// Both byte limits use actual stream bytes even when stored metadata underreports size.
#[test_context(TrustifyContext)]
#[rstest]
#[case::document(4, 100)]
#[case::request(100, 4)]
#[test_log::test(actix_web::test)]
async fn recovery_stream_byte_limits(
    ctx: &TrustifyContext,
    #[case] per_document: usize,
    #[case] per_request: usize,
) -> anyhow::Result<()> {
    use sea_orm::{ActiveModelTrait, Set};
    // Given metadata that falsely claims an empty source.
    let id = Uuid::parse_str(&ctx.ingest_json(cdx(library())).await?.id)?;
    let sbom = sbom::Entity::find_by_id(id).one(&ctx.db).await?.unwrap();
    source_document::ActiveModel {
        id: Set(sbom.source_document_id),
        size: Set(0),
        ..Default::default()
    }
    .update(&ctx.db)
    .await?;
    let rows = PurlService::fetch_sbom_purl_rows(&[id], &ctx.db).await?;
    let limits = RecoveryLimits {
        per_document,
        per_request,
        ..RecoveryLimits::default()
    };
    // When a storage stream supplies more bytes than either allowed budget.
    let result = ReportContext::load_with_limits(
        &rows,
        &HashMap::new(),
        &InputStorage::Bytes(b"12345".to_vec()),
        &ctx.db,
        limits,
    )
    .await;
    // Then rejection occurs at streamed accumulation, not only metadata preflight.
    assert!(matches!(
        result,
        Err(ReportError::Limit {
            reason: "decompressed source byte limit",
            ..
        })
    ));
    Ok(())
}

/// A valid replacement document under the wrong content key is not trustworthy report evidence.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn recovery_source_digest_mismatch(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given an ingested document and a different valid JSON document served under its source key.
    let id = Uuid::parse_str(&ctx.ingest_json(cdx(library())).await?.id)?;
    let rows = PurlService::fetch_sbom_purl_rows(&[id], &ctx.db).await?;
    let mut changed = cdx(library());
    changed["components"][0]["supplier"] = json!({"name":"SUSE"});
    let storage = InputStorage::Bytes(serde_json::to_vec(&changed)?);
    // When parsing would otherwise accept the altered provider statement.
    let result = ReportContext::load_with_limits(
        &rows,
        &HashMap::new(),
        &storage,
        &ctx.db,
        RecoveryLimits::default(),
    )
    .await;
    // Then the immutable source digest, not successful JSON parsing, controls trust.
    assert!(matches!(
        result,
        Err(ReportError::Unavailable {
            reason: "source digest mismatch",
            ..
        })
    ));
    Ok(())
}

/// A describing component with a generated ID is mapped by its actual Describes relation.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn recover_anonymous_describing_component(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given a reportable metadata component whose generated UUID is absent from stored source bytes.
    let mut doc = cdx(library());
    doc["metadata"]["component"] = library();
    doc["metadata"]["component"]["bom-ref"] = Value::Null;
    doc["components"] = json!([]);
    let (id, result) = recover(ctx, doc).await?;
    // When recovery correlates it with the stored describing node.
    let rows = PurlService::fetch_sbom_purl_rows(&[id], &ctx.db).await?;
    // Then the provider survives even though the original source contains no node UUID.
    assert_eq!(rows.len(), 1);
    assert_eq!(
        result.key(id, &rows[0].node_id).provider.as_deref(),
        Some("https://www.redhat.com")
    );
    Ok(())
}

/// Collapsed duplicate explicit refs with incompatible suppliers must not select the first occurrence.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn recovery_duplicate_refs_ambiguous(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given source occurrences sharing an explicit ref but disagreeing about its supplier.
    let mut doc = cdx(library());
    let mut second = library();
    second["supplier"] = json!({"name":"SUSE"});
    doc["components"].as_array_mut().unwrap().push(second);
    let id = Uuid::parse_str(&ctx.ingest_json(doc).await?.id)?;
    let rows = PurlService::fetch_sbom_purl_rows(&[id], &ctx.db).await?;
    // When old conflict-ignore ingestion has collapsed the source occurrences.
    let result =
        ReportContext::load(&rows, &HashMap::new(), &ctx.storage.clone().into(), &ctx.db).await;
    // Then attribution fails explicitly rather than depending on insertion order.
    assert!(matches!(result, Err(ReportError::Ambiguous { .. })));
    Ok(())
}

/// Exactly-at-limit source bytes remain accepted, without an off-by-one rejection.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn recovery_exact_byte_limit(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given limits equal to the actual stored source size.
    let id = Uuid::parse_str(&ctx.ingest_json(cdx(library())).await?.id)?;
    let sbom = sbom::Entity::find_by_id(id).one(&ctx.db).await?.unwrap();
    let metadata = source_document::Entity::find_by_id(sbom.source_document_id)
        .one(&ctx.db)
        .await?
        .unwrap();
    let limit = usize::try_from(metadata.size)?;
    let limits = RecoveryLimits {
        per_document: limit,
        per_request: limit,
        ..RecoveryLimits::default()
    };
    let rows = PurlService::fetch_sbom_purl_rows(&[id], &ctx.db).await?;
    // When all streamed bytes exactly consume the request budget.
    let result =
        ReportContext::load_with_limits(&rows, &HashMap::new(), &ctx.storage, &ctx.db, limits)
            .await?;
    // Then the complete source is still evaluated.
    assert_eq!(
        result.key(id, "lib").provider.as_deref(),
        Some("https://www.redhat.com")
    );
    Ok(())
}

/// Multiple individually acceptable sources must also respect a shared request byte budget.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn recovery_total_byte_budget(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given two valid sources, each smaller than the per-document bound.
    let first = Uuid::parse_str(&ctx.ingest_json(cdx(library())).await?.id)?;
    let mut second = cdx(library());
    second["serialNumber"] = json!("urn:uuid:00000000-0000-0000-0000-744620000002");
    let second = Uuid::parse_str(&ctx.ingest_json(second).await?.id)?;
    let sbom = sbom::Entity::find_by_id(first).one(&ctx.db).await?.unwrap();
    let metadata = source_document::Entity::find_by_id(sbom.source_document_id)
        .one(&ctx.db)
        .await?
        .unwrap();
    let limit = usize::try_from(metadata.size)?;
    let limits = RecoveryLimits {
        per_document: limit,
        per_request: limit * 2 - 1,
        ..RecoveryLimits::default()
    };
    let rows = PurlService::fetch_sbom_purl_rows(&[first, second], &ctx.db).await?;
    // When the combined document bytes would exceed the whole-request limit by one byte.
    let result =
        ReportContext::load_with_limits(&rows, &HashMap::new(), &ctx.storage, &ctx.db, limits)
            .await;
    // Then the request does not return the provider cache for only its first source.
    assert!(matches!(result, Err(ReportError::Limit { .. })));
    Ok(())
}

/// Source component traversal is bounded independently of JSON/parser nesting limits.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn recovery_traversal_depth(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given a valid, shallow source tree exceeding the deliberately reduced traversal budget.
    let doc = cdx(
        json!({"type":"library","name":"outer","components":[{"type":"library","name":"middle","components":[library()]}]}),
    );
    let id = Uuid::parse_str(&ctx.ingest_json(doc).await?.id)?;
    let rows = PurlService::fetch_sbom_purl_rows(&[id], &ctx.db).await?;
    let limits = RecoveryLimits {
        depth: 1,
        ..RecoveryLimits::default()
    };
    // When parsing succeeds but recursive component extraction would exceed its own bound.
    let result =
        ReportContext::load_with_limits(&rows, &HashMap::new(), &ctx.storage, &ctx.db, limits)
            .await;
    // Then extraction fails explicitly rather than recursing without limit.
    assert!(matches!(
        result,
        Err(ReportError::Limit {
            reason: "component traversal depth",
            ..
        })
    ));
    Ok(())
}

/// Canonical context scoping distinguishes wildcard matches, comparable mismatches and unrelated products.
#[test_context(TrustifyContext)]
#[rstest]
#[case::exact("cpe:/a:example:product:8.1", "cpe:/a:example:product:8.1", 100)]
#[case::any("cpe:/a:example:product", "cpe:/a:example:product:8.1", 90)]
#[case::major("cpe:/a:example:product:8", "cpe:/a:example:product:8.1", 90)]
#[case::different("cpe:/a:example:product:8.1", "cpe:/a:example:product:8.2", 0)]
#[case::unrelated("cpe:/a:other:product:8.1", "cpe:/a:example:product:8.1", 70)]
#[test_log::test(actix_web::test)]
async fn weighted_cpe_matching(
    ctx: &TrustifyContext,
    #[case] statement: &str,
    #[case] local: &str,
    #[case] expected: i32,
) -> anyhow::Result<()> {
    // Given a real component's retained local CPE.
    let mut component = library();
    component["cpe"] = json!(local);
    let (id, recovered) = recover(ctx, cdx(component)).await?;
    let statement: cpe::Model =
        cpe::ActiveModel::from_cpe(Cpe::from_str(statement)?).try_into_model()?;
    // When scoring the assertion's product against the component's own scopes.
    let confidence = context::confidence(&statement, &recovered.scopes[&(id, "lib".into())]);
    // Then the canonical confidence/eligibility distinction is preserved.
    assert_eq!(confidence, expected);
    Ok(())
}

/// Multiple graph paths retain only the nearest scope for the same ancestor CPE.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn weighted_context_nearest_path(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given both a direct and a longer dependency path from a describing product to one library.
    let mut doc = cdx(library());
    doc["metadata"]["component"]["cpe"] = json!("cpe:/a:example:product:1.0");
    doc["components"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"library","name":"middle","bom-ref":"middle"}));
    doc["dependencies"] = json!([
        {"ref":"root","dependsOn":["lib","middle"]},
        {"ref":"middle","dependsOn":["lib"]}
    ]);
    let (id, result) = recover(ctx, doc).await?;
    // When building the canonical weighted-context grouping key.
    let distances = result
        .key(id, "lib")
        .scopes
        .into_iter()
        .filter(|(_, source, _)| source == "ancestor_node")
        .map(|(_, _, distance)| distance)
        .collect::<Vec<_>>();
    // Then redundant worse paths do not prevent otherwise equivalent report groups from merging.
    assert_eq!(distances, vec![1]);
    Ok(())
}

/// A document-level issuer is not a substitute for a CSAF namespace, and fragments use the final delimiter.
#[rstest]
#[case::csaf("csaf","https://www.redhat.com/#VEX-1",vec!["namespace:https://www.redhat.com/"],false)]
#[case::fragment("csaf","https://vendor.example/#publisher#VEX-1",vec!["namespace:https://vendor.example/#publisher"],false)]
#[case::noncsaf("osv","https://unrelated.example/#ID",vec!["name:SUSE"],false)]
#[case::lost_cve("cve","CVE-2099-74462",vec![],true)]
#[test_log::test]
fn advisory_provider_identity(
    #[case] kind: &str,
    #[case] identifier: &str,
    #[case] expected: Vec<&str>,
    #[case] unavailable: bool,
) {
    // Given retained metadata with a misleading issuer or an identifier that happens to contain '#'.
    let advisory = advisory::Model {
        id: Uuid::nil(),
        identifier: identifier.into(),
        version: None,
        document_id: "test".into(),
        deprecated: false,
        issuer_id: None,
        published: None,
        modified: None,
        withdrawn: None,
        title: None,
        labels: [("type", kind)].into(),
        source_document_id: Uuid::nil(),
    };
    // When deriving the assertion's source identity, without fetching raw advisory documents.
    let identity = ProviderIdentity::from_advisory(&advisory, Some("SUSE"));
    // Then namespaces are recovered only for CSAF and unavailable attribution stays non-providerless.
    assert_eq!(
        identity.identifiers,
        expected.into_iter().map(str::to_owned).collect()
    );
    assert_eq!(identity.unavailable, unavailable);
}

/// Report evidence identity must use the current winner, not another PURL on the same component.
#[test_log::test]
fn resolve_multiple_node_identifiers() {
    // Given one node with two PURLs, and two tied assessments of its lib recommendation.
    let id = Uuid::from_u128(100);
    let purls = [
        "pkg:maven/com.example/other@1.0.0",
        "pkg:maven/com.example/lib@1.0.0",
    ]
    .map(|purl| Purl::from_str(purl).unwrap());
    let context = ReportContext {
        suppliers: HashMap::new(),
        products: HashMap::new(),
        node_purls: HashMap::from([((id, "lib".into()), purls.to_vec())]),
        scopes: HashMap::new(),
        assertion_cpes: HashMap::new(),
        derived_sources: HashSet::new(),
        source_bytes: 0,
    };
    let statuses = [(1, "A"), (2, "B")].map(|(advisory_id, name)| StatusInfo {
        vuln_id: "CVE-2099-74463".into(),
        status_slug: "fixed".into(),
        remediations: Vec::new(),
        source_id: Uuid::from_u128(advisory_id),
        status_id: Uuid::nil(),
        advisory_pk: Uuid::from_u128(advisory_id),
        context_cpe_id: None,
        range: Arc::new(version_range::Model {
            id: Uuid::nil(),
            version_scheme_id: VersionScheme::Generic,
            low_version: Some("1.0.0.redhat-00001".into()),
            low_inclusive: Some(true),
            high_version: Some("1.0.0.redhat-00001".into()),
            high_inclusive: Some(true),
        }),
        provider: ProviderIdentity::default(),
        csaf: true,
        advisory_id: Some(name.into()),
    });
    // When resolving the lib assessments; canonical main reference UUIDs are 9dc9c5a2... (A), 7c089e7c... (B).
    let base = Purl::from_str("pkg:maven/com.example/lib").unwrap();
    let selected = context.resolve(id, "lib", &base, &statuses).unwrap();
    // Then B wins. The unrelated 'other' identifier would reverse the reference ordering to A.
    assert_eq!(
        selected
            .iter()
            .map(|info| info.advisory_id.as_deref())
            .collect::<Vec<_>>(),
        vec![Some("B")]
    );
}

/// Existing ML-model references are reportable, but their supplier is not a stored package supplier.
#[test_context(TrustifyContext)]
#[rstest]
#[case::explicit(Some("lib"))]
#[case::anonymous(None)]
#[test_log::test(actix_web::test)]
async fn recover_ml_model_references(
    ctx: &TrustifyContext,
    #[case] reference: Option<&str>,
) -> anyhow::Result<()> {
    // Given a model with a persisted PURL reference and a known product supplier.
    let mut model = library();
    model["type"] = json!("machine-learning-model");
    model["bom-ref"] = json!(reference);
    model["supplier"] = json!({"name":"SUSE"});
    let mut doc = cdx(model);
    doc["specVersion"] = json!("1.6");
    doc["metadata"]["supplier"] = json!({"name":"Red Hat"});
    let id = Uuid::parse_str(&ctx.ingest_json(doc).await?.id)?;
    let rows = PurlService::fetch_sbom_purl_rows(&[id], &ctx.db).await?;
    assert_eq!(
        rows.len(),
        1,
        "the model must actually have a reportable reference"
    );
    // When source recovery follows the original model ref or its unique retained identity.
    let result =
        ReportContext::load(&rows, &HashMap::new(), &ctx.storage.clone().into(), &ctx.db).await;
    assert!(
        result.is_ok(),
        "readable model source must be recoverable: {:?}",
        result.as_ref().err()
    );
    // Then its ignored source supplier does not override the product fallback.
    assert_eq!(
        result?.key(id, &rows[0].node_id).provider.as_deref(),
        Some("https://www.redhat.com")
    );
    Ok(())
}

/// Per-node attributes are loaded once rather than allocating a copy per evidence PURL.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn report_input_attributes_do_not_multiply(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given one moderately large name and multiple small aliases, well below source/package limits.
    let name = "n".repeat(32 * 1024);
    let mut component = library();
    component["name"] = json!(name);
    component["evidence"] = json!({"identity":(0..32).map(|index| json!({
        "field":"purl","confidence":1.0,"concludedValue":format!("pkg:maven/com.example/alias{index}@1.0.0")
    })).collect::<Vec<_>>()});
    let mut doc = cdx(component);
    doc["specVersion"] = json!("1.6");
    let id = Uuid::parse_str(&ctx.ingest_json(doc).await?.id)?;
    // When the report materializes all identifiers for this node.
    let rows = PurlService::fetch_sbom_purl_rows(&[id], &ctx.db).await?;
    assert_eq!(rows.len(), 33);
    let allocated = rows
        .iter()
        .map(|row| (row.node_name.as_ptr() as usize, row.node_name.len()))
        .collect::<HashMap<_, _>>();
    // Then only one name allocation is retained, not 33 separate 32-KiB strings.
    assert_eq!(allocated.values().sum::<usize>(), name.len());
    Ok(())
}

/// Input projection is rejected before large attributes are fetched when source metadata is over budget.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn report_input_metadata_preflight(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use sea_orm::{ActiveModelTrait, Set};
    // Given a source known to exceed the decompressed per-document bound.
    let id = Uuid::parse_str(&ctx.ingest_json(cdx(library())).await?.id)?;
    let sbom = sbom::Entity::find_by_id(id).one(&ctx.db).await?.unwrap();
    source_document::ActiveModel {
        id: Set(sbom.source_document_id),
        size: Set(64 * 1024 * 1024 + 1),
        ..Default::default()
    }
    .update(&ctx.db)
    .await?;
    // When preparing report inputs, before any source recovery or repeated attribute projection.
    let result = PurlService::fetch_sbom_purl_rows(&[id], &ctx.db).await;
    // Then the input gate itself enforces the resource bound.
    assert!(matches!(
        result,
        Err(crate::Error::Report(ReportError::Limit { .. }))
    ));
    Ok(())
}

/// RPM contexts retain main's qualifier precedence and supported Red Hat/SUSE release mappings.
#[rstest]
#[case::redhat_qualifier("pkg:rpm/redhat/lib@1.0-1.el8?distro=rhel-9.4",Some(("cpe:2.3:*:redhat:enterprise_linux:9:*:*:*:*:*:*:*","purl_qualifier")))]
#[case::redhat_release("pkg:rpm/redhat/lib@1.0-1.module%2Bel8.7%2B123",Some(("cpe:2.3:*:redhat:enterprise_linux:8:*:*:*:*:*:*:*","purl_release")))]
#[case::suse_qualifier("pkg:rpm/suse/lib@1.0?distro=sles-15.6",Some(("cpe:2.3:o:suse:*:15:sp6:*:*:*:*:*:*","purl_qualifier")))]
#[case::suse_release("pkg:rpm/suse/lib@1.0-150600.3.1",Some(("cpe:2.3:o:suse:*:15:sp6:*:*:*:*:*:*","purl_release")))]
#[case::suse_ga("pkg:rpm/suse/lib@1.0-150000.3.1",Some(("cpe:2.3:o:suse:*:15:*:*:*:*:*:*:*","purl_release")))]
#[case::unsupported_suse("pkg:rpm/suse/lib@1.0-160000.3.1", None)]
#[case::non_rpm("pkg:maven/com.example/lib@1.0", None)]
#[test_log::test]
fn rpm_product_contexts(
    #[case] input: &str,
    #[case] expected: Option<(&str, &str)>,
) -> anyhow::Result<()> {
    // Given only the component's stated identifier, without a graph CPE.
    let input = Purl::from_str(input)?;
    // When applying the canonical distribution/release hint mapping.
    let actual = context::rpm_context(&input).map(|scope| context::key(&[scope]));
    // Then the product and source weight class match the supported main mapping.
    assert_eq!(
        actual,
        expected.map(|(cpe, source)| vec![(cpe.to_owned(), source.to_owned(), 0)])
    );
    Ok(())
}

/// Related and unrelated release streams preserve canonical range eligibility and confidence tiers.
#[rstest]
#[case::exact(
    "pkg:rpm/redhat/lib@1.0-1.el8_6",
    Some("2.0-2.el8_6"),
    Some(context::StreamScope::Exact)
)]
#[case::major(
    "pkg:rpm/redhat/lib@1.0-1.el8",
    Some("2.0-2.el8_6"),
    Some(context::StreamScope::Major)
)]
#[case::minor(
    "pkg:rpm/redhat/lib@1.0-1.el8_6",
    Some("2.0-2.el8_7"),
    Some(context::StreamScope::Minor)
)]
#[case::different("pkg:rpm/redhat/lib@1.0-1.el8", Some("2.0-2.el9"), None)]
#[case::suse_exact(
    "pkg:rpm/suse/lib@1.0-150600.1",
    Some("2.0-150600.2"),
    Some(context::StreamScope::Exact)
)]
#[case::suse_other("pkg:rpm/suse/lib@1.0-150600.1", Some("2.0-150700.2"), None)]
#[case::suse_one_unscoped("pkg:rpm/suse/lib@1.0-13.1", Some("2.0-150600.2"), None)]
#[case::unbounded(
    "pkg:rpm/suse/lib@1.0-150600.1",
    None,
    Some(context::StreamScope::Unscoped)
)]
#[case::non_rpm(
    "pkg:maven/com.example/lib@1.0-1.el8",
    Some("2.0-2.el9"),
    Some(context::StreamScope::Unscoped)
)]
#[test_log::test]
fn rpm_range_streams(
    #[case] target: &str,
    #[case] high: Option<&str>,
    #[case] expected: Option<context::StreamScope>,
) -> anyhow::Result<()> {
    // Given the same range shape evaluated in each package ecosystem.
    let target = Purl::from_str(target)?;
    let range = version_range::Model {
        id: Uuid::nil(),
        version_scheme_id: VersionScheme::Rpm,
        low_version: None,
        low_inclusive: Some(false),
        high_version: high.map(str::to_owned),
        high_inclusive: Some(false),
    };
    // When evaluating the bound's stream against the recommended version.
    let actual = context::stream_match(&target, &range);
    // Then cross-stream evidence is dropped rather than becoming a stated affected winner.
    assert_eq!(actual, expected);
    Ok(())
}

/// Publisher-policy evidence cannot vote solely on the default unconfirmed-product confidence.
#[test_log::test]
fn required_product_context_is_confirmed() -> anyhow::Result<()> {
    // Given an assertion whose product is not confirmed by any component scope.
    let cpe: cpe::Model = cpe::ActiveModel::from_cpe(Cpe::from_str("cpe:/a:example:product:1.0")?)
        .try_into_model()?;
    // When comparing stated and context-required publisher-policy applicability.
    assert_eq!(context::confidence(&cpe, &[]), 70);
    // Then only the stated evidence can retain the unconfirmed fallback.
    assert_eq!(context::confidence_required(&cpe, &[], true), 0);
    Ok(())
}

/// A small shared allocation must not bypass the bound on expanded per-assessment report metadata.
#[test_log::test]
fn expanded_evidence_metadata_budget() -> anyhow::Result<()> {
    // Given many matched records sharing one moderate-size range, without allocating a huge fixture.
    let version = format!("1.0.0.redhat-{}", "0".repeat(32 * 1024));
    let target = Purl::from_str(&format!("pkg:maven/com.example/lib@{version}"))?;
    let id = Uuid::from_u128(100);
    let context = ReportContext {
        suppliers: HashMap::new(),
        products: HashMap::new(),
        node_purls: HashMap::from([((id, "lib".into()), vec![target.clone()])]),
        scopes: HashMap::new(),
        assertion_cpes: HashMap::new(),
        derived_sources: HashSet::new(),
        source_bytes: 0,
    };
    let range = Arc::new(version_range::Model {
        id: Uuid::nil(),
        version_scheme_id: VersionScheme::Generic,
        low_version: Some(version.clone()),
        low_inclusive: Some(true),
        high_version: Some(version),
        high_inclusive: Some(true),
    });
    let statuses = (0..10_000)
        .map(|index| StatusInfo {
            vuln_id: "CVE-2099-74506".into(),
            status_slug: "fixed".into(),
            remediations: Vec::new(),
            source_id: Uuid::from_u128(index),
            status_id: Uuid::nil(),
            advisory_pk: Uuid::nil(),
            context_cpe_id: None,
            range: range.clone(),
            provider: ProviderIdentity::default(),
            csaf: true,
            advisory_id: Some("SHARED-RANGE".into()),
        })
        .collect::<Vec<_>>();
    // When expanding evidence identifiers/ranges into per-CVE resolution groups.
    let result = context.resolve(id, "lib", &target, &statuses);
    // Then shared input storage does not permit unbounded downstream copies or hashing work.
    assert!(matches!(
        result,
        Err(ReportError::Limit {
            reason: "expanded report evidence metadata byte limit",
            ..
        })
    ));
    Ok(())
}
