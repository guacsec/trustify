//! The factors a match confidence can be made of, for explaining them.
use crate::{
    error::Error,
    extractor::{context, cpe::VersionCheck, digest, product_identifier, purl},
    model::{ConfidenceCatalog, ConfidenceFactorInfo, ConfidenceReason},
};
use purl::ecosystem::StreamMatch;
use sea_orm::ConnectionTrait;

/// All factors, with the version range rules as currently configured.
pub async fn catalog<C: ConnectionTrait>(connection: &C) -> Result<ConfidenceCatalog, Error> {
    let plain = |reason, factor| ConfidenceFactorInfo {
        reason,
        factor,
        per_hop: None,
    };

    let mut factors = vec![
        plain(ConfidenceReason::Digest, digest::CONFIDENCE),
        plain(
            ConfidenceReason::ProductIdentifier,
            product_identifier::CONFIDENCE,
        ),
    ];
    factors.extend(
        [VersionCheck::Exact, VersionCheck::Range, VersionCheck::Any]
            .map(|check| check.factor())
            .into_iter()
            .chain(
                [
                    StreamMatch::Unscoped,
                    StreamMatch::Exact,
                    StreamMatch::Major,
                    StreamMatch::Minor,
                ]
                .map(|stream| stream.factor()),
            )
            .map(|f| plain(f.reason, f.factor)),
    );
    factors.push(plain(
        ConfidenceReason::DefaultStatus,
        purl::DEFAULT_CONFIDENCE,
    ));
    factors.extend(purl::rule::rules(connection).await?.iter().map(|rule| {
        plain(
            ConfidenceReason::Rule {
                rule: rule.id().into(),
            },
            rule.confidence(),
        )
    }));
    factors.extend(context::catalog());

    Ok(ConfidenceCatalog {
        factors,
        wildcard_cpe: context::ANY_MATCH,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use sea_orm::TransactionTrait;
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::TrustifyContext;

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn catalog_lists_factors(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let catalog = catalog(&ctx.db.begin().await?).await?;
        let factor = |reason: ConfidenceReason| {
            catalog
                .factors
                .iter()
                .find(|f| f.reason == reason)
                .map(|f| f.factor)
        };

        assert_eq!(factor(ConfidenceReason::CpeAnyVersion), Some(0.5));
        assert_eq!(
            factor(ConfidenceReason::Rule {
                rule: "purl_vls_range".into()
            }),
            Some(0.6)
        );
        assert_eq!(factor(ConfidenceReason::ProductNotConfirmed), Some(0.7));
        assert_eq!(catalog.wildcard_cpe, 0.9);
        Ok(())
    }
}
