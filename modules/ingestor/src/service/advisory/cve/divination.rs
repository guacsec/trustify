//! Helpers to try to divine pURLs from arbitrary bits of information.
//!
//! A CVE record identifies a package by its `packageName` in a package collection
//! (`collectionURL`), which "determines the meaning of packageName". Well-known collections are
//! translated to a PURL.

use std::str::FromStr;

use cve::common::Product;
use trustify_common::purl::Purl;

pub fn divine_purl(product: &Product) -> Option<Purl> {
    let collection = product.collection_url.as_deref()?.trim_end_matches('/');
    let package_name = product.package_name.as_deref()?;

    match collection {
        "https://repo.maven.apache.org/maven2" => divine_maven(package_name),
        "https://pkg.go.dev" => divine_golang(package_name),
        // add more here as we determine the correct heuristics
        _ => None,
    }
}

/// A Maven package: `groupId:artifactId`.
fn divine_maven(package_name: &str) -> Option<Purl> {
    let (group_id, artifact_id) = package_name.split_once(':')?;
    if artifact_id.contains(':') {
        return None;
    }
    Purl::from_str(&format!("pkg:maven/{group_id}/{artifact_id}")).ok()
}

/// A Go package: its import path, e.g. `golang.org/x/net/http2`.
fn divine_golang(package_name: &str) -> Option<Purl> {
    let (namespace, name) = package_name.rsplit_once('/')?;
    Purl::from_str(&format!("pkg:golang/{namespace}/{name}")).ok()
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    fn product(collection_url: &str, package_name: &str) -> Product {
        serde_json::from_value(serde_json::json!({
            "collectionURL": collection_url,
            "packageName": package_name,
        }))
        .expect("valid product")
    }

    #[rstest]
    #[case(
        "https://repo.maven.apache.org/maven2/",
        "org.apache.commons:commons-compress",
        Some("pkg:maven/org.apache.commons/commons-compress")
    )]
    #[case(
        "https://repo.maven.apache.org/maven2",
        "org.apache.activemq:artemis-server",
        Some("pkg:maven/org.apache.activemq/artemis-server")
    )]
    #[case("https://repo.maven.apache.org/maven2", "a:b:c", None)]
    #[case(
        "https://pkg.go.dev",
        "golang.org/x/net/http2",
        Some("pkg:golang/golang.org/x/net/http2")
    )]
    #[case("https://pkg.go.dev", "stdlib", None)]
    #[case("https://wordpress.org/plugins", "akismet", None)]
    #[test]
    fn divine(
        #[case] collection_url: &str,
        #[case] package_name: &str,
        #[case] expected: Option<&str>,
    ) {
        assert_eq!(
            divine_purl(&product(collection_url, package_name)).map(|purl| purl.to_string()),
            expected.map(str::to_string)
        );
    }
}
