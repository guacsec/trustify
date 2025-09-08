//! Helpers to try to divine pURLs from arbitrary bits of information.

use std::str::FromStr;

use cve::common::Product;
use trustify_common::purl::Purl;

pub fn divine_purl(product: &Product) -> Option<Purl> {
    divine_maven(product)
    // add more here as we determine the correct heuristics
}

fn divine_maven(product: &Product) -> Option<Purl> {
    if matches!( &product.collection_url, Some(url) if url == "https://repo.maven.apache.org/maven2/" )
        && let Some(package_name) = &product.package_name
    {
        let parts = package_name.split(':').collect::<Vec<_>>();

        if parts.len() == 2 {
            let group_id = parts[0];
            let artifact_id = parts[1];
            return Purl::from_str(&format!("pkg:maven/{group_id}/{artifact_id}")).ok();
        }
    }
    None
}
