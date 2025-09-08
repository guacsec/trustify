use osv::schema::{Ecosystem, Package};
use packageurl::PackageUrl;

const MAVEN_DEFAULT_REPO: &str = "https://repo.maven.apache.org/maven2";

/// Try converting an ecosystem/name pair into a purl.
pub fn to_purl(
    Package {
        ecosystem,
        name,
        purl: _,
    }: &Package,
) -> Option<PackageUrl<'_>> {
    translate(ecosystem, name)
}

/// Also see: <https://ossf.github.io/osv-schema/#affectedpackage-field>
fn translate<'a>(ecosystem: &Ecosystem, name: &'a str) -> Option<PackageUrl<'a>> {
    match ecosystem {
        Ecosystem::CRAN => PackageUrl::new("cran", name).ok(),
        Ecosystem::CratesIO => PackageUrl::new("cargo", name).ok(),
        Ecosystem::Npm => split_name(name, "npm", "/"),
        Ecosystem::Maven(repo) => {
            let split = name.split(':').collect::<Vec<_>>();
            if split.len() == 2 {
                let namespace = split[0];
                let name = split[1];
                PackageUrl::new("maven", name)
                    .and_then(|mut purl| {
                        purl.with_namespace(namespace);
                        if repo != MAVEN_DEFAULT_REPO {
                            purl.add_qualifier("repository_url", repo.clone())?;
                        }
                        Ok(purl)
                    })
                    .ok()
            } else {
                None
            }
        }
        Ecosystem::PyPI => PackageUrl::new("pypi", name).ok(),
        Ecosystem::Go => split_name(name, "golang", "/"),
        Ecosystem::Packagist => split_name(name, "composer", "/"),
        Ecosystem::NuGet => PackageUrl::new("nuget", name).ok(),
        Ecosystem::RubyGems => PackageUrl::new("gem", name).ok(),
        Ecosystem::Hex => PackageUrl::new("hex", name).ok(),
        Ecosystem::SwiftURL => split_name(name, "swift", "/"),
        Ecosystem::Pub => PackageUrl::new("pub", name).ok(),
        _ => None,
    }
}

fn split_name<'a>(name: &'a str, ty: &'a str, separator: &str) -> Option<PackageUrl<'a>> {
    let split = name.split(separator).collect::<Vec<_>>();
    match split.len() {
        0 => None,
        1 => PackageUrl::new(ty, split[0]).ok(),
        _ => {
            let namespace = split[0..=split.len() - 2].join(separator);
            let name = split[split.len() - 1];
            PackageUrl::new(ty, name)
                .map(|mut purl| {
                    purl.with_namespace(namespace);
                    purl
                })
                .ok()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    #[test_log::test(rstest)]
    #[case(Ecosystem::CratesIO, "packageurl", Some("pkg:cargo/packageurl"))]
    #[case(
        Ecosystem::Maven(MAVEN_DEFAULT_REPO.to_string()),
        "groupid:artifactid",
        Some("pkg:maven/groupid/artifactid")
    )]
    #[case(
        Ecosystem::Maven("http://other/repo".to_string()),
        "groupid:artifactid",
        Some("pkg:maven/groupid/artifactid?repository_url=http://other/repo")
    )]
    #[case(Ecosystem::PyPI, "aiohttp", Some("pkg:pypi/aiohttp"))]
    #[case(Ecosystem::Go, "tailscale.com", Some("pkg:golang/tailscale.com"))]
    #[case(
        Ecosystem::Go,
        "code.gitea.io/gitea",
        Some("pkg:golang/code.gitea.io/gitea")
    )]
    #[case(
        Ecosystem::Go,
        "github.com/minio/minio",
        Some("pkg:golang/github.com/minio/minio")
    )]
    #[case(
        Ecosystem::Npm,
        "@fastify/passport",
        Some("pkg:npm/%40fastify/passport")
    )]
    #[case(
        Ecosystem::Packagist,
        "typo3/cms-backend",
        Some("pkg:composer/typo3/cms-backend")
    )]
    #[case(
        Ecosystem::NuGet,
        "Microsoft.NETCore.App.Runtime.win-x86",
        Some("pkg:nuget/Microsoft.NETCore.App.Runtime.win-x86")
    )]
    #[case(Ecosystem::NuGet, "PowerShell", Some("pkg:nuget/PowerShell"))]
    #[case(Ecosystem::RubyGems, "pwpush", Some("pkg:gem/pwpush"))]
    #[case(
        Ecosystem::RubyGems,
        "activerecord-session_store",
        Some("pkg:gem/activerecord-session_store")
    )]
    #[case(Ecosystem::Hex, "mtproto_proxy", Some("pkg:hex/mtproto_proxy"))]
    #[case(
        Ecosystem::SwiftURL,
        "github.com/sparkle-project/Sparkle",
        Some("pkg:swift/github.com/sparkle-project/Sparkle")
    )]
    #[case(Ecosystem::Pub, "agent_dart", Some("pkg:pub/agent_dart"))]
    fn test_translate(
        #[case] ecosystem: Ecosystem,
        #[case] name: &str,
        #[case] outcome: Option<&str>,
    ) {
        assert_eq!(
            to_purl(&Package {
                ecosystem,
                name: name.to_string(),
                purl: None,
            })
            .map(|purl| purl.to_string())
            .as_deref(),
            outcome
        );
    }
}
