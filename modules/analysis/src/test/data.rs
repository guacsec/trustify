use crate::test::Join;

pub const BASE: &str = "cyclonedx/rh/latest_filters/TC-3278/";

#[derive(Debug, Clone, Copy)]
pub enum Set {
    Container,
    Middleware,
    Rpm,
}

#[derive(Debug, Clone, Copy)]
pub enum Phase {
    Older,
    Later,
}

struct Source(Set, Phase);

impl From<Source> for Vec<String> {
    fn from(Source(set, phase): Source) -> Self {
        match (set, phase) {
            (Set::Container, Phase::Older) => container::older().collect(),
            (Set::Container, Phase::Later) => container::later().collect(),
            (Set::Middleware, Phase::Older) => middleware::older().collect(),
            (Set::Middleware, Phase::Later) => middleware::later().collect(),
            (Set::Rpm, Phase::Older) => rpm::older().collect(),
            (Set::Rpm, Phase::Later) => rpm::later().collect(),
        }
    }
}

impl IntoIterator for Source {
    type Item = String;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        Vec::from(self).into_iter()
    }
}

pub struct Sources<S: IntoIterator<Item = Set>, P: IntoIterator<Item = Phase>>(pub S, pub P);

impl<S: IntoIterator<Item = Set>, P: IntoIterator<Item = Phase>> IntoIterator for Sources<S, P> {
    type Item = String;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let Self(set, phase) = self;

        let phase = Vec::from_iter(phase);

        let result: Vec<String> = set
            .into_iter()
            .flat_map(|set| phase.iter().map(move |phase| Source(set, *phase)))
            .flatten()
            .collect();

        result.into_iter()
    }
}

pub mod container {

    use super::*;

    pub fn older() -> impl Iterator<Item = String> {
        BASE.join("container/cnv-4.17/older/".join(
            &[
                "binary-2025-11-25-3E72AAC00183431.json",
                "binary-2025-11-25-32EBB9C7E6914AD.json",
                "image-index-2025-11-25-CBE2989E64414F5.json",
                "product-2025-11-25-D05BF995974542F.json",
            ][..],
        ))
    }

    pub fn later() -> impl Iterator<Item = String> {
        BASE.join("container/cnv-4.17/latest/".join(
            &[
                "binary-2025-12-02-5C502A658F36477.json",
                "binary-2025-12-02-C0CF40B259B1491.json",
                "image-index-2025-12-02-693F980C32C444A.json",
                "product-2025-12-02-ED1F188BB5C94D8.json",
            ][..],
        ))
    }
}

pub mod middleware {

    use super::*;

    pub fn older() -> impl Iterator<Item = String> {
        BASE.join(
            "middleware/quarkus-3.20/older/".join(&["product-2025-10-14-28954C62C811417.json"][..]),
        )
    }

    pub fn later() -> impl Iterator<Item = String> {
        BASE.join(
            "middleware/quarkus-3.20/latest/"
                .join(&["product-2025-12-01-EDA6638AD2F4451.json"][..]),
        )
    }
}

pub mod rpm {

    use super::*;

    pub fn older() -> impl Iterator<Item = String> {
        BASE.join("rpm/webkit2gtk3/older/".join(
            &[
                "product-2025-11-11-7764C2C0C91542B.json",
                "rpm-2025-10-14-CC595A02EB3545E.json",
            ][..],
        ))
    }

    pub fn later() -> impl Iterator<Item = String> {
        BASE.join("rpm/webkit2gtk3/latest/".join(
            &[
                "product-2025-12-08-A9F140D67EB2408.json",
                "rpm-2025-12-05-3705CE313B0F437.json",
            ][..],
        ))
    }
}
