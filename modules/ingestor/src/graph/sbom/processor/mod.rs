use crate::graph::{
    cpe::CpeCreator,
    purl::creator::PurlCreator,
    sbom::{ExternalNodeCreator, PackageCreator},
};
use std::fmt::Debug;
use trustify_entity::package_relates_to_package;

mod rh_prod_comp;
pub use rh_prod_comp::RedHatProductComponentRelationships;

/// A processor for the ingestion process. Allowing to intervene with the ingestion.
pub trait Processor: Debug + Send {
    /// Called exactly once, before all others
    fn init(&mut self, _ctx: InitContext) {}

    /// Called once, after all components have been processed, but before storing into the database.
    fn post(&self, _ctx: &mut PostContext) {}
}

#[derive(Copy, Clone)]
pub struct InitContext<'a> {
    pub suppliers: &'a [&'a str],
    pub document_node_id: &'a str,
}

pub struct PostContext<'a> {
    pub cpes: &'a CpeCreator,
    pub purls: &'a PurlCreator,
    pub packages: &'a mut PackageCreator,
    pub relationships: &'a mut Vec<package_relates_to_package::ActiveModel>,
    pub externals: &'a mut ExternalNodeCreator,
}

/// Helper running processors
pub trait RunProcessors {
    fn run(&mut self, processors: &mut [Box<dyn Processor>]);
}

impl RunProcessors for InitContext<'_> {
    fn run(&mut self, processors: &mut [Box<dyn Processor>]) {
        for processor in processors {
            processor.init(*self);
        }
    }
}

impl RunProcessors for PostContext<'_> {
    fn run(&mut self, processors: &mut [Box<dyn Processor>]) {
        for processor in processors {
            processor.post(self);
        }
    }
}
