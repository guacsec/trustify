use std::process::ExitCode;

use sbom_walker::{
    retrieve::RetrievingVisitor,
    source::{DispatchSource, FileSource, HttpSource},
    validation::ValidationVisitor,
    walker::Walker,
};
use trustify_api::system::InnerSystem;
use trustify_common::config::Database;
use url::Url;
use walker_common::{fetcher::Fetcher, validate::ValidationOptions};

mod process;

#[derive(clap::Args, Debug)]
pub struct ImportSbomCommand {
    #[command(flatten)]
    pub database: Database,

    /// Source URL or path
    #[arg(short, long)]
    pub(crate) source: String,
}

impl ImportSbomCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        env_logger::init();

        println!("Ingesting SBOMs");

        let system = InnerSystem::with_config(&self.database).await?;

        let source: DispatchSource = match Url::parse(&self.source) {
            Ok(url) => HttpSource {
                url,
                fetcher: Fetcher::new(Default::default()).await?,
                options: Default::default(),
                // options: HttpOptions {
                //     keys: self.options.keys.clone(),
                //     since: *since,
                // },
            }
            .into(),
            Err(_) => FileSource::new(&self.source, None)?.into(),
        };

        let process = process::ProcessVisitor { system };

        let validation = ValidationVisitor::new(process).with_options(ValidationOptions {
            validation_date: None,
        });

        Walker::new(source.clone())
            .walk(RetrievingVisitor::new(source, validation))
            .await?;

        Ok(ExitCode::SUCCESS)
    }
}
