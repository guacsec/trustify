use crate::endpoints::tests::CallService;
use actix_http::{Request, StatusCode};
use actix_web::test::TestRequest;
use serde_json::Value;

/// Request on the analysis API
#[derive(Default, Copy, Clone)]
pub struct Req<'a> {
    /// request against "latest" API
    pub latest: bool,
    /// Level of ancestors to request
    pub ancestors: Option<u64>,
    /// Level of descendants to request
    pub descendants: Option<u64>,
    /// What is being requested
    pub what: What<'a>,
}

/// Indication of what is being requested
#[derive(Default, Copy, Clone)]
pub enum What<'a> {
    /// Everything
    #[default]
    None,
    /// Search by `q` parameter
    Q(&'a str),
    /// By ID
    Id(&'a str),
}

pub trait ReqExt {
    /// Process request
    async fn req(&self, req: Req<'_>) -> anyhow::Result<Value>;
}

impl<C: CallService> ReqExt for C {
    async fn req(&self, req: Req<'_>) -> anyhow::Result<Value> {
        let Req {
            latest,
            what: loc,
            ancestors,
            descendants,
        } = req;

        let latest = match latest {
            true => "latest/",
            false => "",
        };

        const BASE: &str = "/api/v2/analysis/";

        let mut uri = match loc {
            What::None => {
                format!("{BASE}{latest}component?",)
            }
            What::Q(q) => {
                format!("{BASE}{latest}component?q={q}&", q = urlencoding::encode(q),)
            }
            What::Id(id) => {
                format!(
                    "{BASE}{latest}component/{id}?",
                    id = urlencoding::encode(id),
                )
            }
        };

        if let Some(ancestors) = ancestors {
            uri = format!("{uri}ancestors={ancestors}&");
        }

        if let Some(descendants) = descendants {
            uri = format!("{uri}descendants={descendants}&");
        }

        let request: Request = TestRequest::get().uri(&uri).to_request();

        let response = self.call_service(request).await;

        assert_eq!(response.status(), StatusCode::OK);

        Ok(actix_web::test::read_body_json(response).await)
    }
}
