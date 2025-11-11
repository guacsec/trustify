use crate::endpoints::tests::CallService;
use actix_http::{Request, StatusCode};
use actix_web::test::TestRequest;
use serde_json::Value;

#[derive(Default, Copy, Clone)]
pub struct Req<'a> {
    pub latest: bool,
    pub ancestors: Option<u64>,
    pub descendants: Option<u64>,
    pub loc: Loc<'a>,
}

#[derive(Default, Copy, Clone)]
pub enum Loc<'a> {
    #[default]
    None,
    Q(&'a str),
    Id(&'a str),
}

pub trait ReqExt {
    async fn req(&self, req: Req<'_>) -> anyhow::Result<Value>;
}

impl<C: CallService> ReqExt for C {
    async fn req(&self, req: Req<'_>) -> anyhow::Result<Value> {
        let Req {
            latest,
            loc,
            ancestors,
            descendants,
        } = req;

        let latest = match latest {
            true => "latest/",
            false => "",
        };

        let mut uri = match loc {
            Loc::None => {
                format!("/api/v2/analysis/{latest}component?",)
            }
            Loc::Q(q) => {
                format!(
                    "/api/v2/analysis/{latest}component?q={q}&",
                    q = urlencoding::encode(q),
                )
            }
            Loc::Id(id) => {
                format!(
                    "/api/v2/analysis/{latest}component/{id}?",
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
