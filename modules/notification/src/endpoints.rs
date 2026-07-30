use actix_web::{HttpRequest, HttpResponse, web};
use futures::StreamExt;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::broadcast;
use trustify_auth::{
    Permission, authenticator::Authenticator, authenticator::user::UserInformation,
    authorizer::Authorizer,
};
use trustify_common::db::change::{ChangeBroadcaster, ChangeEntity, ChangeEntry};
use trustify_infrastructure::app::new_auth;
use utoipa_actix_web::service_config::ServiceConfig;
use uuid::Uuid;

use crate::inject_token::QueryTokenInjector;

#[derive(Debug, Deserialize)]
pub struct NotificationQuery {
    pub after: Option<Uuid>,
    pub token: Option<String>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum Message {
    Connection,
}

#[derive(serde::Serialize)]
struct ConnectionMessage {
    r#type: Message,
    cursor: Uuid,
}

pub fn configure(
    config: &mut ServiceConfig,
    broadcaster: ChangeBroadcaster,
    auth: Option<Arc<Authenticator>>,
) {
    config.app_data(web::Data::new(broadcaster)).map(|svc| {
        svc.service(
            web::resource("/api/v3/notifications")
                .wrap(new_auth(auth))
                .wrap(QueryTokenInjector)
                .route(web::get().to(ws_handler)),
        )
    });
}

async fn ws_handler(
    req: HttpRequest,
    body: web::Payload,
    query: web::Query<NotificationQuery>,
    broadcaster: web::Data<ChangeBroadcaster>,
    user: UserInformation,
) -> Result<HttpResponse, actix_web::Error> {
    let authorizer = req
        .app_data::<web::Data<Authorizer>>()
        .cloned()
        .unwrap_or_default();

    let can_read_sbom = authorizer.require(&user, Permission::ReadSbom).is_ok();
    let can_read_advisory = authorizer.require(&user, Permission::ReadAdvisory).is_ok();

    if !can_read_sbom && !can_read_advisory {
        return Ok(HttpResponse::Forbidden().finish());
    }

    let (response, session, msg_stream) = actix_ws::handle(&req, body)?;

    let broadcaster = broadcaster.into_inner();
    let after = query.into_inner().after;

    actix_web::rt::spawn(async move {
        if let Err(err) = run_ws_session(
            session,
            msg_stream,
            &broadcaster,
            after,
            can_read_sbom,
            can_read_advisory,
        )
        .await
        {
            tracing::warn!(%err, "WebSocket notification session error");
        }
    });

    Ok(response)
}

pub(crate) fn is_allowed(
    entry: &ChangeEntry,
    can_read_sbom: bool,
    can_read_advisory: bool,
) -> bool {
    match entry.r#type {
        ChangeEntity::Sbom => can_read_sbom,
        ChangeEntity::Advisory => can_read_advisory,
    }
}

async fn run_ws_session(
    mut session: actix_ws::Session,
    mut msg_stream: actix_ws::MessageStream,
    broadcaster: &ChangeBroadcaster,
    after: Option<Uuid>,
    can_read_sbom: bool,
    can_read_advisory: bool,
) -> Result<(), anyhow::Error> {
    // Subscribe before backfill/cursor fetch to avoid gaps.
    let mut rx = broadcaster.subscribe();

    if let Some(cursor) = after {
        match broadcaster.fetch_after(&cursor).await {
            Ok(entries) => {
                for entry in entries {
                    if !is_allowed(&entry, can_read_sbom, can_read_advisory) {
                        continue;
                    }
                    let json = serde_json::to_string(&entry)?;
                    if session.text(json).await.is_err() {
                        return Ok(());
                    }
                }
            }
            Err(err) => {
                tracing::warn!(%err, "notification backfill query failed");
            }
        }
    } else {
        let cursor = broadcaster.fetch_latest_cursor().await;
        let msg = ConnectionMessage {
            r#type: Message::Connection,
            cursor,
        };
        let json = serde_json::to_string(&msg)?;
        if session.text(json).await.is_err() {
            return Ok(());
        }
    }

    let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(30));

    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Ok(entry) => {
                        if !is_allowed(&entry, can_read_sbom, can_read_advisory) {
                            continue;
                        }
                        let json = serde_json::to_string(&entry)?;
                        if session.text(json).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(lagged = n, "WebSocket notification client lagged");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }

            msg = msg_stream.next() => {
                match msg {
                    Some(Ok(actix_ws::Message::Ping(data))) => {
                        let _ = session.pong(&data).await;
                    }
                    Some(Ok(actix_ws::Message::Close(reason))) => {
                        let _ = session.close(reason).await;
                        break;
                    }
                    Some(Err(_)) | None => break,
                    _ => {}
                }
            }

            _ = heartbeat.tick() => {
                if session.ping(b"").await.is_err() {
                    break;
                }
            }
        }
    }

    Ok(())
}
