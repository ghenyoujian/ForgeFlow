//! Native blueprint transport; PostgreSQL remains the review and import authority.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlueprintSourceQuery {
    catalog_id: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlueprintImportRequest {
    expected_revision: u64,
    review_sha256: String,
}

fn blueprint_identity(
    headers: &HeaderMap,
    actor: &Principal,
    project: &str,
) -> Result<CommandIdentity, ApiError> {
    let original = identity(headers, actor)?;
    Ok(CommandIdentity {
        actor_id: "native-blueprint-service".into(),
        idempotency_key: format!(
            "native-blueprint:{}:{}:{}",
            actor.actor_id, project, original.idempotency_key
        ),
    })
}

/// Owners may inspect destination choices without a native panel credential.
pub async fn context(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
) -> ApiResult<Value> {
    if actor.worker {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "OWNER_REQUIRED",
            "blueprint import context requires Owner authentication",
        ));
    }
    Ok(view(s.store.native_blueprint_context(&project).await?))
}

/// The Store supplies the complete bounded page and its authority context.
pub async fn source(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Query(query): Query<BlueprintSourceQuery>,
) -> ApiResult<Value> {
    native_panel::authenticate(&actor, &headers)?;
    let limit = query.limit.unwrap_or(100);
    if !(1..=100).contains(&limit) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "BLUEPRINT_PAGE_LIMIT_INVALID",
            "blueprint source page limit must be between 1 and 100",
        ));
    }
    Ok(Json(
        s.store
            .native_blueprint_source(
                &project,
                query.catalog_id.as_deref(),
                query.cursor.as_deref(),
                limit,
            )
            .await?,
    ))
}

pub async fn preview(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(request): Json<NativeBlueprintPreviewRequest>,
) -> ApiResult<Value> {
    native_panel::authenticate(&actor, &headers)?;
    let receipt = s
        .store
        .execute_command(
            blueprint_identity(&headers, &actor, &project)?,
            CatalogCommand::PreviewNativeBlueprint {
                project_id: project,
                requested_by: actor.actor_id,
                request,
            },
        )
        .await?;
    Ok(Json(json!({
        "data": receipt.value,
        "operation_id": receipt.operation_id,
        "replayed": receipt.replayed,
        "request_id": headers.get("x-request-id").and_then(|value| value.to_str().ok()),
        "source": "postgres"
    })))
}

pub async fn import(
    State(s): State<App>,
    Path((project, review)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(request): Json<BlueprintImportRequest>,
) -> ApiResult<Value> {
    native_panel::authenticate(&actor, &headers)?;
    let receipt = s
        .store
        .execute_command(
            blueprint_identity(&headers, &actor, &project)?,
            CatalogCommand::ImportNativeBlueprint {
                project_id: project,
                preview_id: review,
                expected_revision: request.expected_revision,
                review_sha256: request.review_sha256,
                approved_by: actor.actor_id,
            },
        )
        .await?;
    Ok(Json(json!({
        "data": receipt.value,
        "operation_id": receipt.operation_id,
        "replayed": receipt.replayed,
        "request_id": headers.get("x-request-id").and_then(|value| value.to_str().ok()),
        "source": "postgres"
    })))
}
