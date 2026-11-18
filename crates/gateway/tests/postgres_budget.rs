//! Real PostgreSQL transaction test; synthetic fixture is not a real-model qualification.
use forgeflow_gateway::{
    GatewayBudgetLimits, PgRequestAuthority, RequestAuthority, RequestSettlement,
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{collections::BTreeMap, sync::Arc};

async fn setup() -> (PgPool, String, PgPool) {
    let url=std::env::var("FORGEFLOW_TEST_DATABASE_URL").or_else(|_|std::env::var("DATABASE_URL")).expect("real PostgreSQL DATABASE_URL required; missing database is not a passing qualification");
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("gateway_test_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let search_path = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(16)
        .after_connect(move |conn, _| {
            let statement = format!("SET search_path TO {search_path}");
            Box::pin(async move {
                sqlx::query(&statement).execute(conn).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/0001_control.sql"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql(include_str!(
        "../../../migrations/0002_authority_hardening.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    (pool, schema, admin)
}

async fn cleanup(pool: PgPool, schema: String, admin: PgPool) {
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

async fn seed(pool: &PgPool, project: &str, attempt: &str, max_requests: u32) {
    let now = chrono::Utc::now();
    let env = json!({"schema_version":"forgeflow.execution.v1","operation_id":format!("op-{attempt}"),"project_id":project,"task_id":"task","task_revision":1,"attempt_id":attempt,"lease_id":format!("lease-{attempt}"),"generation":1,"worker_id":"worker","workspace_root":"/tmp/forgeflow-request-budget-test","base_sha":"a".repeat(40),"context_manifest":{"artifact_id":"context","sha256":"b".repeat(64),"mandatory_paths":[],"rendered_utf8_bytes":0,"token_estimate":null,"tokenizer_id":null},"write_set":[],"prompt_artifact":{"artifact_id":"prompt","sha256":"c".repeat(64)},"model_route_id":"route","executor_profile_id":"profile","resource_profile_id":"resource","verification_plan_id":"verification","allowed_effects":["READ_WORKSPACE","REQUEST_APPROVED_MODEL"],"issued_at":now.to_rfc3339(),"expires_at":(now+chrono::Duration::hours(1)).to_rfc3339(),"deadline_at":(now+chrono::Duration::hours(2)).to_rfc3339(),"artifact_prefix":"/tmp/forgeflow-request-budget-test/artifacts","secret_refs":[],"idempotency_key":attempt,"trace_id":attempt,"enforcement":{"model_budget_mode":"gateway_enforced","stage_resource_mode":"ATTEMPT_RESERVATION","build_capable":false,"gateway_coverage_receipt_id":"synthetic-unit-fixture-not-qualification","tool_guard_receipt_id":null,"attempt_reserved_build_permits":0,"all_model_routes_covered":true,"disabled_tool_entry_ids":[]},"session_purpose":"PLANNING","max_model_requests":max_requests,"resume_session_id":null});
    sqlx::query(
        "INSERT INTO projects(project_id,revision,authority_mode,data) VALUES($1,1,'MANAGED','{}')",
    )
    .bind(project)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO owner_nodes(project_id,owner_id,data) VALUES($1,'owner','{}')")
        .bind(project)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO flow_revisions(project_id,flow_revision,revision,state,input_digest,data) VALUES($1,1,1,'COMMITTED','digest','{}')").bind(project).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO tasks(project_id,task_id,task_revision,flow_revision,team_id,owner_id,state,input_digest,fence_epoch,revision,data) VALUES($1,'task',1,1,'owner','owner','READY_FOR_ADMISSION','digest',1,1,'{}')").bind(project).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO task_revisions(project_id,task_id,task_revision,data) VALUES($1,'task',1,'{}')").bind(project).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO attempts(project_id,attempt_id,task_id,task_revision,lease_id,generation,worker_id,operation_id,state,revision,data,envelope) VALUES($1,$2,'task',1,$3,1,'worker',$4,'LEASED',1,'{}',$5)").bind(project).bind(attempt).bind(format!("lease-{attempt}")).bind(format!("op-{attempt}")).bind(&env).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO leases(project_id,lease_id,attempt_id,generation,worker_id,capability_scope,issued_at,expires_at) VALUES($1,$2,$3,1,'worker','[]',clock_timestamp(),clock_timestamp()+interval '1 hour')").bind(project).bind(format!("lease-{attempt}")).bind(attempt).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO workers(worker_id,boot_id,capabilities) VALUES('worker','fixture-boot','[]') ON CONFLICT(worker_id) DO NOTHING").execute(pool).await.unwrap();
    sqlx::query("INSERT INTO outbox(outbox_id,project_id,operation_id,kind,payload) VALUES($1,$2,$3,'attempt.start',$4)").bind(format!("start-{attempt}")).bind(project).bind(format!("op-{attempt}")).bind(env).execute(pool).await.unwrap();
}

/// Synthetic fixture for a committed claim, not evidence of a real worker launch.
async fn claim_fixture(pool: &PgPool, attempt: &str) {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(46001337)")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE attempts SET state='STARTING',revision=revision+1 WHERE attempt_id=$1")
        .bind(attempt)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE outbox SET claimed_by='worker',delivered_at=clock_timestamp() WHERE operation_id=$1 AND kind='attempt.start'").bind(format!("op-{attempt}")).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn postgres_atomic_caps_idempotent_settlement_and_fencing() {
    let (pool, schema, admin) = setup().await;
    seed(&pool, "p1", "a1", 2).await;
    seed(&pool, "p2", "a2", 10).await;
    claim_fixture(&pool, "a1").await;
    claim_fixture(&pool, "a2").await;
    let limits = GatewayBudgetLimits {
        per_attempt_inflight: 1,
        global_inflight: 1,
        project_inflight: 1,
        global_window_requests: 100,
        project_window_requests: 100,
        route_window_requests: 100,
        window_seconds: 3600,
    };
    let authority = Arc::new(
        PgRequestAuthority::new(
            pool.clone(),
            limits.clone(),
            BTreeMap::from([("route".into(), "model".into())]),
        )
        .unwrap()
        .with_issuer_seed("qualification-fixture-not-production-issuer-seed".into())
        .unwrap(),
    );
    let token = authority.issue_scope("p1", "a1").await.unwrap();
    let other_token = authority.issue_scope("p2", "a2").await.unwrap();
    assert_eq!(
        authority.issue_scope("p1", "a1").await.unwrap(),
        token,
        "scope retry must replay identical token and never reset budget"
    );
    let restarted = PgRequestAuthority::new(
        pool.clone(),
        limits.clone(),
        BTreeMap::from([("route".into(), "model".into())]),
    )
    .unwrap()
    .with_issuer_seed("qualification-fixture-not-production-issuer-seed".into())
    .unwrap();
    assert_eq!(
        restarted.issue_scope("p1", "a1").await.unwrap(),
        token,
        "server restart with persisted issuer must replay the exact scope"
    );
    let changed_issuer = PgRequestAuthority::new(
        pool.clone(),
        limits,
        BTreeMap::from([("route".into(), "model".into())]),
    )
    .unwrap()
    .with_issuer_seed("different-qualification-issuer-seed-unrelated".into())
    .unwrap();
    assert_eq!(
        changed_issuer
            .issue_scope("p1", "a1")
            .await
            .unwrap_err()
            .code,
        "FROZEN_GATEWAY_SCOPE_MISMATCH"
    );
    assert_eq!(
        authority
            .admit(&token, "route", "other-model")
            .await
            .unwrap_err()
            .code,
        "FROZEN_MODEL_ROUTE_MISMATCH"
    );
    let mut tasks = Vec::new();
    for _ in 0..32 {
        let a = authority.clone();
        let t = token.clone();
        tasks.push(tokio::spawn(
            async move { a.admit(&t, "route", "model").await },
        ));
    }
    let mut admitted = Vec::new();
    let mut denied = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(p) => admitted.push(p),
            Err(e) => {
                assert_eq!(e.code, "WAITING_MODEL_BUDGET");
                denied += 1;
            }
        }
    }
    assert_eq!(admitted.len(), 1);
    assert_eq!(denied, 31);
    assert_eq!(
        authority
            .admit(&other_token, "route", "model")
            .await
            .unwrap_err()
            .code,
        "WAITING_MODEL_BUDGET",
        "global inflight applies across projects"
    );
    let receipt = RequestSettlement {
        request_id: admitted[0].request_id.clone(),
        outcome: "RESPONSE_BODY_COMPLETED".into(),
        upstream_status: Some(200),
        received_bytes: 20,
        usage: Some(json!({"input_tokens":2,"output_tokens":1})),
        usage_completeness: "PROVIDER_REPORTED_STREAM_COMPLETE".into(),
    };
    let mut settlements = Vec::new();
    for _ in 0..16 {
        let a = authority.clone();
        let s = receipt.clone();
        settlements.push(tokio::spawn(async move { a.settle(s).await }));
    }
    for s in settlements {
        s.await.unwrap().unwrap();
    }
    let inflight: i64 =
        sqlx::query_scalar("SELECT inflight FROM gateway_scope_budget WHERE attempt_id='a1'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(inflight, 0);
    let second = authority.admit(&token, "route", "model").await.unwrap();
    authority
        .settle(RequestSettlement {
            request_id: second.request_id,
            ..receipt.clone()
        })
        .await
        .unwrap();
    assert_eq!(
        authority
            .admit(&token, "route", "model")
            .await
            .unwrap_err()
            .code,
        "WAITING_MODEL_BUDGET",
        "attempt cumulative request count remains charged"
    );
    sqlx::query("UPDATE tasks SET fence_epoch=2 WHERE project_id='p2'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        authority
            .admit(&other_token, "route", "model")
            .await
            .unwrap_err()
            .code,
        "STALE_EXECUTION_AUTHORITY"
    );
    let events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM events WHERE kind IN ('ModelRequestAdmitted','ModelRequestSettled')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(events, 4);
    let permits: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM model_request_permit")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(permits, 2);
    let public_usage: Value =
        sqlx::query_scalar("SELECT data FROM provider_requests WHERE request_id=$1")
            .bind(&receipt.request_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(public_usage["usage"]["input_tokens"], 2);
    sqlx::query("UPDATE tasks SET fence_epoch=1 WHERE project_id='p2'")
        .execute(&pool)
        .await
        .unwrap();
    let pending = authority
        .admit(&other_token, "route", "model")
        .await
        .unwrap();
    let uncertain = RequestSettlement {
        request_id: pending.request_id.clone(),
        outcome: "CLIENT_DISCONNECTED_OR_STREAM_DROPPED".into(),
        upstream_status: Some(200),
        received_bytes: 1,
        usage: None,
        usage_completeness: "UNKNOWN_OR_PARTIAL".into(),
    };
    authority.settle(uncertain.clone()).await.unwrap();
    authority.settle(uncertain.clone()).await.unwrap();
    let held: i64 =
        sqlx::query_scalar("SELECT inflight FROM gateway_scope_budget WHERE attempt_id='a2'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        held, 1,
        "unknown upstream cancellation must retain reservation"
    );
    let status: String =
        sqlx::query_scalar("SELECT status FROM model_request_permit WHERE request_id=$1")
            .bind(&pending.request_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status, "QUARANTINED");
    assert_eq!(
        authority
            .admit(&other_token, "route", "model")
            .await
            .unwrap_err()
            .code,
        "WAITING_MODEL_BUDGET"
    );
    authority.revoke_scope("p2", "a2").await.unwrap();
    assert_eq!(
        authority
            .admit(&other_token, "route", "model")
            .await
            .unwrap_err()
            .code,
        "STALE_EXECUTION_AUTHORITY"
    );
    authority
        .settle(RequestSettlement {
            outcome: "RECOVERY_CONFIRMED_REQUEST_CLOSED".into(),
            ..uncertain
        })
        .await
        .unwrap();
    let held: i64 =
        sqlx::query_scalar("SELECT inflight FROM gateway_scope_budget WHERE attempt_id='a2'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(held, 0);
    cleanup(pool, schema, admin).await;
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn postgres_gateway_requires_claimed_dispatch_for_scope_and_permits() {
    let (pool, schema, admin) = setup().await;
    seed(&pool, "p", "a", 10).await;
    sqlx::query("INSERT INTO workers(worker_id,boot_id,capabilities) VALUES('other-worker','other-fixture-boot','[]')").execute(&pool).await.unwrap();
    let authority = PgRequestAuthority::new(
        pool.clone(),
        GatewayBudgetLimits {
            per_attempt_inflight: 1,
            global_inflight: 10,
            project_inflight: 10,
            global_window_requests: 100,
            project_window_requests: 100,
            route_window_requests: 100,
            window_seconds: 3600,
        },
        BTreeMap::from([("route".into(), "model".into())]),
    )
    .unwrap()
    .with_issuer_seed("dispatch-fixture-not-production-issuer-seed".into())
    .unwrap();
    assert_eq!(
        authority.issue_scope("p", "a").await.unwrap_err().code,
        "STALE_EXECUTION_AUTHORITY",
        "an admitted LEASED envelope does not authorize model effects"
    );
    sqlx::query("UPDATE attempts SET state='STARTING' WHERE attempt_id='a'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        authority.issue_scope("p", "a").await.unwrap_err().code,
        "STALE_EXECUTION_AUTHORITY",
        "a state transition alone does not prove dispatch"
    );
    let scopes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM gateway_scope_budget")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(scopes, 0, "denied issuance must not create a scope");

    claim_fixture(&pool, "a").await;
    let token = authority.issue_scope("p", "a").await.unwrap();
    assert_eq!(authority.issue_scope("p", "a").await.unwrap(), token);
    // A valid token must not retain authority when current dispatch proof is missing,
    // incomplete, bound to another identity, or superseded by lease/state authority.
    let cases = [
        (
            "claimed LEASED",
            "UPDATE attempts SET state='LEASED' WHERE attempt_id='a'",
        ),
        (
            "missing start",
            "DELETE FROM outbox WHERE outbox_id='start-a'",
        ),
        (
            "unclaimed start",
            "UPDATE outbox SET claimed_by=NULL,delivered_at=NULL WHERE outbox_id='start-a'",
        ),
        (
            "delivery without claim",
            "UPDATE outbox SET claimed_by=NULL WHERE outbox_id='start-a'",
        ),
        (
            "claim without delivery",
            "UPDATE outbox SET delivered_at=NULL WHERE outbox_id='start-a'",
        ),
        (
            "other worker claim",
            "UPDATE outbox SET claimed_by='other-worker' WHERE outbox_id='start-a'",
        ),
        (
            "wrong project payload",
            "UPDATE outbox SET payload=payload || '{\"project_id\":\"other-project\"}'::jsonb WHERE outbox_id='start-a'",
        ),
        (
            "wrong attempt payload",
            "UPDATE outbox SET payload=payload || '{\"attempt_id\":\"other-attempt\"}'::jsonb WHERE outbox_id='start-a'",
        ),
        (
            "wrong operation payload",
            "UPDATE outbox SET payload=payload || '{\"operation_id\":\"other-operation\"}'::jsonb WHERE outbox_id='start-a'",
        ),
        (
            "wrong lease payload",
            "UPDATE outbox SET payload=payload || '{\"lease_id\":\"other-lease\"}'::jsonb WHERE outbox_id='start-a'",
        ),
        (
            "wrong worker payload",
            "UPDATE outbox SET payload=payload || '{\"worker_id\":\"other-worker\"}'::jsonb WHERE outbox_id='start-a'",
        ),
        (
            "wrong generation payload",
            "UPDATE outbox SET payload=payload || '{\"generation\":2}'::jsonb WHERE outbox_id='start-a'",
        ),
        (
            "noncanonical generation payload",
            "UPDATE outbox SET payload=payload || '{\"generation\":\"1\"}'::jsonb WHERE outbox_id='start-a'",
        ),
        (
            "recovery state",
            "UPDATE attempts SET state='RECOVERY_REQUIRED' WHERE attempt_id='a'",
        ),
        (
            "revoked lease",
            "UPDATE leases SET revoked_at=clock_timestamp() WHERE attempt_id='a'",
        ),
        (
            "expired lease",
            "UPDATE leases SET issued_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE attempt_id='a'",
        ),
        (
            "superseded generation",
            "UPDATE tasks SET fence_epoch=2 WHERE project_id='p'",
        ),
    ];
    for (case, mutation) in cases {
        sqlx::query("UPDATE attempts SET state='STARTING' WHERE attempt_id='a'")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE leases SET issued_at=clock_timestamp(),expires_at=clock_timestamp()+interval '1 hour',revoked_at=NULL WHERE attempt_id='a'").execute(&pool).await.unwrap();
        sqlx::query("UPDATE tasks SET fence_epoch=1 WHERE project_id='p'")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO outbox(outbox_id,project_id,operation_id,kind,payload,claimed_by,delivered_at) SELECT 'start-a',project_id,operation_id,'attempt.start',envelope,worker_id,clock_timestamp() FROM attempts WHERE attempt_id='a' ON CONFLICT(outbox_id) DO UPDATE SET payload=EXCLUDED.payload,claimed_by=EXCLUDED.claimed_by,delivered_at=EXCLUDED.delivered_at").execute(&pool).await.unwrap();
        sqlx::query(mutation).execute(&pool).await.unwrap();
        assert_eq!(
            authority.issue_scope("p", "a").await.unwrap_err().code,
            "STALE_EXECUTION_AUTHORITY",
            "scope issuance accepted {case}"
        );
        assert_eq!(
            authority
                .admit(&token, "route", "model")
                .await
                .unwrap_err()
                .code,
            "STALE_EXECUTION_AUTHORITY",
            "model admission accepted {case}"
        );
        let budget: (i64, i64) = sqlx::query_as(
            "SELECT requests_used,inflight FROM gateway_scope_budget WHERE attempt_id='a'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(budget, (0, 0), "denied {case} changed model budget");
        let effects: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT COUNT(*) FROM model_request_permit),(SELECT COUNT(*) FROM provider_requests),(SELECT COUNT(*) FROM events)").fetch_one(&pool).await.unwrap();
        assert_eq!(effects, (0, 0, 0), "denied {case} persisted an effect");
    }

    sqlx::query("UPDATE attempts SET state='STARTING' WHERE attempt_id='a'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE leases SET issued_at=clock_timestamp(),expires_at=clock_timestamp()+interval '1 hour',revoked_at=NULL WHERE attempt_id='a'").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO outbox(outbox_id,project_id,operation_id,kind,payload,claimed_by,delivered_at) SELECT 'start-a',project_id,operation_id,'attempt.start',envelope,worker_id,clock_timestamp() FROM attempts WHERE attempt_id='a' ON CONFLICT(outbox_id) DO UPDATE SET payload=EXCLUDED.payload,claimed_by=EXCLUDED.claimed_by,delivered_at=EXCLUDED.delivered_at").execute(&pool).await.unwrap();
    sqlx::query("UPDATE tasks SET fence_epoch=1 WHERE project_id='p'")
        .execute(&pool)
        .await
        .unwrap();
    let starting = authority.admit(&token, "route", "model").await.unwrap();
    authority
        .settle(RequestSettlement {
            request_id: starting.request_id,
            outcome: "RESPONSE_BODY_COMPLETED".into(),
            upstream_status: Some(200),
            received_bytes: 1,
            usage: None,
            usage_completeness: "UNKNOWN_OR_PARTIAL".into(),
        })
        .await
        .unwrap();
    sqlx::query("UPDATE attempts SET state='RUNNING' WHERE attempt_id='a'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(authority.issue_scope("p", "a").await.unwrap(), token);
    let running = authority.admit(&token, "route", "model").await.unwrap();
    let uncertain = RequestSettlement {
        request_id: running.request_id.clone(),
        outcome: "CLIENT_DISCONNECTED_OR_STREAM_DROPPED".into(),
        upstream_status: Some(200),
        received_bytes: 1,
        usage: None,
        usage_completeness: "UNKNOWN_OR_PARTIAL".into(),
    };
    authority.settle(uncertain.clone()).await.unwrap();
    assert_eq!(
        authority
            .admit(&token, "route", "model")
            .await
            .unwrap_err()
            .code,
        "WAITING_MODEL_BUDGET",
        "uncertain effects must retain inflight capacity"
    );
    sqlx::query("UPDATE attempts SET state='RECOVERY_REQUIRED' WHERE attempt_id='a'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE leases SET revoked_at=clock_timestamp() WHERE attempt_id='a'")
        .execute(&pool)
        .await
        .unwrap();
    authority.revoke_scope("p", "a").await.unwrap();
    assert_eq!(
        authority.issue_scope("p", "a").await.unwrap_err().code,
        "STALE_EXECUTION_AUTHORITY"
    );
    assert_eq!(
        authority
            .admit(&token, "route", "model")
            .await
            .unwrap_err()
            .code,
        "STALE_EXECUTION_AUTHORITY"
    );
    let retained: (String, i64, i64) = sqlx::query_as("SELECT p.status,b.requests_used,b.inflight FROM model_request_permit p JOIN gateway_scope_budget b ON b.token_sha256=p.scope_token_digest WHERE p.request_id=$1").bind(&running.request_id).fetch_one(&pool).await.unwrap();
    assert_eq!(retained, ("QUARANTINED".into(), 2, 1));
    // Closing already admitted effects remains authorized after dispatch/lease revocation.
    authority
        .settle(RequestSettlement {
            outcome: "RECOVERY_CONFIRMED_REQUEST_CLOSED".into(),
            ..uncertain
        })
        .await
        .unwrap();
    let budget: (i64, i64) = sqlx::query_as(
        "SELECT requests_used,inflight FROM gateway_scope_budget WHERE attempt_id='a'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(budget, (2, 0));
    cleanup(pool, schema, admin).await;
}
