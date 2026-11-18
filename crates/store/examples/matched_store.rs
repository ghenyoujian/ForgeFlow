//! Benchmark-only protocol around actual Store catalog transactions. Requires a
//! dedicated forgeflow_matched_* database; never edits production safety logic.
use forgeflow_domain::{AuthorityMode, CatalogCommand, CommandIdentity, DataOrigin, Project};
use forgeflow_store::{Store, StoreError};
use serde_json::{Value, json};
use sqlx::postgres::PgConnectOptions;
use std::{
    io::{self, BufRead},
    str::FromStr,
};

const PROJECT: &str = "matched";
const DOCUMENT: &str = "counter";
fn error_code(error: StoreError) -> String {
    match error {
        StoreError::Domain(error) => error.code,
        _ => "DATABASE_OR_CONTRACT_ERROR".into(),
    }
}
async fn mutation(store: &Store, key: String, counter: u64, reject: bool) -> Result<(), String> {
    store
        .execute_command(
            CommandIdentity {
                actor_id: "matched-benchmark".into(),
                idempotency_key: key,
            },
            CatalogCommand::PutDocument {
                project_id: PROJECT.into(),
                collection: "operations".into(),
                id: DOCUMENT.into(),
                expected_revision: Some(counter + 1),
                value: json!({"counter":counter+1,"reject_commit":reject}),
            },
        )
        .await
        .map(|_| ())
        .map_err(error_code)
}
async fn snapshot(store: &Store) -> Result<Value, String> {
    let document = store
        .get_document(PROJECT, "operations", DOCUMENT)
        .await
        .map_err(error_code)?;
    let events:Vec<Value>=sqlx::query_scalar("SELECT payload->'document'->'counter' FROM events WHERE project_id=$1 AND object_id=$2 ORDER BY project_seq")
        .bind(PROJECT).bind(DOCUMENT).fetch_all(store.pool()).await.map_err(|_|"EVENT_READ_FAILED")?;
    let revision = document["revision"].as_u64().ok_or("REVISION_MISSING")?;
    Ok(
        json!({"counter":document["counter"],"logical_revision":revision-1,
        "mutation_events":events.len().saturating_sub(1),"event_payload_counters":events.into_iter().skip(1).collect::<Vec<_>>(),
        "native_revision":revision,"storage":"PostgreSQL","implementation":"actual forgeflow_store::Store"}),
    )
}
async fn initialize(store: &Store) -> Result<Value, String> {
    store
        .create_project(Project {
            project_id: PROJECT.into(),
            name: "Matched isolated transaction fixture".into(),
            root_path: "/tmp/forgeflow-matched-counter".into(),
            authority_mode: AuthorityMode::Managed,
            data_origin: DataOrigin::Native,
            goal: "Counter CAS/event/rollback/reopen subset only".into(),
            technology_stack: vec![],
            timezone: "UTC".into(),
            paused: false,
            archived: false,
            revision: 1,
        })
        .await
        .map_err(error_code)?;
    store
        .execute_command(
            CommandIdentity {
                actor_id: "matched-benchmark".into(),
                idempotency_key: "initialize".into(),
            },
            CatalogCommand::PutDocument {
                project_id: PROJECT.into(),
                collection: "operations".into(),
                id: DOCUMENT.into(),
                expected_revision: None,
                value: json!({"counter":0,"reject_commit":false}),
            },
        )
        .await
        .map_err(error_code)?;
    // Narrow commit failure injection exists only in this dedicated benchmark DB.
    // Actual Store writes the row/event; the PostgreSQL transaction must roll back.
    sqlx::query("CREATE FUNCTION matched_reject_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.project_id='matched' AND NEW.object_id='counter' AND NEW.payload->'document'->>'reject_commit'='true' THEN RAISE EXCEPTION 'MATCHED_FORCED_ROLLBACK'; END IF; RETURN NEW; END; $$")
        .execute(store.pool()).await.map_err(|_|"BENCHMARK_TRIGGER_SETUP_FAILED")?;
    sqlx::query("CREATE TRIGGER matched_forced_rollback BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION matched_reject_event()")
        .execute(store.pool()).await.map_err(|_|"BENCHMARK_TRIGGER_SETUP_FAILED")?;
    snapshot(store).await
}
async fn run(store: &Store, request: Value) -> Result<Value, String> {
    if request["schema_version"] != "forgeflow.matched-store.v1" {
        return Err("PROTOCOL_VERSION_INVALID".into());
    }
    let operation = request["operation"].as_str().ok_or("OPERATION_REQUIRED")?;
    let counter = request["expected_counter"].as_u64().unwrap_or(0);
    if counter > 100_000 {
        return Err("COUNTER_BOUND_EXCEEDED".into());
    }
    let began = std::time::Instant::now();
    let result = match operation {
        "initialize" => initialize(store).await?,
        "snapshot" => snapshot(store).await?,
        "mutate" | "force_rollback" => {
            let key = request["request_id"]
                .as_str()
                .ok_or("REQUEST_ID_REQUIRED")?;
            match mutation(store, key.into(), counter, operation == "force_rollback").await {
                Ok(()) => json!({"accepted":true}),
                Err(code) => json!({"accepted":false,"code":code}),
            }
        }
        "race" => {
            let key = request["request_id"]
                .as_str()
                .ok_or("REQUEST_ID_REQUIRED")?;
            let first = mutation(store, format!("{key}/0"), counter, false);
            let second = mutation(store, format!("{key}/1"), counter, false);
            let (a, b) = tokio::join!(first, second);
            json!({"results":[match a{Ok(())=>json!({"accepted":true}),Err(code)=>json!({"accepted":false,"code":code})},match b{Ok(())=>json!({"accepted":true}),Err(code)=>json!({"accepted":false,"code":code})}]})
        }
        "close" => {
            store.pool().close().await;
            json!({"closed":true})
        }
        _ => return Err("UNKNOWN_OPERATION".into()),
    };
    Ok(
        json!({"schema_version":"forgeflow.matched-store-result.v1","operation":operation,"data":result,
        "elapsed_ns":began.elapsed().as_nanos(),"timed_scope":"ACTUAL_STORE_CATALOG_COMMAND_AND_COMMIT", "storage":"PostgreSQL"}),
    )
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let setup = async {
        let url = std::env::var("FORGEFLOW_MATCHED_DATABASE_URL")
            .map_err(|_| "DEDICATED_DATABASE_ENV_REQUIRED")?;
        let options = PgConnectOptions::from_str(&url).map_err(|_| "DATABASE_URL_INVALID")?;
        if !options
            .get_database()
            .is_some_and(|db| db.starts_with("forgeflow_matched_") && db.len() > 18)
        {
            return Err("DEDICATED_BENCHMARK_DATABASE_REQUIRED");
        }
        let store = Store::connect(&url)
            .await
            .map_err(|_| "BENCHMARK_DATABASE_UNAVAILABLE")?;
        store.migrate().await.map_err(|_| "MIGRATION_FAILED")?;
        Ok::<Store, &str>(store)
    }
    .await;
    let store = match setup {
        Ok(store) => store,
        Err(error) => {
            println!("{}", json!({"error":error}));
            return;
        }
    };
    for line in io::stdin().lock().lines() {
        let result = match line {
            Ok(line) => match serde_json::from_str::<Value>(&line) {
                Ok(request) => run(&store, request).await,
                Err(_) => Err("JSON_INVALID".into()),
            },
            Err(_) => Err("STDIN_READ_FAILED".into()),
        };
        let closed = result
            .as_ref()
            .ok()
            .is_some_and(|reply| reply["operation"] == "close");
        println!(
            "{}",
            match result {
                Ok(reply) => reply,
                Err(error) => json!({"error":error}),
            }
        );
        if closed {
            break;
        }
    }
}
