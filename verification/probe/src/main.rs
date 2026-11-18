//! JSONL seam into actual production algorithms. Expected outputs live elsewhere.
use std::io::{self, BufRead};
use serde_json::{json, Value};
use forgeflow_domain::{AttemptState, FlowRevision};

fn run(value: Value) -> Result<Value, String> {
    let started = std::time::Instant::now();
    let operation = value["operation"].as_str().ok_or("operation missing")?;
    let data = match operation {
        "compile" => {
            let flow: FlowRevision = serde_json::from_value(value["flow"].clone()).map_err(|e|e.to_string())?;
            let context = serde_json::from_value(value["context"].clone()).map_err(|e|e.to_string())?;
            serde_json::to_value(forgeflow_planner::compile(&flow, &context)).map_err(|e|e.to_string())?
        },
        "schedule" => {
            let input = serde_json::from_value(value["input"].clone()).map_err(|e|e.to_string())?;
            serde_json::to_value(forgeflow_scheduler::ready_frontier(input)).map_err(|e|e.to_string())?
        },
        "state_pairs" => {
            let names = ["LEASED", "STARTING", "RUNNING", "VERIFYING", "REVIEW_READY", "MERGE_QUEUED", "MERGING", "STOPPING", "RECOVERY_REQUIRED", "SUCCEEDED", "FAILED", "CANCELLED"];
            let mut pairs = Vec::new();
            for from in names {
                for to in names {
                    let a: AttemptState = serde_json::from_value(json!(from)).map_err(|e|e.to_string())?;
                    let b: AttemptState = serde_json::from_value(json!(to)).map_err(|e|e.to_string())?;
                    pairs.push(json!({"from":from,"to":to,"allowed":a.can_transition(b)}));
                }
            }
            json!(pairs)
        },
        other => return Err(format!("unknown operation {other}")),
    };
    Ok(json!({"data":data,"elapsed_ns":started.elapsed().as_nanos(),"implementation":"actual Rust production algorithms"}))
}

fn main() {
    for line in io::stdin().lock().lines() {
        let result = line.map_err(|e|e.to_string())
            .and_then(|text|serde_json::from_str(&text).map_err(|e|e.to_string()))
            .and_then(run);
        let output = match result { Ok(value)=>value, Err(error)=>json!({"error":error}) };
        println!("{}",output);
    }
}
