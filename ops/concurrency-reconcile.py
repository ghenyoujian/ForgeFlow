#!/usr/bin/env python3
"""Reconcile a provider billing export with exact authoritative native request IDs.

Read-only; never settles model custody, releases resources or awards G20.
Provider exports are explicit operator-supplied evidence, not inferred prices.
"""
import argparse
from decimal import Decimal, InvalidOperation
import importlib.util
import json
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location("billing_campaign", Path(__file__).with_name("concurrency-readiness.py"))
C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)


def reconcile(snapshot, billing, campaign, budget, source_hash):
    C.require(type(snapshot) is dict and snapshot.get("source") == "POSTGRESQL_AUTHORITY",
        "authoritative final snapshot required")
    C.require(type(campaign) is str and campaign.strip() == campaign and bool(campaign),
        "nonempty exact campaign identity required")
    C.require(type(source_hash) is str and C.SHA.fullmatch(source_hash),
        "lowercase SHA-256 provider response binding required")
    C.require(type(billing) is dict and billing.get("schema_version") == "forgeflow.provider-billing.v1"
        and billing.get("campaign_id") == campaign, "matching provider billing export required")
    C.require(billing.get("source_response_sha256") == source_hash, "raw provider export binding differs")
    requests = snapshot.get("native_model_requests")
    C.require(type(requests) is list and bool(requests), "nonempty authoritative model request denominator required")
    expected = set()
    for request in requests:
        C.require(type(request) is dict, "authoritative model request row must be an object")
        request_id = request.get("request_id")
        C.require(type(request_id) is str and request_id.strip() == request_id and bool(request_id),
            "authoritative model request identity must be an exact nonempty string")
        C.require(request_id not in expected, "duplicate authoritative model request identity")
        C.require(request.get("status") == "SETTLED" and request.get("usage_complete") is True,
            "nonempty fully settled request denominator required")
        expected.add(request_id)
    observed, provider_ids, total = set(), set(), Decimal(0)
    exported = billing.get("requests")
    C.require(isinstance(exported, list) and exported, "nonempty provider request export required")
    for row in exported:
        C.require(isinstance(row, dict), "provider request row must be an object")
        try: identity, upstream = row["request_id"], row["provider_request_id"]
        except KeyError: raise C.Blocked("provider request identity fields required") from None
        C.require(type(identity) is str and identity.strip() == identity and bool(identity)
            and identity in expected and identity not in observed
            and type(upstream) is str and upstream.strip() == upstream and bool(upstream)
            and upstream not in provider_ids,
            "billing request IDs are missing, duplicated or outside campaign")
        try: amount = Decimal(str(row["cost_usd"]))
        except (KeyError, InvalidOperation, TypeError, ValueError): raise C.Blocked("invalid provider cost") from None
        C.require(amount.is_finite() and amount >= 0, "finite nonnegative observed provider cost required")
        observed.add(identity); provider_ids.add(upstream); total += amount
    C.require(observed == expected, "provider export does not cover every actual native request")
    try: declared_total = Decimal(str(billing["total_cost_usd"]))
    except (KeyError, InvalidOperation, TypeError, ValueError): raise C.Blocked("invalid provider total") from None
    C.require(declared_total.is_finite() and declared_total >= 0
        and total == declared_total, "provider total differs from its request population")
    try: budget_value = Decimal(str(budget))
    except (InvalidOperation, TypeError, ValueError): raise C.Blocked("invalid provider budget") from None
    C.require(budget_value.is_finite() and budget_value >= 0 and total <= budget_value,
        "observed provider cost exceeded campaign budget")
    return {"status": "PROVIDER_EXPORT_RECONCILED", "campaign_id": campaign, "requests": len(expected),
        "observed_cost_usd": str(total), "source_response_sha256": source_hash,
        "provider_source_trust": "EXPLICIT_OPERATOR_SUPPLIED_EXPORT_REQUIRES_OWNER_REVIEW",
        "custody_changed": False, "resources_released": False, "g20": "INCONCLUSIVE"}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--snapshot", required=True, type=Path)
    p.add_argument("--snapshot-sha256", required=True)
    p.add_argument("--billing", required=True, type=Path)
    p.add_argument("--billing-sha256", required=True)
    p.add_argument("--provider-source", required=True, type=Path)
    p.add_argument("--provider-source-sha256", required=True)
    p.add_argument("--campaign-id", required=True)
    p.add_argument("--max-cost-usd", required=True)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    try:
        snapshot = C.read_json(C.pin({"path": str(a.snapshot.absolute()), "sha256": a.snapshot_sha256}))
        billing = C.read_json(C.pin({"path": str(a.billing.absolute()), "sha256": a.billing_sha256}))
        C.pin({"path": str(a.provider_source.absolute()), "sha256": a.provider_source_sha256})
        result = reconcile(snapshot.get("data", snapshot), billing, a.campaign_id, a.max_cost_usd, a.provider_source_sha256)
        C.write_json(a.output, result); print(json.dumps(result)); return 0
    except Exception as error:
        print(json.dumps({"status": "BLOCKED", "error_type": type(error).__name__,
            "reason": str(error) if isinstance(error, C.Blocked) else "Private evidence retained; no custody changes", "g20": "INCONCLUSIVE"})); return 2


if __name__ == "__main__": sys.exit(main())
