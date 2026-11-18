#!/usr/bin/env python3
"""Registered finite read-only artifact oracle; execution is never inferred from registration."""
import json
import os
from pathlib import Path

artifact = os.environ.get('FORGEFLOW_ARTIFACT_PATH')
text = Path(artifact).read_text() if artifact else ''
expected = ('ONE_SHOT_RECEIPT', 'WORKFLOW_RECEIPT', 'TEAM_RECEIPT', 'TEAM_RESUME_RECEIPT')
def accepted(value):
    return all(label in value for label in expected)
cases = [{'name': 'finite_receipt_labels', 'kind': 'positive', 'outcome': 'passed' if accepted(text) else 'failed'},
         {'name': 'empty_receipt_rejected', 'kind': 'negative', 'outcome': 'passed' if not accepted('') else 'failed'}]
report = {'binding': json.loads(os.environ['FORGEFLOW_EVIDENCE_BINDING']),
          'oracle_id': 'canonical-finite-artifact.v1', 'cases': cases}
Path(os.environ['FORGEFLOW_REPORT_PATH']).write_text(json.dumps(report))
raise SystemExit(0 if all(case['outcome'] == 'passed' for case in cases) else 1)
