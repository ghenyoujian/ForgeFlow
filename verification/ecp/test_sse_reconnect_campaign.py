from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

from sse_reconnect_campaign import data_body, read_sse_frame, run


class _SseHandler(BaseHTTPRequestHandler):
    frame = b"id: project-1:4\ndata: {\"project_id\":\"project-1\",\"project_seq\":4}\n\n"

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        self.wfile.write(self.frame)
        self.wfile.flush()

    def log_message(self, *_args):
        return


class SseReconnectCampaignTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _SseHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_sse_frame_parser_preserves_identity_and_sequence(self):
        frame = read_sse_frame(
            f"http://127.0.0.1:{self.server.server_port}",
            "project-1",
            3,
            "token",
            "workspace",
            2,
        )
        self.assertEqual(frame["id"], "project-1:4")
        self.assertEqual(frame["payload"], {"project_id": "project-1", "project_seq": 4})

    def test_data_body_rejects_non_object_payload(self):
        with self.assertRaises(AssertionError):
            data_body({"data": ["not-an-object"]})

    def test_campaign_without_run_is_explicitly_not_run(self):
        report = run(SimpleNamespace(run=False, base_url=None, token=None, workspace=None, timeout=1.0))
        self.assertEqual(report["status"], "NOT_RUN")
        self.assertEqual(report["qualification"], "NOT_RUN")
        self.assertEqual(report["denominator"]["passed"], 0)


if __name__ == "__main__":
    unittest.main()
