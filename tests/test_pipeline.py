import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from mobsec.llm import LLM, parse_json
from mobsec.pipeline import detect_kind, run
from mobsec.report import write_all
from helpers import vulnerable_manifest, make_apk


@pytest.fixture
def apk(tmp_path, monkeypatch):
    monkeypatch.setenv("MOBSEC_HOME", str(tmp_path / "home"))  # curated notes only, no network
    p = tmp_path / "demo.apk"
    p.write_bytes(make_apk(vulnerable_manifest()))
    return p


def test_detect_kind(tmp_path, apk):
    assert detect_kind(str(apk)) == "apk"
    assert detect_kind(str(tmp_path)) == "source"


def test_offline_run_and_reports(tmp_path, apk):
    r = run(str(apk), log=lambda *a: None)
    assert r.app["analysis_mode"].startswith("offline")
    assert 0 <= r.app["score"] <= 100
    f = next(x for x in r.findings if x.rule_id == "AND-EXPORTED-PROVIDER")
    assert f.guidance and f.guidance[0]["origin"] == "curated"
    assert f.analysis["fix_steps"]
    paths = write_all(r, tmp_path / "out")
    sarif = json.loads(paths["sarif"].read_text())
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]
    data = json.loads(paths["json"].read_text())
    assert data["findings"] and "files" in data
    html = paths["html"].read_text()
    assert "Exported content provider" in html and "<script>" in html
    assert paths["md"].read_text().startswith("# Mobile security report")


class _Mock(BaseHTTPRequestHandler):
    calls = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        _Mock.calls.append(body)
        system = body["messages"][0]["content"]
        if "executive summary" in system:
            text = "Mock summary."
        else:
            text = json.dumps({"verdict": "likely_false_positive" if "ALLOW-BACKUP" in body["messages"][1]["content"] else "true_positive",
                               "severity": "high", "risk": "r", "attack_scenario": "a", "fix_steps": ["s1"],
                               "fix_code": "x", "fix_language": "xml", "how_to_verify": "v",
                               "false_positive_locations": [], "references": []})
        out = json.dumps({"choices": [{"message": {"content": text}}]}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def test_llm_triage_with_openai_compatible_server(apk):
    srv = HTTPServer(("127.0.0.1", 0), _Mock)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        llm = LLM("ollama", "mock", f"http://127.0.0.1:{srv.server_port}/v1")
        r = run(str(apk), llm=llm, log=lambda *a: None)
    finally:
        srv.shutdown()
    assert r.summary == "Mock summary."
    backup = next(x for x in r.findings if x.rule_id == "AND-ALLOW-BACKUP")
    assert backup.verdict == "likely_false_positive"
    assert r.findings[-1].verdict == "likely_false_positive"  # false positives sorted last
    prompt = _Mock.calls[0]["messages"][1]["content"]
    assert "<evidence>" in prompt and "<references>" in prompt
    assert "DATA" in _Mock.calls[0]["messages"][0]["content"]  # prompt-injection guard present


def test_parse_json_tolerant():
    assert parse_json('blah ```json\n{"a": 1,}\n```')["a"] == 1
