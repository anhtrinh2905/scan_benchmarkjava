"""normalize_zap — same shape as normalize_sarif/normalize_bench_summary, tested the same way:
pure function, real fixture file in, list[Alert] out."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from alert_normalizer import normalize_zap  # noqa: E402

ZAP_REPORT = {
    "site": [
        {
            "@name": "http://juice-shop:3000",
            "alerts": [
                {
                    "pluginid": "40018",
                    "alert": "SQL Injection",
                    "name": "SQL Injection",
                    "riskcode": "3",
                    "cweid": "89",
                    "desc": "SQL injection may be possible.",
                    "instances": [
                        {"uri": "http://juice-shop:3000/rest/user/login", "method": "POST"},
                        {"uri": "http://juice-shop:3000/rest/products/search?q=x", "method": "GET"},
                    ],
                },
                {
                    "pluginid": "10038",
                    "alert": "Content Security Policy Header Not Set",
                    "name": "Content Security Policy Header Not Set",
                    "riskcode": "1",
                    "cweid": "-1",
                    "desc": "CSP header missing.",
                    "instances": [{"uri": "http://juice-shop:3000/"}],
                },
            ],
        }
    ]
}


def _write(tmp_path, data) -> Path:
    path = tmp_path / "zap-report.json"
    path.write_text(json.dumps(data))
    return path


def test_one_alert_per_instance(tmp_path):
    alerts = normalize_zap(_write(tmp_path, ZAP_REPORT))
    assert len(alerts) == 3
    assert all(a.tool == "zap" for a in alerts)


def test_riskcode_maps_to_severity_and_file_or_url_is_the_real_uri(tmp_path):
    alerts = normalize_zap(_write(tmp_path, ZAP_REPORT))
    sqli = [a for a in alerts if a.rule_id == "40018"]
    assert {a.severity for a in sqli} == {"high"}
    assert {a.file_or_url for a in sqli} == {
        "http://juice-shop:3000/rest/user/login",
        "http://juice-shop:3000/rest/products/search?q=x",
    }
    assert sqli[0].cwe == "CWE-89"


def test_missing_cweid_or_riskcode_falls_back_instead_of_raising(tmp_path):
    alerts = normalize_zap(_write(tmp_path, ZAP_REPORT))
    csp = next(a for a in alerts if a.rule_id == "10038")
    assert csp.cwe is None          # cweid "-1" means "no CWE", not CWE--1
    assert csp.severity == "low"    # riskcode "1"


def test_alert_with_no_instances_still_produces_one_alert(tmp_path):
    report = {"site": [{"@name": "http://x", "alerts": [{"pluginid": "1", "name": "n", "desc": "d"}]}]}
    alerts = normalize_zap(_write(tmp_path, report))
    assert len(alerts) == 1
    assert alerts[0].file_or_url == "http://x"   # falls back to the site name
    assert alerts[0].severity == "medium"         # DEFAULT_SEVERITY when riskcode is absent
