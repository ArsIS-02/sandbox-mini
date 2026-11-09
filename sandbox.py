#!/usr/bin/env python3
"""Песочница-мини: прогон файла в изолированном podman-контейнере, отчёт в Graylog.

Использование: python3 sandbox.py <файл> [--image localhost/sandbox-mini:latest]
Отчёт: ~/sandbox/reports/<sha256>.json + событие GELF (tool=sandbox).
"""
import gzip, json, os, socket, subprocess, sys, tempfile, time
from pathlib import Path

IMAGE = "localhost/sandbox-mini:latest"
REPORTS = Path(os.environ.get("SB_REPORTS", "~/sandbox/reports")).expanduser()
GELF_HOST = os.environ.get("SB_GELF_HOST", "127.0.0.1")
GELF_PORT = int(os.environ.get("SB_GELF_PORT", "12206"))
HOST = socket.gethostname()


def read_lines(p):
    try:
        return [l.strip() for l in p.read_text(errors="replace").splitlines() if l.strip()]
    except Exception:
        return []


def build_report(raw_dir, sample_name):
    """Собирает отчёт из сырых файлов контейнера."""
    d = Path(raw_dir)
    rep = {
        "file": sample_name,
        "sha256": read_lines(d / "sha256")[0] if read_lines(d / "sha256") else "",
        "filetype": " ".join(read_lines(d / "filetype")),
        "ran": read_lines(d / "ran") == ["1"],
        "urls": read_lines(d / "urls"),
        "ips": read_lines(d / "ips"),
        "interesting_strings": read_lines(d / "interesting"),
        "yara": read_lines(d / "yara"),
        "imports": read_lines(d / "imports"),
        "net_attempts": read_lines(d / "net_attempts"),
        "fs_ops": read_lines(d / "fs_ops"),
        "execve": read_lines(d / "execve"),
    }
    return rep


def verdict(rep):
    """Эвристика подозрительности: (level, reasons)."""
    reasons = []
    yara_hits = [y for y in rep.get("yara", []) if not y.startswith(("EICAR", "UPX"))]
    if rep.get("yara"):
        # EICAR — контроль конвейера, UPX — лишь упаковка: их не считаем угрозой сами по себе
        if yara_hits:
            reasons.append(f"YARA: {', '.join(yara_hits[:5])}")
        else:
            reasons.append(f"YARA (контекст): {', '.join(rep['yara'][:5])}")
    if rep["net_attempts"]:
        reasons.append(f"сетевые обращения: {', '.join(rep['net_attempts'][:5])}")
    suspicious_fs = [p for p in rep["fs_ops"]
                     if p.startswith(("/etc", "/root", "/home")) or ".service" in p or "cron" in p]
    if suspicious_fs:
        reasons.append(f"работа с системными путями: {', '.join(suspicious_fs[:5])}")
    extra_exec = [e for e in rep["execve"][1:]]  # первый — сам образец
    if extra_exec:
        reasons.append(f"запускает: {', '.join(extra_exec[:5])}")
    # URL по IP-литералу — сильный сигнал; URL на домены в строках — только контекст
    ip_urls = [u for u in rep["urls"]
               if u.split("://")[-1].split("/")[0].split(":")[0].replace(".", "").isdigit()]
    if ip_urls:
        reasons.append(f"URL по IP-литералу: {', '.join(ip_urls[:3])}")
    return (3 if reasons else 5), reasons


def send_gelf(fields):
    msg = {"version": "1.1", "host": HOST, "short_message": fields.pop("short"),
           "timestamp": time.time(), "level": fields.pop("level", 5)}
    msg.update({f"_{k}": v for k, v in fields.items()})
    data = gzip.compress(json.dumps(msg).encode())
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(data, (GELF_HOST, GELF_PORT))
    sock.close()


def run_sandbox(sample, image=IMAGE):
    sample = Path(sample).resolve()
    if not sample.is_file():
        sys.exit(f"нет файла: {sample}")
    with tempfile.TemporaryDirectory() as tmp:
        cmd = ["podman", "run", "--rm", "--network", "none", "--read-only",
               "--cap-drop", "ALL", "--pids-limit", "64", "--memory", "256m",
               "-v", f"{sample}:/sample:ro,z", "-v", f"{tmp}:/work/report_raw:Z",
               image, "/sample"]
        subprocess.run(cmd, capture_output=True, timeout=120)
        rep = build_report(tmp, sample.name)
    rep["analyzed_at"] = time.strftime("%Y-%m-%d %H:%M:%S %z")
    return rep


def main():
    if len(sys.argv) < 2:
        sys.exit("использование: sandbox.py <файл>")
    rep = run_sandbox(sys.argv[1])
    level, reasons = verdict(rep)
    rep["verdict_reasons"] = reasons

    REPORTS.mkdir(parents=True, exist_ok=True)
    out = REPORTS / f"{rep['sha256'] or int(time.time())}.json"
    out.write_text(json.dumps(rep, ensure_ascii=False, indent=1))

    send_gelf({
        "short": f"sandbox: {rep['file']} — " +
                 (f"ПОДОЗРИТЕЛЬНО ({'; '.join(reasons[:2])})" if reasons else "признаков угроз не видно"),
        "level": level, "tool": "sandbox", "homelab_app": "sandbox",
        "sb_event": "alert" if reasons else "run",
        "sb_file": rep["file"], "sb_sha256": rep["sha256"],
        "sb_type": rep["filetype"][:80], "sb_ran": rep["ran"],
        "sb_net_attempts": len(rep["net_attempts"]), "sb_urls": len(rep["urls"]),
        "sb_yara": ",".join(rep.get("yara", []))[:200],
        "sb_report": str(out),
    })
    print(json.dumps(rep, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
