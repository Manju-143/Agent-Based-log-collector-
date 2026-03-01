import subprocess
import sys
from pathlib import Path
def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
def test_verify_logfile_passes_on_untampered(tmp_path: Path):
   
    logfile = Path("data") / "verified_logs.jsonl"
    assert logfile.exists(), "Generate logs first so data/verified_logs.jsonl exists."
    cmd = [sys.executable, "-m", "tools.verify_logfile", str(logfile)]
    p = _run(cmd)
    assert p.returncode == 0, p.stdout
def test_verify_logfile_fails_on_tampered(tmp_path: Path):
    logfile = Path("data") / "verified_logs.jsonl"
    assert logfile.exists(), "Generate logs first so data/verified_logs.jsonl exists."
    tampered = tmp_path / "verified_logs_tampered.jsonl"
    tampered.write_text(logfile.read_text(encoding="utf-8"), encoding="utf-8")
    txt = tampered.read_text(encoding="utf-8")
    assert len(txt) > 20
    tampered.write_text(txt.replace("{", "[", 1), encoding="utf-8")
    cmd = [sys.executable, "-m", "tools.verify_logfile", str(tampered)]
    p = _run(cmd)
    assert p.returncode != 0, "Verifier should fail on tampered logfile."