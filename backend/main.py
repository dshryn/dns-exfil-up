from __future__ import annotations

import time

import shutil
import subprocess
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from detection import analyze_records
from utils import parse_dns_log

app = FastAPI(title="DNS Exfiltration Detector")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent

FRONTEND_DIR = BASE_DIR / "frontend"

if not (FRONTEND_DIR / "index.html").exists():
    print("WARNING: Frontend not found, API will still run")

UPLOAD_DIR = BASE_DIR / "uploads"
OUTPUT_DIR = BASE_DIR / "output"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/")
def root():
    return FileResponse(str(FRONTEND_DIR / "index.html"))


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/analyze")
def analyze_info():
    return {"message": "Use POST request with a PCAP file"}


def to_wsl_path(path: Path) -> str:
    """
    Convert a Windows path to a WSL path.
    Example: D:\\CyberProject\\file.pcap -> /mnt/d/CyberProject/file.pcap
    """
    path = path.resolve()
    path_str = str(path).replace("\\", "/")

    if path.drive:
        drive_letter = path.drive.rstrip(":").lower()
        tail = path_str[len(path.drive):]
        if tail.startswith("/"):
            tail = tail[1:]
        return f"/mnt/{drive_letter}/{tail}"

    return path_str

def run_zeek(pcap_path: Path, job_dir: Path) -> None:
    if not pcap_path.exists():
        raise HTTPException(status_code=500, detail="PCAP file missing before Zeek run")

    ZEEK_PATH = "zeek" 

    cmd = [
        ZEEK_PATH,
        "-C",
        "-r",
        str(pcap_path),
        "LogAscii::use_json=T",
    ]

    print("Running Zeek:", " ".join(cmd))
    print("Working directory:", job_dir)

    try:
        result = subprocess.run(
            cmd,
            cwd=job_dir,
            capture_output=True,
            text=True,
            timeout=300
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=500,
            detail="Zeek execution timed out"
        )

    print("Zeek STDOUT:\n", result.stdout)
    print("Zeek STDERR:\n", result.stderr)

    if result.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail=f"Zeek failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )

    if not (job_dir / "dns.log").exists():
        print("Warning: dns.log not generated")


@app.post("/analyze")
async def analyze_pcap(file: UploadFile = File(...)):
    filename = (file.filename or "").lower()

    if not filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="Only PCAP files allowed")

    job_id = str(uuid.uuid4())[:8]
    job_dir = OUTPUT_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    suffix = ".pcapng" if filename.endswith(".pcapng") else ".pcap"
    pcap_path = UPLOAD_DIR / f"{job_id}{suffix}"

    overall_start = time.perf_counter()
    zeek_start = time.perf_counter()

    try:
        with pcap_path.open("wb") as out:
            shutil.copyfileobj(file.file, out)

        run_zeek(pcap_path, job_dir)
        zeek_time = time.perf_counter() - zeek_start

        dns_log_path = job_dir / "dns.log"

        if not dns_log_path.exists():
            total_time = time.perf_counter() - overall_start
            return {
                "job_id": job_id,
                "total_records": 0,
                "suspicious_count": 0,
                "suspicious": [],
                "no_dns": True,
                "message": "No DNS traffic found in this PCAP",
                "zeek_time_seconds": round(zeek_time, 4),
                "detection_time_seconds": 0.0,
                "total_time_seconds": round(total_time, 4),
            }

        parse_start = time.perf_counter()
        records = parse_dns_log(dns_log_path)
        parse_time = time.perf_counter() - parse_start

        detect_start = time.perf_counter()
        suspicious = analyze_records(records)
        detection_time = time.perf_counter() - detect_start

        total_time = time.perf_counter() - overall_start

        return {
            "job_id": job_id,
            "total_records": len(records),
            "suspicious_count": len(suspicious),
            "suspicious": suspicious,
            "zeek_time_seconds": round(zeek_time, 4),
            "parse_time_seconds": round(parse_time, 4),
            "detection_time_seconds": round(detection_time, 4),
            "total_time_seconds": round(total_time, 4),
        }

    finally:
        pass
