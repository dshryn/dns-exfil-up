# Holistic DNS Exfiltration Detection Pipeline

_Detecting covert data exfiltration at the network layer using passive traffic analysis, behavioral feature engineering, and supervised machine learning._

**Live:** [dns-exfil-up-4.onrender.com](https://dns-exfil-up-4.onrender.com)

---

## Overview

DNS is one of the most dangerous and most overlooked exfiltration vectors in modern threat landscapes. Because DNS (UDP/53) is almost universally permitted through enterprise firewalls, and rarely inspected at depth, adversaries exploit it as a covert channel to silently drain sensitive data from compromised networks, often operating undetected for weeks or months.

This is a DNS exfiltration detection system that operates at the raw packet level. Upload a PCAP. The pipeline runs Zeek deep packet inspection against it, extracts DNS telemetry, engineers 11 behavioral features per query, and scores every record through a trained Random Forest classifier, surfacing tunneled, encoded, or otherwise anomalous DNS activity with a severity rating, entropy score, subdomain depth, and ML confidence per alert.

No signature matching. No known-bad domain lists. Pure structural and behavioral analysis on query content.

**What this system catches:**

- Active DNS tunneling sessions (iodine, dnscat2, dns2tcp)
- Staged data exfiltration via base64 / hex-encoded subdomains
- Domain Generation Algorithm (DGA) C2 callbacks
- Long-haul covert channels operating below bandwidth detection thresholds
- High-frequency beaconing patterns masked as legitimate resolution traffic

---

## Full Detection Pipeline

```
+---------------------------------------------------------------+
|                    ANALYST / BLUE TEAM                        |
|           Submits network capture for investigation           |
+-------------------------------+-------------------------------+
                                |
                         [ PCAP File ]
                                |
                                v
+---------------------------------------------------------------+
|                     INGESTION LAYER                           |
|                  FastAPI Backend — /analyze                   |
|                                                               |
|  - Validates .pcap / .pcapng extension                        |
|  - Assigns UUID8 job_id                                       |
|  - Writes file to uploads/                                    |
|  - Spawns Zeek subprocess                                     |
+-------------------------------+-------------------------------+
                                |
                                v
+---------------------------------------------------------------+
|              DEEP PACKET INSPECTION LAYER                     |
|            Zeek Network Security Monitor                      |
|                                                               |
|  cmd: zeek -C -r <file.pcap> local LogAscii::use_json=T       |
|  cwd: output/<job_id>/                                        |
|                                                               |
|  Zeek dissects every DNS frame and emits:                     |
|    ts, uid, id.orig_h, id.resp_h, proto,                      |
|    query, qtype_name, rcode, answers[], TTL[]                 |
|                                                               |
|  Output: dns.log (newline-delimited JSON)                     |
+-------------------------------+-------------------------------+
                                |
                           [ dns.log ]
                                |
                                v
+---------------------------------------------------------------+
|               LOG PARSING & NORMALIZATION                     |
|                 utils.parse_dns_log()                         |
|                                                               |
|  - Line-by-line JSON decode                                   |
|  - UTF-8 with error ignoring for malformed captures           |
|  - Returns raw record list for feature extraction             |
+-------------------------------+-------------------------------+
                                |
                                v
+---------------------------------------------------------------+
|           BEHAVIORAL FEATURE ENGINEERING                      |
|              utils.extract_features()                         |
|                                                               |
|  11 features computed per DNS query:                          |
|                                                               |
|   length              total query char count                  |
|   num_digits          count of digit characters               |
|   num_subdomains      label depth (dot-split count)           |
|   entropy             **Shannon entropy** of raw label chars  |
|   vowel_ratio         vowels / total chars                    |
|   unique_ratio        unique chars / total length             |
|   longest_label       length of longest single label          |
|   consonant_ratio     consonants / total chars                |
|   digit_ratio         digits / total chars                    |
|   special_ratio       non-alphanum chars / total chars        |
|   repeated_char_ratio 1 - (unique chars / total length)       |
+-------------------------------+-------------------------------+
                                |
                  [ 11-dimensional feature vector ]
                                |
                                v
+---------------------------------------------------------------+
|           MACHINE LEARNING CLASSIFICATION                     |
|       detection.analyze_records() — dns_rf_model.pkl          |
|                                                               |
|  StandardScaler applied before inference                      |
|  RandomForestClassifier — 400 trees, depth 15                 |
|  class_weight=balanced, threshold=0.65                        |
|                                                               |
|  Composite score formula (0–100):                             |
|    ml_score        = prob^0.7 * 60                            |
|    entropy_score   = min(entropy / 5, 1) * 20                 |
|    subdomain_score = min(subdomains / 10, 1) * 20             |
|    final_score     = sum of above                             |
|                                                               |
| Classified based on thresholds for Critical, High, and Medium |
+-------------------------------+-------------------------------+
                                |
                   [ Scored & Ranked Alert List ]
                                |
                                v
+---------------------------------------------------------------+
|                      RESULTS LAYER                            |
|             FastAPI JSON Response + Browser UI                |
|                                                               |
|  Per alert: score, severity, entropy, num_subdomains,         |
|  length, src_ip, timestamp, qtype, reasons[]                  |
|  Duration: zeek_time, parse_time, detection_time, total_time  |
+---------------------------------------------------------------+
```

---

## Threat Model Coverage

```
MITRE ATT&CK TECHNIQUES DETECTED:


[T1048.001] Exfiltration Over Alternative Protocol (DNS)
     |
     +-- DNS Tunneling (full session)
     |        Tools: iodine, dnscat2, dns2tcp
     |        Signal: high subdomain depth + elevated entropy + repeat rate
     |
     +-- Chunked Payload Exfiltration
     |        Method: base64 / hex encoding packed into subdomain labels
     |        Signal: suppressed vowel_ratio + high digit_ratio + unique_ratio
     |
     +-- DGA-based C2 Beaconing
     |        Method: algorithmically generated domains for C2 callback
     |        Signal: high entropy + low vowel_ratio + longest_label spike
     |
     +-- Slow-Burn / Low-Frequency Exfiltration
              Method: designed to stay under volume-based detection thresholds
              Signal: feature vector scoring is rate-independent, caught regardless
```

---

## Detection Features

| Feature               | Why It Matters                                                                      |
| --------------------- | ----------------------------------------------------------------------------------- |
| `length`              | Tunneling tools encode data in labels, producing queries >200–500 chars             |
| `num_digits`          | Hex-encoded payloads spike digit count far above any natural hostname               |
| `num_subdomains`      | Legitimate domains rarely exceed 3–4 labels; exfil channels routinely stack 6-100+  |
| `entropy`             | Encoded data scores >3.5 bits/char; human-readable hostnames score 2.0–2.8          |
| `vowel_ratio`         | Natural hostnames carry ~35–45% vowels; encoding suppresses this toward zero        |
| `unique_ratio`        | High lexical diversity in a single label is a strong DGA / encoding indicator       |
| `longest_label`       | A single oversized label is a hallmark of base64-chunked payload delivery           |
| `consonant_ratio`     | Complements vowel_ratio for full character distribution fingerprinting              |
| `digit_ratio`         | Standalone digit density; directly correlated with hex and numeric encoding schemes |
| `special_ratio`       | Detects unusual non-alphanum patterns surfaced by obfuscated query construction     |
| `repeated_char_ratio` | Inverse of unique_ratio; catches repetitive encoded blocks and padding characters   |

---

## Machine Learning Model

**Algorithm:** `RandomForestClassifier` with 400 estimators, max depth 15, balanced class weights, inference threshold 0.65

The composite scoring formula deliberately blends ML probability with interpretable structural signals so that even queries where the model is moderately confident still surface if their entropy or subdomain depth is extreme. This prevents low-confidence misses on novel encoding schemes the model has not seen.

**Training corpus:**

| Source                            | Label     |
| --------------------------------- | --------- |
| Clean enterprise DNS traffic      | Benign    |
| iodine DNS tunnel sessions        | Malicious |
| dnscat2 C2 channel captures       | Malicious |
| Base64-encoded subdomain payloads | Malicious |
| DGA callback domain samples       | Malicious |
| CDN and cloud provider traffic    | Benign    |

**Evaluation metrics computed at training time:**

ROC-AUC, PR-AUC, Matthews Correlation Coefficient, Cohen's Kappa, Log Loss, Brier Score, Balanced Accuracy, Specificity

Model is serialized as a self-contained bundle at `backend/models/dns_rf_model.pkl`:

---

## Dockerization

Getting Zeek and the full Python stack to coexist reliably inside a container was non-trivial. The Dockerfile handles:

- Installing Zeek from the official Zeek package repository into `/opt/zeek/`
- Explicitly prepending `/opt/zeek/bin` to PATH at both build time and runtime
- Verifying the `zeek` binary resolves correctly before the app starts
- Installing all Python dependencies in a single layer to keep image size down
- Exposing port 8080 and launching via `uvicorn`

The app also guards against non-standard Zeek install paths at runtime:

```python
os.environ["PATH"] = "/opt/zeek/bin:" + os.environ.get("PATH", "")
```

And the `/debug` endpoint exposes Zeek path resolution and binary availability for live diagnostics inside the running container:

```
GET /debug
```

```json
{
  "zeek_path": "/opt/zeek/bin/zeek",
  "PATH": "/opt/zeek/bin:/usr/local/bin:...",
  "opt_exists": true,
  "usr_local_exists": false
}
```

**Build and run:**

```bash
docker build -t dns-exfil .
docker run -p 8080:8080 dns-exfil
```

The container runs the complete pipeline end-to-end, including Zeek subprocess, Python feature extraction, and ML inference, with no external dependencies.

---

## API Reference

### Analyze PCAP

```
POST /analyze
Content-Type: multipart/form-data

file: <capture.pcap | capture.pcapng>
```

**Response:**

```json
{
  "job_id": "7e9d9f0b",
  "total_records": 222,
  "suspicious_count": 41,
  "suspicious": [
    {
      "timestamp": 1282379449.0,
      "src_ip": "10.0.2.30",
      "query": "rdeyd4i.xechd.xbf.xde.xee4cohd.xbf.xde.xee4cohd",
      "qtype": "NULL",
      "score": 76.4,
      "severity": "HIGH",
      "entropy": 3.129,
      "num_subdomains": 94,
      "length": 516,
      "reasons": ["Entropy: 3.13", "Subdomains: 94", "ML confidence: 0.731"]
    }
  ],
  "zeek_time_seconds": 1.842,
  "parse_time_seconds": 0.011,
  "detection_time_seconds": 0.034,
  "total_time_seconds": 1.903
}
```

If no DNS traffic is present in the capture:

```json
{
  "job_id": "...",
  "total_records": 0,
  "suspicious_count": 0,
  "no_dns": true,
  "message": "No DNS traffic found in this PCAP"
}
```

---

### Supporting Endpoints

| Method | Endpoint      | Description                                         |
| ------ | ------------- | --------------------------------------------------- |
| GET    | `/health`     | Liveness check, returns standard `{"status": "ok"}` |
| GET    | `/debug`      | Zeek path, PATH env, binary existence flags         |
| GET    | `/check-zeek` | Resolves zeek binary via `shutil.which`             |

---

## Sample Detection Output

From a real capture, job `7e9d9f0b`, 222 DNS records analyzed, 41 flagged:

| Score | Severity | Source IP | Query (truncated)                 | Length | Entropy | Subdomains |
| ----- | -------- | --------- | --------------------------------- | ------ | ------- | ---------- |
| 76.4  | HIGH     | 10.0.2.30 | rdeyd4i.xechd.xbf.xde.xee4cohd... | 516    | 3.129   | 94         |
| 74.1  | HIGH     | 10.0.2.30 | rdkad0i.xebg.xc1h.xce.xe60ang...  | 516    | 3.345   | 94         |
| 68.8  | MEDIUM   | 10.0.2.30 | rdfqd3i.xeb.xe4.xf15.xda.xec3b... | 687    | 3.302   | 151        |
| 68.8  | MEDIUM   | 10.0.2.30 | 1eaba82.xca2hb.xbe.xeey.xd6wgi... | 188    | 4.053   | 34         |

All traffic originating from a single internal host (`10.0.2.30`) using NULL record type queries, which is a textbook DNS tunneling pattern. Subdomain depths of 94-151 labels and query lengths up to 687 characters are orders of magnitude beyond any legitimate DNS resolution.

---

## Technology Stack

| Layer              | Technology                             |
| ------------------ | -------------------------------------- |
| Packet analysis    | Zeek Network Security Monitor          |
| Backend            | FastAPI + Python                       |
| ML model           | scikit-learn RandomForestClassifier    |
| Feature extraction | 11 behavioral DNS features (custom)    |
| Model bundle       | joblib (model + scaler + feature list) |
| Containerization   | Docker                                 |
| Frontend           | HTML5 / Vanilla JavaScript             |
| Hosting            | Render                                 |

---

## Operational Use Cases

- **SOC Tier-1 / Tier-2 Triage**: Pre-screen DNS captures to surface and prioritize alerts before analyst review
- **Incident Response Forensics**: Post-breach PCAP analysis to reconstruct exfiltration timelines and identify affected hosts
- **Threat Hunting**: Proactive detection of low-and-slow tunneling campaigns that evade volume-based controls
- **Red Team Validation**: Verify detection coverage against known DNS exfiltration tooling (iodine, dnscat2)
- **Blue Team R&D**: Functional baseline for building production DNS monitoring pipelines
- **Network Forensics**: Behavioral profiling of DNS-based adversary infrastructure and C2 patterns

---

## Future Work

| Milestone                 | Description                                                                 |
| ------------------------- | --------------------------------------------------------------------------- |
| Live capture mode         | Real-time ingestion via AF_PACKET / libpcap socket                          |
| Streaming pipeline        | Kafka-backed event bus for continuous DNS telemetry                         |
| SIEM integration          | Native connectors for Splunk HEC, Elastic Beats, QRadar                     |
| MITRE ATT&CK auto-tagging | Per-alert technique mapping (T1048.001, T1071.004, T1568.002)               |
| Deep learning model       | LSTM / Transformer on query sequences for session-level behavioral analysis |
| Multi-model ensemble      | Voting classifier combining RF, XGBoost, and neural network outputs         |
| Threat intel enrichment   | MISP / OpenCTI integration for domain reputation correlation                |
| Per-host risk dashboard   | Historical trend analysis, risk scoring, and anomaly timeline per source IP |
| Webhook alerting          | PagerDuty, Slack, and email notification on Critical/High severity hits     |
