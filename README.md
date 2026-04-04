# DNS Exfiltration Detection using Zeek and Machine Learning

## Overview

This project focuses on detecting potential DNS tunneling and data exfiltration activity through network traffic analysis. The system processes packet capture (PCAP) files using Zeek to generate structured DNS logs, which are then indexed into OpenSearch for analysis. Machine learning techniques will be applied to identify anomalous DNS query patterns that may indicate covert data exfiltration.

The project emphasizes network security monitoring and threat analysis. Machine learning is used as a detection layer after structured log generation and feature extraction, making the project a cybersecurity analytics pipeline rather than a standalone machine learning task.

---

## Architecture

```
PCAP Network Traffic
        |
        v
Zeek Network Analyzer
        |
        v
DNS Logs (dns.log)
        |
        v
Log Ingestion Script
        |
        v
OpenSearch Index
        |
        v
Feature Extraction
        |
        v
Machine Learning Detection
```

---

## Project Structure

```
DNS-EXFILTRATION
│
├── pcaps
│   └── dns-tunnel-iodine.pcap
│
├── zeek-logs
│   ├── dns.log
│   ├── conn.log
│   ├── weird.log
│   └── packet_filter.log
│
├── scripts
│   └── ingest_dns.py
│
├── models
│
├── venv
│
└── opensearch
```

---

## Progress Achieved

### 1. Dataset Acquisition

A DNS tunneling dataset (`dns-tunnel-iodine.pcap`) has been obtained and stored in the `pcaps` directory.

### 2. Network Traffic Analysis

Zeek has been used to analyze the PCAP file and generate structured network logs including:

- `dns.log`
- `conn.log`
- `weird.log`

The DNS logs are exported in JSON format for easier downstream processing.

### 3. Log Inspection

Initial inspection confirms characteristics consistent with DNS tunneling, including:

- Long subdomain queries
- High entropy domain names
- Repeated root domains
- Unusual DNS record types such as `NULL`

### 4. Log Ingestion Pipeline

A Python ingestion script (`ingest_dns.py`) has been implemented to parse Zeek DNS logs and send them to an OpenSearch index.

### 5. Environment Setup

A Python virtual environment has been created to manage dependencies required for log processing and future machine learning modules.

---

## Work Remaining

### 1. OpenSearch Deployment

Install and start the OpenSearch server to enable log indexing and querying.

### 2. Log Indexing

Execute the ingestion script to push DNS logs into the OpenSearch index.

### 3. Feature Engineering

Extract statistical and behavioral features from DNS queries, including:

- Query length
- Domain entropy
- Subdomain count
- Digit ratio
- Query frequency patterns

### 4. Machine Learning Model

Train a detection model capable of identifying suspicious DNS activity. Possible approaches include:

- Random Forest
- Isolation Forest
- Gradient Boosting

### 5. Visualization and Analysis

Use OpenSearch dashboards to visualize DNS traffic patterns and highlight anomalous queries.

---

## Expected Outcome

The completed system will be capable of:

- Processing raw network traffic
- Extracting DNS activity logs
- Indexing logs for search and analytics
- Detecting potential DNS based data exfiltration using machine learning

This project demonstrates a practical pipeline for DNS threat detection inspired by real world security monitoring systems.

---

## Tools and Technologies

- Zeek
- OpenSearch
- Python
- Machine Learning (Scikit-learn)
- PCAP Network Datasets

---

## Future Improvements

- Real time traffic monitoring
- Integration with SIEM systems
- Advanced anomaly detection models
- Automated alerting for suspicious DNS activity
