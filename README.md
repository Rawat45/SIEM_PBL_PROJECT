# 🛡️ SIEM (Security Information and Event Management) System

A lightweight, real-time SIEM system built with Python and Flask. It supports log collection, keyword-based alerting, anomaly detection, and a web dashboard to search and visualize logs.

## 📌 Features

- 🔄 **Real-Time Log Collection** (Mac log file monitored)
- ⚠️ **Keyword-based Alerts**
- 🚨 **Anomaly Detection** (Spike detection within time window)
- 💾 **Persistent Log Storage** (SQLite and JSONL)
- 🧪 **Searchable Dashboard** (Filter logs by keyword)
- 📈 **Anomaly Dashboard**
- 🔔 **Alerts Page** for real-time detections

---

## 🏗️ System Architecture


Client (Log Collector)
|
V
[HTTP POST] ---> Flask Server (/ingest)
|
|---> SQLite DB (logs)
|---> Alerts Table
|---> JSONL Log File (for anomaly analysis)
|
[Web Dashboard: Logs, Anomalies, Alerts]
🌐 Web Dashboard
Home Page / – View all logs and search by keyword.

Anomalies Page /anomalies – Shows spike-based anomalies.

Alerts Page /alerts – Shows triggered alerts from keyword rules.

