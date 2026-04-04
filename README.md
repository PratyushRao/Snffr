# 🛡️ SNFFR - A Distributed Intrusion Detection & Autonomous Response System

This project is a cross-platform, modular Intrusion Detection & Prevention System (IDS/IPS) that uses distributed agents on Linux and Windows machines to capture network traffic and send structured data to a centralized detection engine. The system analyzes traffic using both signature-based techniques (inspired by Snort) and machine learning-based anomaly detection to identify potential threats. It further enhances security by enabling automated response actions such as blocking malicious IPs and generating real-time alerts, simulating a mini enterprise-grade network defense system.

---

## ⚙️ Tech Stack

- **Packet Capture:** Scapy, libpcap (Linux), Npcap (Windows)  
- **Backend:** Python (Flask / FastAPI)  
- **Machine Learning:** scikit-learn  
- **Communication:** REST APIs (JSON)  
- **Dashboard:** React / HTML, CSS, JavaScript  
- **Operating Systems:** Linux, Windows  
