<div align="center">

# 🌐 HTTP Log Analysis using Splunk

<img width="638" height="193" alt="image" src="https://github.com/user-attachments/assets/0944d89c-51dd-4489-a997-d8c6432a5407" />

![Splunk](https://img.shields.io/badge/SIEM-Splunk-orange)
![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity-blue)
![Logs](https://img.shields.io/badge/Logs-HTTP%20%7C%20JSON-green)
![Zeek](https://img.shields.io/badge/Source-Zeek-lightgrey)
![Status](https://img.shields.io/badge/Project-Completed-success)

*A hands-on SIEM project for analyzing HTTP traffic, detecting anomalies, and identifying suspicious web activity using Splunk.*

---
</div>

## 🎯 Objective

This project aims to:

- Ingest and analyze HTTP logs using Splunk
- Detect client-side (4xx) and server-side (5xx) HTTP errors
- Identify suspicious User-Agents and URI access attempts
- Detect large file transfers that may indicate data exfiltration
- Gain practical experience using Splunk SPL (Search Processing Language)

---

## 🧰 Tools & Technologies

- **SIEM Tool:** Splunk Enterprise
- **Log Format:** Zeek-style HTTP logs (JSON)
- **Index:** `http_lab`
- **Sourcetype:** `json` or `zeek:http`

---

## 🖥️ Lab Setup

### ✅ Prerequisites

- Splunk installed and accessible via Splunk Web
- HTTP log file in JSON format (`http_logs.json`)

---

## 📥 Data Ingestion Steps

1. Open **Splunk Web**
<img width="1919" height="962" alt="1" src="https://github.com/user-attachments/assets/14992741-bee9-4142-8d69-a1bd08fcc589" />

2. Navigate to **Settings → Add Data**
<img width="1919" height="958" alt="2" src="https://github.com/user-attachments/assets/6ea0d83f-6695-42ad-8007-1317612f456c" />

3. Select **Upload**
<img width="1919" height="960" alt="3" src="https://github.com/user-attachments/assets/95345951-45b2-406a-8333-5f9d0d5447c1" />
<img width="1919" height="962" alt="4" src="https://github.com/user-attachments/assets/40911cbb-315d-4ca1-806e-5a2733277dfe" />


4. Upload the file `http_logs.json`
<img width="1919" height="1079" alt="5" src="https://github.com/user-attachments/assets/87919ea9-97c4-43cd-8c68-346c0fb30da1" />
<img width="1919" height="962" alt="6" src="https://github.com/user-attachments/assets/b51282bd-14b9-46c4-80e8-5190dab04c1a" />

5. Configure the following:
   - **Source type:** `json` (or create `zeek:http`)
   - **Index:** `http_lab` (recommended)
<img width="1919" height="963" alt="7" src="https://github.com/user-attachments/assets/3e3322e5-5341-4d05-9e02-55a21f497dc0" />
<img width="1919" height="961" alt="8" src="https://github.com/user-attachments/assets/55d76e0d-1f31-46d1-8048-6eeea35c1e18" />
<img width="1919" height="963" alt="9" src="https://github.com/user-attachments/assets/71960a2e-c134-447c-b632-7ef1cede49d4" />
<img width="1919" height="965" alt="10" src="https://github.com/user-attachments/assets/01631597-847e-41d3-9dc1-5fef2c16e415" />
<img width="1919" height="960" alt="11" src="https://github.com/user-attachments/assets/4952ae2c-91bd-42b1-84e9-2fba5ed360de" />
<img width="1919" height="962" alt="12" src="https://github.com/user-attachments/assets/d11de988-f9b5-4c56-a312-4912251bf86f" />

6. Complete the upload and confirm that data is indexed
<img width="1919" height="962" alt="13" src="https://github.com/user-attachments/assets/9b4da24a-7cf0-4919-a43b-30287ef181e9" />
<img width="1919" height="960" alt="14" src="https://github.com/user-attachments/assets/ca2599e0-8e74-4fa3-90a9-1997013508a3" />

---

## 🔍 Lab Tasks & SPL Queries

### 🔹 Task 1: Find the Top 10 Endpoints Generating Web Traffic

```spl
index=http_lab
| stats count by "id.orig_h"
| sort -count
| head 10
````

**Purpose:**
Identifies the most active client IPs generating HTTP traffic.
<img width="1919" height="961" alt="15" src="https://github.com/user-attachments/assets/e93bd239-e1aa-4e44-8c86-3c08ea63652f" />

---

### 🔹 Task 2: Count the Number of Server Errors (HTTP 5xx)

```spl
index=http_lab status_code>=500 status_code<600
| stats count as server_errors
```

**Purpose:**
Detects backend or server-side application errors.
<img width="1919" height="960" alt="16" src="https://github.com/user-attachments/assets/6d8703f2-c29b-4f05-a177-01708d406ff4" />

---

### 🔹 Task 3: Identify Suspicious / Scripted User-Agents

```spl
index=http_lab 
user_agent IN ("sqlmap/1.5.1", "curl/7.68.0", "python-requests/2.25.1", "botnet-checker/1.0")
| stats count by user_agent
```

**Purpose:**
Identifies automated tools often used for scanning, exploitation, or bot activity.
<img width="1919" height="963" alt="17" src="https://github.com/user-attachments/assets/db11f260-3b29-4932-be97-78cec8fb364a" />

---

### 🔹 Task 4: Detect Large File Transfers (> 500 KB)

```spl
index=http_lab resp_body_len>500000
| table ts "id.orig_h" "id.resp_h" uri resp_body_len
| sort -resp_body_len
```

**Purpose:**
Helps identify abnormal data transfers that may indicate data leakage or exfiltration.
<img width="1919" height="963" alt="18" src="https://github.com/user-attachments/assets/4584c2c1-dceb-4e45-8559-27d0ba358415" />

---

### 🔹 Task 5: Detect Suspicious URI Access Attempts

```spl
index=http_lab 
uri IN ("/admin","/shell.php","/etc/passwd")
| stats count by uri, "id.orig_h"
```

**Purpose:**
Detects attempts to access sensitive files, admin panels, or web shells.
<img width="1919" height="940" alt="19" src="https://github.com/user-attachments/assets/e80c1ebf-8322-4b7b-8d68-9ee7680c9232" />

---

## 🚨 Security Insights

Using this lab, you can:

* Detect malicious web reconnaissance activity
* Identify brute-force or vulnerability scanning tools
* Monitor abnormal HTTP behavior
* Spot potential data exfiltration attempts
* Build detection logic used in real SOC environments

---

## 📊 Future Enhancements

* Create Splunk alerts for:

  * Repeated HTTP 5xx errors
  * Large file transfers
  * Suspicious User-Agents
* Build dashboards for:

  * HTTP status trends
  * Top URIs and IPs
* Integrate threat intelligence feeds

---

## 🧠 Learning Outcomes

By completing this project, you have:

* Learned how to ingest and analyze HTTP logs in Splunk
* Gained hands-on experience with SPL queries
* Improved skills in web traffic monitoring and threat detection
* Strengthened SIEM and SOC analyst fundamentals

---

## ⭐ Conclusion

This project demonstrates how Splunk can be used to analyze HTTP traffic and detect security anomalies using log data. It is ideal for students and professionals pursuing careers in **Cybersecurity, SOC Analysis, and Blue Team Operations**.

---

🚀 *A strong portfolio project for cybersecurity and SIEM-focused roles.*

```



