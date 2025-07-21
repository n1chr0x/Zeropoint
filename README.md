# ZeroPoint.ps1

> ⚠ A defensive PowerShell utility to detect and mitigate exploitation of the *CVE-2025-53770* zero-day vulnerability in *Microsoft SharePoint Server*.


---

## 🔍 What it Does

This PowerShell script is designed to:

- Detect compromise indicators, such as suspicious .aspx webshells
- Parse ULS logs to identify deserialization/spoofing activity
- Verify critical security settings like AMSI and Microsoft Defender
- Provide *optional emergency mitigation* to disconnect external interfaces

---

## 🚨 CVE Details

- *CVE:* CVE-2025-53770  
- *Type:* Remote Code Execution (RCE)  
- *CVSS Score:* 9.8 (Critical)  
- *Affected:* Microsoft SharePoint Server (on-premises)  
- *Status:* Zero-day *actively exploited*, no official patch at time of script release  

---

## 👨‍💻 Authors

- @n1chr0x
- @BlackRazer67

---

## 🧰 Usage

### 🔸 Run the script on your SharePoint server:

1. Open *PowerShell as Administrator*
2. Navigate to the script directory.
3. Run "powershell -ep bypass"
4. Run the script ".\ZeroPoint.ps1"

## ✨ Features

- Clean CLI output
- Easily auditable
- Safe for production — does *not* exploit or modify SharePoint
- Compatible with:
  - Windows Server 2016+
  - SharePoint Server 2016 / 2019 / Subscription Edition
