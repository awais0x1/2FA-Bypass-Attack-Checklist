# 🔐 2FA Bypass Attack Checklist

A comprehensive, research-based checklist of **Two-Factor Authentication (2FA) Bypass Techniques** gathered from real-world bug bounty cases, write-ups, and field tests.  
This repository aims to help **security researchers** and **bug bounty hunters** identify common 2FA misconfigurations and bypass methods.

> ⚠️ **Disclaimer:** This repository is for educational and ethical testing purposes only.  
> Do **not** use this information for unauthorized or illegal activities.

---

## 🧭 Overview

Two-Factor Authentication (2FA) is a critical security layer — but it’s often implemented incorrectly.  
This checklist compiles **practical attack vectors** and **testing approaches** for discovering 2FA bypass vulnerabilities during penetration testing or bug bounty assessments.

---

## 🚀 Common 2FA Bypasses (Test on Every Website)

| # | Technique | Description | Impact |
|:-:|------------|--------------|---------|
| 1️⃣ | **Missing 2FA Enforcement** | After login, sensitive actions (password change, profile edit, etc.) don’t require OTP revalidation. | Account takeover without OTP |
| 2️⃣ | **Bypass via Alternate Endpoint** | OTP validation occurs only on frontend routes — backend APIs accept requests without OTP. | Full bypass of 2FA protection |
| 3️⃣ | **No Rate Limiting on OTP Attempts** | Allows brute-force on 4-6 digit OTP codes via automated tools (Burp Intruder, etc.) | OTP brute-force and unauthorized login |
| 4️⃣ | **Replay Old OTP** | OTP remains valid after successful verification or for an extended duration. | Reuse of OTP → login bypass |
| 5️⃣ | **Change 2FA Settings Without OTP** | Users can reset/change 2FA secret, phone number, or backup codes without verifying old OTP. | 2FA reset → account takeover |
| 6️⃣ | **IDOR in 2FA Recovery Flow** | Attacker can trigger OTP delivery to another user’s number/email by modifying user ID parameters. | Hijack victim OTP → unauthorized login |
| 7️⃣ | **Race Condition on OTP Verification** | Multiple concurrent OTP requests processed incorrectly, allowing bypass or desync. | OTP validation bypass |
| 8️⃣ | **Backup Code Misuse** | Backup codes not properly invalidated or generated without proper validation. | Persistent access without OTP |
| 9️⃣ | **Cross-Account 2FA Mapping** | OTP or recovery code mapped to wrong identifier (email instead of user ID). | Access to another user’s 2FA token |
| 🔟 | **Weak OTP Format** | Predictable OTPs (e.g., sequential, timestamp-based, or short validity window). | OTP guessing or timing attack |

---

## 🧩 Impact Summary

| Impact | Description |
|--------|--------------|
| 🔓 **Account Takeover** | Full access to victim’s account without OTP verification |
| 💣 **2FA Mechanism Broken** | Defeats purpose of MFA; weakens authentication system |
| 🕵️ **Cross-Account OTP Delivery** | OTP or recovery code sent to attacker’s controlled device |
| ⚙️ **2FA Reset Abuse** | Attackers reset 2FA and take control of user session |

---

## 📚 References & Inspirations

- [OWASP MFA/2FA Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- Bug bounty write-ups on 2FA bypass:
  - “How I Cracked 2FA with Simple Brute Force”
  - “Bypassing 2FA via IDOR in Recovery Flow”
  - “2FA Race Condition Exploit”
  - “2FA Brute Force on OTP Verification API”

---

## ✨ Contribute

Have you found a new 2FA bypass technique?  
Feel free to contribute!

1. Fork the repo 🍴  
2. Add your new finding (with title, description & impact)  
3. Submit a Pull Request 💡  

---

## 🧠 Maintainer

**👤 Awais**  
Security Researcher | Full-time Bug Bounty Hunter  
📫 Twitter / X: [@AwaisSec](#)  
🌐 Website: *coming soon...*

---

### ⭐ Support
If you find this checklist helpful, please consider giving it a **⭐ star** on GitHub and sharing with the community!

---

> _Stay Ethical. Stay Curious. Hack Responsibly._

