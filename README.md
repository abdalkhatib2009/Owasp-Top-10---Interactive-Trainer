# OWASP Top 10 – Advanced Interactive Trainer (Flask)

An advanced, interactive **OWASP Top 10 learning simulator** built entirely with **Flask** and **vanilla HTML/JS**, designed to make each security concept intuitive and easy to understand through **real-world scenarios**, **hands-on simulations**, and **quizzes**.
<img width="1633" height="762" alt="image" src="https://github.com/user-attachments/assets/60fec013-8c91-4e72-a842-f5f3407cb6c7" />

---

## 🚀 Features

### 🧠 Comprehensive Coverage
- Covers all **OWASP Top 10 (2021)** vulnerabilities: A01–A10
- Each topic includes:
  - **Learn tab**: real-life scenario + goals + animated risk visualization
  - **Simulate tab**: interactive exercises demonstrating the concept safely
  - **Quiz tab**: short self-assessment with automatic scoring

### 🎮 Fully Interactive
- 100% **client-side** interaction; no external API calls or data persistence needed
- **Progress tracking** (via browser localStorage)
- Instant visual feedback on every action (risk meters, highlights, color-coded results)
- **Reset Progress** option to restart anytime

### 🌍 Real-life Scenarios (Simplified & Safe)
Each OWASP item is explained through an engaging and realistic example:
- **A01** Broken Access Control → Direct URL bypass & IDOR examples
- **A02** Cryptographic Failures → Password storage and encryption demo
- **A03** Injection → SQL & HTML encoding simulation
- **A04** Insecure Design → Recovery flow abuse
- **A05** Security Misconfiguration → Config audit simulation
- **A06** Vulnerable Components → CVE scanner (demo)
- **A07** Authentication Failures → MFA & lockout simulation
- **A08** Integrity Failures → Unsigned package supply chain example
- **A09** Logging Failures → Incident detection demo
- **A10** SSRF → URL allowlist/denylist simulation

### 🧩 Architecture
| Component | Description |
|------------|-------------|
| **Flask Backend** | Serves the single-page web app (no DB required) |
| **HTML + JS Frontend** | Handles all interaction, simulations, and scoring locally |
| **LocalStorage** | Stores user progress safely in the browser |

---

## ⚙️ Quick Start

```bash
git clone https://github.com/<your-username>/owasp-top10-trainer.git
cd owasp-top10-trainer
pip install flask
python app.py
```

Open your browser at:
```
http://127.0.0.1:5000
```

---

## 🧠 Educational Use Cases
- Cybersecurity classrooms & training centers
- Self-paced learner environments
- Awareness sessions for developers & non-security professionals
- Ideal for **HCT labs**, **CTF prep**, and **corporate awareness workshops**

---

## 🏆 Learning Outcomes
By completing all 10 modules, learners will be able to:
- Identify and describe OWASP Top 10 vulnerabilities
- Recognize real-world exploit paths and mitigations
- Apply preventive coding & configuration practices
- Demonstrate comprehension through hands-on simulations and quizzes

---

## 🧑‍💻 Developer Info
**Author:** Abdallah Alkhatib  
**Role:** Cybersecurity Instructor & Developer  
**Institution:** Higher Colleges of Technology – Abu Dhabi Campus

---

## 📜 License
This project is provided under the **MIT License**. You may freely reuse, modify, and distribute it for educational or training purposes.

---

### 💡 Future Enhancements
- Certificate of Completion export (PDF)
- Leaderboard & analytics dashboard
- Integration with real security labs (e.g., DVWA, Juice Shop, HackTheBox EDU)

---

**Interactive, visual, and educational — making OWASP learning fun and effective!**
