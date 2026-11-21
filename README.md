
# PhishGuard
## Phishing Email Detection System

**Developer:** Gollapudi Keziya  
**Organisation:** LaunchED Global  
**Domain:** Cybersecurity Internship

### Project Overview
PhishGuard is a Python-based phishing email detection application developed to identify suspicious keywords and potentially harmful website links in email messages.

### Technologies Used
- Python
- Streamlit
- Regular Expressions
- HTML and CSS
- Visual Studio Code

### Features
- Email text analysis
- Suspicious keyword detection
- URL extraction
- Suspicious URL pattern detection
- Risk score calculation
- LOW, MEDIUM and HIGH risk classification
- Security recommendations
- Scan history
- Dark navy and electric blue interface

### Risk Scoring
Risk Score = (Suspicious Keywords × 10) + (Suspicious URLs × 25)

Maximum score: 100

- 0–14: LOW RISK
- 15–44: MEDIUM RISK
- 45–100: HIGH RISK

### How to Run

1. Install Python.
2. Install dependencies:

   pip install -r requirements.txt

3. Run the application:

   streamlit run webapp.py

### Project Files
- app.py – Terminal-based phishing detection.
- webapp.py – Streamlit web application.
- requirements.txt – Required Python packages.

### Limitations
PhishGuard uses predefined rules and keyword matching. It does not use machine learning or live URL reputation checking. A low-risk result does not guarantee that an email is safe.
