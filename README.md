# SafeNet AI — AI-Powered Cybersecurity & Phishing Detection Platform

**SafeNet AI** is a proposed AI-powered cybersecurity platform designed to help users identify potentially malicious websites, phishing URLs, and suspicious online activities.

The project aims to use **Machine Learning and cybersecurity techniques** to analyze URLs, identify potentially risky patterns, generate a cybersecurity risk score, and provide simple security recommendations to users.

> 🚧 **Project Status: Initial Development**
>
> This project has just been started and is currently in the planning and initial development stage. The features described below represent the proposed functionality of the project and may change as development progresses.

---

## 🎯 Project Objective

The main objective of SafeNet AI is to develop an intelligent system that can assist users in identifying potentially dangerous URLs before they interact with them.

The system is planned to analyze different characteristics of a URL and use Machine Learning algorithms to determine whether the URL may be legitimate or potentially malicious.

The project will focus on making cybersecurity information easy to understand by providing users with a **risk score, threat level, explanation of detected risks, and security recommendations**.

---

## 💡 Planned Features

The following features are planned for future development:

### 1. 🔐 User Authentication
- User registration and login
- Secure password handling
- User session management
- Personalized scan history

### 2. 🔎 URL Analysis
Users will be able to enter a URL and analyze it for potentially suspicious characteristics.

The system may examine features such as:

- IP address-based URLs
- Use of `@` symbols
- HTTP/HTTPS protocol
- Number of subdomains
- Suspicious keywords
- Excessive hyphens
- URL length
- URL shortening services
- Other lexical and structural URL characteristics

### 3. 🤖 Machine Learning-Based Detection

A Machine Learning model will be developed to classify URLs based on their characteristics.

Possible algorithms that will be explored include:

- Random Forest
- Logistic Regression
- Other suitable classification algorithms

The model will be trained and evaluated using a phishing/malicious URL dataset.

### 4. 📊 Cybersecurity Risk Score

The system is planned to generate a **0–100 risk score** based on the analysis.

The score may be categorized into:

| Score | Risk Level |
|------:|------------|
| 0–25 | 🟢 Low |
| 26–50 | 🟡 Medium |
| 51–75 | 🟠 High |
| 76–100 | 🔴 Critical |

These ranges are currently proposed and may be modified during development.

### 5. 💬 Risk Explanation

Instead of only displaying a prediction, SafeNet AI will aim to explain the detected risks in simple language.

For example:

> "The website uses an IP address instead of a traditional domain name, which may be a suspicious characteristic."

### 6. 🛡️ Security Recommendations

Based on the detected risks, the system will provide recommendations such as:

- Avoid entering sensitive information.
- Verify the website domain.
- Avoid downloading files from suspicious websites.
- Check whether the website uses HTTPS.
- Do not provide passwords or financial information to suspicious websites.

### 7. 📈 Dashboard & Analytics

A dashboard is planned to provide information such as:

- Number of URLs scanned
- Safe and suspicious URLs
- Recent scans
- Risk score trends
- Threat-level distribution

### 8. 📝 Scan History

The system is planned to maintain a history of previously analyzed URLs so that users can review their previous scans.

---

## 🏗️ Proposed Technology Stack

### Backend
- Python
- Flask

### Machine Learning
- Scikit-learn
- Pandas
- NumPy

### Frontend
- HTML
- CSS
- JavaScript
- Bootstrap

### Database
- SQLite during development
- MySQL/PostgreSQL may be considered for production

### Development Tools
- Git & GitHub
- VS Code
- Jupyter Notebook / Google Colab (for ML experimentation)

---

## 📂 Initial Project Structure

The project structure will evolve as development progresses.

A possible structure is:

```text
SafeNetAI/
│
├── app/
│   ├── routes/
│   ├── models/
│   ├── templates/
│   ├── static/
│   └── utils/
│
├── ml/
│   ├── data/
│   ├── saved_model/
│   └── train_model.py
│
├── tests/
│
├── requirements.txt
├── config.py
├── run.py
└── README.md
