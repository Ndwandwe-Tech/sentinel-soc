# 🛡️ Sentinel SOC Platform

**Security Operations Center (SOC) Monitoring & Incident Response System**

🔗 **Live Demo:** https://sentinel-soc-e2w6.vercel.app/

---

## 🎯 Overview

Sentinel SOC is a web-based Security Operations Center platform designed to monitor security alerts, manage incidents, and support SOC analysts in detecting, analyzing, and responding to threats. The system simulates a real-world SOC environment with alert tracking, severity classification, and incident response workflows.

The platform provides a centralized dashboard for monitoring security events and managing incident response activities.

---

## 🚀 Features

* 🛡️ Security alert monitoring
* 🚨 Incident creation & tracking
* ⚠️ Severity levels (Low, Medium, High, Critical)
* 👨‍💻 SOC analyst dashboard
* 📊 Incident status tracking
* 🔐 Secure authentication
* 🧠 Threat detection workflow
* 📅 Timestamped alerts
* 📁 Incident lifecycle management
* 🔎 Search & filter incidents
* 👥 Analyst assignment

---

## 🧩 SOC Workflow

1. Security alert generated
2. Alert logged in system
3. Severity level assigned
4. SOC analyst investigates
5. Incident response initiated
6. Incident resolved
7. Case closed

---

## 🛠️ Technology Stack

### Frontend

* React / TypeScript
* HTML5
* CSS3
* Tailwind CSS

### Backend / Cloud

* Firebase Authentication
* Firestore Database
* Firebase Hosting

### Security Design

* Role-based access control
* Incident lifecycle tracking
* Secure authentication
* Cloud-based logging

---

## 📂 Project Structure

```
sentinel-soc/
│
├── src/
│   ├── components/
│   ├── pages/
│   ├── firebase.ts
│   ├── dashboard.tsx
│   ├── alerts.ts
│   └── auth.ts
│
├── public/
├── package.json
└── README.md
```

---

## 🔐 Authentication

The system includes secure authentication:

* SOC analyst login
* User registration
* Protected dashboard access
* Session-based authentication

---

## 🔒 Security

The platform implements strict **Firestore Security Rules**:

* Authentication required
* Role-based access control
* Analyst-only dashboard access
* Admin incident management permissions
* Data validation for alerts
* Protected routes

---

## 🚨 Alert Fields

Each security alert contains:

* Alert ID
* Alert Title
* Description
* Severity
* Status
* Created Date
* Assigned Analyst
* Incident Notes
* Source
* Last Updated

---

## 📊 Incident Lifecycle

New → Investigating → Contained → Resolved → Closed

---

## ⚙️ Installation

Clone repository

```
git clone https://github.com/Lindamkhatshwa/sentinel-soc.git
```

Navigate to project

```
cd sentinel-soc
```

Install dependencies

```
npm install
```

Run project

```
npm run dev
```

---

## 🔥 Firebase Setup

Enable Authentication:

* Email/Password

Create Firestore collection:

```
alerts
```

Example fields:

* title
* description
* severity
* status
* assignedTo
* createdAt

---

## 🎯 Use Cases

* Security Operations Center (SOC)
* Incident response simulation
* Threat monitoring dashboard
* Cybersecurity portfolio project
* SIEM-style alert management
* SOC analyst training platform

---

## 📌 Future Improvements

* MITRE ATT&CK mapping
* SIEM integration
* Email alert notifications
* Threat intelligence feed
* Analyst activity logs
* Dashboard analytics
* Multi-tenant SOC

---

## 👨‍💻 Author

Linda Bonginkosi Mkhatshwa
IT Support Technician | Cybersecurity Analyst | AI Developer

GitHub
https://github.com/Lindamkhatshwa

---

## 📄 License

This project is developed for portfolio and educational purposes.
