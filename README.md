# ExamShield - Software Prototype

A simple educational prototype for the project:
"Cryptographically Secured Examination Content Distribution and Leak Detection System"

## Features
- Faculty/admin login
- Upload question paper
- AES-256-GCM encryption
- SHA-256 integrity hash
- Secure encrypted file storage
- Staff authentication
- Decryption and integrity verification
- Audit/access logs
- Demo suspicious-access/leak alert

## Run in VS Code

1. Open this folder in VS Code.
2. Open Terminal.
3. Create a virtual environment:
   `python -m venv venv`
4. Activate it:
   Windows:
   `venv\Scripts\activate`
5. Install:
   `pip install -r requirements.txt`
6. Start:
   `python app.py`
7. Open the local address shown by Flask, normally:
   `http://127.0.0.1:5000`

## Demo accounts
Admin: admin / admin123
Staff: staff / staff123

## Demo flow
Admin login → upload PDF → AES encrypt + SHA-256 → secure storage → logout → Staff login → decrypt & open → view logs as admin.

Note: This is a classroom prototype. Real deployment should use a proper identity provider, secure key management/HSM, HTTPS, strict exam-time policies, rate limiting, and stronger leak-prevention controls. A software system cannot reliably detect every case where a user photographs or manually shares a paper; this prototype demonstrates access monitoring and suspicious-activity alerts.
