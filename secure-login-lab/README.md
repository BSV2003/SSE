# Secure Login System with Attack Simulation & Defense

## Overview
This project demonstrates a **secure authentication system** built using Flask. It showcases:

- Password hashing using **bcrypt**
- Simulation of a **credential stuffing attack**
- Security mechanisms:
  - Rate limiting
  - Account lockout
- **Two-Factor Authentication (2FA)** using TOTP

The project highlights how insecure systems can be exploited and how proper defenses prevent attacks.

---

## Objectives
- Implement secure login with hashed passwords
- Simulate credential stuffing attack using a wordlist
- Apply rate limiting and account lockout
- Integrate TOTP-based 2FA

---

## Tech Stack

- **Backend:** Flask (Python)
- **Database:** SQLite
- **Security:**
  - bcrypt (password hashing)
  - pyotp (2FA)
  - qrcode (QR generation)
- **Attack Simulation:** requests
- **Authenticator:** Google Authenticator
- **Dataset:** rockyou.txt

---

## Project Structure

```

secure-login-lab/
│
├── app.py
├── attack.py
├── users.db
├── requirements.txt
│
├── static/
│   └── qr.png
│
├── templates/
│   ├── login.html
│   ├── register.html
│   ├── twofa.html
│   └── dashboard.html
│
└── README.md

````

---

## Setup & Installation

### 1. Clone Repository
```bash
git clone <repo-link>
cd secure-login-lab
````

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run Application

```bash
python app.py
```

Open in browser:

```
http://127.0.0.1:5000/
```

---

## Usage

### Register

* Create a user account
* Password is securely hashed using bcrypt

### Login

* Enter credentials
* Redirects to 2FA verification

### 2FA Setup

* Scan QR using Google Authenticator
* Enter OTP to access dashboard

---

## Credential Stuffing Attack

### Prepare Wordlist

```bash
python make_small.py
```

### Run Attack Script

```bash
python attack.py
```

### Attack Logic

* Sends login requests using passwords from wordlist
* Detects success via redirect to `/2fa`
* Detects lockout via response message

---

## Results

### Before Protection

* Password cracked successfully

```
CREDENTIAL FOUND: alice / password123
```

### After Protection

* Account locked after 5 failed attempts
* Attack blocked before password discovery

```
LOCKED (rate limiting blocked us!)
```

---

## Two-Factor Authentication (2FA)

* Implemented using TOTP (pyotp)
* QR code scanned using Google Authenticator

### Behavior

* Correct OTP → Login success
* Incorrect OTP → Rejected
* Reused OTP → Rejected

---

## Security Features

* bcrypt password hashing
* Rate limiting (max 5 attempts)
* Account lockout (60 seconds)
* TOTP-based 2FA

---

## Key Learnings

* Credential stuffing attacks and risks
* Importance of hashing passwords
* Effectiveness of rate limiting & lockout
* Role of multi-factor authentication


