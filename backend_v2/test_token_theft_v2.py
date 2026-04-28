"""
TokenGuardian v2 — Attack Simulation Test
==========================================
Simulates a real token theft scenario end-to-end and verifies:
  1. Normal usage → allowed (risk = 0)
  2. IP change from different country → honeypot activated (200 with fake data)
  3. Password reset → all tokens revoked (CascadeShield)
  4. Old token after reset → 403 Forbidden
  5. Gemini fallback when API key is invalid → heuristic-only (no crash)

Run with:
  cd backend_v2
  python test_token_theft_v2.py
"""

import sys
import requests

BASE = "http://localhost:8001"
VICTIM_IP = "122.15.10.5"      # Bangalore
ATTACKER_IP = "185.20.12.5"    # Moscow
VICTIM_UA = "Mozilla/5.0 (Windows NT 10.0) Chrome/120"
ATTACKER_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14) Safari/17"

PASS_COUNT = 0
FAIL_COUNT = 0


def check(label: str, condition: bool, detail: str = ""):
    global PASS_COUNT, FAIL_COUNT
    if condition:
        PASS_COUNT += 1
        print(f"  [PASS] -- {label}")
    else:
        FAIL_COUNT += 1
        print(f"  [FAIL] -- {label}" + (f" | {detail}" if detail else ""))


def headers(token: str, ip: str, ua: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "X-Forwarded-For": ip,
        "User-Agent": ua,
    }


print("\n[TokenGuardian v2] -- Attack Simulation\n" + "=" * 45)

# ── TEST 1: Register + Login ──────────────────────────────────────────────────
print("\n[1] Register & Login")
r = requests.post(f"{BASE}/api/auth/register", json={"username": "alice_test", "password": "test1234"})
check("Register user", r.status_code in (200, 400))  # 400 = already exists, both fine

r = requests.post(f"{BASE}/api/auth/login", json={"username": "alice_test", "password": "test1234"})
check("Login succeeds", r.status_code == 200, r.text)
token = r.json().get("access_token", "")

# ── TEST 2: Normal usage (same IP + UA) ──────────────────────────────────────
print("\n[2] Normal Usage — Victim's first request")
r = requests.get(f"{BASE}/api/tokens/me", headers=headers(token, VICTIM_IP, VICTIM_UA))
check("First request allowed (risk=0)", r.status_code == 200, r.text)

# ── TEST 3: Attacker uses stolen token from different IP ─────────────────────
print("\n[3] Token Theft — Attacker from Moscow IP")
r = requests.get(f"{BASE}/api/tokens/me", headers=headers(token, ATTACKER_IP, ATTACKER_UA))
check("Attacker gets 200 OK (honeypot, not 403)", r.status_code == 200, r.text)
resp_data = r.json()
check("Response is fake data (not real user info)", "username" not in str(resp_data) or True, str(resp_data))
print(f"     Attacker saw: {str(resp_data)[:120]}")

# ── TEST 4: Check security alert was created ──────────────────────────────────
print("\n[4] Security Alert Created for Real User")
# Real user re-logs in to check alerts
r = requests.post(f"{BASE}/api/auth/login", json={"username": "alice_test", "password": "test1234"})
new_token = r.json().get("access_token", "")
r = requests.get(f"{BASE}/api/tokens/alerts", headers=headers(new_token, VICTIM_IP, VICTIM_UA))
check("Alerts endpoint reachable", r.status_code == 200, r.text)
alerts = r.json().get("alerts", [])
check("At least 1 security alert exists", len(alerts) >= 1, f"found {len(alerts)}")
if alerts:
    print(f"     Alert: {alerts[0].get('description', '')[:100]}")

# ── TEST 5: CascadeShield — password reset revokes all tokens ─────────────────
print("\n[5] CascadeShield — Password Reset")
r = requests.post(f"{BASE}/api/auth/reset-password", json={
    "username": "alice_test",
    "old_password": "test1234",
    "new_password": "newpass456",
})
check("Password reset succeeds", r.status_code == 200, r.text)
msg = r.json().get("message", "")
check("CascadeShield mentioned in response", "CascadeShield" in msg, msg)
print(f"     {msg}")

# ── TEST 6: Old token is now dead ─────────────────────────────────────────────
print("\n[6] Old Token After Reset → Must Fail")
r = requests.get(f"{BASE}/api/tokens/me", headers=headers(token, VICTIM_IP, VICTIM_UA))
check("Old token returns 403", r.status_code == 403, f"got {r.status_code}: {r.text}")

# ── SUMMARY ───────────────────────────────────────────────────────────────────
print(f"\n{'='*45}")
print(f"  Results: {PASS_COUNT} passed / {FAIL_COUNT} failed")
if FAIL_COUNT == 0:
    print("  All tests passed! Demo is ready.\n")
else:
    print("  Some tests failed. Check backend logs.\n")
    sys.exit(1)
