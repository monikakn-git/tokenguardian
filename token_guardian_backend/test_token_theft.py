import requests
import time
import random
import string

BASE_URL = "http://127.0.0.1:8000"

def random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

username = f"user_{random_string()}"
password = "securepassword123"
new_password = "newpassword456"

print(f"--- Starting TokenGuardian Test for user {username} ---")

# 1. Register
print("\n[1] Registering user...")
res = requests.post(f"{BASE_URL}/api/auth/register", json={"username": username, "password": password})
print("Register:", res.status_code, res.json())

# 2. Login (Device 1)
print("\n[2] Logging in from IP 192.168.1.5 (Device 1)...")
headers_dev1 = {
    "X-Forwarded-For": "192.168.1.5",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
}
res = requests.post(f"{BASE_URL}/api/auth/login", data={"username": username, "password": password}, headers=headers_dev1)
print("Login:", res.status_code)
token1 = res.json().get("access_token")
auth_headers1 = {"Authorization": f"Bearer {token1}", **headers_dev1}

# 3. Access Protected Route (Device 1)
print("\n[3] Accessing /api/tokens/me with Token 1 from Device 1...")
res = requests.get(f"{BASE_URL}/api/tokens/me", headers=auth_headers1)
print("Access:", res.status_code, res.json())

# 4. Hacker Steals Token and uses from different IP/Device
print("\n[4] HACKER ALERT: Accessing /api/tokens/me with Token 1 from Moscow IP (185.20.12.5)...")
headers_hacker = {
    "X-Forwarded-For": "185.20.12.5",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15"
}
auth_headers_hacker = {"Authorization": f"Bearer {token1}", **headers_hacker}
res = requests.get(f"{BASE_URL}/api/tokens/me", headers=auth_headers_hacker)
print("Hacker Access (Expect 403 Forbidden due to high risk):", res.status_code, res.json())

# 5. Check Alerts
print("\n[5] Checking Security Alerts...")
res = requests.get(f"{BASE_URL}/api/tokens/alerts", headers=auth_headers1)
# Note: token1 might be revoked now if the risk was high enough (e.g. > 70).
# Let's see if the legitimate user can still use it.
print("Alerts (Token1):", res.status_code, res.json())

# 6. User Logs in again (Device 1) and resets password
print("\n[6] User logs in again to reset password...")
res = requests.post(f"{BASE_URL}/api/auth/login", data={"username": username, "password": password}, headers=headers_dev1)
token2 = res.json().get("access_token")
auth_headers2 = {"Authorization": f"Bearer {token2}", **headers_dev1}

print("Resetting password...")
res = requests.post(
    f"{BASE_URL}/api/auth/reset-password",
    json={"old_password": password, "new_password": new_password},
    headers=auth_headers2
)
print("Reset Password:", res.status_code, res.json())

# 7. Try using Token 2 again (should be revoked)
print("\n[7] Try using Token 2 after password reset (should be blocked)...")
res = requests.get(f"{BASE_URL}/api/tokens/me", headers=auth_headers2)
print("Access after reset:", res.status_code, res.json())
