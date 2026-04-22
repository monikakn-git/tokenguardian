# TokenGuardian Backend

TokenGuardian is a proactive cybersecurity backend designed to defend against AI-augmented social engineering and, specifically, **OAuth token theft**.

Based on the 2026 cybersecurity landscape, hackers are bypassing traditional passwords and MFA by stealing active session tokens. TokenGuardian solves this by tracking how and where tokens are used, instantly revoking them if anomalous behavior is detected.

## 🧠 Core Features Implemented

1. **Token Tracking (The Foundation)**
   - Instead of issuing standard JWTs that the server forgets about, every login generates a token with a unique ID (`jti`) that is saved into our database (`TokenFamily`).
   - Every time a user accesses a protected route in the app, the backend records the **IP Address** and **User-Agent** (device type) in a `TokenUsage` log.

2. **Anomaly Detection Engine ("Guardian Service")**
   - Every single API request goes through `services/guardian_service.py` before hitting the endpoint.
   - **Heuristics**: It checks if the current IP address or device drastically differs from the last time the token was used. 
   - **AI Scoring**: It is pre-wired to send the context switch to Google Gemini (e.g., used in New York, and 5 minutes later in Moscow) to calculate an "Impossible Travel" risk score.
   - **Auto-Revocation**: If the calculated risk is too high (>= 70), the backend automatically kills the token, issues a `SecurityAlert` to the database, and throws a `403 Forbidden` error to the hacker.

3. **The "Password Reset" Fix**
   - A major issue in modern hacks is that changing your password doesn't kick the hacker out if they already stole your token. 
   - The `/api/auth/reset-password` endpoint contains logic to look up **all active tokens** for the user and mark them as `is_revoked = True`. This instantly cuts off any attacker who might be hiding in the system.

---

## 🏗️ Architecture & Tech Stack

- **Framework**: `FastAPI` (Python) - Blazing fast, highly scalable, and excellent for AI integrations.
- **Database**: `SQLite` via `SQLAlchemy ORM` (Can be changed to PostgreSQL with zero code changes just by editing the `.env` file).
- **Authentication**: Stateless JSON Web Tokens (JWT) paired with stateful database tracking.
- **AI**: `google-generativeai` package ready to interface with Gemini 1.5 Pro.

---

## 🚀 How to Run the Backend

1. **Navigate to the backend folder**:
   Ensure you are in the `token_guardian_backend` directory in your terminal.

2. **Activate the Virtual Environment**:
   ```powershell
   .\venv\Scripts\Activate.ps1
   ```

3. **Start the Server**:
   ```powershell
   uvicorn main:app --reload --port 8000
   ```
   *The server is now running locally at `http://127.0.0.1:8000`.*

---

## 🧪 How to Test the Backend

You have two great ways to test that the backend works:

### Method 1: The Interactive Swagger UI (Manual Testing)
FastAPI automatically generates a beautiful dashboard to test your API without writing any frontend code.
1. Start the server (see above).
2. Open your web browser and go to: **http://127.0.0.1:8000/docs**
3. **Register a User**: Expand `POST /api/auth/register`, click "Try it out", enter a username and password, and click "Execute".
4. **Login**: Expand `POST /api/auth/login`, click "Try it out", enter your credentials, and execute. You'll get an `access_token`.
5. **Authorize**: Scroll to the top of the page, click the green **Authorize** button, paste your `access_token`, and click authorize. Now you can hit the protected `/api/tokens/me` route!

### Method 2: The Automated Attack Simulation (test_token_theft.py)
I wrote a Python script that acts like a real application and simulates a hacker stealing a token.

1. Ensure your server is running in one terminal.
2. Open a **second terminal** in the `token_guardian_backend` folder.
3. Run the attack simulation script:
   ```powershell
   .\venv\Scripts\python.exe test_token_theft.py
   ```

**What the script does when you run it:**
- It creates a dummy user and logs them in.
- It accesses the API normally from a local IP address.
- 🚨 **The Hack**: It fakes a request coming from an IP address in Moscow (`185.20.12.5`), using the stolen token.
- **The Defense**: You will see the backend intercept the request, flag the impossible travel anomaly, and return a `403 Forbidden` error!
- It then tests the password reset feature, proving that old tokens are instantly killed.
