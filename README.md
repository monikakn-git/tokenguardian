# TokenGuardian 🛡️

A proactive phishing and social engineering defense system built for the Google Hackathon.

**Frontend:** https://github.com/monikakn-git/tokenguardian/tree/main/frontend

## Architecture

```
┌─────────────────────────┐    ┌──────────────────────┐
│   React 19 + Vite       │    │ FastAPI + Uvicorn    │
│   Frontend              │    │ Backend              │
│   (Port 5175)           │◄──►│ (Port 8000)          │
│                         │    │                      │
│ - Dashboard Stats       │    │ - /api/analyze       │
│ - Content Analyzer      │    │ - /api/stats         │
│ - Threat Map (D3)       │    │ - /api/history       │
│ - Scan History          │    │ - /api/graph         │
│ - IP Session Security   │    │ - Rate Limiting      │
└─────────────────────────┘    └──────────────────────┘
         │                              │
         └──────────────────────────────┘
              Firestore (GCP)
```

## Features

- **Real-time Phishing Analysis**: Analyze URLs, emails, and messages for phishing indicators
- **Rule-based Scoring**: Heuristic-driven threat detection (keywords, URLs, urgency patterns)
- **Adaptive Detection**: Uses Google Gemini AI fallback when available
- **Risk Scoring**: 0-100 score with color-coded risk levels (LOW/MEDIUM/HIGH)
- **Session Security**: IP-based session tracking with rate limiting (40 req/min)
- **User Blocking**: Temporary blocking of abusive IPs/sessions (1 hour)
- **Analysis History**: Full scan history with timestamps and verdicts
- **Threat Visualization**: D3-based force graph for network threat mapping
- **Offline Mode**: Graceful degradation with safe error handling
- **Mobile Responsive**: Modern UI with Tailwind CSS

## Quick Start

### Prerequisites
- Docker and Docker Compose
- Node.js 18+ (for local development)
- Python 3.11+ (for local development)

### Run with Docker Compose

1. Clone the repository
2. Navigate to the project root
3. Run the application:

```bash
docker-compose up --build
```

4. Open your browser to `http://localhost:5173`

### Local Development

#### Backend
```bash
cd token_guardian_backend
pip install -r requirements.txt
uvicorn main:app --reload
```

#### Frontend
```bash
cd frontend
npm install
npm run dev
```

## API Endpoints

### POST /api/analyze
Analyze content for phishing risk.

**Request:**
```json
{
  "content": "Check out this urgent offer: http://bit.ly/fakebank",
  "content_type": "message"
}
```

**Response:**
```json
{
  "score": 85.0,
  "explanation": "Shortened URL detected: http://bit.ly/fakebank; Urgency keyword detected: 'urgent'",
  "risk_level": "high"
}
```

### GET /api/health
Health check endpoint.

### GET /api/stats
Get system statistics.

**Response:**
```json
{
  "total_scans": 42,
  "phishing_detected": 12,
  "safe_count": 30
}
```

### GET /api/history
Get recent analysis history.

## Demo Usage

1. **Paste Content**: Enter a suspicious URL, email text, or message in the input field
2. **Analyze**: Click the "Analyze" button to get instant risk assessment
3. **View Results**: See the risk score, color-coded indicator, and detailed explanation
4. **Check History**: View your last 5 analyses in the history panel
5. **Admin Stats**: Switch to the "Admin Stats" tab to see live system statistics

### Example Test Cases

- **Safe**: "Hello, how are you today?"
- **Suspicious**: "URGENT: Your account will be suspended! Click here: http://bit.ly/login"
- **High Risk**: "Verify your bank details immediately at https://secure-bank-login.com"

## Configuration

### Environment Variables

Create a `.env` file in the backend directory:

```env
PROJECT_NAME=TokenGuardian
SECRET_KEY=your_secret_key_here
DATABASE_URL=sqlite:///./sql_app.db
GEMINI_API_KEY=your_gemini_api_key_here  # Optional
```

### Google Cloud Deployment

1. Set up Google Cloud Project
2. Enable Cloud Build and Cloud Run APIs
3. Create a build trigger with the `cloudbuild.yaml`
4. Set the `_GEMINI_API_KEY` substitution variable
5. Deploy!

## Tech Stack

- **Backend**: FastAPI, SQLAlchemy, Google Generative AI
- **Frontend**: React, Tailwind CSS, Axios
- **Database**: SQLite (easily replaceable with PostgreSQL/MySQL)
- **Deployment**: Docker, Docker Compose, Google Cloud Run

## Security Features

- CORS protection
- Input validation
- Secure API design
- Proactive threat detection
- AI-enhanced analysis with fallback to rules

## Contributing

This is a hackathon project! Feel free to enhance with:
- More sophisticated ML models
- Additional threat detection rules
- User authentication
- Real-time alerts
- Integration with security tools

---

Built with ❤️ for Google Hackathon 2026