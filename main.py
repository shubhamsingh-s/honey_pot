import os
import re
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import uvicorn

import google.generativeai as genai

# =========================
# Environment variables
# =========================
API_KEY = os.getenv("API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY not set")

genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel("gemini-1.5-flash")

# =========================
# FastAPI app
# =========================
app = FastAPI(
    title="Agentic Honeypot API",
    description="Autonomous scam-engagement honeypot for intelligence extraction",
    version="1.0.0"
)

# =========================
# Data Models
# =========================
class MessageData(BaseModel):
    sender: str
    text: str
    timestamp: Optional[str] = None

class HoneypotRequest(BaseModel):
    sessionId: str
    message: MessageData
    conversationHistory: Optional[List[Dict[str, Any]]] = None

class Intelligence(BaseModel):
    upiIds: List[str]
    phishingLinks: List[str]
    phoneNumbers: List[str]
    suspiciousKeywords: List[str]

class HoneypotResponse(BaseModel):
    status: str
    scamDetected: bool
    agentReply: Optional[str]
    extractedIntelligence: Intelligence

# =========================
# Scam detection
# =========================
SCAM_KEYWORDS = [
    "blocked", "verify", "urgent", "kyc", "upi", "refund",
    "lottery", "winner", "bank", "click", "suspend", "expire"
]

def detect_scam(text: str):
    text_l = text.lower()
    found = [k for k in SCAM_KEYWORDS if k in text_l]
    return len(found) > 0, found

# =========================
# Intelligence extraction
# =========================
def extract_intelligence(text: str) -> Intelligence:
    upi = re.findall(r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}", text)
    urls = re.findall(r"https?://[^\s]+", text)
    phones = re.findall(r"(?:\+91[\-\s]?)?[6-9]\d{9}", text)
    _, keywords = detect_scam(text)

    return Intelligence(
        upiIds=list(set(upi)),
        phishingLinks=list(set(urls)),
        phoneNumbers=list(set(phones)),
        suspiciousKeywords=keywords
    )

# =========================
# Gemini agent
# =========================
SYSTEM_PROMPT = """
You are an AI honeypot persona.
Behave like a cautious, slightly confused Indian user.
Never reveal you are AI.
Never mention scam or fraud.
Do NOT provide OTP, PIN, or money.
Ask simple questions to make the sender explain more.
Keep replies short and human-like.
"""

def generate_agent_reply(user_text: str) -> str:
    prompt = f"{SYSTEM_PROMPT}\nMessage received:\n{user_text}\nReply:"
    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception:
        return "I am confused. Can you please explain slowly?"

# =========================
# API endpoint
# =========================
@app.post("/honeypot", response_model=HoneypotResponse)
async def honeypot(
    request: HoneypotRequest,
    x_api_key: Optional[str] = Header(None)
):
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    is_scam, _ = detect_scam(request.message.text)
    intel = extract_intelligence(request.message.text)

    reply = generate_agent_reply(request.message.text) if is_scam else None

    return HoneypotResponse(
        status="success",
        scamDetected=is_scam,
        agentReply=reply,
        extractedIntelligence=intel
    )

# =========================
# Health check
# =========================
@app.get("/")
def root():
    return {"status": "Agentic Honeypot API running"}

# =========================
# Local run
# =========================
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=3000)
