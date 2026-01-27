from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict
import re
import random

app = FastAPI()

API_KEY = "honeypot-secret-123"   # same key jo GUVI me dala hai

# ------------------ Models ------------------

class Message(BaseModel):
    sender: str
    text: str
    timestamp: str

class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[Dict]] = []

class Intelligence(BaseModel):
    upiIds: List[str] = []
    phishingLinks: List[str] = []
    phoneNumbers: List[str] = []
    suspiciousKeywords: List[str] = []

class HoneypotResponse(BaseModel):
    status: str
    scamDetected: bool
    agentReply: Optional[str]
    extractedIntelligence: Intelligence

# ------------------ Logic ------------------

SCAM_KEYWORDS = ["blocked", "verify", "urgent", "kyc", "otp", "bank"]

def detect_scam(text: str):
    found = [k for k in SCAM_KEYWORDS if k in text.lower()]
    return len(found) > 0, found

def extract_intel(text: str) -> Intelligence:
    return Intelligence(
        upiIds=re.findall(r"\w+@\w+", text),
        phishingLinks=re.findall(r"https?://\S+", text),
        phoneNumbers=re.findall(r"\+91\d{10}", text),
        suspiciousKeywords=[k for k in SCAM_KEYWORDS if k in text.lower()]
    )

AGENT_REPLIES = [
    "Why my account blocked?",
    "I am confused, please explain",
    "Is this really from bank?",
    "Please wait, network issue"
]

# ------------------ Routes ------------------

@app.get("/")
def root():
    return {"status": "Agentic Honeypot API running"}

@app.get("/honeypot")
def honeypot_check():
    return {"status": "honeypot endpoint reachable"}

@app.post("/honeypot", response_model=HoneypotResponse)
def honeypot(
    data: HoneypotRequest,
    x_api_key: Optional[str] = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    scam, _ = detect_scam(data.message.text)
    intel = extract_intel(data.message.text)

    reply = random.choice(AGENT_REPLIES) if scam else None

    return HoneypotResponse(
        status="success",
        scamDetected=scam,
        agentReply=reply,
        extractedIntelligence=intel
    )
