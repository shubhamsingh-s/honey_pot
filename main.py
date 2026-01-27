import os
import re
from datetime import datetime
from typing import Dict, List

from fastapi import FastAPI, Request, Header
from fastapi.responses import JSONResponse
import google.generativeai as genai
import uvicorn

# ======================================================
# CONFIG (Environment Variables)
# ======================================================
API_KEY = os.getenv("API_KEY", "honeypot-secret-123")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# Gemini config (safe even if key missing)
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel("gemini-1.5-flash")
else:
    model = None

app = FastAPI(title="Agentic Honeypot API", version="1.0.0")

# ======================================================
# IN-MEMORY SESSION STORE (multi-turn memory)
# ======================================================
SESSION_MEMORY: Dict[str, List[str]] = {}

# ======================================================
# KEYWORDS & RULES
# ======================================================
SCAM_KEYWORDS = [
    "blocked", "verify", "urgent", "otp", "bank", "kyc",
    "upi", "refund", "click", "suspend", "lottery",
    "winner", "prize"
]

SCAM_TYPE_RULES = {
    "UPI_FRAUD": ["upi", "@", "collect"],
    "PHISHING": ["http", "https", "click"],
    "OTP_FRAUD": ["otp", "one time password"],
    "IMPERSONATION": ["bank", "customer care", "support"],
    "LOTTERY": ["lottery", "winner", "prize"]
}

# ======================================================
# UTILS
# ======================================================
def detect_scam(text: str):
    text_l = text.lower()
    found = [k for k in SCAM_KEYWORDS if k in text_l]
    return len(found) > 0, found

def classify_scam_type(text: str) -> str:
    text_l = text.lower()
    for scam_type, keys in SCAM_TYPE_RULES.items():
        if any(k in text_l for k in keys):
            return scam_type
    return "UNKNOWN"

def extract_intelligence(text: str):
    return {
        "upiIds": re.findall(r"[a-zA-Z0-9.\-_]+@[a-zA-Z]+", text),
        "phishingLinks": re.findall(r"https?://[^\s]+", text),
        "phoneNumbers": re.findall(r"(?:\+91)?[6-9]\d{9}", text),
        "suspiciousKeywords": detect_scam(text)[1]
    }

# ======================================================
# LANGUAGE DETECTION
# ======================================================
def detect_language_style(text: str) -> str:
    # Hindi (Devanagari)
    if re.search(r'[\u0900-\u097F]', text):
        return "HINDI"
    # Hinglish (common Hindi words in English letters)
    if any(w in text.lower() for w in ["kyu", "kyon", "hai", "nahi", "kya", "ka", "ke"]):
        return "HINGLISH"
    return "ENGLISH"

# ======================================================
# GEMINI SMART PERSONA
# ======================================================
SYSTEM_PROMPT = """
You are a real Indian mobile user.
You are non-technical, cautious, and slightly confused.
You do NOT know about scams, AI, police, or security.
You NEVER give OTP, PIN, passwords, or money.

Behavior rules:
- Reply in the SAME language style as the sender.
- Hindi → Hindi (Devanagari).
- Hinglish → Hinglish.
- English → Simple English.
- Ask short, human-like questions.
- Sometimes delay or hesitate.
- Never sound smart or technical.
"""

def build_memory_summary(session_id: str) -> str:
    history = SESSION_MEMORY.get(session_id, [])
    if not history:
        return "No prior conversation."
    return " | ".join(history[-4:])  # last 4 messages only

def gemini_reply(session_id: str, user_text: str) -> str:
    if not model:
        return "Samajh nahi aa raha, thoda simple batana."

    memory_summary = build_memory_summary(session_id)
    lang = detect_language_style(user_text)

    language_instruction = {
        "HINDI": "Reply ONLY in simple Hindi (Devanagari).",
        "HINGLISH": "Reply in Hinglish (Hindi words in English letters).",
        "ENGLISH": "Reply in simple English."
    }.get(lang, "Reply in Hinglish.")

    prompt = f"""
{SYSTEM_PROMPT}

Conversation summary:
{memory_summary}

Language rule:
{language_instruction}

New message:
"{user_text}"

Reply:
"""
    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception:
        return "Samajh nahi aa raha, thoda simple batana."

# ======================================================
# ROUTES
# ======================================================
@app.get("/")
def health():
    return {"status": "Agentic Honeypot API running"}

@app.post("/honeypot")
async def honeypot(request: Request, x_api_key: str = Header(None)):
    try:
        # Soft auth (never crash)
        if x_api_key != API_KEY:
            return JSONResponse(
                status_code=200,
                content={"status": "error", "message": "Invalid API key"}
            )

        # Safe JSON parsing
        try:
            body = await request.json()
        except Exception:
            body = {}

        session_id = body.get("sessionId", "unknown-session")
        msg = body.get("message", {})
        text = msg.get("text", "") or ""
        timestamp = msg.get("timestamp") or datetime.utcnow().isoformat()

        # Init session memory
        SESSION_MEMORY.setdefault(session_id, [])
        SESSION_MEMORY[session_id].append(f"Scammer: {text}")

        # Core logic
        is_scam, _ = detect_scam(text)
        scam_type = classify_scam_type(text)
        intelligence = extract_intelligence(text)

        agent_reply = None
        if is_scam:
            agent_reply = gemini_reply(session_id, text)
            SESSION_MEMORY[session_id].append(f"User: {agent_reply}")

        return {
            "status": "success",
            "sessionId": session_id,
            "scamDetected": is_scam,
            "scamType": scam_type,
            "agentReply": agent_reply,
            "extractedIntelligence": intelligence
        }

    except Exception:
        # Absolute fallback — NEVER crash
        return {
            "status": "success",
            "scamDetected": False,
            "scamType": "UNKNOWN",
            "agentReply": "Please explain again, I am not understanding.",
            "extractedIntelligence": {
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": []
            }
        }

# ======================================================
# LOCAL RUN
# ======================================================
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=3000)
