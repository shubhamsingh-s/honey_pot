import os
import re
import requests
from datetime import datetime
from typing import Dict, List

from fastapi import FastAPI, Request, Header
from fastapi.responses import JSONResponse
import google.generativeai as genai
import uvicorn

# ======================================================
# CONFIG
# ======================================================
API_KEY = os.getenv("API_KEY", "honeypot-secret-123")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# Gemini setup (safe if key missing)
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel("gemini-1.5-flash")
else:
    model = None

app = FastAPI(title="Agentic Honeypot API", version="1.0.0")

# ======================================================
# IN-MEMORY STORES
# ======================================================
SESSION_MEMORY: Dict[str, List[str]] = {}
CALLBACK_SENT = set()

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
# UTILITY FUNCTIONS
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
# CONFIDENCE SCORE (EXPLAINABLE)
# ======================================================
def calculate_confidence_score(intelligence: dict, scam_type: str, message_count: int) -> float:
    score = 0.0

    score += min(len(intelligence.get("suspiciousKeywords", [])) * 0.1, 0.4)

    if scam_type != "UNKNOWN":
        score += 0.2

    if intelligence.get("phishingLinks"):
        score += 0.15

    if intelligence.get("phoneNumbers"):
        score += 0.1

    if intelligence.get("upiIds"):
        score += 0.15

    if message_count >= 4:
        score += 0.1

    return round(min(score, 1.0), 2)

# ======================================================
# LANGUAGE DETECTION
# ======================================================
def detect_language_style(text: str) -> str:
    if re.search(r'[\u0900-\u097F]', text):
        return "HINDI"
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

Rules:
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
    return " | ".join(history[-4:])

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
# GUVI CALLBACK
# ======================================================
def send_guvi_callback(session_id: str, total_messages: int, intelligence: dict, scam_type: str):
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": {
            "bankAccounts": [],
            "upiIds": intelligence.get("upiIds", []),
            "phishingLinks": intelligence.get("phishingLinks", []),
            "phoneNumbers": intelligence.get("phoneNumbers", []),
            "suspiciousKeywords": intelligence.get("suspiciousKeywords", [])
        },
        "agentNotes": f"Detected scam type: {scam_type}"
    }
    try:
        resp = requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            timeout=5,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code >= 400:
            msg = f"[GUVI CALLBACK ERROR] status={resp.status_code} body={resp.text}\n"
            print(msg)
            try:
                with open("guvi_callback.log", "a", encoding="utf-8") as f:
                    f.write(f"{datetime.utcnow().isoformat()} - {msg}")
            except Exception:
                pass
    except Exception as e:
        msg = f"[GUVI CALLBACK EXCEPTION] {e}\n"
        print(msg)
        try:
            with open("guvi_callback.log", "a", encoding="utf-8") as f:
                f.write(f"{datetime.utcnow().isoformat()} - {msg}")
        except Exception:
            pass

# ======================================================
# ROUTES
# ======================================================
@app.api_route("/", methods=["GET", "POST", "HEAD"])
async def root():
    return {
        "status": "Agentic Honeypot API running",
        "note": "Use POST /honeypot for scam detection"
    }

@app.post("/honeypot")
async def honeypot(request: Request, x_api_key: str = Header(None)):
    try:
        if x_api_key != API_KEY:
            return JSONResponse(
                status_code=200,
                content={"status": "error", "message": "Invalid API key"}
            )

        try:
            body = await request.json()
        except Exception:
            body = {}

        session_id = body.get("sessionId", "unknown-session")
        msg = body.get("message", {})
        text = msg.get("text", "") or ""

        SESSION_MEMORY.setdefault(session_id, [])
        SESSION_MEMORY[session_id].append(f"Scammer: {text}")

        is_scam, _ = detect_scam(text)
        scam_type = classify_scam_type(text)
        intelligence = extract_intelligence(text)

        confidence_score = calculate_confidence_score(
            intelligence=intelligence,
            scam_type=scam_type,
            message_count=len(SESSION_MEMORY.get(session_id, []))
        )

        agent_reply = None
        if is_scam:
            agent_reply = gemini_reply(session_id, text)
            SESSION_MEMORY[session_id].append(f"User: {agent_reply}")

        if (
            is_scam
            and session_id not in CALLBACK_SENT
            and len(SESSION_MEMORY.get(session_id, [])) >= 4
        ):
            send_guvi_callback(
                session_id=session_id,
                total_messages=len(SESSION_MEMORY.get(session_id, [])),
                intelligence=intelligence,
                scam_type=scam_type
            )
            CALLBACK_SENT.add(session_id)

        return {
            "status": "success",
            "sessionId": session_id,
            "scamDetected": is_scam,
            "scamType": scam_type,
            "confidenceScore": confidence_score,
            "agentReply": agent_reply,
            "extractedIntelligence": intelligence
        }

    except Exception:
        return {
            "status": "success",
            "scamDetected": False,
            "scamType": "UNKNOWN",
            "confidenceScore": 0.0,
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
    port = int(os.getenv("PORT", "3000"))
    uvicorn.run(app, host="0.0.0.0", port=port)

import os
import re
import requests
from datetime import datetime
from typing import Dict, List

from fastapi import FastAPI, Request, Header
from fastapi.responses import JSONResponse
import google.generativeai as genai
import uvicorn

# ======================================================
# CONFIG
# ======================================================
API_KEY = os.getenv("API_KEY", "honeypot-secret-123")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# Gemini setup (safe if key missing)
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel("gemini-1.5-flash")
else:
    model = None

app = FastAPI(title="Agentic Honeypot API", version="1.0.0")

# ======================================================
# IN-MEMORY STORES
# ======================================================
SESSION_MEMORY: Dict[str, List[str]] = {}
CALLBACK_SENT = set()

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
# UTILITY FUNCTIONS
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
# CONFIDENCE SCORE (EXPLAINABLE)
# ======================================================
def calculate_confidence_score(intelligence: dict, scam_type: str, message_count: int) -> float:
    score = 0.0

    score += min(len(intelligence.get("suspiciousKeywords", [])) * 0.1, 0.4)

    if scam_type != "UNKNOWN":
        score += 0.2

    if intelligence.get("phishingLinks"):
        score += 0.15

    if intelligence.get("phoneNumbers"):
        score += 0.1

    if intelligence.get("upiIds"):
        score += 0.15

    if message_count >= 4:
        score += 0.1

    return round(min(score, 1.0), 2)

# ======================================================
# LANGUAGE DETECTION
# ======================================================
def detect_language_style(text: str) -> str:
    if re.search(r'[\u0900-\u097F]', text):
        return "HINDI"
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

Rules:
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
    return " | ".join(history[-4:])

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
# GUVI CALLBACK
# ======================================================
def send_guvi_callback(session_id: str, total_messages: int, intelligence: dict, scam_type: str):
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": {
            "bankAccounts": [],
            "upiIds": intelligence.get("upiIds", []),
            "phishingLinks": intelligence.get("phishingLinks", []),
            "phoneNumbers": intelligence.get("phoneNumbers", []),
            "suspiciousKeywords": intelligence.get("suspiciousKeywords", [])
        },
        "agentNotes": f"Detected scam type: {scam_type}"
    }
    try:
        requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
    except Exception:
        pass  # never crash

# ======================================================
# ROUTES
# ======================================================
@app.api_route("/", methods=["GET", "POST", "HEAD"])
async def root():
    return {
        "status": "Agentic Honeypot API running",
        "note": "Use POST /honeypot for scam detection"
    }

@app.post("/honeypot")
async def honeypot(request: Request, x_api_key: str = Header(None)):
    try:
        if x_api_key != API_KEY:
            return JSONResponse(
                status_code=200,
                content={"status": "error", "message": "Invalid API key"}
            )

        try:
            body = await request.json()
        except Exception:
            body = {}

        session_id = body.get("sessionId", "unknown-session")
        msg = body.get("message", {})
        text = msg.get("text", "") or ""

        SESSION_MEMORY.setdefault(session_id, [])
        SESSION_MEMORY[session_id].append(f"Scammer: {text}")

        is_scam, _ = detect_scam(text)
        scam_type = classify_scam_type(text)
        intelligence = extract_intelligence(text)

        confidence_score = calculate_confidence_score(
            intelligence=intelligence,
            scam_type=scam_type,
            message_count=len(SESSION_MEMORY.get(session_id, []))
        )

        agent_reply = None
        if is_scam:
            agent_reply = gemini_reply(session_id, text)
            SESSION_MEMORY[session_id].append(f"User: {agent_reply}")

        if (
            is_scam
            and session_id not in CALLBACK_SENT
            and len(SESSION_MEMORY.get(session_id, [])) >= 4
        ):
            send_guvi_callback(
                session_id=session_id,
                total_messages=len(SESSION_MEMORY.get(session_id, [])),
                intelligence=intelligence,
                scam_type=scam_type
            )
            CALLBACK_SENT.add(session_id)

        return {
            "status": "success",
            "sessionId": session_id,
            "scamDetected": is_scam,
            "scamType": scam_type,
            "confidenceScore": confidence_score,
            "agentReply": agent_reply,
            "extractedIntelligence": intelligence
        }

    except Exception:
        return {
            "status": "success",
            "scamDetected": False,
            "scamType": "UNKNOWN",
            "confidenceScore": 0.0,
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
