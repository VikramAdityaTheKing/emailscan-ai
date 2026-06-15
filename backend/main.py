import os
import re
import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from backend.outlook_reader import OutlookReader
from backend.classifier import EmailClassifier
from datetime import datetime, timedelta, timezone
import json

load_dotenv()

AZURE_AI_ENDPOINT = os.getenv("AZURE_AI_ENDPOINT")
AZURE_AI_KEY = os.getenv("AZURE_AI_KEY")
AZURE_AI_MODEL = os.getenv("AZURE_AI_MODEL", "Phi-4-reasoning")

app = FastAPI(title="EmailScan AI - Outlook Agent")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
outlook_reader = OutlookReader()
classifier = EmailClassifier()

# Store user tokens in memory (for demo; use Redis/DB in production)
user_tokens = {}

@app.get("/")
async def root():
    """Serve the UI"""
    return FileResponse("./ui/index.html")

@app.get("/auth/login")
async def login():
    """Start OAuth flow"""
    auth_url = outlook_reader.get_auth_url()
    return {"auth_url": auth_url}

@app.post("/api/analyze-link")
async def analyze_link(payload: dict):
    url_to_check = (payload.get("url") or "").strip()
    if not url_to_check:
        raise HTTPException(status_code=400, detail="No URL provided")

    prompt = (
        "You are a phishing-link risk analyzer. Without visiting the URL, "
        "reason step by step about its structure (domain, subdomains, TLD, "
        "brand impersonation, hyphenation, lookalike characters, path) and "
        "assess phishing risk.\n\n"
        "After your reasoning, finish your entire response with exactly this "
        "block, on its own lines, using this exact format:\n"
        "---SUMMARY---\n"
        "VERDICT: <SAFE, SUSPICIOUS, or PHISHING>\n"
        "RECOMMENDATION: <one short sentence telling the user what to do>\n\n"
        f"URL: {url_to_check}"
    )

    try:
        resp = requests.post(
            AZURE_AI_ENDPOINT,
            headers={"Authorization": f"Bearer {AZURE_AI_KEY}", "Content-Type": "application/json"},
            json={
                "model": AZURE_AI_MODEL, 
                "messages": [{"role": "user", "content": prompt}], 
                "max_tokens": 2000,
                "temperature": 0.3,             # Slightly higher temperature prevents getting stuck
                "frequency_penalty": 1.2,       # Heavily penalizes repeating the exact same words
                "presence_penalty": 1.0         # Encourages moving on to new topics
            },
            timeout=60
        )
        resp.raise_for_status()
        analysis = resp.json()["choices"][0]["message"]["content"]

        reasoning = analysis
        verdict = None
        recommendation = None

        if "---SUMMARY---" in analysis:
            reasoning_part, summary_part = analysis.split("---SUMMARY---", 1)
            reasoning = reasoning_part.strip()

            verdict_match = re.search(r"VERDICT:\s*(.+)", summary_part)
            rec_match = re.search(r"RECOMMENDATION:\s*(.+)", summary_part)
            if verdict_match:
                verdict = verdict_match.group(1).strip()
            if rec_match:
                recommendation = rec_match.group(1).strip()
                
        # --- PYTHON ANTI-LOOP FALLBACK ---
        # If the model still somehow outputs repeating sentences, strip them out purely for the UI display
        clean_sentences = []
        seen_sentences = set()
        for sentence in reasoning.split('. '):
            s_clean = sentence.strip()
            if s_clean not in seen_sentences and len(s_clean) > 0:
                clean_sentences.append(s_clean)
                seen_sentences.add(s_clean)
        
        cleaned_reasoning = '. '.join(clean_sentences)
        if not cleaned_reasoning.endswith('.'):
            cleaned_reasoning += '.'

        return {
            "url": url_to_check,
            "analysis": cleaned_reasoning,
            "verdict": verdict,
            "recommendation": recommendation
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Link analysis failed: {str(e)}")

@app.get("/auth/callback")
async def callback(code: str = None):
    """Handle OAuth callback"""
    if not code:
        raise HTTPException(status_code=400, detail="No authorization code received")
    
    try:
        token = outlook_reader.get_token_from_code(code)
        user_tokens["current_user"] = token
        
        # Redirect to dashboard
        return RedirectResponse(url="/?code=success")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
@app.get("/auth/logout")
async def logout():
    """Clear the stored token so a new account can sign in"""
    user_tokens.clear()
    return RedirectResponse(url="/")

@app.get("/api/digest")
async def get_digest(limit: int = 20, range: str = "all"):
    try:
        if "current_user" not in user_tokens:
            raise HTTPException(status_code=401, detail="Not authenticated. Call /auth/login first")

        since, until = _get_date_range(range)

        emails = outlook_reader.get_emails(limit=limit, since=since, until=until)
        classified_emails = []
        for email in emails:
            email["known_contact"] = outlook_reader.get_relationship_known(email.get("from"))
            classified_emails.append(classifier.classify(email))

        digest = _generate_digest_summary(classified_emails)

        junk_emails = outlook_reader.get_junk_emails(limit=limit, since=since, until=until)
        junk_classified = []
        for email in junk_emails:
            email["known_contact"] = outlook_reader.get_relationship_known(email.get("from"))
            junk_classified.append(classifier.classify(email))

        folder_check = _generate_folder_check(classified_emails, junk_classified)

        return {
            "timestamp": datetime.now().isoformat(),
            "total_emails": len(classified_emails),
            "digest": digest,
            "emails": classified_emails,
            "folder_check": folder_check
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/health")
async def health():
    """Health check"""
    return {"status": "ok", "service": "EmailScan AI Outlook Agent"}

@app.post("/api/email/{email_id}/report")
async def report_email(email_id: str):
    """Move an email to Junk - used as the 'Report' action in the UI"""
    if "current_user" not in user_tokens:
        raise HTTPException(status_code=401, detail="Not authenticated. Call /auth/login first")
    try:
        outlook_reader.move_message(email_id, "junkemail")
        return {"status": "ok", "action": "report", "email_id": email_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/email/{email_id}/delete")
async def delete_email(email_id: str):
    """Move an email to Deleted Items (reversible) - used as the 'Delete' action in the UI"""
    if "current_user" not in user_tokens:
        raise HTTPException(status_code=401, detail="Not authenticated. Call /auth/login first")
    try:
        outlook_reader.move_message(email_id, "deleteditems")
        return {"status": "ok", "action": "delete", "email_id": email_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/email/{email_id}/unsubscribe")
async def unsubscribe_email(email_id: str, payload: dict):
    """Unsubscribe via the email's List-Unsubscribe header (RFC 8058 one-click where supported).
    Only emails not flagged as PHISHING_RISK/SUSPICIOUS ever carry an unsubscribe_url
    (see classifier.classify), so this never acts on a flagged sender's links."""
    if "current_user" not in user_tokens:
        raise HTTPException(status_code=401, detail="Not authenticated. Call /auth/login first")

    url = (payload or {}).get("url", "").strip()
    one_click = bool((payload or {}).get("one_click", False))

    if not url:
        raise HTTPException(status_code=400, detail="No unsubscribe link available for this email")

    try:
        success = outlook_reader.unsubscribe(url, one_click=one_click)
        if not success:
            raise HTTPException(status_code=502, detail="Unsubscribe request did not succeed")
        return {"status": "ok", "action": "unsubscribe", "email_id": email_id, "one_click": one_click}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def _get_date_range(range_key: str):
    """Return (since, until) ISO 8601 strings for Graph $filter, or (None, None) for 'all'"""
    now = datetime.now(timezone.utc)

    if range_key == "today":
        since = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return since.strftime("%Y-%m-%dT%H:%M:%SZ"), None
    elif range_key == "week":
        since = now - timedelta(days=7)
        return since.strftime("%Y-%m-%dT%H:%M:%SZ"), None
    elif range_key == "lastweek":
        start_this_week = now - timedelta(days=now.weekday())
        since = start_this_week - timedelta(days=7)
        return since.strftime("%Y-%m-%dT%H:%M:%SZ"), start_this_week.strftime("%Y-%m-%dT%H:%M:%SZ")
    elif range_key == "month":
        since = now - timedelta(days=30)
        return since.strftime("%Y-%m-%dT%H:%M:%SZ"), None
    else:
        return None, None

def _generate_folder_check(inbox_emails: list, junk_emails: list) -> dict:
    """Compare classifier output to actual Outlook folder placement"""

    inbox_risky = [
        {
            "subject": e.get("subject"),
            "from": e.get("from"),
            "from_name": e.get("from_name"),
            "category": e.get("category"),
            "risk_score": e.get("phishing_score"),
            "indicators": e.get("indicators", []),
            "email_id": e.get("email_id"),
            "web_link": e.get("web_link", ""),
            "detected_link": e.get("detected_link"),
        }
        for e in inbox_emails
        if e.get("category") in ("PHISHING_RISK", "SUSPICIOUS")
    ]

    junk_legit = [
        {
            "subject": e.get("subject"),
            "from": e.get("from"),
            "from_name": e.get("from_name"),
            "category": e.get("category"),
            "risk_score": e.get("phishing_score"),
            "indicators": e.get("indicators", []),
            "email_id": e.get("email_id"),
            "web_link": e.get("web_link", ""),
            "detected_link": e.get("detected_link"),
        }
        for e in junk_emails
        if e.get("category") not in ("PHISHING_RISK", "SUSPICIOUS")
    ]

    return {
        "inbox_risky_count": len(inbox_risky),
        "inbox_risky": inbox_risky,
        "junk_legit_count": len(junk_legit),
        "junk_legit": junk_legit
    }

def _generate_digest_summary(classified_emails: list) -> dict:
    """Generate summary statistics from classified emails"""
    
    summary = {
        "phishing_risk": [],
        "suspicious": [],
        "subscriptions": [],
        "priority": [],
        "normal": []
    }
    
    for email in classified_emails:
        category = email.get("category", "NORMAL")
        
        email_summary = {
            "subject": email.get("subject"),
            "from": email.get("from"),
            "from_name": email.get("from_name"),
            "indicators": email.get("indicators", []),
            "email_id": email.get("email_id"),
            "web_link": email.get("web_link", ""),
            "detected_link": email.get("detected_link"),
            "unsubscribe_url": email.get("unsubscribe_url", ""),
            "unsubscribe_one_click": email.get("unsubscribe_one_click", False),
        }
        
        if category == "PHISHING_RISK":
            summary["phishing_risk"].append({**email_summary, "risk_score": email.get("phishing_score")})
        elif category == "SUSPICIOUS":
            summary["suspicious"].append({**email_summary, "risk_score": email.get("phishing_score")})
        elif category == "SUBSCRIPTION":
            summary["subscriptions"].append(email_summary)
        elif category == "PRIORITY":
            summary["priority"].append(email_summary)
        else:
            summary["normal"].append(email_summary)
    
    return {
        "counts": {
            "phishing_risk": len(summary["phishing_risk"]),
            "suspicious": len(summary["suspicious"]),
            "subscriptions": len(summary["subscriptions"]),
            "priority": len(summary["priority"]),
            "normal": len(summary["normal"])
        },
        "categories": summary
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3000)