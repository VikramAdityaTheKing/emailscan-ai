import os
import re
from dotenv import load_dotenv
import requests

load_dotenv()

CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
TENANT_ID = os.getenv("AZURE_TENANT_ID")
REDIRECT_URI = os.getenv("AZURE_REDIRECT_URI")

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["Mail.ReadWrite", "People.Read"]
GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0"

class OutlookReader:
    def __init__(self):
        self.token = None
    
    def get_auth_url(self):
        """Generate the login URL for user consent"""
        auth_url = f"{AUTHORITY}/oauth2/v2.0/authorize"
        params = {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "scope": " ".join(SCOPES),
            "redirect_uri": REDIRECT_URI,
            "response_mode": "query",
            "prompt": "select_account"
        }
        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        return f"{auth_url}?{query_string}"
    
    def get_token_from_code(self, code):
        """Exchange auth code for access token"""
        token_url = f"{AUTHORITY}/oauth2/v2.0/token"
        data = {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code",
            "scope": " ".join(SCOPES)
        }
        
        response = requests.post(token_url, data=data)
        if response.status_code == 200:
            self.token = response.json()["access_token"]
            return self.token
        else:
            raise Exception(f"Failed to get token: {response.text}")

    def get_emails(self, limit=10, since=None, until=None):
        """Fetch recent emails from Outlook inbox"""
        if not self.token:
            raise Exception("No token. User must authenticate first.")

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Prefer": 'outlook.body-content-type="text"'
        }

        url = f"{GRAPH_ENDPOINT}/me/mailFolders/inbox/messages"
        params = {
            "$top": limit if not (since or until) else 100,
            "$orderby": "receivedDateTime desc",
            "$select": "id,from,subject,bodyPreview,body,receivedDateTime,isRead,webLink,internetMessageHeaders"
        }

        filter_parts = []
        if since:
            filter_parts.append(f"receivedDateTime ge {since}")
        if until:
            filter_parts.append(f"receivedDateTime le {until}")
        if filter_parts:
            params["$filter"] = " and ".join(filter_parts)

        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            emails = response.json().get("value", [])
            return [self._parse_email(email) for email in emails]
        else:
            raise Exception(f"Failed to fetch emails: {response.text}")

    def get_relationship_known(self, email_address):
        """Work IQ signal: does the user have an established relationship 
        with this sender, per Graph's People relevance ranking?"""
        if not self.token or not email_address:
            return None
        headers = {"Authorization": f"Bearer {self.token}"}
        url = f"{GRAPH_ENDPOINT}/me/people"
        params = {"$search": f'"{email_address}"', "$top": 1}
        try:
            response = requests.get(url, headers=headers, params=params, timeout=5)
            if response.status_code == 200:
                results = response.json().get("value", [])
                if not results:
                    return False
                scored = results[0].get("scoredEmailAddresses", [])
                return any(e.get("address", "").lower() == email_address.lower() for e in scored)
        except Exception:
            pass
        return None  # lookup failed - don't penalize on uncertainty
    
    def get_junk_emails(self, limit=20, since=None, until=None):
        """Fetch emails from the Junk Email folder for the folder-placement check"""
        if not self.token:
            raise Exception("No token. User must authenticate first.")

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Prefer": 'outlook.body-content-type="text"'
        }

        url = f"{GRAPH_ENDPOINT}/me/mailFolders/junkemail/messages"
        params = {
            "$top": limit,
            "$orderby": "receivedDateTime desc",
            "$select": "id,from,subject,bodyPreview,body,receivedDateTime,isRead,webLink,internetMessageHeaders"
        }

        filter_parts = []
        if since:
            filter_parts.append(f"receivedDateTime ge {since}")
        if until:
            filter_parts.append(f"receivedDateTime le {until}")
        if filter_parts:
            params["$filter"] = " and ".join(filter_parts)

        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            emails = response.json().get("value", [])
            return [self._parse_email(email) for email in emails]
        else:
            # Don't fail the whole digest if Junk folder is empty/inaccessible
            return []

    def _parse_email(self, email):
        """Parse email data"""
        headers_list = email.get("internetMessageHeaders") or []
        list_unsubscribe = ""
        list_unsubscribe_post = ""
        for h in headers_list:
            name = h.get("name", "").lower()
            if name == "list-unsubscribe":
                list_unsubscribe = h.get("value", "")
            elif name == "list-unsubscribe-post":
                list_unsubscribe_post = h.get("value", "")

        unsubscribe_url = ""
        unsubscribe_one_click = False
        url_match = re.search(r"<(https?://[^>]+)>", list_unsubscribe)
        if url_match:
            unsubscribe_url = url_match.group(1)
            unsubscribe_one_click = "one-click" in list_unsubscribe_post.lower()

        return {
            "id": email.get("id"),
            "from": email.get("from", {}).get("emailAddress", {}).get("address", "Unknown"),
            "from_name": email.get("from", {}).get("emailAddress", {}).get("name", "Unknown"),
            "subject": email.get("subject", "No Subject"),
            "preview": email.get("bodyPreview", ""),
            "body": email.get("body", {}).get("content", ""),
            "received": email.get("receivedDateTime", ""),
            "web_link": email.get("webLink", ""),
            "is_read": email.get("isRead", False),
            "unsubscribe_url": unsubscribe_url,
            "unsubscribe_one_click": unsubscribe_one_click
        }

    def move_message(self, message_id, destination):
        """Move a message to another well-known folder (e.g. 'junkemail' or 'deleteditems').
        Used for the Report and Delete actions in the UI."""
        if not self.token:
            raise Exception("No token. User must authenticate first.")

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

        url = f"{GRAPH_ENDPOINT}/me/messages/{message_id}/move"
        payload = {"destinationId": destination}

        response = requests.post(url, headers=headers, json=payload)

        if response.status_code in (200, 201):
            return True
        else:
            raise Exception(f"Failed to move message: {response.text}")

    def unsubscribe(self, url, one_click=False):
        """Attempt to unsubscribe via the email's List-Unsubscribe URL.
        Uses RFC 8058 one-click POST when the sender supports it
        (List-Unsubscribe-Post: List-Unsubscribe=One-Click), otherwise
        falls back to a plain GET on the unsubscribe URL."""
        try:
            if one_click:
                response = requests.post(
                    url,
                    data="List-Unsubscribe=One-Click",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=10
                )
            else:
                response = requests.get(url, timeout=10)
            return 200 <= response.status_code < 300
        except Exception:
            return False