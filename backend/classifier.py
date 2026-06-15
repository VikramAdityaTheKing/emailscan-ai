import re
from typing import Dict, List

class EmailClassifier:
    def __init__(self):
        # Phishing indicators
        self.phishing_keywords = [
            "verify", "confirm", "urgent", "immediately", "act now", "click here",
            "update", "validate", "re-enter", "suspended", "locked", "unusual activity",
            "unauthorized", "confirm identity", "reset password", "authenticate", "supension", "account alert", "security notice"
        ]

        self.suspicious_domains = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".click", ".top"]

        self.impersonated_brands = [
            "paypal", "amazon", "apple", "microsoft", "google", "bank", "netflix",
            "fedex", "ups", "dhl", "coinbase", "github", "linkedin"
        ]

        # Subscription keywords
        self.subscription_keywords = [
            "unsubscribe", "newsletter", "subscription", "weekly digest", "monthly report",
            "promotional", "marketing", "offer", "deal", "discount", "sale"
        ]

        # Priority keywords
        self.priority_keywords = [
            "urgent", "important", "action required", "due date", "deadline",
            "asap", "critical", "alert", "emergency"
        ]

        # Financial / reward scam language (fake invoices, fake winnings, gift cards, etc.)
        self.scam_keywords = [
            "overdue", "invoice", "payment required", "gift card", "winner",
            "congratulations", "claim now", "reward", "non-transferable",
            "exclusive offer", "act before", "expires"
        ]

        # Terms commonly used in fake "security"/billing link domains
        self.suspicious_link_terms = [
            "secure", "verify", "confirm", "login", "account",
            "billing", "claim", "reward", "payment", "update", "alert"
        ]

    def _extract_suspicious_link(self, full_text: str):
        """Return the first link that looks suspicious, for display in the UI."""
        urls = re.findall(r"https?://[^\s\)\]\>\"']+", full_text)
        for url in urls:
            url = url.rstrip(".,;:!?")
            domain_match = re.match(r"https?://([a-zA-Z0-9.\-]+)", url)
            if domain_match:
                domain = domain_match.group(1)
                if "-" in domain and any(term in domain for term in self.suspicious_link_terms):
                    return url
        return None

    def classify(self, email: Dict) -> Dict:
        """Classify an email and return analysis"""

        subject = email.get("subject", "").lower()
        preview = email.get("preview", "").lower()
        body = email.get("body", "").lower()
        from_addr = email.get("from", "").lower()
        full_text = f"{subject} {preview}".lower()
        link_search_text = f"{body} {full_text}"
        detected_link = self._extract_suspicious_link(link_search_text)

        known_contact = email.get("known_contact")

        # Detect phishing indicators
        phishing_score = self._calculate_phishing_score(subject, from_addr, full_text)

        # Work IQ signal: no prior relationship with this sender
        if known_contact is False:
            phishing_score = min(phishing_score + 10, 100)

        # Detect subscription/promotional
        is_subscription = self._detect_subscription(subject, preview, from_addr)

        # Detect priority
        is_priority = self._detect_priority(subject, full_text)

        # Classify category
        category = self._determine_category(phishing_score, is_subscription, is_priority)

        # Only surface a one-click unsubscribe action for senders we don't flag as risky -
        # any "unsubscribe" link in a phishing/suspicious email isn't a real unsubscribe
        # mechanism and shouldn't be acted on, regardless of what headers it carries.
        if category in ("PHISHING_RISK", "SUSPICIOUS"):
            unsubscribe_url = ""
            unsubscribe_one_click = False
        else:
            unsubscribe_url = email.get("unsubscribe_url", "")
            unsubscribe_one_click = email.get("unsubscribe_one_click", False)

        return {
            "email_id": email.get("id"),
            "web_link": email.get("web_link", ""),
            "detected_link": detected_link,
            "unsubscribe_url": unsubscribe_url,
            "unsubscribe_one_click": unsubscribe_one_click,
            "subject": email.get("subject"),
            "from": email.get("from"),
            "from_name": email.get("from_name"),
            "category": category,
            "phishing_score": phishing_score,
            "is_subscription": is_subscription,
            "is_priority": is_priority,
            "indicators": self._get_indicators(subject, from_addr, full_text, phishing_score, known_contact=known_contact)
        }

    def _calculate_phishing_score(self, subject: str, from_addr: str, full_text: str) -> int:
        """Calculate phishing risk score 0-100"""
        score = 0

        # Check for urgency + action keywords (strong indicator)
        urgency_keywords = ["urgent", "immediately", "now", "asap"]
        action_keywords = ["click", "verify", "confirm", "update", "claim", "pay",
                            "login", "sign in", "renew", "activate", "redeem"]

        # Urgency in the subject, OR a deadline-style phrase anywhere in the email
        deadline_pattern = re.search(
            r"within \d+ hours?|expires? (in|within)|deadline|act now|last chance|limited time|today only",
            full_text
        )

        has_urgency = any(kw in subject for kw in urgency_keywords) or bool(deadline_pattern)
        has_action = any(kw in full_text for kw in action_keywords)

        if has_urgency and has_action:
            score += 25

        # Check for suspicious sender domain
        for domain in self.suspicious_domains:
            if domain in from_addr:
                score += 20

        # Check for brand impersonation
        for brand in self.impersonated_brands:
            if brand in subject and brand not in from_addr:
                score += 15  # Subject mentions brand but sender doesn't

        # Check for generic greeting (no personalization)
        if any(greeting in full_text for greeting in ["dear user", "dear customer", "hello there"]):
            score += 10

        # Check for phishing keyword density
        phishing_keyword_count = sum(1 for kw in self.phishing_keywords if kw in full_text)
        score += min(phishing_keyword_count * 2, 20)

        # Check for financial/reward scam language
        scam_keyword_count = sum(1 for kw in self.scam_keywords if kw in full_text)
        score += min(scam_keyword_count * 3, 15)

        # Check for suspicious patterns (URL shorteners)
        if re.search(r"http://", from_addr) or "bit.ly" in full_text or "tinyurl" in full_text:
            score += 15

        # Check for suspicious-looking link domains (hyphenated fake-brand domains)
        url_domains = re.findall(r"https?://([a-zA-Z0-9.\-]+)", full_text)
        for domain in url_domains:
            if "-" in domain and any(term in domain for term in self.suspicious_link_terms):
                score += 20
                break
        # Credential-harvesting: asks for a password alongside a sign-in/verify action
        if "password" in full_text and any(kw in full_text for kw in ["sign in", "login", "log in", "verify"]):
            score += 10

        # Fake financial/transaction fraud alert: dollar amount + dispute-style language
        financial_alert_terms = ["unauthorized", "transaction", "dispute", "charge", "card number", "cvv"]
        if re.search(r"\$[\d,]+\.\d{2}", full_text) and sum(1 for kw in financial_alert_terms if kw in full_text) >= 2:
            score += 30
        return min(score, 100)

    def _detect_subscription(self, subject: str, preview: str, from_addr: str) -> bool:
        """Detect if email is a subscription/promotional email"""
        text = f"{subject} {preview}".lower()

        # Check for unsubscribe link in preview
        if "unsubscribe" in text:
            return True

        # Check for subscription keywords
        subscription_count = sum(1 for kw in self.subscription_keywords if kw in text)
        if subscription_count >= 2:
            return True

        # Check sender patterns (newsletters, promotions)
        if any(pattern in from_addr for pattern in ["noreply", "newsletter", "promo", "marketing"]):
            return True

        return False

    def _detect_priority(self, subject: str, full_text: str) -> bool:
        """Detect if email needs priority attention"""
        combined = f"{subject} {full_text}".lower()

        priority_count = sum(1 for kw in self.priority_keywords if kw in combined)
        return priority_count >= 2

    def _determine_category(self, phishing_score: int, is_subscription: bool, is_priority: bool) -> str:
        """Determine email category"""
        if phishing_score >= 60:
            return "PHISHING_RISK"
        elif phishing_score >= 30:
            return "SUSPICIOUS"
        elif is_subscription:
            return "SUBSCRIPTION"
        elif is_priority:
            return "PRIORITY"
        else:
            return "NORMAL"

    def _get_indicators(self, subject: str, from_addr: str, full_text: str, phishing_score: int, known_contact: bool = None) -> List[str]:
        """Get list of detected indicators"""
        indicators = []

        if phishing_score >= 30:
            deadline_pattern = re.search(
                r"within \d+ hours?|expires? (in|within)|deadline|act now|last chance|limited time|today only",
                full_text
            )
            if "password" in full_text and any(kw in full_text for kw in ["sign in", "login", "log in", "verify"]):
                indicators.append("Credential-harvesting language")

            if known_contact is False:
                indicators.append("First-time sender (no relationship history — Work IQ)")
            elif known_contact is True:
                indicators.append("⚠️ Known contact — their account may be compromised (Work IQ)")

            financial_alert_terms = ["unauthorized", "transaction", "dispute", "charge", "card number", "cvv"]
            if re.search(r"\$[\d,]+\.\d{2}", full_text) and sum(1 for kw in financial_alert_terms if kw in full_text) >= 2:
                indicators.append("Fake financial/transaction alert")
            if any(kw in full_text for kw in ["urgent", "immediately", "now"]) or deadline_pattern:
                indicators.append("High urgency language")

            if any(kw in full_text for kw in ["verify", "confirm", "click", "claim", "pay", "login", "renew", "activate"]):
                indicators.append("Action-oriented language")

            for domain in self.suspicious_domains:
                if domain in from_addr:
                    indicators.append(f"Suspicious domain extension: {domain}")

            if "bit.ly" in full_text or "tinyurl" in full_text:
                indicators.append("URL shortener detected")

            url_domains = re.findall(r"https?://([a-zA-Z0-9.\-]+)", full_text)
            for domain in url_domains:
                if "-" in domain and any(term in domain for term in self.suspicious_link_terms):
                    indicators.append("Suspicious-looking link domain")
                    break

            scam_keyword_count = sum(1 for kw in self.scam_keywords if kw in full_text)
            if scam_keyword_count >= 2:
                indicators.append("Reward/payment scam language")

        if any(greeting in full_text for greeting in ["dear user", "dear customer"]):
            indicators.append("Generic greeting (no personalization)")

        return indicators
