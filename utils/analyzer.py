
import re
from urllib.parse import urlparse


# ---------------------------------------------------------
# TRUSTLENS AI - RULE-BASED MESSAGE ANALYZER
# Experimental prototype; not a certified fraud detector.
# ---------------------------------------------------------

PATTERNS = {
    "Credential request": (
        r"\b(otp|one[- ]time password|password|pin|"
        r"cvv|security code|verification code)\b"
    ),
    "Account threat": (
        r"\b(account|bank account|card|wallet)\b.{0,60}"
        r"\b(blocked|suspended|restricted|locked|disabled|"
        r"closed|deactivated|terminated)\b"
        r"|"
        r"\b(blocked|suspended|restricted|locked|disabled)\b"
        r".{0,60}\b(account|bank account|card|wallet)\b"
    ),
    "Urgency": (
        r"\b(urgent|immediately|right now|act now|"
        r"today|within \d+ hours|before midnight|"
        r"final warning|last chance|without delay)\b"
    ),
    "Link action": (
        r"\b(click|tap|open|visit|follow)\b.{0,60}"
        r"\b(link|website|url|button)\b"
    ),
    "Personal detail verification": (
        r"\b(verify|confirm|update|validate)\b.{0,60}"
        r"\b(details|account|information|identity|"
        r"payment|card|profile)\b"
    ),
    "Prize or reward": (
        r"\b(won|winner|prize|reward|cashback|"
        r"free gift|lottery)\b"
    ),
    "Payment pressure": (
        r"\b(pay now|send money|transfer now|"
        r"processing fee|claim fee|pay fee|"
        r"deposit now|urgent payment)\b"
    ),
    "Refund fee request": (
        r"\b(refund|reimbursement)\b.{0,60}"
        r"\b(fee|charge|payment|deposit)\b"
    ),
}

URL_PATTERN = r"https?://[^\s]+|www\.[^\s]+"

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rb.gy",
}


def contains_pattern(pattern, message):
    return bool(re.search(pattern, message, re.IGNORECASE))


def find_urls(message):
    return re.findall(URL_PATTERN, message, re.IGNORECASE)


def check_suspicious_urls(message):
    indicators = []

    for url in find_urls(message):
        candidate = url.strip(".,!?;:()[]{}")

        if candidate.lower().startswith("www."):
            candidate = "https://" + candidate

        try:
            parsed = urlparse(candidate)
            domain = (parsed.hostname or "").lower()

            if domain in SHORTENER_DOMAINS:
                indicators.append("Shortened URL detected")

            if parsed.scheme.lower() == "http":
                indicators.append("Unencrypted HTTP link detected")

            if "@" in parsed.netloc:
                indicators.append("URL contains an unusual @ symbol")

        except ValueError:
            indicators.append("URL could not be parsed")

    return list(dict.fromkeys(indicators))


def analyze_message(message):
    """
    Analyze a message using transparent pattern-based rules.

    Returns:
        score: heuristic score from 0 to 100
        risk: 'Suspicious' or 'Safe' for dashboard compatibility
        risk_level: Critical / High / Medium / Low Risk
        classification: Suspicious or Safe
        indicators: list of matched warning indicators
        confidence: heuristic indicator-strength estimate
        recommendation: suggested safe next step
    """

    if not isinstance(message, str):
        raise TypeError("Message must be a string.")

    message = message.strip()

    if not message:
        raise ValueError("Please enter a message to analyze.")

    score = 0
    indicators = []

    # Detect individual patterns.
    detected = {}

    for name, pattern in PATTERNS.items():
        detected[name] = contains_pattern(pattern, message)

    # Credential requests are especially important.
    if detected["Credential request"]:
        score += 90
        indicators.append(
            "Request involving sensitive credentials detected"
        )

    if detected["Link action"]:
        score += 15
        indicators.append("Request to access a link detected")

    if detected["Personal detail verification"]:
        score += 10
        indicators.append(
            "Request to verify personal details detected"
        )

    if detected["Prize or reward"]:
        score += 25
        indicators.append("Prize or reward claim detected")

    if detected["Payment pressure"]:
        score += 25
        indicators.append("Payment pressure detected")

    if detected["Refund fee request"]:
        score += 40
        indicators.append("Refund-related fee request detected")

    # Check URLs separately.
    url_indicators = check_suspicious_urls(message)

    for item in url_indicators:
        score += 25
        indicators.append(item)

    # Combination rules: multiple warning signs increase risk.
    if (
        detected["Account threat"]
        and detected["Link action"]
        and detected["Personal detail verification"]
    ):
        score += 15
        indicators.append(
            "Account threat combined with link-based verification"
        )

    if (
        detected["Prize or reward"]
        and detected["Payment pressure"]
    ):
        score += 15
        indicators.append(
            "Prize claim combined with payment request"
        )

    if (
        detected["Account threat"]
        and detected["Urgency"]
    ):
        score += 10
        indicators.append(
            "Account threat combined with urgency"
        )

    # Keep the score within 0-100.
    score = min(score, 100)

    # Risk levels.
    if detected["Credential request"] or score >= 80:
        risk_level = "Critical Risk"
    elif score >= 55:
        risk_level = "High Risk"
    elif score >= 25:
        risk_level = "Medium Risk"
    else:
        risk_level = "Low Risk"

    # Dashboard-compatible classification.
    if score >= 25:
        classification = "Suspicious"
        risk = "Suspicious"
    else:
        classification = "Safe"
        risk = "Safe"

    # This is a heuristic strength indicator, not an ML probability.
    if risk_level == "Critical Risk":
        confidence = 99
    elif risk_level == "High Risk":
        confidence = 92
    elif risk_level == "Medium Risk":
        confidence = 82
    elif indicators:
        confidence = 72
    else:
        confidence = 65

    # Recommended next step.
    if risk_level == "Critical Risk":
        recommendation = (
            "Do not share OTPs, PINs, passwords or card security "
            "codes. Contact the organization using its official "
            "website or app."
        )
    elif risk_level == "High Risk":
        recommendation = (
            "Do not click the link or provide personal details. "
            "Verify the message independently through the "
            "organization's official website or app."
        )
    elif risk_level == "Medium Risk":
        recommendation = (
            "Review the message carefully. Avoid making payments "
            "or sharing information until the sender is verified."
        )
    else:
        recommendation = (
            "No strong suspicious patterns were detected by this "
            "prototype. This does not guarantee the message is safe. "
            "Verify unexpected requests independently."
        )

    return {
        "score": score,
        "risk": risk,
        "risk_level": risk_level,
        "classification": classification,
        "indicators": list(dict.fromkeys(indicators)),
        "confidence": confidence,
        "recommendation": recommendation,
    }
