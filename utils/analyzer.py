
import re
from urllib.parse import urlparse


# =========================================================
# TRUSTLENS AI - PAYMENT MESSAGE RISK ANALYZER
# Transparent rule-based risk scoring for demo/testing
# =========================================================

# Strong indicators: requests for sensitive credentials
CREDENTIAL_PATTERNS = [
    r"\b(share|send|provide|tell|reply with|forward)\b.{0,45}\b(otp|pin|password|passcode|verification code)\b",
    r"\b(otp|pin|password|passcode|verification code)\b.{0,45}\b(share|send|provide|tell|reply with)\b",
]

# Urgency and account threats
URGENCY_PATTERN = (
    r"\b(urgent|immediately|right now|act now|within 24 hours|"
    r"today only|final warning)\b"
)

ACCOUNT_THREAT_PATTERN = (
    r"\b(account will be blocked|account blocked|account suspended|"
    r"account restricted|account will be closed|"
    r"account suspension|service will be suspended|"
    r"wallet blocked|connection will be disconnected)\b"
)

# Rewards and payment scams
PRIZE_PATTERN = (
    r"\b(won|winner|lottery|prize|free gift|"
    r"cashback reward|selected for a reward)\b"
)

FEE_PATTERN = (
    r"\b(processing fee|registration fee|delivery charges|"
    r"claim fee|activation fee|pay a fee|advance payment)\b"
)

REFUND_FEE_PATTERN = (
    r"\b(refund|money back)\b.{0,60}\b(fee|charges|payment)\b"
)

# Suspicious links
URL_PATTERN = r"https?://[^\s]+|www\.[^\s]+"

SHORT_URL_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "shorturl.at"
}

SUSPICIOUS_URL_WORDS = {
    "verify",
    "account-alert",
    "secure-update",
    "claim-reward",
    "free-gift",
    "login-verification"
}


def contains_pattern(pattern, text):
    return bool(re.search(pattern, text, re.IGNORECASE))


def analyze_urls(message):
    """Check URLs for basic suspicious patterns."""

    found = []

    urls = re.findall(URL_PATTERN, message, re.IGNORECASE)

    for url in urls:
        candidate = url.rstrip(".,!?;:)")

        if candidate.startswith("www."):
            candidate = "https://" + candidate

        try:
            parsed = urlparse(candidate)
            domain = (parsed.hostname or "").lower()

            if domain in SHORT_URL_DOMAINS:
                found.append("Shortened URL detected")

            if any(
                word in candidate.lower()
                for word in SUSPICIOUS_URL_WORDS
            ):
                found.append("Suspicious URL wording detected")

            if parsed.scheme.lower() == "http":
                found.append("Unencrypted HTTP link detected")

        except ValueError:
            found.append("URL could not be fully checked")

    return list(dict.fromkeys(found))


def analyze_message(message):

    if not isinstance(message, str):
        raise TypeError("Message must be a string.")

    message = message.strip()

    if not message:
        raise ValueError("Please enter a payment message.")

    score = 0
    indicators = []

    # -----------------------------------------------------
    # 1. CRITICAL CREDENTIAL REQUEST
    # -----------------------------------------------------

    credential_request = any(
        contains_pattern(pattern, message)
        for pattern in CREDENTIAL_PATTERNS
    )

    if credential_request:
        score += 90
        indicators.append(
            "Sensitive credential sharing request detected"
        )

    # -----------------------------------------------------
    # 2. ACCOUNT THREATS
    # -----------------------------------------------------

    account_threat = contains_pattern(
        ACCOUNT_THREAT_PATTERN, message
    )

    if account_threat:
        score += 25
        indicators.append("Account suspension or blocking threat")

    # -----------------------------------------------------
    # 3. URGENT LANGUAGE
    # -----------------------------------------------------

    urgency = contains_pattern(
        URGENCY_PATTERN, message
    )

    if urgency:
        score += 12
        indicators.append("Urgent or pressure-based language")

    # -----------------------------------------------------
    # 4. FAKE PRIZE / REWARD
    # -----------------------------------------------------

    prize = contains_pattern(
        PRIZE_PATTERN, message
    )

    fee = contains_pattern(
        FEE_PATTERN, message
    )

    if prize:
        score += 25
        indicators.append("Unexpected prize or reward claim")

    if fee:
        score += 25
        indicators.append("Advance or processing fee request")

    # -----------------------------------------------------
    # 5. REFUND FEE SCAM
    # -----------------------------------------------------

    if contains_pattern(REFUND_FEE_PATTERN, message):
        score += 40
        indicators.append("Suspicious refund fee request")

    # -----------------------------------------------------
    # 6. SUSPICIOUS URL CHECK
    # -----------------------------------------------------

    url_indicators = analyze_urls(message)

    if url_indicators:
        score += 25
        indicators.extend(url_indicators)

    # -----------------------------------------------------
    # 7. COMBINATION-BASED RISK
    # -----------------------------------------------------

    if account_threat and urgency:
        score += 15
        indicators.append(
            "Combined account threat and urgency pattern"
        )

    if prize and fee:
        score += 15
        indicators.append(
            "Prize claim combined with payment request"
        )

    # -----------------------------------------------------
    # 8. FINAL SCORE
    # -----------------------------------------------------

    score = min(score, 100)

    # Critical risk for credential theft attempts
    if credential_request or score >= 80:
        risk = "Critical Risk"

    elif score >= 55:
        risk = "High Risk"

    elif score >= 25:
        risk = "Medium Risk"

    else:
        risk = "Low Risk"

    # Dashboard-compatible binary classification
    classification = (
        "Suspicious"
        if risk in ["Medium Risk", "High Risk", "Critical Risk"]
        else "Safe"
    )

    # -----------------------------------------------------
    # 9. CONFIDENCE INDICATOR
    # -----------------------------------------------------

    if credential_request:
        confidence = 99.0
    elif score >= 55:
        confidence = 95.0
    elif score >= 25:
        confidence = 85.0
    elif score > 0:
        confidence = 75.0
    else:
        confidence = 92.0

    # -----------------------------------------------------
    # 10. RECOMMENDATION
    # -----------------------------------------------------

    if risk == "Critical Risk":
        recommendation = (
            "Do not share OTP, PIN or passwords. "
            "Verify independently through your official bank."
        )

    elif risk == "High Risk":
        recommendation = (
            "Do not make payments or follow suspicious links. "
            "Verify the sender through official channels."
        )

    elif risk == "Medium Risk":
        recommendation = (
            "Review the message carefully before taking action."
        )

    else:
        recommendation = (
            "No strong suspicious patterns were detected. "
            "Still verify the sender before making payments."
        )

    return {
        "score": score,
        "risk": risk,
        "classification": classification,
        "indicators": list(dict.fromkeys(indicators)),
        "confidence": confidence,
        "recommendation": recommendation
    }
