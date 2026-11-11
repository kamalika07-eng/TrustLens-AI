
import re
from functools import lru_cache

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


# Synthetic demonstration dataset.
# Replace with a properly validated dataset for real evaluation.

TRAINING_DATA = [
    ("Your payment was successful. Thank you for using our service.", "normal"),
    ("Your monthly payment receipt is available in your account.", "normal"),
    ("Your transaction confirmation has been sent to your email.", "normal"),
    ("Please check your official account for payment details.", "normal"),
    ("Your refund has been processed. Check your account.", "normal"),
    ("Your payment statement is ready for download.", "normal"),
    ("Thank you. Your order confirmation is ready.", "normal"),
    ("Your subscription payment was received successfully.", "normal"),
    ("Your invoice is available in the official application.", "normal"),
    ("A transaction notification is available in your account.", "normal"),
    ("Your purchase receipt is ready to view.", "normal"),
    ("Your payment information has been updated successfully.", "normal"),
    ("Your account activity summary is now available.", "normal"),
    ("Your scheduled payment reminder is available.", "normal"),
    ("Your order has been confirmed successfully.", "normal"),
    ("Please review your transaction details in the official app.", "normal"),

    ("Urgent! Your account is suspended. Verify your password immediately.", "suspicious"),
    ("You won a prize! Pay a processing fee to claim your reward.", "suspicious"),
    ("Send your OTP now to prevent account suspension.", "suspicious"),
    ("Your account is blocked. Click here to restore access immediately.", "suspicious"),
    ("Transfer money now to avoid losing your account.", "suspicious"),
    ("Your payment failed. Share your PIN for verification.", "suspicious"),
    ("Congratulations winner! Pay now to receive your reward.", "suspicious"),
    ("Your account is restricted. Submit your password immediately.", "suspicious"),
    ("Verify your identity using the OTP sent to your phone.", "suspicious"),
    ("Immediate action required! Your wallet will be blocked.", "suspicious"),
    ("Send your bank details to receive your unexpected prize.", "suspicious"),
    ("Click this link and enter your password to unlock your account.", "suspicious"),
    ("Pay a small fee immediately to release your refund.", "suspicious"),
    ("Your account will be closed unless you verify your PIN.", "suspicious"),
    ("Share your verification code to complete this transaction.", "suspicious"),
    ("Act now! Transfer funds to secure your payment.", "suspicious"),
]


@lru_cache(maxsize=1)
def get_model():

    messages = [item[0] for item in TRAINING_DATA]
    labels = [item[1] for item in TRAINING_DATA]

    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            max_features=3000
        )),
        ("classifier", LogisticRegression(
            max_iter=1000,
            class_weight="balanced"
        ))
    ])

    model.fit(messages, labels)

    return model


def analyze_message(message):

    model = get_model()

    probabilities = model.predict_proba([message])[0]

    classes = list(model.classes_)

    suspicious_probability = float(
        probabilities[classes.index("suspicious")]
    )

    score = round(suspicious_probability * 100)

    if score >= 70:
        risk = "High Risk"
    elif score >= 40:
        risk = "Medium Risk"
    else:
        risk = "Low Risk"

    patterns = {
        "Urgent language": r"urgent|immediately|right now|act now",
        "Account warning": r"suspended|blocked|restricted|closed",
        "Credential request": r"password|otp|pin|verification code",
        "Prize or reward": r"won|winner|prize|reward",
        "Payment pressure": r"pay now|send money|transfer now|processing fee"
    }

    indicators = []

    for name, pattern in patterns.items():
        if re.search(pattern, message, re.IGNORECASE):
            indicators.append(name)

    return {
        "score": score,
        "risk": risk,
        "indicators": indicators,
        "confidence": round(
            max(probabilities) * 100, 2
        )
    }
