"""Custom Presidio recognizers. Regexes are compiled once at module import."""
import re
from presidio_analyzer import Pattern, PatternRecognizer

EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+(?![\w.-])",
    re.IGNORECASE,
)
IPV4_RE = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"
)
US_SSN_RE = re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}(?!\d)")
PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d{1,3}[\s().-]*)?(?:\(?\d{2,4}\)?[\s().-]*)\d{3,4}[\s.-]*\d{3,4}(?!\w)")
CREDIT_CARD_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")


def build_custom_recognizers() -> list[PatternRecognizer]:
    """Create recognizers for structured PII; checksum validation happens post-detection."""
    return [
        PatternRecognizer(
            supported_entity="EMAIL_ADDRESS",
            patterns=[Pattern("custom_email", "(?i)" + EMAIL_RE.pattern, 0.75)],
            context=["email", "e-mail", "contact"],
            name="CustomEmailRecognizer",
        ),
        PatternRecognizer(
            supported_entity="IP_ADDRESS",
            patterns=[Pattern("custom_ipv4", IPV4_RE.pattern, 0.65)],
            context=["ip", "address", "server"],
            name="CustomIPv4Recognizer",
        ),
        PatternRecognizer(
            supported_entity="US_SSN",
            patterns=[Pattern("custom_ssn", US_SSN_RE.pattern, 0.65)],
            context=["ssn", "social security"],
            name="CustomSSNRecognizer",
        ),
        PatternRecognizer(
            supported_entity="PHONE_NUMBER",
            patterns=[Pattern("custom_phone", PHONE_RE.pattern, 0.35)],
            context=["phone", "call", "mobile", "tel"],
            name="CustomPhoneRecognizer",
        ),
        PatternRecognizer(
            supported_entity="CREDIT_CARD",
            patterns=[Pattern("custom_card_candidate", CREDIT_CARD_CANDIDATE_RE.pattern, 0.35)],
            context=["card", "credit", "visa", "mastercard", "payment"],
            name="CustomCreditCardRecognizer",
        ),
    ]
