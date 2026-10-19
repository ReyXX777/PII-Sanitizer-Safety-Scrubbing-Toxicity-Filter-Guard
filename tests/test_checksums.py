from pii_toxicity_guard.pii.checksums import luhn_valid


def test_luhn_known_valid_card_candidate():
    assert luhn_valid("4111 1111 1111 1111")


def test_luhn_rejects_invalid_candidate():
    assert not luhn_valid("4111 1111 1111 1112")


def test_luhn_rejects_too_short():
    assert not luhn_valid("123456")
