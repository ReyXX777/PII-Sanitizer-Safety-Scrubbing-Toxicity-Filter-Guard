from pii_toxicity_guard.pii.recognizers import EMAIL_RE, IPV4_RE, US_SSN_RE


def test_email_normal_and_mixed_case():
    assert EMAIL_RE.search("Reach Alice.Example+tag@Example.com today")
    assert EMAIL_RE.search("user@example.co.uk")


def test_obfuscated_email_is_not_claimed_as_supported_by_regex():
    # This documents a limitation: a conventional email regex will not detect this.
    assert not EMAIL_RE.search("alice [at] example [dot] com")


def test_ipv4_valid_shape_and_invalid_octet():
    assert IPV4_RE.search("host 192.168.1.10")
    assert not IPV4_RE.search("999.999.999.999")


def test_ssn_shape_excludes_obvious_invalid_prefix():
    assert US_SSN_RE.search("123-45-6789")
    assert not US_SSN_RE.search("000-12-3456")
