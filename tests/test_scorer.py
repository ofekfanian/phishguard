import pytest

from phishguard.scorer import score_domain

THRESHOLD = 50


@pytest.mark.parametrize("domain", [
    "leumi.co.il",
    "www.paypal.com",
    "login.microsoftonline.com",
    "example.com",
    "discount-shoes.com",
    "my-blog.co.il",
])
def test_legitimate_domains_score_zero(domain):
    assert score_domain(domain).score == 0


def test_brand_name_alone_is_below_threshold():
    # "Mizrahi" is also a common surname: the name alone is not enough.
    result = score_domain("mizrahi-family.com")
    assert 0 < result.score < THRESHOLD


def test_brand_with_phishing_words_and_bad_tld():
    result = score_domain("leumi-secure-login.xyz")
    assert result.brand == "Bank Leumi"
    assert result.severity == "high"


def test_digit_lookalike():
    result = score_domain("paypa1-verify.com")
    assert result.brand == "PayPal"
    assert result.score >= THRESHOLD
    assert any("Lookalike" in r for r in result.reasons)


def test_cyrillic_lookalike_in_punycode():
    fake = "pаypal".encode("idna").decode()  # the "а" is Cyrillic
    assert fake.startswith("xn--")
    result = score_domain(f"{fake}.com")
    assert result.brand == "PayPal"
    assert result.score >= THRESHOLD
    assert any("punycode" in r for r in result.reasons)


def test_typosquatting():
    result = score_domain("paypol-login.com")
    assert result.brand == "PayPal"
    assert any("Typosquatting" in r for r in result.reasons)


def test_real_domain_embedded_as_subdomain():
    result = score_domain("leumi.co.il.verify-account.top")
    assert result.registered_domain == "verify-account.top"
    assert result.score >= 90
    assert any("Embeds the real domain" in r for r in result.reasons)


def test_wildcard_and_case_are_normalised():
    assert score_domain("*.BankHapoalim-Update.online").domain == "bankhapoalim-update.online"


def test_garbage_input_does_not_crash():
    for junk in ["", "localhost", "...", "a" * 300, "xn--zzzzzz.com"]:
        assert score_domain(junk).score == 0


def test_brand_hidden_inside_longer_word():
    result = score_domain("paypall-login.com")
    assert result.brand == "PayPal"
    assert any("hidden inside" in r for r in result.reasons)


def test_brands_internal_domains_are_not_flagged():
    assert score_domain("auto-s1-pbi-kv-zone.z1.w.api.fabric.microsoft-int.com").score == 0


# --- Cases found while running on live Certificate Transparency data ---

def test_l_and_i_are_lookalikes():
    result = score_domain("mlcros0ft.com")
    assert result.brand == "Microsoft"
    assert any("Lookalike" in r for r in result.reasons)
    assert score_domain("paypai-login.com").brand == "PayPal"


@pytest.mark.parametrize("domain", ["playpal.uk", "microsport.gr", "www.microot.app"])
def test_a_typo_alone_is_below_threshold(domain):
    assert 0 < score_domain(domain).score < THRESHOLD


def test_typo_with_supporting_evidence_is_detected():
    assert score_domain("paypol-login.com").score >= THRESHOLD


def test_official_domain_must_match_whole_labels():
    result = score_domain("theoutlook.com.ua")
    assert not any("Embeds the real domain" in r for r in result.reasons)
    assert result.score < THRESHOLD
