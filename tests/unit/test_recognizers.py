"""Recognizer + validator specs: valid samples pass, near-misses die."""

from onprem_dlp.domain import recognizers as r
from onprem_dlp.domain.models import EntityType


def _scan(text: str):
    findings = []
    for rec in r.default_recognizers():
        findings.extend(r.run_recognizer(rec, text))
    return findings


def _types(text: str):
    return {f.entity_type for f in _scan(text)}


class TestChecksums:
    def test_luhn(self):
        assert r.luhn_valid("4111111111111111")
        assert not r.luhn_valid("4111111111111112")

    def test_sg_nric(self):
        for value in ("S1234567D", "S8712345F", "T0212345I", "F2412345Q", "G9612345R"):
            assert r.sg_nric_valid(value), value
        assert not r.sg_nric_valid("S1234567A")
        assert not r.sg_nric_valid("A1234567D")

    def test_sg_nric_m_prefix(self):
        # the M-series (foreigners, from 2022) uses s += 3 and its own check table;
        # pin it so a future edit to the M-branch can't silently break
        assert r.sg_nric_valid("M1234567X")
        assert not r.sg_nric_valid("M1234567A")

    def test_degenerate_all_identical_digits_rejected(self):
        assert not r.luhn_valid("0000000000000")
        assert not r.luhn_valid("1111111111111111")
        assert not r.jp_my_number_valid("000000000000")

    def test_hk_hkid(self):
        assert r.hk_hkid_valid("A123456(3)")
        assert r.hk_hkid_valid("AB123456(9)")
        assert not r.hk_hkid_valid("A123456(4)")

    def test_jp_my_number(self):
        assert r.jp_my_number_valid("123456789018")
        assert r.jp_my_number_valid("1234 5678 9018")
        assert not r.jp_my_number_valid("123456789019")

    def test_au_tfn(self):
        assert r.au_tfn_valid("123456782")
        assert not r.au_tfn_valid("123456789")

    def test_au_abn(self):
        assert r.au_abn_valid("51824753556")
        assert r.au_abn_valid("51 824 753 556")
        assert not r.au_abn_valid("51824753557")

    def test_au_medicare(self):
        assert r.au_medicare_valid("2123456701")
        assert not r.au_medicare_valid("2123456711")

    def test_iban(self):
        assert r.iban_valid("DE89370400440532013000")
        assert r.iban_valid("DE89 3704 0044 0532 0130 00")
        assert not r.iban_valid("DE89370400440532013001")

    def test_ipv4(self):
        assert r.ipv4_valid("10.20.30.40")
        assert not r.ipv4_valid("999.20.30.40")

    def test_us_ssn(self):
        assert r.us_ssn_valid("536-90-4399")
        assert not r.us_ssn_valid("000-12-3456")
        assert not r.us_ssn_valid("666-12-3456")


class TestDetectionBehaviour:
    def test_email_and_nric_detected(self):
        types = _types("Contact jane.doe@example.com, NRIC S1234567D.")
        assert EntityType.EMAIL_ADDRESS in types
        assert EntityType.SG_NRIC in types

    def test_checksum_failure_is_dropped(self):
        assert EntityType.SG_NRIC not in _types("Ref S1234567A on file.")
        assert EntityType.CREDIT_CARD not in _types("card 4111 1111 1111 1112 thanks")

    def test_context_required_patterns(self):
        # passport-shaped token without the word "passport" nearby: silence
        assert EntityType.PASSPORT not in _types("Order code E1234567 shipped.")
        assert EntityType.PASSPORT in _types("My passport E1234567 expires soon.")

    def test_tfn_requires_context_even_with_valid_checksum(self):
        assert EntityType.AU_TFN not in _types("Invoice total 123 456 782 dollars.")
        assert EntityType.AU_TFN in _types("My tax file number is 123 456 782.")

    def test_my_number_does_not_fire_inside_longer_card_runs(self):
        # first 12 digits of this Luhn-INVALID card pass the MyNumber checksum;
        # the boundary lookarounds must keep MyNumber out of grouped longer runs
        assert _types("PO number 4111 1111 1111 1112 for the renewal.") == set()
        assert EntityType.JP_MY_NUMBER in _types("her My Number is 1234 5678 9018.")

    def test_dob_requires_birth_context(self):
        assert EntityType.DATE_OF_BIRTH not in _types("Meeting on 12/03/2025 at 9am.")
        assert EntityType.DATE_OF_BIRTH in _types("She was born on 12/03/1985 in Perth.")

    def test_dob_requires_a_real_calendar_date(self):
        assert r.date_of_birth_valid("29/02/2000")
        assert r.date_of_birth_valid("2000-02-29")
        assert not r.date_of_birth_valid("29/02/2023")
        assert not r.date_of_birth_valid("1985-13-12")
        assert EntityType.DATE_OF_BIRTH not in _types("生年月日：2023-02-29")
        assert EntityType.DATE_OF_BIRTH not in _types("生年月日：1985-13-12")

    def test_japanese_context_words_enable_context_required_patterns(self):
        assert EntityType.PHONE_NUMBER in _types("携帯電話：090-1234-5678")
        assert EntityType.PASSPORT in _types("パスポート番号：TR1234560")
        assert EntityType.DATE_OF_BIRTH in _types("生年月日：1985-03-12")

    def test_japanese_business_identifiers_do_not_trigger_without_context(self):
        assert EntityType.PHONE_NUMBER not in _types("受付番号：090-1234-5678")
        assert EntityType.PASSPORT not in _types("出荷コード：TR1234560")
        assert EntityType.DATE_OF_BIRTH not in _types("次回会議：2026-03-12")

    def test_context_boosts_confidence(self):
        with_ctx = [
            f
            for f in _scan("Send to email jane@example.com please")
            if f.entity_type is EntityType.EMAIL_ADDRESS
        ][0]
        without_ctx = [
            f for f in _scan("jane@example.com") if f.entity_type is EntityType.EMAIL_ADDRESS
        ][0]
        assert with_ctx.confidence > without_ctx.confidence
        assert with_ctx.context_boosted

    def test_match_ratio_uses_fullmatch_and_validator(self):
        rec = next(x for x in r.default_recognizers() if x.name == "sg_nric")
        values = ["S1234567D", "S8712345F", "not-an-nric", None, ""]
        assert r.match_ratio(rec, values) == 2 / 3
