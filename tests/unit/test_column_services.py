from onprem_dlp.domain.column_classifier_service import ColumnClassifierService
from onprem_dlp.domain.column_profile_service import ColumnProfileService
from onprem_dlp.domain.models import ColumnCategory, EntityType

profiler = ColumnProfileService()
classifier = ColumnClassifierService()


def _classify(name, values, adjudication=None):
    return classifier.classify(profiler.profile("t", name, values), adjudication)


def _emails(n=30):
    return [f"user{i}@example.com" for i in range(n)]


class TestProfile:
    def test_cardinality_and_nulls(self):
        p = profiler.profile("t", "c", ["a", "a", "b", None, ""])
        assert p.total_count == 5
        assert p.null_count == 2
        assert p.distinct_count == 2
        assert abs(p.cardinality_ratio - 2 / 3) < 1e-9

    def test_type_inference(self):
        assert profiler.profile("t", "c", ["12", "3.5"]).inferred_type == "numeric"
        assert profiler.profile("t", "c", ["2020-01-02"]).inferred_type == "date"
        assert profiler.profile("t", "c", ["yes", "no"]).inferred_type == "boolean"
        assert profiler.profile("t", "c", ["hello"]).inferred_type == "text"
        assert profiler.profile("t", "c", []).inferred_type == "empty"

    def test_pattern_hits_use_shared_recognizers(self):
        p = profiler.profile("t", "contact", _emails())
        assert p.best_pattern()[0] is EntityType.EMAIL_ADDRESS
        assert p.best_pattern()[1] == 1.0


class TestClassifier:
    def test_email_column_is_direct_pii_even_with_opaque_name(self):
        c = _classify("col_47", _emails())
        assert c.category is ColumnCategory.PII_DIRECT
        assert c.entity_type is EntityType.EMAIL_ADDRESS
        assert not c.needs_review

    def test_gender_low_cardinality_is_quasi(self):
        c = _classify("gender", ["M", "F"] * 20)
        assert c.category is ColumnCategory.PII_QUASI

    def test_salary_is_sensitive(self):
        c = _classify("salary_sgd", [str(40000 + i) for i in range(30)])
        assert c.category is ColumnCategory.SENSITIVE

    def test_plain_measure_is_non_pii(self):
        c = _classify("account_balance", [f"{i}.50" for i in range(30)])
        assert c.category is ColumnCategory.NON_PII
        assert c.score < 0.3

    def test_generic_date_column_is_not_flagged(self):
        c = _classify("order_date", [f"2024-0{1 + i % 9}-1{i % 9}" for i in range(30)])
        assert c.category is ColumnCategory.NON_PII

    def test_birth_date_column_is_quasi(self):
        c = _classify("date_of_birth", [f"198{i % 10}-01-1{i % 9}" for i in range(30)])
        assert c.category is ColumnCategory.PII_QUASI
        assert not c.needs_review

    def test_ambiguous_column_escalates_without_adjudicator(self):
        c = _classify("customer_id", [f"CUST{i:05d}" for i in range(30)])
        assert c.needs_review
        assert c.category is ColumnCategory.PII_QUASI

    def test_adjudicator_verdict_nudges_but_is_bounded(self):
        values = [f"CUST{i:05d}" for i in range(30)]
        base = _classify("customer_id", values)
        confirmed = _classify("customer_id", values, adjudication=(True, 1.0, "joins to person"))
        rejected = _classify("customer_id", values, adjudication=(False, 1.0, "surrogate key"))
        nudge = classifier.adjudicator_nudge
        assert abs(confirmed.score - min(1.0, base.score + nudge)) < 1e-6
        assert abs(rejected.score - max(0.0, base.score - nudge)) < 1e-6
        assert confirmed.llm_adjudicated and confirmed.llm_rationale

    def test_compound_names_do_not_trigger_person_name(self):
        # word-boundary matching: 'name' must not match filename/username/hostname
        for name in ("filename", "username", "hostname", "nickname"):
            c = _classify(name, [f"val{i}" for i in range(30)])
            assert c.entity_type is not EntityType.PERSON_NAME, name
            assert c.category is not ColumnCategory.PII_DIRECT, name

    def test_condition_code_is_not_health_sensitive(self):
        c = _classify("condition_code", [f"C{i % 5}" for i in range(30)])
        assert c.category is not ColumnCategory.SENSITIVE
        # but a genuine health column still classifies SENSITIVE
        assert (
            _classify("health_condition", ["diabetes", "none", "asthma"] * 10).category
            is ColumnCategory.SENSITIVE
        )

    def test_real_person_name_columns_still_match(self):
        for name in ("full_name", "customer_name", "surname", "first_name"):
            c = _classify(name, [f"Person {i}" for i in range(30)])
            assert c.entity_type is EntityType.PERSON_NAME, name

    def test_camelcase_names_are_split_and_matched(self):
        # boundary matching must still see the words in camelCase / PascalCase columns;
        # a name column's ONLY PII evidence is its name, so missing it is fail-open
        for name in ("fullName", "customerName", "FirstName"):
            c = _classify(name, [f"Person {i}" for i in range(30)])
            assert c.entity_type is EntityType.PERSON_NAME, name
            assert c.category is ColumnCategory.PII_DIRECT, name
        assert (
            _classify("dateOfBirth", [f"198{i % 10}-01-1{i % 9}" for i in range(30)]).category
            is ColumnCategory.PII_QUASI
        )
        assert (
            _classify("creditCardNumber", [f"tok{i}" for i in range(30)]).entity_type
            is EntityType.CREDIT_CARD
        )
        # and case-splitting must NOT reintroduce the compound-word false positives
        assert _classify("filename", ["a"] * 30).category is not ColumnCategory.PII_DIRECT

    def test_acronym_fused_names_are_split(self):
        # an all-caps ID acronym fused to a word (NRICNumber, SSNValue) must still be
        # seen even when the values are opaque tokens — missing it is fail-open
        assert (
            _classify("NRICNumber", [f"tok{i}" for i in range(30)]).entity_type
            is EntityType.SG_NRIC
        )
        assert (
            _classify("SSNValue", [f"tok{i}" for i in range(30)]).entity_type is EntityType.US_SSN
        )
        # standalone acronyms and lowercase-acronym camelCase still work; no false split
        assert _classify("NRIC", [f"tok{i}" for i in range(30)]).entity_type is EntityType.SG_NRIC
        assert (
            _classify("customerNRIC", [f"tok{i}" for i in range(30)]).entity_type
            is EntityType.SG_NRIC
        )

    def test_signals_are_explainable(self):
        c = _classify("email", _emails())
        codes = {s.code for s in c.signals}
        assert any(code.startswith("name:") for code in codes)
        assert any(code.startswith("pattern:") for code in codes)
