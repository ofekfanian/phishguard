import json

from phishguard.pipeline import Pipeline
from phishguard.sources import parse_certstream_message
from phishguard.store import Store


def make_pipeline(tmp_path):
    return Pipeline(Store(f"sqlite:///{tmp_path}/test.db"), threshold=50, source_name="test")


def test_only_suspicious_domains_are_saved(tmp_path):
    p = make_pipeline(tmp_path)
    for d in ["example.com", "leumi-secure-login.xyz", "www.paypal.com", "mizrahi-family.com"]:
        p.handle(d)
    saved = p.store.list()
    assert [d["domain"] for d in saved] == ["leumi-secure-login.xyz"]
    assert saved[0]["brand"] == "Bank Leumi"
    assert p.processed == 4


def test_repeated_domains_are_processed_once(tmp_path):
    p = make_pipeline(tmp_path)
    assert p.handle("paypa1-verify.com") is not None
    assert p.handle("paypa1-verify.com") is None
    assert p.processed == 1
    assert p.store.counts()["total"] == 1


def test_parse_domains_only_message():
    raw = json.dumps({"message_type": "dns_entries", "data": ["a.com", "*.b.com"]})
    assert parse_certstream_message(raw) == ["a.com", "*.b.com"]


def test_parse_full_message():
    raw = json.dumps({"message_type": "certificate_update",
                      "data": {"leaf_cert": {"all_domains": ["a.com"]}}})
    assert parse_certstream_message(raw) == ["a.com"]


def test_parse_ignores_malformed_messages():
    for raw in ["not json", "[]", "{}", '{"message_type":"heartbeat"}',
                '{"message_type":"dns_entries","data":"oops"}',
                '{"message_type":"certificate_update","data":{"leaf_cert":null}}',
                '{"message_type":"dns_entries","data":[1, null, "ok.com"]}']:
        assert parse_certstream_message(raw) in ([], ["ok.com"])


def test_one_detection_per_registered_domain(tmp_path):
    p = make_pipeline(tmp_path)
    for sub in ["a", "b", "c"]:
        p.handle(f"{sub}.leumi-secure-login.xyz")
    assert p.processed == 3
    assert p.store.counts()["total"] == 1
