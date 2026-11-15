import asyncio
from datetime import date

from phishguard.enrich import parse_bootstrap, registration_date
from phishguard.pipeline import Pipeline
from phishguard.scorer import apply_domain_age, score_domain
from phishguard.store import Store

TODAY = date(2026, 11, 15)


def test_parse_bootstrap():
    data = {"services": [
        [["com", "NET"], ["https://rdap.example/v1"]],
        [["uk"], ["http://insecure.example/", "https://rdap.uk.example/uk/"]],
        [["bad"], []],
        "garbage",
    ]}
    assert parse_bootstrap(data) == {
        "com": "https://rdap.example/v1/", "net": "https://rdap.example/v1/",
        "uk": "https://rdap.uk.example/uk/",
    }


def test_registration_date():
    rdap = {"events": [{"eventAction": "expiration", "eventDate": "2027-04-29T00:00:00Z"},
                       {"eventAction": "registration", "eventDate": "2026-04-29T12:30:00Z"}]}
    assert registration_date(rdap) == date(2026, 4, 29)
    for junk in [{}, {"events": None}, {"events": [{"eventAction": "registration"}]}, [], None]:
        assert registration_date(junk) is None


def test_new_domain_scores_higher():
    result = apply_domain_age(score_domain("paypa1-verify.com"), date(2026, 11, 10), TODAY)
    assert result.score == 85
    assert result.severity == "high"
    assert "Registered only 5 day(s) ago (2026-11-10)" in result.reasons


def test_old_domain_scores_lower():
    before = score_domain("playpal.uk")
    after = apply_domain_age(before, date(2023, 8, 15), TODAY)
    assert before.score == 50 and after.score == 30
    assert any("3 years ago" in r for r in after.reasons)


def test_unknown_age_changes_nothing():
    before = score_domain("paypa1-verify.com")
    assert apply_domain_age(before, None, TODAY) == before
    assert apply_domain_age(score_domain("example.com"), date(2026, 11, 10), TODAY).score == 0


def run_pipeline(tmp_path, ages: dict, domains: list[str]):
    async def lookup(domain):
        return ages.get(domain)

    async def go():
        p = Pipeline(Store(f"sqlite:///{tmp_path}/t.db"), 50, "test", age_lookup=lookup)
        for d in domains:
            p.handle(d)
        await p.drain()
        return p.store.list()
    return asyncio.run(go())


def test_pipeline_drops_old_lookalike_and_keeps_unknown(tmp_path):
    old = date(2015, 1, 1)
    saved = run_pipeline(tmp_path, {"playpal.uk": old}, ["playpal.uk", "paypa1-verify.com"])
    assert [d["domain"] for d in saved] == ["paypa1-verify.com"]
    assert saved[0]["registered_on"] is None


def test_pipeline_promotes_brand_name_on_brand_new_domain(tmp_path):
    # "mizrahi-family.com" scores 40: below the threshold unless it is brand new.
    fresh = date.today()
    saved = run_pipeline(tmp_path, {"mizrahi-family.com": fresh}, ["mizrahi-family.com"])
    assert len(saved) == 1 and saved[0]["score"] == 55
    assert saved[0]["registered_on"] == fresh.isoformat()


def test_pipeline_ignores_brand_name_alone_when_age_is_unknown(tmp_path):
    assert run_pipeline(tmp_path, {}, ["mizrahi-shop.com"]) == []


def test_lookup_failure_does_not_lose_the_detection(tmp_path):
    async def broken(domain):
        raise RuntimeError("registry down")

    async def go():
        p = Pipeline(Store(f"sqlite:///{tmp_path}/t.db"), 50, "test", age_lookup=broken)
        p.handle("paypa1-verify.com")
        await p.drain()
        return p.store.list()
    assert [d["domain"] for d in asyncio.run(go())] == ["paypa1-verify.com"]


def test_old_database_gets_the_new_column(tmp_path):
    import sqlite3
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE detections (id INTEGER PRIMARY KEY, domain VARCHAR(255) UNIQUE, "
                "registered_domain VARCHAR(255), brand VARCHAR(100), score INTEGER, severity VARCHAR(10), "
                "reasons JSON, source VARCHAR(20), first_seen DATETIME)")
    con.execute("INSERT INTO detections VALUES (1,'a.com','a.com','PayPal',60,'medium','[]','ct','2026-11-15 10:00:00')")
    con.commit(); con.close()
    store = Store(f"sqlite:///{path}")
    assert store.list()[0]["registered_on"] is None
    assert store.save(score_domain("paypa1-verify.com"), "test", date(2026, 11, 1))
    assert store.list()[0]["registered_on"] == "2026-11-01"
