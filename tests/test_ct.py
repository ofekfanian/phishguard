import base64
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from phishguard.ct import domains_from_entry, domains_from_tile, pick_logs, tile_path


def make_cert(names: list[str]) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def with_length(der: bytes) -> bytes:
    return len(der).to_bytes(3, "big") + der


def leaf_header(entry_type: int) -> bytes:
    return b"\x00\x00" + (0).to_bytes(8, "big") + entry_type.to_bytes(2, "big")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def test_certificate_entry():
    der = make_cert(["a.example.com", "*.b.example.com"])
    leaf = leaf_header(0) + with_length(der) + b"\x00\x00"
    assert domains_from_entry(b64(leaf), "") == ["a.example.com", "*.b.example.com"]


def test_precertificate_entry_is_read_from_extra_data():
    der = make_cert(["pre.example.com"])
    leaf = leaf_header(1) + b"\x00" * 32 + with_length(b"tbs") + b"\x00\x00"
    extra = with_length(der) + with_length(b"")
    assert domains_from_entry(b64(leaf), b64(extra)) == ["pre.example.com"]


def test_malformed_entries_are_ignored():
    assert domains_from_entry("not base64!", "") == []
    assert domains_from_entry("", "") == []
    assert domains_from_entry(b64(leaf_header(0) + with_length(b"garbage")), "") == []
    assert domains_from_entry(b64(leaf_header(7)), "") == []


def test_pick_logs_keeps_only_usable_current_logs():
    def entry(url, state, start, end):
        return {"url": url, "monitoring_url": url, "state": {state: {}},
                "temporal_interval": {"start_inclusive": start, "end_exclusive": end}}
    log_list = {"operators": [{
        "logs": [
            entry("https://current/", "usable", "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"),
            entry("https://future/", "usable", "2027-01-01T00:00:00Z", "2028-01-01T00:00:00Z"),
            entry("https://retired/", "retired", "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"),
            {"url": "https://broken/", "state": {"usable": {}}},
        ],
        "tiled_logs": [entry("https://tiled/", "usable", "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")],
    }]}
    now = datetime(2026, 11, 15, tzinfo=timezone.utc)
    assert pick_logs(log_list, now) == ["https://current/"]
    assert pick_logs(log_list, now, tiled=True) == ["https://tiled/"]


def test_tile_path():
    assert tile_path(5) == "005"
    assert tile_path(1234) == "x001/234"
    assert tile_path(1234067) == "x001/x234/067"


def tile_leaf(names: list[str], precert: bool) -> bytes:
    der = make_cert(names)
    timestamp, extensions, chain = (0).to_bytes(8, "big"), b"\x00\x00", (32).to_bytes(2, "big") + b"\x11" * 32
    if precert:
        return (timestamp + b"\x00\x01" + b"\x22" * 32 + with_length(b"tbs-bytes")
                + extensions + with_length(der) + chain)
    return timestamp + b"\x00\x00" + with_length(der) + extensions + chain


def test_tile_with_certificates_and_precertificates():
    tile = tile_leaf(["a.example.com"], False) + tile_leaf(["b.example.com", "c.example.com"], True)
    assert domains_from_tile(tile) == [["a.example.com"], ["b.example.com", "c.example.com"]]


def test_truncated_tile_keeps_the_complete_entries():
    tile = tile_leaf(["a.example.com"], False) + tile_leaf(["b.example.com"], True)[:-40]
    assert domains_from_tile(tile) == [["a.example.com"]]
    assert domains_from_tile(b"") == []
    assert domains_from_tile(b"\x00" * 5) == []
