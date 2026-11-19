import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from beacon_hunter.cli import main
from beacon_hunter.detector import BeaconDetector, Settings, classify, looks_like_text

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "beacon_sample.pcap"
T0 = datetime(2026, 11, 18, 19, 55, 0)


def feed(detector, offsets, dst="10.0.0.5", port=9000):
    events = []
    for i, off in enumerate(offsets):
        events.append(detector.on_connection(T0 + timedelta(seconds=off), "10.0.0.23", 50000 + i, dst, port))
    return events


def test_regular_series_is_periodic_from_third_connection():
    events = feed(BeaconDetector(), [0, 30, 60, 90, 120])
    assert [e.periodic for e in events] == [False, False, True, True, True]
    assert events[-1].mean == pytest.approx(30.0)
    assert events[-1].cv == pytest.approx(0.0)


def test_source_port_changes_do_not_split_the_flow():
    detector = BeaconDetector()
    feed(detector, [0, 30, 60])
    assert len(detector.flows) == 1


def test_irregular_series_is_not_periodic():
    events = feed(BeaconDetector(), [0, 3, 40, 41, 95, 180])
    assert not events[-1].periodic


def test_jitter_within_tolerance_is_still_periodic():
    events = feed(BeaconDetector(), [0, 57, 120, 178, 241, 300])  # cerca de 60 s com 5% de jitter
    assert events[-1].periodic


def test_tolerance_is_configurable():
    offsets = [0, 30, 75, 100, 150, 180]  # cv perto de 25%
    assert not feed(BeaconDetector(Settings(max_cv=0.15)), offsets)[-1].periodic
    assert feed(BeaconDetector(Settings(max_cv=0.35)), offsets)[-1].periodic


def test_bursts_below_min_interval_are_ignored():
    events = feed(BeaconDetector(), [0, 0.2, 0.4, 0.6, 0.8])
    assert not events[-1].periodic


def test_flows_are_independent():
    detector = BeaconDetector()
    feed(detector, [0, 30, 60, 90], port=9000)
    feed(detector, [5, 9, 50, 51], port=443)
    verdicts = {s.dst_port: s.periodic for s in detector.summaries()}
    assert verdicts == {9000: True, 443: False}


def test_payload_is_attached_to_its_connection():
    detector = BeaconDetector()
    event = detector.on_connection(T0, "10.0.0.23", 50001, "10.0.0.5", 9000)
    detector.on_payload("10.0.0.23", 50001, "10.0.0.5", 9000, b"Host=WS-LAB01 | Usuario=aluno")
    assert event.payload_text.startswith("Host=WS-LAB01")
    assert event.cleartext is True


def test_payload_from_unknown_connection_is_ignored():
    detector = BeaconDetector()
    assert detector.on_payload("10.0.0.23", 1, "10.0.0.5", 9000, b"x") is None


def test_text_heuristic():
    assert looks_like_text(b"Host=lab | Sistema=Windows")
    assert not looks_like_text(bytes(range(256)))
    assert not looks_like_text(b"")


def test_classify_needs_min_events():
    periodic, *_ = classify([30.0], Settings(min_events=3))
    assert not periodic


@pytest.mark.skipif(not SAMPLE.exists(), reason="rode samples/generate_sample.py antes")
def test_sample_pcap_end_to_end(tmp_path, capsys):
    db = tmp_path / "beacons.db"
    out = tmp_path / "out.json"
    assert main(["-r", str(SAMPLE), "--db", str(db), "--json", str(out), "--no-color", "-q"]) == 0

    conn = sqlite3.connect(db)
    rows = conn.execute(
        "SELECT dst_ip, dst_port, COUNT(*) FROM detections WHERE periodic = 1 GROUP BY dst_ip, dst_port ORDER BY dst_port"
    ).fetchall()
    assert rows == [("203.0.113.50", 443, 8), ("10.10.0.5", 9000, 10)]
    lab_payload = conn.execute(
        "SELECT payload FROM detections WHERE dst_port = 9000 AND payload IS NOT NULL LIMIT 1"
    ).fetchone()[0]
    assert "Host=WS-LAB01" in lab_payload
    assert out.exists()
