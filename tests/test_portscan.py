"""Tests for portscan parsing and scanning logic."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from portscan import parse_ports, scan_port, COMMON_PORTS


def test_parse_single():
    assert parse_ports("22") == [22]


def test_parse_list():
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_parse_range():
    assert parse_ports("80-85") == [80, 81, 82, 83, 84, 85]


def test_parse_mixed():
    assert parse_ports("22,80,100-102") == [22, 80, 100, 101, 102]


def test_parse_dedupes_and_sorts():
    assert parse_ports("80,22,80") == [22, 80]


def test_common_ports_defined():
    assert 22 in COMMON_PORTS
    assert 443 in COMMON_PORTS


def test_scan_localhost_closed_port():
    # Port 1 is almost certainly closed
    assert scan_port("127.0.0.1", 1, timeout=0.5) is False


if __name__ == "__main__":
    test_parse_single()
    test_parse_list()
    test_parse_range()
    test_parse_mixed()
    test_parse_dedupes_and_sorts()
    test_common_ports_defined()
    test_scan_localhost_closed_port()
    print("All tests passed.")
