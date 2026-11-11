"""Every shipped rule, checked against real output captured from the lab hosts."""

from __future__ import annotations

import pytest

from infra_discovery.dsl import Rule
from infra_discovery.engine import analyze
from infra_discovery.models import RawScan


def by_name(rules: list[Rule], name: str) -> Rule:
    return next(r for r in rules if r.name == name)


@pytest.mark.parametrize(
    ("host", "os_name", "os_version", "pkg"),
    [
        ("web", "Debian GNU/Linux", "13", "dpkg"),
        ("db", "Rocky Linux", "9.8", "rpm"),
        ("cache", "Alpine Linux", "3.22.8", "apk"),
        ("app", "Alpine Linux", "3.22.8", "apk"),
    ],
)
def test_os(rules: list[Rule], raws: dict[str, RawScan], host: str, os_name: str, os_version: str, pkg: str) -> None:
    inv = analyze(raws[host], rules)
    assert inv.host.name == host
    assert inv.host.attrs["os_name"] == os_name
    assert inv.host.attrs["os_version"] == os_version
    assert inv.host.attrs["os_family"] == "Linux"
    assert inv.host.attrs["package_manager"] == pkg
    assert inv.host.attrs["arch"] == "x86_64"
    assert inv.host.attrs["kernel"]


@pytest.mark.parametrize(
    ("rule", "host", "version"),
    [
        ("nginx", "web", "1.26.3"),
        ("postgresql", "db", "13.23"),
        ("redis", "cache", "8.0.4"),
        ("redis_cli", "app", "8.0.4"),
        ("psql_client", "app", "17.11"),
        ("sshd", "web", "10.0p1"),
        ("sshd", "db", "9.9p1"),
        ("sshd", "cache", "10.0_p1"),
    ],
)
def test_software_rule_fires(rules: list[Rule], raws: dict[str, RawScan], rule: str, host: str, version: str) -> None:
    attrs = by_name(rules, rule).evaluate(raws[host].outputs)
    assert attrs is not None
    assert attrs["version"] == version


@pytest.mark.parametrize(
    ("rule", "host"),
    [("nginx", "db"), ("postgresql", "app"), ("redis", "app"), ("redis_cli", "cache"), ("psql_client", "db")],
)
def test_software_rule_does_not_fire(rules: list[Rule], raws: dict[str, RawScan], rule: str, host: str) -> None:
    assert by_name(rules, rule).evaluate(raws[host].outputs) is None


def test_postgres_extra_attr(rules: list[Rule], raws: dict[str, RawScan]) -> None:
    attrs = by_name(rules, "postgresql").evaluate(raws["db"].outputs)
    assert attrs is not None
    assert attrs["data_dir"] == "/var/lib/pgsql/data"


def test_rpm_and_dpkg_package_formats(rules: list[Rule]) -> None:
    redis = by_name(rules, "redis")
    assert redis.evaluate({"ps": "1 redis redis-server *:6379", "packages": "redis 7.2.4\n"}) == {
        "name": "redis",
        "process": "redis-server",
        "ports": "6379",
        "category": "key-value store",
        "version": "7.2.4",
    }
    attrs = redis.evaluate({"ps": "1 redis redis-server *:6379", "packages": "redis-server 5:7.0.15-1\n"})
    assert attrs is not None
    assert attrs["version"] == "7.0.15"
