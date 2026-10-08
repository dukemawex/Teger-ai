"""SSRF regression tests for the outbound-destination guard."""
import ipaddress

import pytest

from teger_security_core.netguard import (
    DestinationBlocked, check_destination, is_forbidden_ip, validate_redirect,
)


def resolver_for(*answers):
    return lambda host, port: list(answers)


def failing_resolver(host, port):
    raise AssertionError("resolver must not be called")


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "10.0.0.1", "172.16.5.4", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
    "224.0.0.1", "255.255.255.255", "192.0.2.10", "198.18.0.1", "::1", "fe80::1", "fc00::1", "fec0::1",
    "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "2002:7f00:1::", "ff02::1", "::",
])
def test_forbidden_ips(ip):
    assert is_forbidden_ip(ipaddress.ip_address(ip))


@pytest.mark.parametrize("ip", ["93.184.216.34", "8.8.8.8", "2606:4700:4700::1111"])
def test_public_ips_allowed(ip):
    assert not is_forbidden_ip(ipaddress.ip_address(ip))


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://2130706433/", "http://0x7f.1/", "http://[::ffff:169.254.169.254]/",
    "http://169.254.169.254/latest/meta-data/", "http://localhost/", "http://app.localhost/",
    "http://metadata.google.internal/", "http://printer.local/", "http://intranet/",
])
def test_blocks_private_literals_and_internal_names_without_dns(url):
    with pytest.raises(DestinationBlocked):
        check_destination(url, resolver=failing_resolver)


def test_blocks_dns_answer_pointing_to_private_network():
    with pytest.raises(DestinationBlocked):
        check_destination("https://rebind.example/", resolver=resolver_for("10.1.2.3"))


def test_blocks_mixed_public_and_private_answers():
    with pytest.raises(DestinationBlocked):
        check_destination("https://mixed.example/", resolver=resolver_for("93.184.216.34", "127.0.0.1"))


def test_blocks_scoped_ipv6_answer():
    with pytest.raises(DestinationBlocked):
        check_destination("https://scoped.example/", resolver=resolver_for("fe80::1%eth0"))


def test_blocks_resolution_failure():
    def boom(host, port):
        raise OSError("nxdomain")
    with pytest.raises(DestinationBlocked):
        check_destination("https://nx.example/", resolver=boom)


def test_blocks_userinfo_and_odd_ports():
    with pytest.raises(DestinationBlocked):
        check_destination("https://user:pw@public.example/", resolver=resolver_for("93.184.216.34"))
    with pytest.raises(DestinationBlocked):
        check_destination("https://public.example:6379/", resolver=resolver_for("93.184.216.34"))


def test_allows_public_destination_and_returns_pinned_ips():
    ips = check_destination("https://public.example/", resolver=resolver_for("93.184.216.34"))
    assert ips == [ipaddress.ip_address("93.184.216.34")]


def test_redirect_to_private_address_blocked():
    with pytest.raises(DestinationBlocked):
        validate_redirect("https://public.example/", "http://127.0.0.1/admin", 0, resolver=failing_resolver)


def test_relative_redirect_resolved_and_rechecked():
    parsed, _ = validate_redirect("https://public.example/a", "/b", 0, resolver=resolver_for("93.184.216.34"))
    assert parsed.normalized == "https://public.example/b"
    with pytest.raises(DestinationBlocked):
        validate_redirect("https://public.example/a", "/b", 0, resolver=resolver_for("192.168.0.1"))


def test_redirect_downgrade_and_loop_limit():
    with pytest.raises(DestinationBlocked):
        validate_redirect("https://public.example/", "http://public.example/", 0, resolver=resolver_for("8.8.8.8"))
    with pytest.raises(DestinationBlocked):
        validate_redirect("https://public.example/", "/next", 5, resolver=resolver_for("8.8.8.8"))


def test_redirect_to_dangerous_scheme_blocked():
    with pytest.raises(DestinationBlocked):
        validate_redirect("https://public.example/", "javascript:alert(1)", 0, resolver=failing_resolver)
