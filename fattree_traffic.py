#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate repeatable traffic for the Fat-Tree microsegmentation demo.

This module does not create Mininet itself. It receives the running ``Mininet``
object from ``fattree_topo.py`` and executes commands in separate host network
namespaces.

The demonstration covers six requirements:
1. normal access: an Operations host is allowed to access Core Web;
2. blocked unauthorized request: policy blocks a Guest host from that service;
3. simulated scan: another Guest host rapidly probes five destination IPs;
4. tier 1 response: the first offence throttles that scanner without cutting
   it off -- it stays reachable, but rate-limited by an OpenFlow meter;
5. tier 2 response: the same host reoffends and is escalated to a full
   quarantine drop, now that it has a strike on record;
6. continued availability: another authorized host can still access Core Web.

Items 3, 4 and 5 must use the same host. Both response rules are installed for
the source switch port and source IP; testing a different host would not prove
that the scanner itself was acted upon automatically.

WHY REACHABILITY ALONE IS NOT ENOUGH
------------------------------------
Under graduated response a throttled host is still reachable, so a successful
ping no longer proves the absence of enforcement. Each check therefore also
reads the switch's response table (table 1) and identifies the active tier by
flow cookie: 0x400 = throttle, 0x300 = quarantine, absent = no response.
"""

import time

from mininet.log import info


# ---------------------------------------------------------------------------
# Demonstration role assignment
# ---------------------------------------------------------------------------
# Pod 0 = Core Services, Pod 1 = Operations, Pod 2 = Guest, Pod 3 = IoT.
# Different source hosts are used for independent business behaviors so that
# connection state from one scenario does not affect the next. The scanner is
# reused for the response tiers for the reason documented above.
NORMAL_CLIENT = "h_1_0_2"
UNAUTHORIZED_CLIENT = "h_2_0_2"
SCANNER_AND_QUARANTINED_HOST = "h_2_0_3"
SCANNER_EDGE_SWITCH = "e_2_0"          # edge switch the scanner is attached to
AVAILABILITY_CLIENT = "h_1_1_2"
TRUSTED_HOST = "h_0_1_2"               # listed in FatTreeRouting.trusted_sources
TRUSTED_EDGE_SWITCH = "e_0_1"
TRUSTED_CHECK_TARGET = "10.0.1.3"      # same pod as the trusted host

CORE_WEB_IP = "10.0.0.2"
CORE_WEB_PORT = 80

# ---- must match fattree_routing.py ----------------------------------------
RESPONSE_TABLE = 1
COOKIE_THROTTLE = "0x400"
COOKIE_QUARANTINE = "0x300"
THROTTLE_TIMEOUT = 10      # self.throttle_timeout
WAIT_FOR_RELEASE = 12      # > THROTTLE_TIMEOUT, < strike_decay (20s)

# These five unique destinations span several security zones. By default, the
# controller acts after one host contacts five unique destination IP addresses
# within a 10-second window.
SCAN_TARGETS = (
    # The first target shares the Guest Pod with the scanner and is permitted
    # by the same-pod allow rule. Re-probing it later is what distinguishes
    # "throttled but connected" from "quarantined", because the ACL itself
    # never blocks it -- only a response-table rule can.
    "10.2.1.2",
    "10.0.0.2",  # Core Web
    "10.0.0.3",  # Core/IoT management endpoint
    "10.1.0.2",  # Operations
    "10.3.0.2",  # IoT
)

# Four targets only. Below the base threshold of five, but at or above the
# tightened threshold of four that applies once the host has one strike.
REOFFENCE_TARGETS = (
    "10.1.1.2",
    "10.3.1.2",
    "10.0.1.2",
    "10.2.1.3",
)
REOFFENCE_CHECK_TARGET = "10.2.1.3"    # same pod, already in the list above


def _http_status(host, destination_ip, destination_port):
    """Return the HTTP status code as a string using Python 3's stdlib.

    ``000`` means that no HTTP response arrived before the timeout. The short
    timeout prevents policy-dropped packets from stalling the automated demo.
    ``urllib`` is used instead of curl because minimal Mininet images may not
    include curl.
    """
    command = (
        "python3 -c \"import urllib.request; "
        "print(urllib.request.urlopen('http://%s:%d/', timeout=2).status)\" "
        "2>/dev/null || echo 000"
        % (destination_ip, destination_port)
    )
    return host.cmd(command).strip()


def _ping_once(host, destination_ip):
    """Send exactly one IPv4 probe and return True only if it receives a reply."""
    output = host.cmd(
        "ping -c 1 -W 1 %s >/dev/null 2>&1; echo $?" % destination_ip
    ).strip()
    return output.endswith("0")


def _response_state(net, switch_name, source_ip):
    """Read the response table off the switch: (has_throttle, has_quarantine).

    Filtered to one source IP. Several demo hosts share an edge switch --
    h_2_0_2 and h_2_0_3 both sit on e_2_0 -- so an unfiltered cookie search
    could report another host's enforcement as this one's. ovs-ofctl renders
    an ipv4_src match as ``nw_src=<addr>``, so a plain substring test on each
    flow line is enough to isolate this host's rules.
    """
    switch = net.get(switch_name)
    dump = switch.cmd(
        "ovs-ofctl -O OpenFlow13 dump-flows %s table=%d"
        % (switch_name, RESPONSE_TABLE)
    )
    mine = "\n".join(line for line in dump.splitlines() if source_ip in line)
    return (COOKIE_THROTTLE in mine, COOKIE_QUARANTINE in mine)


def _describe_tier(has_throttle, has_quarantine):
    if has_quarantine:
        return "TIER 2 (quarantine drop)"
    if has_throttle:
        return "TIER 1 (metered throttle)"
    return "none"


def _probe_targets(host, host_name, targets, label):
    """Send one probe to each target, logging every result."""
    replies = {}
    for target in targets:
        replied = _ping_once(host, target)
        replies[target] = replied
        info("*** %s probe: %s -> %s (%s)\n" % (
            label, host_name, target,
            "reply" if replied else "blocked/no reply"
        ))
    return replies


def _show_result(title, passed, detail):
    """Print one consistently formatted PASS/FAIL result in the Mininet log."""
    state = "PASS" if passed else "FAIL"
    info("*** [%s] %s: %s\n" % (state, title, detail))
    return passed


def run_traffic_demo(net):
    """Run all six traffic scenarios and return True when every check passes."""
    normal = net.get(NORMAL_CLIENT)
    unauthorized = net.get(UNAUTHORIZED_CLIENT)
    scanner = net.get(SCANNER_AND_QUARANTINED_HOST)
    availability = net.get(AVAILABILITY_CLIENT)
    scanner_ip = scanner.IP()

    info("\n*** Starting automated microsegmentation traffic demo\n")
    info("*** normal client:       %s\n" % NORMAL_CLIENT)
    info("*** unauthorized client: %s\n" % UNAUTHORIZED_CLIENT)
    info("*** scanner/offender:    %s (%s, edge %s)\n"
         % (SCANNER_AND_QUARANTINED_HOST, scanner_ip, SCANNER_EDGE_SWITCH))
    info("*** availability client: %s\n\n" % AVAILABILITY_CLIENT)

    # Give the background http.server processes a moment to accept connections.
    time.sleep(1)
    results = []

    # 1) Normal access: Pod 1 (Operations) -> Core Web TCP/80 is allow-listed.
    status = _http_status(normal, CORE_WEB_IP, CORE_WEB_PORT)
    results.append(_show_result(
        "normal access",
        status == "200",
        "%s -> http://%s:%d returned HTTP %s"
        % (NORMAL_CLIENT, CORE_WEB_IP, CORE_WEB_PORT, status or "no response")
    ))

    # 2) Unauthorized request: Pod 2 (Guest) cannot access the Core service.
    # The client should receive no HTTP response, producing 000 or an empty value.
    status = _http_status(unauthorized, CORE_WEB_IP, CORE_WEB_PORT)
    results.append(_show_result(
        "blocked unauthorized request",
        status in ("000", ""),
        "%s -> http://%s:%d returned HTTP %s (expected 000)"
        % (UNAUTHORIZED_CLIENT, CORE_WEB_IP, CORE_WEB_PORT,
           status or "no response")
    ))

    # 3) Simulated scan: rapidly send one probe to each of five unique IPs.
    # A reply is not required because the controller observes attempted access
    # to distinct destinations. Each ping waits at most one second, keeping the
    # sequence within the 10-second detection window.
    info("\n*** scenario 3: simulated scan (5 distinct targets)\n")
    scan_replies = _probe_targets(
        scanner, SCANNER_AND_QUARANTINED_HOST, SCAN_TARGETS, "scan")
    results.append(_show_result(
        "simulated scan",
        scan_replies[SCAN_TARGETS[0]],
        "%s sent probes to %d unique targets; pre-response same-pod "
        "reachability=%s"
        % (SCANNER_AND_QUARANTINED_HOST, len(SCAN_TARGETS),
           "reachable" if scan_replies[SCAN_TARGETS[0]] else "unreachable")
    ))

    # 4) Tier 1: the first offence degrades the host rather than banning it.
    # Packet-In and Flow-Mod processing is asynchronous, so allow one second for
    # Ryu to install the metered rule. The host must remain reachable -- that is
    # the whole point of the tier -- so the proof is the flow table, not a ping.
    time.sleep(1)
    same_pod_target = SCAN_TARGETS[0]
    still_reachable = _ping_once(scanner, same_pod_target)
    throttled, quarantined = _response_state(
        net, SCANNER_EDGE_SWITCH, scanner_ip)
    results.append(_show_result(
        "tier 1 throttle (degraded, not disconnected)",
        throttled and not quarantined and still_reachable,
        "%s -> %s is %s; response tier on %s is %s"
        % (SCANNER_AND_QUARANTINED_HOST, same_pod_target,
           "reachable" if still_reachable else "blocked",
           SCANNER_EDGE_SWITCH, _describe_tier(throttled, quarantined))
    ))

    info("\n*** waiting %ds for the throttle to expire; the strike stays on "
         "record\n" % WAIT_FOR_RELEASE)
    time.sleep(WAIT_FOR_RELEASE)

    # 5) Tier 2: the same host reoffends. It now carries one strike, so its
    # detection window has tightened to 8s/4 targets AND its response escalates
    # from throttle to a full quarantine drop.
    info("\n*** scenario 5: reoffence (only 4 targets, tightened window)\n")
    _probe_targets(scanner, SCANNER_AND_QUARANTINED_HOST,
                   REOFFENCE_TARGETS, "reoffence")
    time.sleep(1)
    now_blocked = not _ping_once(scanner, REOFFENCE_CHECK_TARGET)
    throttled, quarantined = _response_state(
        net, SCANNER_EDGE_SWITCH, scanner_ip)
    results.append(_show_result(
        "tier 2 escalation (repeat offender fully isolated)",
        quarantined and now_blocked,
        "%s -> %s is %s after only %d targets; response tier on %s is %s"
        % (SCANNER_AND_QUARANTINED_HOST, REOFFENCE_CHECK_TARGET,
           "blocked" if now_blocked else "still reachable",
           len(REOFFENCE_TARGETS), SCANNER_EDGE_SWITCH,
           _describe_tier(throttled, quarantined))
    ))

    # 6) Continued availability: both response tiers match only the scanner's
    # ingress port and source IP. Neither may affect another Operations host or
    # interrupt the Core Web service.
    status = _http_status(availability, CORE_WEB_IP, CORE_WEB_PORT)
    results.append(_show_result(
        "continued availability of the core service",
        status == "200",
        "%s -> http://%s:%d returned HTTP %s while the scanner is quarantined"
        % (AVAILABILITY_CLIENT, CORE_WEB_IP, CORE_WEB_PORT,
           status or "no response")
    ))

    passed = all(results)
    info("\n*** Demo result: %s (%d/%d checks passed)\n\n" % (
        "PASS" if passed else "FAIL",
        sum(1 for result in results if result),
        len(results)
    ))
    return passed


def run_trusted_source_demo(net):
    """Optional scenario: an allowlist relaxes detection, not privilege.

    The trusted host sends the same broad five-target probe that just cost the
    scanner a strike. It is never acted upon -- and its probe results are
    unchanged from any other Pod 0 host, because ``trusted_sources`` grants no
    ACL exception whatsoever.

        mininet> py __import__('fattree_traffic').run_trusted_source_demo(net)
    """
    trusted = net.get(TRUSTED_HOST)
    trusted_ip = trusted.IP()

    info("\n*** Trusted-source scenario\n")
    info("*** %s (%s) is exempt from scan detection but holds no extra ACL "
         "rights\n" % (TRUSTED_HOST, trusted_ip))

    _probe_targets(trusted, TRUSTED_HOST, SCAN_TARGETS, "trusted")
    time.sleep(1)

    reachable = _ping_once(trusted, TRUSTED_CHECK_TARGET)
    throttled, quarantined = _response_state(
        net, TRUSTED_EDGE_SWITCH, trusted_ip)
    passed = reachable and not throttled and not quarantined

    _show_result(
        "trusted source exempt from detection",
        passed,
        "%s -> %s is %s; response tier on %s is %s"
        % (TRUSTED_HOST, TRUSTED_CHECK_TARGET,
           "reachable" if reachable else "blocked",
           TRUSTED_EDGE_SWITCH, _describe_tier(throttled, quarantined))
    )
    info("*** note: its cross-pod probes still failed -- the allowlist "
         "bypasses the detector, never the policy\n\n")
    return passed
