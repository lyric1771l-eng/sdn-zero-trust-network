#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fully automated demo of the graduated zero-trust response in
fattree_routing.py. One call, no manual ping typing.

    mininet> py __import__('verify_dynamic_window').verify_complete_demo(net)

FIVE checks, run back to back:

  1. TIER 1 THROTTLE — an unknown host scanning 5 distinct targets inside
     the base 10s window earns its first strike. The response is NOT a
     ban: a metered rule degrades it to rate_limit_kbps while leaving it
     connected. Verified two ways: its permitted same-pod traffic still
     gets through, AND a throttle flow (cookie 0x400) is present in the
     response table.
  2. TIER 2 QUARANTINE — once the throttle expires the SAME host reoffends
     with only 4 targets (its window/threshold tightened to 8s/4 after the
     first strike). Because it already has a strike on record, the response
     escalates to a full priority-200 drop. Now it really is cut off.
  3. PER-HOST ISOLATION — an innocent host sends the exact 4-target pattern
     that just quarantined the scanner, and nothing happens to it: its own
     reputation is clean, so it still needs 5 targets, not 4.
  4. TRUSTED WHITELIST — the designated trusted host sends a full 5-target
     broad probe, enough to trip anyone else, and is exempt entirely.
  5. RECOVERY — after strike_decay seconds clean, the scanner's reputation
     resets. The same 4-target pattern now produces NO response at all,
     not even a throttle. The penalty was temporary, not a permanent mark.

TWO RULES FOR CHECK TARGETS (both matter, both caused false results before):
  (a) same-pod address — the ACL permits same-pod traffic unconditionally,
      so it reads "blocked" only when a response-table rule is overriding
      it. A cross-pod address reads "blocked" from the ACL alone for hosts
      with no cross-pod privileges (Pod 2 / Guest), telling us nothing.
  (b) an address ALREADY in the probe set — a fresh address would add one
      more distinct destination and can itself trip the detector.

REACHABILITY ALONE IS NO LONGER SUFFICIENT. Under graduated response a
throttled host is still reachable, so steps 3 and 5 also assert that no
throttle/quarantine flow exists in the response table. Reachability plus
flow-table inspection together distinguish "no response" from "tier 1".

Assumes demo-speed timers in fattree_routing.py: throttle 10s,
quarantine 10s, strike decay 20s. Total runtime roughly 50 seconds.
"""

import re
import time

from mininet.log import info

# ---- Step 1, 2, 5: the attacker (Pod 2 / Guest) --------------------------
SCANNER = "h_2_0_3"
SCANNER_SWITCH = "e_2_0"          # edge switch this host is attached to

FIRST_ROUND_TARGETS = (
    "10.2.1.2",
    "10.0.0.2",
    "10.0.0.3",
    "10.1.0.2",
    "10.3.0.2",
)
FIRST_ROUND_CHECK_TARGET = "10.2.1.2"   # same pod, already in the list

SECOND_ROUND_TARGETS = (
    "10.1.1.2",
    "10.3.1.2",
    "10.0.1.2",
    "10.2.1.3",
)
SECOND_ROUND_CHECK_TARGET = "10.2.1.3"  # same pod, already in the list

# ---- Step 3: the innocent bystander --------------------------------------
ISOLATION_HOST = "h_1_0_2"              # normal client, Pod 1 / Operations
ISOLATION_SWITCH = "e_1_0"
ISOLATION_TARGETS = SECOND_ROUND_TARGETS
ISOLATION_CHECK_TARGET = "10.1.1.2"     # same pod, already in the list

# ---- Step 4: the trusted host --------------------------------------------
TRUSTED_HOST = "h_0_1_2"                # in FatTreeRouting.trusted_sources
TRUSTED_SWITCH = "e_0_1"
TRUSTED_TARGETS = (
    "10.2.1.2",
    "10.0.0.2",
    "10.0.0.3",
    "10.1.0.2",
    "10.3.0.2",
)
TRUSTED_CHECK_TARGET = "10.0.1.3"       # same pod; exempt hosts never count

RECOVERY_TARGETS = SECOND_ROUND_TARGETS
RECOVERY_CHECK_TARGET = SECOND_ROUND_CHECK_TARGET

# ---- must match fattree_routing.py ---------------------------------------
COOKIE_THROTTLE = "0x400"
COOKIE_QUARANTINE = "0x300"
RESPONSE_TABLE = 1

THROTTLE_TIMEOUT = 10
WAIT_FOR_RELEASE = 12    # > throttle_timeout
STRIKE_DECAY = 20
RECOVERY_BUFFER = 3


# ------------------------------------------------------------------------
# low-level helpers
# ------------------------------------------------------------------------

def _ping_once(host, destination_ip):
    output = host.cmd(
        "ping -c 1 -W 1 %s >/dev/null 2>&1; echo $?" % destination_ip
    ).strip()
    return output.endswith("0")


def _dump_response_table(net, switch_name):
    """Read the response table straight off the switch."""
    switch = net.get(switch_name)
    return switch.cmd(
        "ovs-ofctl -O OpenFlow13 dump-flows %s table=%d"
        % (switch_name, RESPONSE_TABLE)
    )


def _response_state(net, switch_name, source_ip):
    """Inspect this source only, excluding neighbours on the same switch."""
    dump = _dump_response_table(net, switch_name)
    pattern = r"\bnw_src=" + re.escape(source_ip) + r"(?:[,\s]|$)"
    flows = [line for line in dump.splitlines() if re.search(pattern, line)]
    return (any(COOKIE_THROTTLE in line for line in flows),
            any(COOKIE_QUARANTINE in line for line in flows))


def _describe_response(has_throttle, has_quarantine):
    if has_quarantine:
        return "TIER 2 (quarantine drop)"
    if has_throttle:
        return "TIER 1 (metered throttle)"
    return "none"


def _meter_summary(net, switch_name):
    """Read the meter config so the demo can quote the actual rate."""
    switch = net.get(switch_name)
    dump = switch.cmd("ovs-ofctl -O OpenFlow13 dump-meters %s" % switch_name)
    match = re.search(r"drop\s+(?:burst\s+)?kbps\s+rate=(\d+)", dump)
    if match:
        return "meter present, rate=%skbps" % match.group(1)
    if "meter=" in dump:
        return "meter present"
    return "no meter (fallback mode or unsupported)"


def _probe(net, host_name, targets, label):
    host = net.get(host_name)
    info("*** [%s] sending probes to %d distinct targets\n"
         % (label, len(targets)))
    for target in targets:
        replied = _ping_once(host, target)
        info("*** [%s] probe: %s -> %s (%s)\n" % (
            label, host_name, target,
            "reply" if replied else "blocked/no reply"))


def _check(net, host_name, switch_name, check_target, label):
    """Return (reachable, has_throttle, has_quarantine)."""
    time.sleep(1)  # let Packet-In / Flow-Mod settle
    reachable = _ping_once(net.get(host_name), check_target)
    has_throttle, has_quarantine = _response_state(net, switch_name, net.get(host_name).IP())
    info("*** [%s] post-probe check: %s -> %s is %s | response tier on %s: %s\n\n"
         % (label, host_name, check_target,
            "reachable" if reachable else "blocked",
            switch_name, _describe_response(has_throttle, has_quarantine)))
    return reachable, has_throttle, has_quarantine


# ------------------------------------------------------------------------
# main
# ------------------------------------------------------------------------

def verify_complete_demo(net):
    """Single entry point. Runs all five checks and prints a PASS/FAIL
    matrix. Total runtime roughly 50 seconds."""
    results = {}

    info("\n============ STEP 1/5: TIER 1 — THROTTLE, NOT BAN ============\n")
    info("*** %s scans 5 distinct targets: first strike. Expect the host to "
         "be DEGRADED but still connected.\n" % SCANNER)
    _probe(net, SCANNER, FIRST_ROUND_TARGETS, "THROTTLE")
    reachable, throttled, quarantined = _check(
        net, SCANNER, SCANNER_SWITCH, FIRST_ROUND_CHECK_TARGET, "THROTTLE")
    info("*** [THROTTLE] %s\n\n" % _meter_summary(net, SCANNER_SWITCH))
    # Tier 1 = throttle rule installed, no quarantine, host still reachable.
    results["tier1_throttle"] = throttled and not quarantined and reachable

    info("*** waiting %ds for the throttle to expire "
         "(strike stays at 1, strike_decay=%ds)...\n\n"
         % (WAIT_FOR_RELEASE, STRIKE_DECAY))
    time.sleep(WAIT_FOR_RELEASE)

    info("============ STEP 2/5: TIER 2 — ESCALATE TO QUARANTINE ============\n")
    info("*** %s reoffends with only 4 targets (window now 8s, threshold 4). "
         "Having a strike on record, the response escalates to full "
         "isolation.\n" % SCANNER)
    _probe(net, SCANNER, SECOND_ROUND_TARGETS, "QUARANTINE")
    t_last_strike = time.time()
    reachable, throttled, quarantined = _check(
        net, SCANNER, SCANNER_SWITCH, SECOND_ROUND_CHECK_TARGET, "QUARANTINE")
    results["tier2_quarantine"] = quarantined and not reachable

    info("============ STEP 3/5: PER-HOST ISOLATION ============\n")
    info("*** %s repeats the exact 4-target pattern that just quarantined "
         "%s, but has a clean reputation of its own\n"
         % (ISOLATION_HOST, SCANNER))
    _probe(net, ISOLATION_HOST, ISOLATION_TARGETS, "ISOLATION")
    reachable, throttled, quarantined = _check(
        net, ISOLATION_HOST, ISOLATION_SWITCH, ISOLATION_CHECK_TARGET,
        "ISOLATION")
    results["isolation"] = reachable and not throttled and not quarantined

    info("============ STEP 4/5: TRUSTED WHITELIST ============\n")
    info("*** %s sends a full 5-target broad probe, enough to trip anyone "
         "else, but is listed in trusted_sources\n" % TRUSTED_HOST)
    _probe(net, TRUSTED_HOST, TRUSTED_TARGETS, "TRUSTED")
    reachable, throttled, quarantined = _check(
        net, TRUSTED_HOST, TRUSTED_SWITCH, TRUSTED_CHECK_TARGET, "TRUSTED")
    results["trusted_whitelist"] = reachable and not throttled and not quarantined

    info("============ STEP 5/5: RECOVERY (strike decay) ============\n")
    elapsed = time.time() - t_last_strike
    remaining = (STRIKE_DECAY + RECOVERY_BUFFER) - elapsed
    if remaining > 0:
        info("*** waiting %.0fs more so %s goes strike_decay=%ds clean since "
             "its last strike...\n" % (remaining, SCANNER, STRIKE_DECAY))
        time.sleep(remaining)
    info("*** %s repeats the SAME 4-target pattern. Reputation has decayed "
         "to base (window 10s, threshold 5), so 4 targets should produce NO "
         "response at all — not even a tier 1 throttle.\n" % SCANNER)
    _probe(net, SCANNER, RECOVERY_TARGETS, "RECOVERY")
    reachable, throttled, quarantined = _check(
        net, SCANNER, SCANNER_SWITCH, RECOVERY_CHECK_TARGET, "RECOVERY")
    results["recovery"] = reachable and not throttled and not quarantined

    info("============ SUMMARY ============\n")
    labels = (
        ("tier1_throttle",
         "1. Tier 1 throttle  (5 targets -> degraded, still connected)"),
        ("tier2_quarantine",
         "2. Tier 2 escalation (repeat offence -> fully isolated)"),
        ("isolation",
         "3. Per-host isolation (innocent host: no response tier)"),
        ("trusted_whitelist",
         "4. Trusted whitelist (exempt host: no response tier)"),
        ("recovery",
         "5. Recovery after decay (same pattern -> no response at all)"),
    )
    all_pass = True
    for key, text in labels:
        passed = results[key]
        all_pass = all_pass and passed
        info("*** [%s] %s\n" % ("PASS" if passed else "FAIL", text))
    info("*** ---------------------------------------------\n")
    info("*** OVERALL: %s\n\n" % ("PASS" if all_pass else "FAIL"))
    return all_pass
