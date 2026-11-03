#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ryu/OpenFlow 1.3 routing and microsegmentation controller for Python 3.

Example command:
    ryu-manager fattree_routing.py --verbose

THREE-TABLE PIPELINE
--------------------
    Table 0  POLICY    zero-trust ACL / microsegmentation (allow -> goto 1)
    Table 1  RESPONSE  graduated enforcement against misbehaving hosts
    Table 2  ROUTING   Fat-Tree two-level prefix/suffix forwarding

The response table sits BETWEEN policy and routing on purpose. Putting a
rate-limit rule in table 0 would have to jump straight to routing and would
therefore bypass the ACL entirely -- a throttled host would silently gain
full reachability. With a dedicated table, traffic must first be permitted
by the ACL, and only then is the host's enforcement tier applied.

GRADUATED RESPONSE
------------------
Detection is unchanged (sliding window of distinct destination IPs per
host, with a reputation-based dynamic window/threshold). What changed is
what happens when the detector fires:

    strike 0 -> first violation   : THROTTLE
                OpenFlow meter, drop band at self.rate_limit_kbps.
                The host stays connected and its permitted flows still
                work -- they are just bandwidth-limited. A scan is slowed
                to a crawl; a false positive is merely inconvenienced.

    strike >=1 -> repeat violation : QUARANTINE
                priority-200 drop in the response table. Full isolation.

Both tiers are temporary (hard_timeout) and both bump the strike count,
so a repeat offender also gets a tighter detection window next time.
strike_decay seconds of clean behaviour resets everything.

ALLOWLIST IS NOT A PRIVILEGE ESCALATION
---------------------------------------
self.trusted_sources exempts a host from scan detection only. It grants no
ACL exception of any kind, so a listed host's reachability is exactly what
it always was. A broad sweep from 10.0.1.2 is not counted as a horizontal
scan, and it still cannot reach anything it was not already allowed to.

The two service endpoints are listed for a different reason. The detector
counts distinct destination IPs per source, which cannot distinguish an
outbound scan from an inbound service answering many clients: every reply
a server sends is another distinct destination on its own record. Left
unexempted, the Core web server would throttle itself once five clients
contacted it inside one window -- a false positive produced entirely by
correct behaviour. Servers are destinations by design, never initiators,
so exempting them removes the false positive at its root.

Granting it cross-pod ICMP was considered and rejected: ICMP payloads are
not matchable in OpenFlow 1.3, so fabric-wide echo would hand a covert
channel to anyone who compromised the one host that the detector ignores.
Detection exemption plus wide reachability on the same host is a single
point of failure not worth the monitoring convenience at this scale.

METER SUPPORT: OVS only implements OpenFlow meters in the kernel datapath
from OVS 2.10 onwards. Check with `ovs-vsctl --version`. If meters are not
available the controller logs a clear warning and automatically falls back
to a no-meter throttle tier (RESTRICTED: same-pod traffic only, all
cross-pod traffic dropped) which conveys the same "partial, graduated"
semantics without needing meter support.

NOTE ON TIMER VALUES: the timers below are SHORTENED demo-speed values so
the verification script runs in under a minute. The design/report values
are 30s quarantine / 60s decay.
"""

from collections import deque
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls
)
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_3


class FatTreeRouting(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # ---- pipeline layout ----
    TABLE_POLICY = 0
    TABLE_RESPONSE = 1
    TABLE_ROUTING = 2

    # ---- priorities inside the response table ----
    PRIO_QUARANTINE = 200
    PRIO_THROTTLE = 100

    # Flow cookies make controller logs and flow-removed handling explicit.
    COOKIE_ALLOW = 0x100
    COOKIE_DENY = 0x200
    COOKIE_QUARANTINE = 0x300
    COOKIE_THROTTLE = 0x400

    def __init__(self, *args, **kwargs):
        super(FatTreeRouting, self).__init__(*args, **kwargs)
        self.k = 4
        self.half = self.k // 2

        # --- detection (reputation-based dynamic window) ---
        self.base_window = 10
        self.base_threshold = 5
        self.window_step = 2
        self.threshold_step = 1
        self.min_window = 4
        self.min_threshold = 2

        # --- graduated response timers (demo-speed; design = 30s / 60s) ---
        self.throttle_timeout = 10      # tier 1 duration
        self.quarantine_timeout = 10    # tier 2 duration
        self.strike_decay = 20          # clean time before reputation resets

        # --- tier 1 rate limit ---
        # 128 kbps still lets ICMP and a slow TCP session through, which is
        # exactly the point: the host is degraded, not disconnected.
        self.rate_limit_kbps = 128
        self.rate_limit_burst = 64      # kb
        self.use_meter_throttle = True  # auto-disabled if the switch rejects meters

        # Key: (edge_dpid, host_ingress_port, source_ip).
        # Value: deque[(timestamp, destination_ip)], trimmed to the active window.
        self.activity = {}
        self.throttled = {}
        self.quarantined = {}

        # Reputation, keyed by (edge_dpid, host_ingress_port) -- follows the
        # physical host regardless of which source IP triggered a strike.
        self.strikes = {}
        self.last_strike_time = {}

        # Meters already pushed to a switch: {(dpid, meter_id)}
        self.meters_installed = set()

        # Hosts exempt from scan detection (still fully subject to the
        # zero-trust ACL -- this bypasses the detector, not policy).
        #
        # The detector counts distinct destination IPs per source and cannot
        # tell an outbound scan from an inbound service answering many
        # clients. A server therefore accumulates targets simply by doing its
        # job: every reply it sends is another distinct destination. With
        # five clients inside one window, the Core web server would throttle
        # itself. Exempting the two service endpoints removes that false
        # positive at its root -- they are destinations by design, never
        # initiators -- while leaving their ACL obligations untouched.
        self.trusted_sources = {
            "10.0.1.2",  # h_0_1_2 -- monitoring host for the Core zone
            "10.0.0.2",  # core web server -- replies to many clients by design
            "10.0.0.3",  # IoT management server -- same
        }

    # ------------------------------------------------------------------
    # flow / meter helpers
    # ------------------------------------------------------------------

    def add_flow(self, datapath, priority, match, actions=None,
                 table_id=0, idle_timeout=0, hard_timeout=0,
                 flags=0, cookie=0, goto_table=None, meter_id=None):
        """Install an OpenFlow rule, optionally metered and/or followed by
        a table jump. Instruction order matters: Meter must precede
        Apply-Actions, which must precede Goto-Table."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        instructions = []

        if meter_id is not None:
            instructions.append(parser.OFPInstructionMeter(
                meter_id, ofproto.OFPIT_METER))

        if actions:
            instructions.append(
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions
                )
            )

        if goto_table is not None:
            instructions.append(parser.OFPInstructionGotoTable(goto_table))

        mod = parser.OFPFlowMod(
            datapath=datapath,
            table_id=table_id,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            flags=flags,
            cookie=cookie
        )
        datapath.send_msg(mod)

    def ensure_meter(self, datapath, meter_id):
        """Create the drop-band meter for this host port once per switch."""
        marker = (datapath.id, meter_id)
        if marker in self.meters_installed:
            return

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        band = parser.OFPMeterBandDrop(
            rate=self.rate_limit_kbps,
            burst_size=self.rate_limit_burst
        )
        mod = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS | ofproto.OFPMF_BURST,
            meter_id=meter_id,
            bands=[band]
        )
        datapath.send_msg(mod)
        self.meters_installed.add(marker)
        self.logger.info(
            "Meter created: switch=%016x meter_id=%d rate=%dkbps burst=%dkb",
            datapath.id, meter_id, self.rate_limit_kbps, self.rate_limit_burst
        )

    def controller_copy_action(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        return parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER
        )

    def decode_dpid(self, dpid):
        byte_1 = (dpid >> 16) & 0xff
        byte_2 = (dpid >> 8) & 0xff
        byte_3 = dpid & 0xff

        # Core switch DPID: 00:00:00:00:00:k:j:i
        if byte_1 == self.k:
            return {"type": "core", "j": byte_2, "i": byte_3}

        # Pod switch DPID: 00:00:00:00:00:pod:switch:01
        pod = byte_1
        switch = byte_2
        last = byte_3

        if last != 1 or pod >= self.k:
            return {"type": "unknown"}

        if switch < self.half:
            return {"type": "edge", "pod": pod, "switch": switch}

        return {"type": "aggregation", "pod": pod, "switch": switch}

    # ------------------------------------------------------------------
    # switch bring-up
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        switch_info = self.decode_dpid(dpid)

        self.logger.info("Switch connected: dpid=%016x, info=%s",
                         dpid, switch_info)

        if switch_info["type"] == "edge":
            self.install_response_default(datapath)
            self.install_edge_flows(datapath, switch_info["pod"],
                                    switch_info["switch"])
        elif switch_info["type"] == "aggregation":
            self.install_transit_pipeline(datapath)
            self.install_aggregation_flows(datapath, switch_info["pod"],
                                           switch_info["switch"])
        elif switch_info["type"] == "core":
            self.install_transit_pipeline(datapath)
            self.install_core_flows(datapath, switch_info["j"],
                                    switch_info["i"])
        else:
            self.logger.warning("Unknown switch DPID: %016x", dpid)

    def install_transit_pipeline(self, datapath):
        """Aggregation/core switches carry no policy and no per-host
        response state, so they jump straight from table 0 to routing."""
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        self.add_flow(datapath, 0, match,
                      table_id=self.TABLE_POLICY,
                      goto_table=self.TABLE_ROUTING)

    def install_response_default(self, datapath):
        """Table 1 default: no active response for this host -> forward on
        to routing. Throttle/quarantine rules sit above this at higher
        priority and are installed dynamically."""
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        self.add_flow(datapath, 0, match,
                      table_id=self.TABLE_RESPONSE,
                      goto_table=self.TABLE_ROUTING)

    def install_edge_flows(self, datapath, pod, edge):
        self.install_edge_policy_flows(datapath, pod, edge)
        self.install_edge_routing_flows(datapath, pod, edge)
        self.logger.info("Installed edge policy/routing flows: pod=%d edge=%d",
                         pod, edge)

    def install_edge_policy_flows(self, datapath, pod, edge):
        parser = datapath.ofproto_parser
        copy_action = self.controller_copy_action(datapath)

        # Uplink packets already passed policy at their source edge, and the
        # response tier is keyed to the source host's own access port, so
        # transit traffic goes straight to routing.
        for port in range(self.half + 1, self.k + 1):
            match = parser.OFPMatch(in_port=port)
            self.add_flow(datapath, 50, match,
                          table_id=self.TABLE_POLICY,
                          goto_table=self.TABLE_ROUTING)

        for host_index in range(self.half):
            in_port = host_index + 1
            source_ip = "10.%d.%d.%d" % (pod, edge, host_index + 2)

            # Same-pod communication is permitted.
            same_pod_net = "10.%d.0.0" % pod
            match = parser.OFPMatch(
                in_port=in_port,
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_dst=(same_pod_net, "255.255.0.0")
            )
            self.add_flow(datapath, 200, match, actions=[copy_action],
                          table_id=self.TABLE_POLICY,
                          cookie=self.COOKIE_ALLOW,
                          goto_table=self.TABLE_RESPONSE)

            # Operations may access only the Core web service on TCP/80.
            if pod == 1:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst="10.0.0.2",
                    ip_proto=6,
                    tcp_dst=80
                )
                self.add_flow(datapath, 300, match, actions=[copy_action],
                              table_id=self.TABLE_POLICY,
                              cookie=self.COOKIE_ALLOW,
                              goto_table=self.TABLE_RESPONSE)

            # IoT may access only the management service on TCP/8000.
            if pod == 3:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst="10.0.0.3",
                    ip_proto=6,
                    tcp_dst=8000
                )
                self.add_flow(datapath, 300, match, actions=[copy_action],
                              table_id=self.TABLE_POLICY,
                              cookie=self.COOKIE_ALLOW,
                              goto_table=self.TABLE_RESPONSE)

            # Service responses must be allowed in the reverse direction.
            if pod == 0 and edge == 0 and host_index == 0:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src="10.0.0.2",
                    ipv4_dst=("10.1.0.0", "255.255.0.0"),
                    ip_proto=6,
                    tcp_src=80
                )
                self.add_flow(datapath, 300, match, actions=[copy_action],
                              table_id=self.TABLE_POLICY,
                              cookie=self.COOKIE_ALLOW,
                              goto_table=self.TABLE_RESPONSE)

            if pod == 0 and edge == 0 and host_index == 1:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src="10.0.0.3",
                    ipv4_dst=("10.3.0.0", "255.255.0.0"),
                    ip_proto=6,
                    tcp_src=8000
                )
                self.add_flow(datapath, 300, match, actions=[copy_action],
                              table_id=self.TABLE_POLICY,
                              cookie=self.COOKIE_ALLOW,
                              goto_table=self.TABLE_RESPONSE)

            # All other IPv4 traffic from a host is denied but monitored.
            match = parser.OFPMatch(
                in_port=in_port,
                eth_type=ether_types.ETH_TYPE_IP
            )
            self.add_flow(datapath, 100, match,
                          actions=[self.controller_copy_action(datapath)],
                          table_id=self.TABLE_POLICY,
                          cookie=self.COOKIE_DENY)

            self.logger.debug("Installed policy for source host %s", source_ip)

    def install_edge_routing_flows(self, datapath, pod, edge):
        parser = datapath.ofproto_parser
        suffix_mask = "0.0.0.%d" % (self.half - 1)

        # Routing table: local host rules.
        for h in range(self.half):
            host_id = h + 2
            dst_ip = "10.%d.%d.%d" % (pod, edge, host_id)
            out_port = h + 1
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_dst=dst_ip
            )
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 100, match, actions,
                          table_id=self.TABLE_ROUTING)

        # Routing table: upward suffix rules.
        for host_id in range(2, self.half + 2):
            suffix_value = host_id & (self.half - 1)
            suffix_addr = "0.0.0.%d" % suffix_value
            out_port = ((host_id - 2 + edge) % self.half) + self.half + 1
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_dst=(suffix_addr, suffix_mask)
            )
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 10, match, actions,
                          table_id=self.TABLE_ROUTING)

    def install_aggregation_flows(self, datapath, pod, switch):
        parser = datapath.ofproto_parser
        suffix_mask = "0.0.0.%d" % (self.half - 1)

        for edge in range(self.half):
            dst_net = "10.%d.%d.0" % (pod, edge)
            out_port = edge + 1
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_dst=(dst_net, "255.255.255.0")
            )
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 100, match, actions,
                          table_id=self.TABLE_ROUTING)

        for host_id in range(2, self.half + 2):
            suffix_value = host_id & (self.half - 1)
            suffix_addr = "0.0.0.%d" % suffix_value
            out_port = ((host_id - 2 + switch) % self.half) + self.half + 1
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_dst=(suffix_addr, suffix_mask)
            )
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 10, match, actions,
                          table_id=self.TABLE_ROUTING)

        self.logger.info("Installed aggregation routing flows: pod=%d switch=%d",
                         pod, switch)

    def install_core_flows(self, datapath, j, i):
        parser = datapath.ofproto_parser

        for dst_pod in range(self.k):
            dst_net = "10.%d.0.0" % dst_pod
            out_port = dst_pod + 1
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_dst=(dst_net, "255.255.0.0")
            )
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 100, match, actions,
                          table_id=self.TABLE_ROUTING)

        self.logger.info("Installed core routing flows: j=%d i=%d", j, i)

    # ------------------------------------------------------------------
    # detection
    # ------------------------------------------------------------------

    def _effective_window_and_threshold(self, host_key, now):
        """Return (window, threshold) for this host, decaying strikes first."""
        strikes = self.strikes.get(host_key, 0)
        if strikes and now - self.last_strike_time.get(host_key, 0) > self.strike_decay:
            self.logger.info("Reputation decayed: host=%s strikes %d -> 0",
                             host_key, strikes)
            strikes = 0
            self.strikes.pop(host_key, None)
            self.last_strike_time.pop(host_key, None)

        window = max(self.min_window,
                     self.base_window - strikes * self.window_step)
        threshold = max(self.min_threshold,
                        self.base_threshold - strikes * self.threshold_step)
        return window, threshold

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Observe host-originated IPv4 attempts and detect horizontal scans.

        Allow and deny rules in table 0 both mirror a copy to the controller,
        so this sees permitted connections and policy-dropped attempts alike.
        The pipeline still decides whether the original packet is forwarded;
        monitoring cannot bypass microsegmentation.
        """
        msg = ev.msg
        datapath = msg.datapath
        switch_info = self.decode_dpid(datapath.id)

        if switch_info["type"] != "edge":
            return

        in_port = msg.match.get("in_port")
        if in_port is None or in_port > self.half:
            return

        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is None:
            return

        source_ip = ip_pkt.src
        destination_ip = ip_pkt.dst

        if source_ip in self.trusted_sources:
            self.logger.debug(
                "Trusted source %s exempt from scan detection "
                "(switch=%016x port=%d)",
                source_ip, datapath.id, in_port
            )
            return

        host_key = (datapath.id, in_port)
        key = (datapath.id, in_port, source_ip)
        now = time.time()

        window, threshold = self._effective_window_and_threshold(host_key, now)
        observations = self.activity.setdefault(key, deque())

        while observations and now - observations[0][0] > window:
            observations.popleft()

        known_destinations = set(item[1] for item in observations)
        if destination_ip not in known_destinations:
            observations.append((now, destination_ip))
            known_destinations.add(destination_ip)
            self.logger.info(
                "Observed IPv4 attempt: source=%s destination=%s "
                "switch=%016x port=%d unique_targets=%d "
                "window=%ds threshold=%d strikes=%d",
                source_ip, destination_ip, datapath.id, in_port,
                len(known_destinations), window, threshold,
                self.strikes.get(host_key, 0)
            )

        response_active = key in self.throttled or key in self.quarantined
        if len(known_destinations) >= threshold and not response_active:
            self.apply_graduated_response(
                datapath, in_port, source_ip, key, host_key, now)

    # ------------------------------------------------------------------
    # graduated response
    # ------------------------------------------------------------------

    def apply_graduated_response(self, datapath, in_port, source_ip,
                                 key, host_key, now):
        """Pick the enforcement tier from the host's record.

        First offence is met with degradation, not disconnection. Only a
        host that reoffends -- after having already been throttled once --
        is fully isolated. This keeps a single false positive cheap while
        still stopping a determined scanner.
        """
        prior_strikes = self.strikes.get(host_key, 0)

        # Record the strike first; both tiers count toward reputation.
        self.strikes[host_key] = prior_strikes + 1
        self.last_strike_time[host_key] = now
        strikes = self.strikes[host_key]

        next_window = max(self.min_window,
                          self.base_window - strikes * self.window_step)
        next_threshold = max(self.min_threshold,
                             self.base_threshold - strikes * self.threshold_step)

        if prior_strikes == 0:
            self.install_throttle(datapath, in_port, source_ip, key,
                                  strikes, next_window, next_threshold)
        else:
            self.install_quarantine(datapath, in_port, source_ip, key,
                                    strikes, next_window, next_threshold)

    def install_throttle(self, datapath, in_port, source_ip, key,
                         strikes, next_window, next_threshold):
        """TIER 1 -- degrade, do not disconnect.

        A metered rule in the response table rate-limits everything the ACL
        already permits from this host. Permitted services keep working at
        reduced speed; a scan becomes impractically slow.
        """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(
            in_port=in_port,
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=source_ip
        )

        if self.use_meter_throttle:
            meter_id = in_port  # unique per host access port on this switch
            self.ensure_meter(datapath, meter_id)
            self.add_flow(
                datapath, self.PRIO_THROTTLE, match,
                table_id=self.TABLE_RESPONSE,
                hard_timeout=self.throttle_timeout,
                flags=ofproto.OFPFF_SEND_FLOW_REM,
                cookie=self.COOKIE_THROTTLE,
                meter_id=meter_id,
                goto_table=self.TABLE_ROUTING
            )
            detail = "rate=%dkbps" % self.rate_limit_kbps
        else:
            # Fallback for switches without meter support: restrict the host
            # to its own pod. Same graduated semantics -- reduced privilege
            # rather than total isolation -- expressed purely with matches.
            pod = (datapath.id >> 16) & 0xff
            same_pod = ("10.%d.0.0" % pod, "255.255.0.0")

            allow_match = parser.OFPMatch(
                in_port=in_port,
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=source_ip,
                ipv4_dst=same_pod
            )
            self.add_flow(
                datapath, self.PRIO_THROTTLE + 10, allow_match,
                table_id=self.TABLE_RESPONSE,
                hard_timeout=self.throttle_timeout,
                cookie=self.COOKIE_THROTTLE,
                goto_table=self.TABLE_ROUTING
            )
            self.add_flow(
                datapath, self.PRIO_THROTTLE, match, actions=[],
                table_id=self.TABLE_RESPONSE,
                hard_timeout=self.throttle_timeout,
                flags=ofproto.OFPFF_SEND_FLOW_REM,
                cookie=self.COOKIE_THROTTLE
            )
            detail = "restricted to same pod (no meter support)"

        self.throttled[key] = True
        self.logger.warning(
            "TIER 1 THROTTLE: source=%s switch=%016x port=%d %s "
            "timeout=%ds strikes=%d next_window=%ds next_threshold=%d "
            "(host degraded, still connected)",
            source_ip, datapath.id, in_port, detail,
            self.throttle_timeout, strikes, next_window, next_threshold
        )

    def install_quarantine(self, datapath, in_port, source_ip, key,
                           strikes, next_window, next_threshold):
        """TIER 2 -- full isolation for a repeat offender.

        Priority above the throttle rule, matching only this host's ingress
        port and source IP, so other hosts and Core services are untouched.
        SEND_FLOW_REM reports expiry so in-memory state can be cleared.
        """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(
            in_port=in_port,
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=source_ip
        )

        self.add_flow(
            datapath, self.PRIO_QUARANTINE, match, actions=[],
            table_id=self.TABLE_RESPONSE,
            hard_timeout=self.quarantine_timeout,
            flags=ofproto.OFPFF_SEND_FLOW_REM,
            cookie=self.COOKIE_QUARANTINE
        )
        self.quarantined[key] = True
        self.logger.warning(
            "TIER 2 QUARANTINE: source=%s switch=%016x port=%d "
            "timeout=%ds strikes=%d next_window=%ds next_threshold=%d "
            "(repeat offender, fully isolated)",
            source_ip, datapath.id, in_port,
            self.quarantine_timeout, strikes, next_window, next_threshold
        )

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        if msg.cookie not in (self.COOKIE_QUARANTINE, self.COOKIE_THROTTLE):
            return

        match = msg.match
        source_ip = match.get("ipv4_src")
        in_port = match.get("in_port")
        if source_ip is None or in_port is None:
            return

        key = (msg.datapath.id, in_port, source_ip)
        self.activity.pop(key, None)

        if msg.cookie == self.COOKIE_QUARANTINE:
            self.quarantined.pop(key, None)
            tier = "TIER 2 quarantine"
        else:
            self.throttled.pop(key, None)
            tier = "TIER 1 throttle"

        self.logger.info(
            "%s expired: source=%s (strikes remain until %ds clean)",
            tier, source_ip, self.strike_decay
        )

    @set_ev_cls(ofp_event.EventOFPErrorMsg,
                [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        """Detect switches without meter support and fall back cleanly."""
        msg = ev.msg
        if msg.type == ofproto_v1_3.OFPET_METER_MOD_FAILED and self.use_meter_throttle:
            self.use_meter_throttle = False
            self.meters_installed.clear()
            self.logger.warning(
                "Meter rejected by switch (OFPET_METER_MOD_FAILED code=%s). "
                "OVS implements meters from 2.10 onwards -- check "
                "`ovs-vsctl --version`. Falling back to the no-meter "
                "throttle tier: throttled hosts are restricted to same-pod "
                "traffic instead of being rate-limited.",
                msg.code
            )
            return

        self.logger.warning("OpenFlow error: type=%s code=%s",
                            msg.type, msg.code)


# Mininet CLI checks:
# sh ovs-ofctl -O OpenFlow13 dump-flows e_2_0 table=0   # zero-trust ACL
# sh ovs-ofctl -O OpenFlow13 dump-flows e_2_0 table=1   # graduated response
# sh ovs-ofctl -O OpenFlow13 dump-flows e_2_0 table=2   # Fat-Tree routing
# sh ovs-ofctl -O OpenFlow13 dump-meters e_2_0
# sh ovs-ofctl -O OpenFlow13 meter-stats e_2_0
