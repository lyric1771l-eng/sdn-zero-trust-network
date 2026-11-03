#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from mininet.topo import Topo # custom topology base class
from mininet.net import Mininet # create and run network
from mininet.node import RemoteController, OVSSwitch # external controller and Open vSwitch
from mininet.link import TCLink # link type with TC support
from mininet.cli import CLI # Command-line interface
from mininet.log import setLogLevel, info # logging level and output

import argparse

# Keep traffic generation separate from topology creation: this file builds the
# network, while the traffic module produces repeatable demonstration traffic.
# The demo can be run automatically with --demo or invoked again from Mininet.
from fattree_traffic import run_traffic_demo, run_trusted_source_demo

# Project-specific security zones and demo services.
CORE_POD = 0
OPS_POD = 1
GUEST_POD = 2
IOT_POD = 3

CORE_WEB_HOST = "h_0_0_2"
CORE_WEB_IP = "10.0.0.2"
CORE_WEB_PORT = 80

IOT_MANAGER_HOST = "h_0_0_3"
IOT_MANAGER_IP = "10.0.0.3"
IOT_MANAGER_PORT = 8000

def set_pod_dpid(pod, switch): # 00:00:00:00:00:pod:switch:01
    return "0000000000%02x%02x01" % (pod, switch)


def set_core_dpid(k, j, i): # 00:00:00:00:00:k:j:i
    return "0000000000%02x%02x%02x" % (k, j, i)


class FatTree(Topo):
    def build(self, k):
        if k != 4:
            raise Exception("This project requires k=4.")
        if k%2 != 0:
            raise Exception("k must be even!")
        k_half = k // 2

        core_switches = {}
        aggregation_switches = {}
        edge_switches = {}
        
        # set core switches
        for j in range(1, k_half+1):
            for i in range(1, k_half+1):
                name = "c_%d_%d" % (j, i)
                dpid = set_core_dpid(k, j, i)

                core_switches[(j, i)] = self.addSwitch(
                    name,
                    dpid=dpid,
                    protocols="OpenFlow13"
                )

        # set pods and edge switches
        for pod in range(k):
            edge_switches[pod] = {}
            aggregation_switches[pod] = {}

            # set edge switches
            for edge in range(k_half):
                name = "e_%d_%d" % (pod, edge)
                dpid = set_pod_dpid(pod, edge)

                edge_switches[pod][edge] = self.addSwitch(
                    name,
                    dpid=dpid,
                    protocols="OpenFlow13"
                )

            # set aggregation switches
            for aggregation_index in range(k_half):
                switch_num = k_half + aggregation_index
                name = "a_%d_%d" % (pod, switch_num)
                dpid = set_pod_dpid(pod, switch_num)

                aggregation_switches[pod][aggregation_index] = self.addSwitch(
                    name,
                    dpid=dpid,
                    protocols="OpenFlow13"
                )

            # set hosts and connect to edge switches
            for edge in range(k_half):
                edge_switch = edge_switches[pod][edge]

                for h in range(k_half):
                    host_id = h + 2
                    host_name = "h_%d_%d_%d" % (pod, edge, host_id)
                    host_ip = "10.%d.%d.%d/24" % (pod, edge, host_id)
                    host = self.addHost(
                        host_name,
                        ip=host_ip
                    )

                    self.addLink(
                        host,
                        edge_switch,
                        port1=1,
                        port2=h+1
                    )

            # connect edge switches to aggregation switches
            for edge in range(k_half):
                edge_switch = edge_switches[pod][edge]
    
                for aggregation_index in range(k_half):
                    aggregation_switch = aggregation_switches[pod][aggregation_index]
    
                    self.addLink(
                        edge_switch,
                        aggregation_switch,
                        port1=k_half+aggregation_index+1,
                        port2=edge+1
                    )
    
        # connect aggregation switches to core switches
        for pod in range(k):
            for aggregation_index in range(k_half):
                aggregation_switch = aggregation_switches[pod][aggregation_index]
                core_row = aggregation_index + 1
    
                for core_col in range(1, k_half + 1):
                    core_switch = core_switches[(core_row, core_col)]
        
                    self.addLink(
                        aggregation_switch,
                        core_switch,
                        port1=k_half+core_col,
                        port2=pod+1
                    )

def set_all(k, run_demo=False):
    topo = FatTree(k=k)

    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        link=TCLink,
        controller=None,
        autoSetMacs=True,
        autoStaticArp=True
    )

    net.addController(
        "controller",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6633
    )

    net.start()

    # allow hosts with /24 IPs to reach the whole 10.0.0.0/8 Fat-Tree network
    for host in net.hosts:
        intf = host.defaultIntf()
        host.cmd("ip route replace 10.0.0.0/8 dev %s" % intf.name)

    net.staticArp()

    start_demo_services(net)

    # --demo runs the complete microsegmentation demonstration before opening
    # the interactive CLI. Without it, the topology remains available for
    # normal manual Mininet testing.
    if run_demo:
        run_traffic_demo(net)
        run_trusted_source_demo(net)

    info("FatTree microsegmentation topology started\n")
    info("Pod %d: Core Services\n" % CORE_POD)
    info("Pod %d: Operations / Media\n" % OPS_POD)
    info("Pod %d: Guest Wi-Fi\n" % GUEST_POD)
    info("Pod %d: IoT Devices\n" % IOT_POD)
    info("Core web server: %s:%d\n" % (CORE_WEB_IP, CORE_WEB_PORT))
    info("IoT management server: %s:%d\n" %
         (IOT_MANAGER_IP, IOT_MANAGER_PORT))
    info("\nRun from the CLI:\n")
    info("  py __import__('fattree_traffic').run_traffic_demo(net)"
         "          # 6-scenario story\n")
    info("  py __import__('verify_dynamic_window').verify_complete_demo(net)"
         "  # 5-check evaluation\n\n")
    CLI(net)

    net.stop()


def start_demo_services(net):
    """Start the two HTTP endpoints used by the project demonstration."""
    web_server = net.get(CORE_WEB_HOST)
    iot_manager = net.get(IOT_MANAGER_HOST)

    web_server.cmd(
        # Python 3 uses http.server. --bind restricts the server to this
        # Mininet host's IP address.
        "python3 -m http.server %d --bind %s "
        ">/tmp/core_web.log 2>&1 &" % (CORE_WEB_PORT, CORE_WEB_IP)
    )
    iot_manager.cmd(
        "python3 -m http.server %d --bind %s "
        ">/tmp/iot_manager.log 2>&1 &"
        % (IOT_MANAGER_PORT, IOT_MANAGER_IP)
    )


if __name__ == "__main__":
    setLogLevel("info")

    parser = argparse.ArgumentParser()
    parser.add_argument("--k", type=int, default=4)
    parser.add_argument(
        "--demo",
        action="store_true",
        help="run the automated microsegmentation traffic demonstration"
    )
    args = parser.parse_args()

    set_all(args.k, run_demo=args.demo)
