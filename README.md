# Traffic Monitoring and Statistics Collector

## Problem Statement
Build an SDN controller that collects and displays traffic statistics,
implements flow-based forwarding, and blocks specific hosts using
explicit OpenFlow match-action rules.

## Topology
3 hosts (h1, h2, h3) connected to 1 OVS switch (s1), 
managed by a remote Ryu controller.

## Setup & Execution
1. Install Mininet: sudo apt-get install mininet
2. Install Ryu: pip3 install ryu  (or use ryu-venv)
3. Terminal 1: ryu-manager traffic_monitor.py
4. Terminal 2: sudo python3 topology.py

## Expected Output
- h1 ping h2 → success (flow rule installed, forwarded)
- h1 ping h3 → fail (DROP rule blocks h3's IP)
- iperf h1→h2 → throughput stats shown
- Flow table updated every 5 seconds with packet/byte counts

## Test Scenarios
| Scenario | Command | Expected Result |
|---|---|---|
| Allowed traffic | h1 ping h2 | 0% packet loss |
| Blocked traffic | h1 ping h3 | 100% packet loss |
| Throughput | iperf h1→h2 | Bandwidth measurement |
| Flow table | ovs-ofctl dump-flows s1 | Rules visible |

## Proof of Execution
[Add your screenshots here]

## References
- Ryu SDN Framework: https://ryu.readthedocs.io
- Mininet: http://mininet.org
- OpenFlow 1.3 Spec: https://opennetworking.org
