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
1. h1 ping h2 -c 5 <img width="645" height="276" alt="Screenshot from 2026-04-06 19-44-13" src="https://github.com/user-attachments/assets/12f7f0b4-a139-416b-8c34-d8ae9c58dd4c" />
2. h1 ping h3 -c 5 <img width="711" height="135" alt="Screenshot from 2026-04-06 19-45-02" src="https://github.com/user-attachments/assets/b4e383ca-3238-4b5f-8647-2fa32e8d854b" />
3. h1 iperf3 -s &
   h2 iperf3 -c h1 <img width="807" height="491" alt="Screenshot from 2026-04-06 20-08-56" src="https://github.com/user-attachments/assets/f28c9c24-6d67-44d3-a3dd-a7c023cbed96" />
4. sh ovs-ofctl dump-flows s1 <img width="807" height="97" alt="Screenshot from 2026-04-06 20-09-39" src="https://github.com/user-attachments/assets/04bd7cbd-7d65-40f6-a368-226b3b249695" />

## References
- Ryu SDN Framework: https://ryu.readthedocs.io
- Mininet: http://mininet.org
- OpenFlow 1.3 Spec: https://opennetworking.org
