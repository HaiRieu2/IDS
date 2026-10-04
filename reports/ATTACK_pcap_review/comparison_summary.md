# ATTACK.pcap: IDS / CICFlowMeter comparison

## Executive result

The capture is **not sufficient to validate bidirectional flow features or demonstrate full IDS coverage**. It contains 764 TCP packets over about 75.5 seconds, but no reverse-direction packets were observed for any of the 206 IDS sessions. There are 103 IPv4 HTTP request flows with one request each and zero responses; there are another 103 IPv6 `::1` sessions containing only a SYN packet. This looks like incomplete/asymmetric loopback capture and/or a server bound only to IPv4, not a clean request/response trace.

## How it was processed

- The original PCAP uses link type 0 (BSD loopback/null), which the project's Scapy parser does not decode as IP directly. The test removed the four-byte loopback pseudo-header and wrapped the original IP packet in a synthetic Ethernet header for parsing. Packet IP/TCP bytes and capture timestamps were kept.
- Input: 764 packets total: 661 IPv4 and 103 IPv6; all decoded packets were TCP.
- The project IDS `parse_packet` + `SessionBuilder` processed the full normalized capture: 206 sessions and all 764 packets accounted for.
- The CIC comparison used IPv4 only, because the Java CICFlowMeter command in the checked-out upstream source sets `readIP6=false`. The actual upstream Java application was not executed: its checked-in Gradle wrapper is 4.2, and this machine has Java 24, which Gradle 4.2 rejects.
- As a practical reference only, I ran the PyPI `cicflowmeter` Python port (version 0.5.0) on the same normalized IPv4 packets. It is not the official Java CICFlowMeter implementation.

## Flow grouping comparison

| Result | IDS project | Python CICFlowMeter port |
|---|---:|---:|
| IPv4 flows | 103 | 103 |
| 5-tuples matched | 103 / 103 | 103 / 103 |
| IPv4 packets expected / input | 661 | 661 |
| Sum of packets in emitted flows | 661 | 764 |
| Backward packets | 0 | 0 |

The tuple grouping agrees for all 103 IPv4 flows. The Python port reports exactly one extra packet for each flow: its `Flow` constructor puts the first packet into the flow, then `FlowSession.process` calls `add_packet` on that same first packet. It also calculates packet length with `len(packet)` on an Ethernet-framed Scapy packet, while upstream Java CICFlowMeter sets packet payload bytes from TCP/UDP payload length. Therefore its numeric feature comparison is diagnostic only, not a trustworthy parity test for the official CICFlowMeter. See `feature_comparison_python_port.csv` with that caveat.

The upstream Java source explicitly uses TCP/UDP payload length for these payload byte features: [PacketReader.java](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/PacketReader.java). The upstream project setup and native jNetPcap requirements are documented in the [official CICFlowMeter repository](https://github.com/ahlashkari/CICFlowMeter).

## IDS alerts and ML results

The IDS pipeline completed with zero detector exceptions:

- Signature: 1 SQLi alert for `/login username=admin'--&password=dwadaw`.
- Signature: 1 XSS alert for `/truyen/4 username=admin&content=<script>alert()</script>`.
- Random Forest: 206 / 206 sessions predicted `BENIGN`.
- Behavior: no Brute Force or DoS alert was produced.
- HTTP: 103 request messages, 0 response messages; 0 of 206 flows had backward packets.

The SQLi and XSS signatures can inspect request content, while this Random Forest receives only the current network-flow feature vector. The `BENIGN` output on those same requests shows that this model is not independently detecting these payload-level attacks in this run. The signature alerts are useful evidence that those two payloads were visible to the IDS, but the PCAP has no labels, so recall, false-negative rate, or overall accuracy cannot be calculated.

## What to fix before using this as a demo/result

1. Capture on the correct Windows loopback adapter (for local client/server tests) or on the actual network interface; verify in Wireshark that each request has a reverse packet from server port 5000 and a response status/body before exporting the PCAP.
2. Check whether the web server listens on IPv4 only. The 103 `::1` sessions are SYN-only, consistent with IPv6 localhost attempts that receive no reply, followed by IPv4 traffic.
3. Re-capture and re-run. A valid test should show both directions for HTTP flows, nonzero response counts, and two-sided TCP close behavior where the connection completes normally.
4. For XSS/SQLi, preserve signature/payload detection and consider adding HTTP request features to a separate application-layer classifier. Do not claim the current flow-only Random Forest catches these classes based on this run.
5. For Brute Force/DoS, capture representative multi-attempt/high-rate scenarios with server replies where applicable; one isolated request per flow does not establish those attack patterns.

## Files produced

- `ids_flows_full.csv`: all IDS sessions, including direction counters, request/response counts, and the 25 model inputs.
- `ids_flows_ipv4_feature_compare.csv`: IDS IPv4 feature rows.
- `cicflowmeter_python_ipv4.csv`: Python port flow output, not official Java CICFlowMeter output.
- `feature_comparison_python_port.csv`: per-feature differences for the matched 103 IPv4 tuples; interpret only with the caveat above.
- `ids_alerts.jsonl`: IDS alerts generated by the isolated offline run. Existing project alert logs and alert counter were not modified.
