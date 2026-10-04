# `http_slowloris.pcap`: IDS / CICFlowMeter comparison

## Result

The IDS now delivers every completed flow segment to the live/offline detection callback, including segments closed when a new packet causes flow rotation. Before the fix, this PCAP replay stored 2,000 sessions but delivered only 1,000. After the fix, it delivered **2,000/2,000 sessions** and accounted for **8,000/8,000 packets**.

This PCAP contains 8,000 IPv4 TCP packets over about 387.6 seconds, grouped as 500 bidirectional five-tuples. With the IDS's 120-second flow lifetime, the capture creates four segments for each tuple (2,000 total). There are 500 one-packet segments. The remaining **1,500 segments with more than one packet** are eligible for the CICFlowMeter-trained model, which matches CICFlowMeter's rule to omit flows with one or fewer packets in its CSV output.

The official CICFlowMeter Java executable was not run on this machine. Its source sets a 120-second flow timeout and a 5-second activity timeout, and the exporter filters out flows with at most one packet. The Python CICFlowMeter port was run as a reference: it emitted 1,500 rows and covered the same 500 five-tuples, but its packet-count and feature semantics are not equivalent to the official Java tool. Do not treat its numeric feature differences as an official parity measurement. The official defaults/filter are visible in [Cmd.java](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/ifm/Cmd.java) and [FlowGenerator.java](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/FlowGenerator.java).

## Feature compatibility and code changes

- The IDS model adapter still emits the same ordered 25 fields in `CIC_FEATURES` and uses CIC units: duration/IAT in microseconds, rates per second, and byte/packet-length values in bytes.
- Flow and direction packet counts are counted once per packet. Payload byte totals use TCP/UDP payload length, as upstream CICFlowMeter does in [PacketReader.java](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/PacketReader.java).
- CICFlowMeter's `BasicFlow.firstPacket()` adds the first payload length twice to the *global packet-length statistics* (but not its packet or byte totals). I updated IDS packet-length mean/std accumulation to match that behavior; see [BasicFlow.java](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java).
- Rotated/timed-out sessions are now queued as clean snapshots and emitted exactly once before the newly created session is processed. This fixes the prior loss of the older flow segment from ML in live traffic and PCAP replay.
- Flows with one packet stay available to behavior/signature analysis but are skipped by ML, because CICFlowMeter training CSVs exclude those rows.

## Model output on this file

The current model classified the 1,500 eligible rows as:

- 1,000 `DoS slowloris`
- 500 `BENIGN`

The IDS's current low-confidence alert backstop uses threshold 0.1. It promotes 284 of those 500 benign predictions to `DoS Hulk`; **216 rows remain BENIGN**. If this whole PCAP is ground-truth Slowloris traffic, these remaining rows show that the current model/threshold still misses some attack-labelled flow segments. Raising recall with the backstop also increases false-positive risk; this PCAP alone cannot measure that tradeoff.

## Files

- `ids_live_capture_ml_flows.csv`: every IDS segment with all 25 inputs, raw prediction, final threshold-adjusted ML result, and whether the flow is eligible for ML.
- `ml_prediction_counts.csv`: effective result counts, including skipped one-packet flows.
- `cicflowmeter_python_reference.csv`: output from the separate Python port, not the official Java executable.
- `run_summary.json`: packet/session/tuple counts from the replay.

## Conclusion

The live flow-to-ML path now delivers every segment and the non-singleton flow count agrees with the CICFlowMeter export rule for this capture. Feature definitions are closer to the official CICFlowMeter implementation, including the first-packet length-statistics behavior. Exact numeric parity against official CICFlowMeter still needs a run of the Java executable; the Python port is not a reliable substitute for that check.
