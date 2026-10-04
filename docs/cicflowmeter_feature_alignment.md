# IDS feature alignment with CICFlowMeter

## Flow through the code

Live capture and PCAP replay use the same path:

1. `ids/capture/packet_parser.py::parse_packet` extracts the IP endpoints,
   TCP/UDP ports, transport payload length, TCP window/flags, and capture time.
2. Capture time is kept in seconds for the IDS timers and as an integer
   microsecond value for CICFlowMeter-style flow features.
3. `ids/capture/session_builder.py::SessionBuilder.add_packet` groups both
   directions by the same 5-tuple, fixes the first observed packet direction
   as forward, and updates packet, payload, flag, window, duration, IAT, and
   packet-length statistics.
4. `ids/detectors/ml/feature_adapter.py::feature_extractor` builds the ordered
   25-value vector from `ids/detectors/ml/features.py::CIC_FEATURES`.

## Feature rules used by the runtime

- **Duration:** last packet timestamp minus first packet timestamp, in integer
  microseconds.
- **Forward/backward packets and payload bytes:** each observed packet is
  counted once, in the direction established by the flow's first packet.
- **Flow bytes/s:** total TCP/UDP payload bytes divided by duration in seconds.
- **Packet rates:** packet counts divided by duration in seconds.
- **Flow IAT:** the timestamp gap between each pair of consecutive packets in
  the flow, in microseconds. Mean and standard deviation use sample-statistics
  behavior.
- **Packet length min/max/mean/std:** TCP/UDP payload lengths. CICFlowMeter's
  `BasicFlow.firstPacket` inserts the first payload length twice into its
  global length statistics; the runtime mirrors that behavior for these four
  fields. Packet totals and directional byte totals still count that packet
  only once.
- **TCP flags:** count each packet carrying the corresponding flag.
- **Initial windows:** forward uses the first forward packet's TCP window;
  backward follows CICFlowMeter's implementation and is overwritten by each
  subsequent backward packet.
- **Destination port:** preserve the actual observed port. The feature adapter
  no longer rewrites a lab service port such as 8080 to 80.

The exported verification replay is
`reports/http_slowloris_pcap_review/ids_cic_compatible_features.csv`.

## Scope of parity

The runtime calculations above follow the CICFlowMeter Java source behavior
for the selected flow statistics. A bit-for-bit comparison still depends on using
the same CICFlowMeter build, packet timestamp precision, timeout settings,
packet visibility, and PCAP decoding. The earlier reference CSV in the report
folder came from the Python `cicflowmeter` package and is not official Java
CICFlowMeter output, so it should not be treated as the parity oracle.

## Expanded Random Forest schema

The Random Forest now uses **67 CICFlowMeter columns**. The added groups are:

- Packet-length min/max/mean/sample standard deviation split by forward and
  backward direction.
- Forward and backward IAT total/mean/sample standard deviation/min/max.
- Directional PSH/URG counts and transport-header byte totals.
- Packet-length variance, down/up ratio, average packet size, directional
  segment averages, active-data-packet count, minimum forward segment size,
  and active/idle statistics.

These columns exist in the project's CIC-IDS-2017 CSV files and are built from
packet counters in `SessionBuilder`. Active/idle spans use CICFlowMeter's
5-second activity boundary. HTTP request contents and request-rate features
are not included in this Random Forest because the current labeled CIC CSVs do
not provide those labels/features. HTTP request content is handled by the
separate TF-IDF/Logistic Regression model documented in
`docs/ARCHITECTURE_AND_DEFENSE_GUIDE.md`; it does not change this flow model's
67-column schema.

After changing this feature schema, retrain with `python -m ml.ml_training`
from the project directory. The saved model and runtime extractor must use the
same ordered schema in `ids/detectors/ml/features.py`.
