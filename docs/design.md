# Design decisions and limitations

## Topology

Each of four pods contains two edge switches, two aggregation switches and four hosts. Four core switches connect the pods. Names follow `h_<pod>_<edge>_<host>`; addresses follow `10.<pod>.<edge>.<host>`, with host suffixes 2 and 3. Static ARP and a route to `10.0.0.0/8` support the teaching topology.

## Enforcement

Table 0 checks access policy, table 1 applies responses, and table 2 forwards allowed traffic. Response priorities are 100 for throttle and 200 for quarantine. Cookies `0x400` and `0x300` identify the two tiers. Quarantine drops source-egress IPv4 traffic; it is not full bidirectional endpoint isolation.

Observations use `(edge_dpid, ingress_port, source_ip)` keys. Strikes use `(edge_dpid, ingress_port)`. The detector stores the first observation of each destination until expiry; repeated packets do not refresh that timestamp. It is an approximation to a rolling destination-diversity detector, not exact last-seen accounting.

Flow expiry clears observations and active response state. Reputation decay is checked on packet arrival relative to the last strike; it does not independently prove a period free of suspicious activity.

## Verification decisions

- Reuse the same scanner for first and repeated offences.
- Probe an already-observed same-pod destination: a cross-pod failure could be the ACL, while a new destination can itself trigger detection.
- Inspect flow rules as well as ping. A throttled host can still respond.
- Filter verification by source IP, avoiding false results from a neighbour on the same switch. This was corrected in the portfolio edition.

## Limitations

- No source-IP binding or authenticated host identity. Spoofed exempt addresses can evade detection.
- Same-pod IPv4 is broadly permitted; return permissions are stateless TCP source-port rules.
- All host IPv4 packets are copied to Ryu, even if subsequently dropped in the response table. Controller-overload resistance is not evaluated.
- Meter rejection disables meters globally for subsequent installations; it does not immediately repair the already attempted throttle. Unsupported-meter recovery requires further testing.
- A meter configuration and successful ping do not prove the achieved bandwidth cap. Measure throughput separately.
- Service-IP exemptions reduce reply-related false positives but also exempt compromised services.
- State is in memory; reconnects, high availability and scale are not validated.
- IPv6, dynamic discovery, slow/distributed scans and false-positive benchmarking are outside this version's evaluation.

## Next improvements

Capture the original VM environment and fresh integration logs; test meter throughput and per-switch fallback; add ingress source binding; compare exact last-seen windows; evaluate legitimate multi-destination clients and slow scans before tuning parameters.
