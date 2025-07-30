# TCP in UDP

Middleboxes can mess up with TCP flows, e.g. intercepting the connections and
dropping MPTCP options. Using an TCP-in-UDP tunnel will force such middleboxes
not to modify such TCP connections. The idea here is inspired by an old [IETF
draft](https://datatracker.ietf.org/doc/html/draft-cheshire-tcp-over-udp-00.html).

This "tunnel" is done in eBPF, from the TC hooks. For more details about why it
has been created, and its particularities, please check this
[blog post](https://blog.mptcp.dev/2025/07/14/TCP-in-UDP.html).

## Headers

[UDP](https://www.ietf.org/rfc/rfc768.html):

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

[TCP](https://www.ietf.org/rfc/rfc9293.html):

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |       |C|E|U|A|P|R|S|F|                               |
| Offset| Reser |R|C|R|C|S|S|Y|I|            Window             |
|       |       |W|E|G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      (Optional) Options                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

[TCP-in-UDP](https://datatracker.ietf.org/doc/html/draft-cheshire-tcp-over-udp-00.html):

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |       |C|E| |A|P|R|S|F|                               |
| Offset| Reser |R|C|0|C|S|S|Y|I|            Window             |
|       |       |W|E| |K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      (Optional) Options                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Modifications:
- `URG` set to 0, `Urgent Pointer` is supposed to be zero (not used).
- Switch `Sequence Number` and `Acknowledgment Number` with `Urgent Pointer` and
  `Checksum`.
- Replace `Urgent Pointer` by the `Length`: Checksum needs to be recomputed.

Checksum:
- No need to recompute it from scratch, it can be derived from the previous
  values, by just changing the protocol.

- [UDP Checksum](https://www.rfc-editor.org/rfc/rfc768) computed from:
  - Source and destination address: from upper layer
  - Protocol (1B): UDP (17)
  - Length (2B): Data (variable) + UDP header (8 octets) lengths
  - TCP header
  - Data

- [TCP Checksum](https://www.ietf.org/rfc/rfc9293.html#section-3.1-6.18.1)
  computed from:
  - Source and destination address: from upper layer
  - Protocol (1B): TCP (6)
  - Length (2B): Data (variable) + TCP header (Between 20 and 56 octets) lengths
  - TCP header
  - Data

- Differences:
  - Source and destination address: not changed
  - Protocol: **changed**: UDP/TCP.
  - Data length: not changed
  - L4 header: **changed**: `UDP Length` vs `TCP Urgent Pointer`
  - Data: not changed


## Build

Build the binary using `make`. CLang and `libbpf` is required, e.g.

```
sudo apt install clang llvm libelf-dev build-essential libc6-dev-i386 libbpf-dev
```


## Setup

Load it with `tc` commands:

- Client:
  ```
  tc qdisc add dev "${IFACE}" clsact
  tc filter add dev "${IFACE}" egress  bpf obj tcp_in_udp_tc.o sec tc_client_egress action csum udp
  tc filter add dev "${IFACE}" ingress bpf da obj tcp_in_udp_tc.o sec tc_client_ingress
  ```
- Server:
  ```
  tc qdisc add dev "${IFACE}" clsact
  tc filter add dev "${IFACE}" egress  bpf obj tcp_in_udp_tc.o sec tc_server_egress action csum udp
  tc filter add dev "${IFACE}" ingress bpf da obj tcp_in_udp_tc.o sec tc_server_ingress
  ```

Generic Segmentation Offload (GSO) and Generic Receive Offload (GRO) cannot be
used for this traffic, because each UDP packet will carry a part of the TCP
headers as part of the data. This part of the data is specific to one packet,
therefore, it cannot be merged with the next data. UDP GRO is only done on
demand, e.g. when the userspace asks it (setsockopt(IPPROTO_UDP, UDP_GRO)) or
for some in-kernel tunnels, so GRO doesn't need to be disabled. To disable GSO:

```
ip link set ${IFACE} gso_max_segs 0
```

Note: to get some stats, in egress, it is possible to use:

```
tc -s action show action csum
tc -s -j action show action csum | jq
```

It might be interesting to monitor the tracing ring buffer for warnings and
other messages generated by the eBPF programs:

```
cat /sys/kernel/debug/tracing/trace_pipe
```

To stop the eBPF programs:

```
tc filter del dev "${IFACE}" egress
tc filter del dev "${IFACE}" ingress
```

## MSS

Because the packets will be in UDP and not TCP, any MSS clamping will have no
effects here. It is important to avoid IP fragmentation. In other words, it
might be required to adapt the MTU (or the MSS).

## Identification

### Client side:

- Ingress: From a specific destination IP and port in UDP
- Egress: To a specific destination IP and port in TCP

### Server side:

- Ingress: To a specific destination IP and port in UDP
- Egress: From a previously used `sk`: use ConnMark to set a specific `SO_MARK`
