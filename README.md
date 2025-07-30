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
  tc filter add dev "${IFACE}" egress  u32 match ip dport "${PORT}" 0xffff action goto chain 1
  tc filter add dev "${IFACE}" egress  chain 1 bpf object-file tcp_in_udp_tc.o section tc action csum udp
  tc filter add dev "${IFACE}" ingress u32 match ip sport "${PORT}" 0xffff action goto chain 1
  tc filter add dev "${IFACE}" ingress chain 1 bpf object-file tcp_in_udp_tc.o section tc direct-action
  ```
- Server:
  ```
  tc qdisc add dev "${IFACE}" clsact
  tc filter add dev "${IFACE}" egress  u32 match ip sport "${PORT}" 0xffff action goto chain 1
  tc filter add dev "${IFACE}" egress  chain 1 bpf object-file tcp_in_udp_tc.o section tc action csum udp
  tc filter add dev "${IFACE}" ingress u32 match ip dport "${PORT}" 0xffff action goto chain 1
  tc filter add dev "${IFACE}" ingress chain 1 bpf object-file tcp_in_udp_tc.o section tc direct-action
  ```

Multiple u32 filters can be used to have more than one port traffic sent to the
BPF programme.

If the TCP programme supports setting marks (SO_MARK), use it for egress to
prevent processing traffic that is not from the TCP programme. For client, this
allows traffic to a different IP address with the same TCP port. For server,
this prevents sending packet to BPF programme if the interface has multiple IP
addresses assigned and if the TCP programme doesn't bind to all of them.

- Client & Server:
  ```
  tc filter add dev "${IFACE}" egress  handle 2 fw action goto chain 1
  ```

Be warned that SO_MARK can't be used for ingress as the system doesn't expect
incoming UDP packets. Therefore, all incoming packets from the interface with
matching port will be sent to the BPF programme. To decrease the chance of this
happening, you're recommended to use ports that are outside of the ephemeral
port range set on net.ipv4.ip_local_port_range (default: 32768-60999). The
net.ipv4.ip_local_port_range option applies to IPv6 too.

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
