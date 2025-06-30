/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>

#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


struct tcp_in_udp_hdr {
	struct udphdr udphdr;
	__be32	doff_flags_window;
	__be32	seq;
	__be32	ack_seq;
};

struct csum_diff {
	__u8 zero;
	__u8 proto;
	union {
		__be16 len;
		__be16 urg;
	};
};

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

__u16 PORT = 5201; // TODO: maybe this can be added in tc filter?
// #define CHECK_CSUM
// #define PRINT_PKT // to be used with checksum.c later on
// #define COMPUTE_FULL_CSUM

/*******************************************
 ** parse_*hdr helpers from XDP tutorials **
 *******************************************/

/* @return: next header */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if ((void *)eth + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	return eth->h_proto; /* network-byte-order */
}

/* @return: next header */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = nh->pos;
	int hdrsize = sizeof(*ip6h);

	if ((void *)ip6h + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ip6hdr = ip6h;

	/* TODO: support extensions */
	return ip6h->nexthdr;
}

/* @return: next header */
static __always_inline int parse_iphdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize = sizeof(*iph);

	if ((void *)iph + hdrsize > data_end)
		return -1;

	hdrsize = iph->ihl << 2;
	/* Sanity check packet field is valid */
	if(hdrsize < sizeof(*iph))
		return -1;

	/* Variable-length IPv4 header, need to use byte-based arithmetic */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}

/* @return: header len */
static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
					void *data_end,
					struct tcphdr **tcphdr)
{
	struct tcphdr *tcph = nh->pos;
	int hdrsize = sizeof(*tcph);

	if ((void *)tcph + hdrsize > data_end)
		return -1;

	hdrsize = tcph->doff << 2;
	/* Sanity check packet field is valid */
	if(hdrsize < sizeof(*tcph))
		return -1;

	/* Variable-length TCP header, need to use byte-based arithmetic */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*tcphdr = tcph;

	return hdrsize;
}

/* @return: payload len */
static __always_inline int parse_udphdr(struct hdr_cursor *nh,
					void *data_end,
					struct udphdr **udphdr)
{
	struct udphdr *udph = nh->pos;
	int hdrsize = sizeof(*udph);
	int len;

	if ((void *)udph + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*udphdr = udph;

	len = bpf_ntohs(udph->len) - hdrsize;
	if (len < 0)
		return -1;

	return len;
}


/*************
 ** Ingress **
 *************/

static __always_inline void
udp_to_tcp(struct __sk_buff *skb, struct hdr_cursor *nh,
	   struct iphdr *iphdr, struct ipv6hdr *ipv6hdr)
{
	void *data_end = (void *)(long)skb->data_end; /* end of the payload */
	void *data = (void *)(long)skb->data;
	struct tcp_in_udp_hdr *tuhdr, tuhdr_cpy;
	struct tcphdr *tcphdr = nh->pos;
	int nh_off = nh->pos - data;
	__be16 zero = 0;

	if (parse_udphdr(nh, data_end, (struct udphdr**)&tuhdr) < 0)
		goto out;

	if (tuhdr->udphdr.source != bpf_htons(PORT) &&
	    tuhdr->udphdr.dest != bpf_htons(PORT))
		goto out;

	if ((void *)tuhdr + sizeof(struct tcphdr) > data_end) {
		bpf_printk("udp-tcp: TODO: data_end too small: ulen:%u\n",
			   bpf_ntohs(tuhdr->udphdr.len));
		goto out;
	}

	if (skb->gso_segs > 1) {
		bpf_printk("udp-tcp: WARNING, GRO/LRO should be disabled: length:%u, segs:%u, size:%u\n",
			   skb->len, skb->gso_segs, skb->gso_size);
		goto out;
	}

	/* Do the modification before calling bpf_...(skb) helpers which can
	 * modify the SKB and cause "invalid mem access 'scalar'" errors.
	 */
	__builtin_memcpy(&tuhdr_cpy, tuhdr, sizeof(struct tcphdr));
	tcphdr->seq = tuhdr_cpy.seq;
	tcphdr->ack_seq = tuhdr_cpy.ack_seq;
	__builtin_memcpy((void *)tcphdr + sizeof(__be32) * 3,
			 &tuhdr_cpy.doff_flags_window, sizeof(__be32));
	tcphdr->check = tuhdr_cpy.udphdr.check;
	tcphdr->urg_ptr = 0;

	/* Change protocol: UDP -> TCP */
	if (iphdr) {
		__be16 proto_old = bpf_htons(IPPROTO_UDP);
		__be16 proto_new = bpf_htons(IPPROTO_TCP);

		iphdr->protocol = IPPROTO_TCP;

		bpf_l3_csum_replace(skb, ((void*)iphdr - data) +
					  offsetof(struct iphdr, check),
				    proto_old, proto_new, sizeof(__be16));
		bpf_l4_csum_replace(skb, nh_off + offsetof(struct tcphdr, check),
				    proto_old, proto_new,
				    BPF_F_PSEUDO_HDR | sizeof(__be16));
	} else if (ipv6hdr) {
		__be32 proto_old = bpf_htonl(IPPROTO_UDP);
		__be32 proto_new = bpf_htonl(IPPROTO_TCP);

		ipv6hdr->nexthdr = IPPROTO_TCP;

		bpf_l4_csum_replace(skb, nh_off + offsetof(struct tcphdr, check),
				    proto_old, proto_new,
				    BPF_F_PSEUDO_HDR | sizeof(__be32));
	}

	/* UDP Length vs Urgent Pointer */
	bpf_l4_csum_replace(skb, nh_off + offsetof(struct tcphdr, check),
			    tuhdr_cpy.udphdr.len, zero,
			    sizeof(__be16));

	#if 0
	__be32 zero = 0;
	__be32 csum = 0;
	__be32 len32;
	len32 = bpf_ntohl(bpf_ntohs(tuhdr_cpy.udphdr.len));
	/* Change protocol: UDP -> TCP */
	if (iphdr) {
		__be16 proto_old = bpf_htons(IPPROTO_UDP);
		__be16 proto_new = bpf_htons(IPPROTO_TCP);
		struct {
			__u8 pad;
			__u8 protocol;
			__be16 len;
		} bp_old, bp_new;

		bp_old.len = bp_new.len = tuhdr_cpy.udphdr.len;
		bp_old.pad = bp_new.pad = 0;
		bp_old.protocol = IPPROTO_TCP;
		bp_new.protocol = IPPROTO_UDP;

		iphdr->protocol = IPPROTO_TCP;

		csum = bpf_csum_diff((void *)&bp_old, sizeof(bp_old),
				     (void *)&bp_new, sizeof(bp_new), 0);

		bpf_l3_csum_replace(skb, ((void*)iphdr - data) +
					  offsetof(struct iphdr, check),
				    proto_old, proto_new, sizeof(__be16));
	} else if (ipv6hdr) {
		__be32 proto_old = bpf_htonl(IPPROTO_UDP);
		__be32 proto_new = bpf_htonl(IPPROTO_TCP);

		ipv6hdr->nexthdr = IPPROTO_TCP;

		csum = bpf_csum_diff((void *)&proto_old, sizeof(__be32),
				     (void *)&proto_new, sizeof(__be32), 0);
	}

	/* UDP Length vs Urgent Pointer */
	csum = bpf_csum_diff((void *)&len32, sizeof(__be32),
			     (void *)&zero, sizeof(__be32), csum);
	bpf_l4_csum_replace(skb, nh_off + offsetof(struct tcphdr, check),
			    0, csum, BPF_F_PSEUDO_HDR);
	#endif

	#if 0
	__be32 csum;
	/* proto has changed */
	csum = bpf_csum_diff((void *)&proto_old, sizeof(__be16),
			     (void *)&proto_new, sizeof(__be16), 0);
	bpf_l4_csum_replace(skb, nh_off + offsetof(struct tcphdr, check),
			    0, csum, BPF_F_PSEUDO_HDR);

	/* UDP Length vs Urgent Pointer */
	csum = bpf_csum_diff((void *)&tuhdr_cpy.udphdr.len, sizeof(__be16),
			     (void *)&zero, sizeof(__be16), 0);
	bpf_l4_csum_replace(skb, nh_off + offsetof(struct tcphdr, check),
			    0, csum, 0);
	#endif

	#if 0
	tcphdr->check = 0;
	if (iphdr)
		tcphdr->check = tcp_checksum(iphdr, tcphdr, data_end);
	#endif
out:
	return;
}

SEC("tc_ingress")
int tcp_ingress_drop(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct hdr_cursor nh = { .pos = data };
	int eth_type, ip_type, ret = TC_ACT_OK;
	struct ipv6hdr *ipv6hdr = NULL;
	struct iphdr *iphdr = NULL;
	struct ethhdr *eth;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	} else {
		goto out;
	}

	if (ip_type == IPPROTO_UDP)
		udp_to_tcp(skb, &nh, iphdr, ipv6hdr);

out:
	return ret;
}


/************
 ** Egress **
 ************/

static __wsum csum_partial(const void *buf, __u16 len, void *data_end)
{
	__u16 *p = (__u16 *)buf;
	int num_u16 = len >> 1;
	__wsum sum = 0;
	int i;

	if (len > 1480 || buf + len != data_end) {
		bpf_printk("we don't have the end of the packet (len:%u)...\n", len);
		return 0;
	}

	for (i = 0; i < 740; i++) {
		if ((void *)(p + i + 1) > data_end)
			break;
		sum += p[i];
	}

	/* left-over byte, if any */
	if (len % 2 != 0) {
		i <<= 1;
		if (buf + i >= data_end) {
			bpf_printk("csum: cannot get the end from len:%u i:%d\n", len, i);
			return sum;
		}
		sum += *((__u8 *)(buf + i));
	}

	return sum;
}

static __u16 csum_fold(__u32 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);

	return (__u16)~csum;
}

static inline __sum16 csum_tcpudp_magic(__be32 saddr, __be32 daddr,
					__u32 len, __u8 proto,
					__wsum csum)
{
	__u64 s = csum;

	s += (__u32)saddr;
	s += (__u32)daddr;
	s += bpf_htons(proto + len);
	s = (s & 0xffffffff) + (s >> 32);
	s = (s & 0xffffffff) + (s >> 32);

	return csum_fold((__u32)s) ? : 0xffff;
}

//typedef __u16 __sum16;
static __always_inline __sum16
udp_checksum(struct __sk_buff *skb, __u8 ip_off, __u8 udp_off)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct iphdr *iph = data + ip_off;
	struct udphdr *udph = data + udp_off;
	unsigned long sum;

	if ((void *)iph + sizeof(*iph) > data_end ||
	    (void *)udph + sizeof(*udph) > data_end) {
		bpf_printk("udp checksum size not OK\n");
		return -1;
	}

	sum = csum_partial(udph, bpf_ntohs(udph->len), data_end);
	return csum_tcpudp_magic(iph->saddr, iph->daddr, bpf_ntohs(udph->len),
				 IPPROTO_UDP, sum);

}

// TODO: split client/server, e.g. client: port dest egress, source ingress

static __always_inline void
tcp_to_udp(struct __sk_buff *skb, struct hdr_cursor *nh,
	   struct iphdr *iphdr, struct ipv6hdr *ipv6hdr)
{
	void *data_end = (void *)(long)skb->data_end; /* !end of the TCP hdr! To get data: bpf_skb_pull_data() */
	void *data = (void *)(long)skb->data;
	struct tcp_in_udp_hdr *tuhdr = nh->pos;
	struct tcphdr *tcphdr, tcphdr_cpy;
	int nh_off = nh->pos - data;
	__be16 udp_len;
	__wsum csum;
	__be16 diff_csum = 0, full_csum = 0;
	struct csum_diff csum_diff_old = { .zero = 0, };
	struct csum_diff csum_diff_new = { .zero = 0, };

	if (parse_tcphdr(nh, data_end, &tcphdr) < 0)
		goto out;

	if (tcphdr->source != bpf_htons(PORT) &&
	    tcphdr->dest != bpf_htons(PORT))
		goto out;

	if (tcphdr->urg) {
		if (iphdr)
			bpf_printk("tcp-udp: Skip: %pI4:%u -> %pI4:%u: urgent\n",
				   bpf_ntohl(iphdr->saddr),
				   bpf_ntohs(tcphdr->source),
				   bpf_ntohl(iphdr->daddr),
				   bpf_ntohs(tcphdr->dest));
		else if (ipv6hdr)
			bpf_printk("tcp-udp: Skip: %pI6c:%u -> %pI6c:%u: urgent\n",
				   &ipv6hdr->saddr,
				   bpf_ntohs(tcphdr->source),
				   &ipv6hdr->daddr,
				   bpf_ntohs(tcphdr->dest));
		goto out; /* TODO: or set to 0 and adapt checksum? */
	}

	if (skb->gso_segs > 1) {
		bpf_printk("tcp-udp: WARNING, GSO/TSO should be disabled: length:%u, segs:%u, size:%u\n",
			   skb->len, skb->gso_segs, skb->gso_size);
		goto out;
	}

	if (iphdr) {
		udp_len = bpf_htons(bpf_ntohs(iphdr->tot_len) -
				    ((void*)tcphdr - (void*)iphdr));
	} else if (ipv6hdr) {
		udp_len = ipv6hdr->payload_len;
	} else {
		goto out;
	}

	/* Do the modification before calling bpf_...(skb) helpers which can
	 * modify the SKB and cause "invalid mem access 'scalar'" errors.
	 */
	__builtin_memcpy(&tcphdr_cpy, tcphdr, sizeof(struct tcphdr));
	tuhdr->udphdr.check = tcphdr_cpy.check;
	__builtin_memcpy(&tuhdr->doff_flags_window,
			 (void *)&tcphdr_cpy + sizeof(__be32) * 3, sizeof(__be32));
	tuhdr->seq = tcphdr_cpy.seq;
	tuhdr->ack_seq = tcphdr_cpy.ack_seq;

	tuhdr->udphdr.len = udp_len;

	csum_diff_old.proto = IPPROTO_TCP;
	csum_diff_new.proto = IPPROTO_UDP;
	csum_diff_old.urg = 0;
	csum_diff_new.len = udp_len;

	/* Change protocol: TCP -> UDP */
	if (iphdr) {
		int ip_off = (void*)iphdr - data;

		iphdr->protocol = IPPROTO_UDP;

#if defined(CHECK_CSUM) || defined(COMPUTE_FULL_CSUM)
		diff_csum = tuhdr->udphdr.check;
#ifdef PRINT_PKT
		bpf_printk("tcp-udp: 0x%x:%u > 0x%x:%u csum:0x%x ulen:%u dlen:%u ilen:%u\n", bpf_ntohl(iphdr->saddr), bpf_ntohs(tuhdr->udphdr.source), bpf_ntohl(iphdr->daddr), bpf_ntohs(tuhdr->udphdr.dest), bpf_ntohs(diff_csum), bpf_ntohs(udp_len), data_end - (void*)tuhdr, bpf_ntohs(iphdr->tot_len));
		__be32 *t = (__be32 *)tuhdr;
		// bpf_printk("tcp-udp: hex: %x %x %x %x %x\n", bpf_ntohl(*t), bpf_ntohl(*(t+1)), bpf_ntohl(*(t+2)), bpf_ntohl(*(t+3)), bpf_ntohl(*(t+4)));
		for (int i = 0; i < 40; i += 4) {
			if ((void *)(t + 1) > data_end) {
				bpf_printk("tcp-udp: end\n");
				break;
			}
			bpf_printk("tcp-udp: hex: %x\n", bpf_ntohl(*t));
			t++;
		}
#endif
		tuhdr->udphdr.check = 0;
		long len_diff = data_end - (void *)tuhdr;
		if (len_diff > 0)
			len_diff = bpf_ntohs(udp_len) - len_diff;
		if (len_diff > 0) {
			bpf_skb_pull_data(skb, data_end - data + len_diff);
			// bpf_printk("tcp-udp: pull more: full:%u, diff:%u, len:%u, seq:%u, ack_seq:%u, s:%u, a:%u, f:%u, r%u, p:%u\n", bpf_ntohs(full_csum), bpf_ntohs(diff_csum), bpf_ntohs(udp_len), bpf_ntohl(tcphdr_cpy.seq), bpf_ntohl(tcphdr_cpy.ack_seq), tcphdr_cpy.syn, tcphdr_cpy.ack, tcphdr_cpy.fin, tcphdr_cpy.rst, tcphdr_cpy.psh);
		}
#ifdef COMPUTE_FULL_CSUM
		diff_csum =
#else
		full_csum =
#endif
			    udp_checksum(skb, ip_off, nh_off);
		bpf_skb_store_bytes(skb, nh_off + offsetof(struct udphdr, check),
				    &diff_csum, sizeof(diff_csum), 0);
#endif

		csum = bpf_csum_diff((void *)&csum_diff_old, sizeof(__be16),
				     (void *)&csum_diff_new, sizeof(__be16), 0);
		bpf_l3_csum_replace(skb, ip_off + offsetof(struct iphdr, check),
				    0, csum, 0);
	} else if (ipv6hdr) {
		ipv6hdr->nexthdr = IPPROTO_UDP;
	}

#ifndef COMPUTE_FULL_CSUM
	/* TODO: split pseudo HDR (needed for PARTIAL) and len/urg */
	csum = bpf_csum_diff((void *)&csum_diff_old, sizeof(__be32),
			     (void *)&csum_diff_new, sizeof(__be32), 0);
	bpf_l4_csum_replace(skb, nh_off + offsetof(struct udphdr, check),
			    0, csum, BPF_F_PSEUDO_HDR);
	/* TODO: handle checksum set to 0: not fixed with BPF_F_MARK_MANGLED_0 */
#if defined(CHECK_CSUM)
	long err = bpf_skb_load_bytes(skb, nh_off + offsetof(struct udphdr, check),
				      &diff_csum, sizeof(__be16));
	if (diff_csum == 0) {
		diff_csum = ~diff_csum;
		bpf_skb_store_bytes(skb, nh_off + offsetof(struct udphdr, check),
				    &diff_csum, sizeof(diff_csum), 0);
	}
	if (full_csum != diff_csum)
		bpf_printk("tcp-udp: csum: full:0x%x, diff:0x%x, len:%u, seq:%u, ack_seq:%u, s:%u, a:%u, f:%u, r%u, p:%u, err:%d\n", bpf_ntohs(full_csum), bpf_ntohs(diff_csum), bpf_ntohs(udp_len), bpf_ntohl(tcphdr_cpy.seq), bpf_ntohl(tcphdr_cpy.ack_seq), tcphdr_cpy.syn, tcphdr_cpy.ack, tcphdr_cpy.fin, tcphdr_cpy.rst, tcphdr_cpy.psh, err);
#endif
#endif

out:
	return;
}

SEC("tc_egress")
int tcp_egress_ack(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct hdr_cursor nh = { .pos = data };
	int eth_type, ip_type, ret = TC_ACT_OK;
	struct ipv6hdr *ipv6hdr = NULL;
	struct iphdr *iphdr = NULL;
	struct ethhdr *eth;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		// TODO: check for packet frag
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	} else {
		goto out;
	}

	if (ip_type == IPPROTO_TCP)
		tcp_to_udp(skb, &nh, iphdr, ipv6hdr);

out:
	return ret;
}
char _license[] SEC("license") = "GPL";

