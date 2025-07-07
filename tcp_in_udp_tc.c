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

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

__u16 PORT = 5201;

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
	void *data_end = (void *)(long)skb->data_end;
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

static __always_inline void
tcp_to_udp(struct __sk_buff *skb, struct hdr_cursor *nh,
	   struct iphdr *iphdr, struct ipv6hdr *ipv6hdr)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct tcp_in_udp_hdr *tuhdr = nh->pos;
	struct tcphdr *tcphdr, tcphdr_cpy;
	int nh_off = nh->pos - data;
	__be16 udp_len;
	__be32 len32, zero = 0;
	__wsum csum;

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

	/* tuhdr->udphdr.len = udp_len; */
	bpf_skb_store_bytes(skb, nh_off + offsetof(struct udphdr, len),
			    &udp_len, sizeof(udp_len), BPF_F_RECOMPUTE_CSUM);

	/* Change protocol: TCP -> UDP */
	if (iphdr) {
		__be16 proto_old = bpf_htons(IPPROTO_TCP);
		__be16 proto_new = bpf_htons(IPPROTO_UDP);
		int ip_off = (void*)iphdr - data;
		__u8 proto = IPPROTO_UDP;

		/* iphdr->protocol = IPPROTO_UDP; */
		bpf_skb_store_bytes(skb, ip_off + offsetof(struct iphdr, protocol),
				    &proto, sizeof(proto), BPF_F_RECOMPUTE_CSUM);

		bpf_l3_csum_replace(skb, ip_off + offsetof(struct iphdr, check),
				    proto_old, proto_new, sizeof(__be16));
	} else if (ipv6hdr) {
		int ip_off = (void*)ipv6hdr - data;
		__u8 proto = IPPROTO_UDP;

		/* ipv6hdr->nexthdr = IPPROTO_UDP; */
		bpf_skb_store_bytes(skb, ip_off + offsetof(struct ipv6hdr, nexthdr),
				    &proto, sizeof(proto), BPF_F_RECOMPUTE_CSUM);

	}
	__be32 proto_old = bpf_htonl(IPPROTO_TCP);
	__be32 proto_new = bpf_htonl(IPPROTO_UDP);
	csum = bpf_csum_diff((void *)&proto_old, sizeof(__be32),
			     (void *)&proto_new, sizeof(__be32), BPF_F_PSEUDO_HDR);

	/* UDP Length vs Urgent Pointer */
	len32 = bpf_ntohl(bpf_ntohs(udp_len));
	csum = bpf_csum_diff((void *)&zero, sizeof(__be32),
			     (void *)&len32, sizeof(__be32), csum);
	bpf_l4_csum_replace(skb, nh_off + offsetof(struct udphdr, check),
			    0, csum, 0);

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

