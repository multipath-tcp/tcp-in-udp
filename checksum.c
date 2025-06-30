#include <netinet/in.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>


static uint16_t ip_checksum(void *vdata, size_t length)
{
	/* Cast the data to 16 bit chunks */
	uint16_t *data = vdata;
	uint32_t sum = 0;

	while (length > 1) {
		sum += *data++;
		length -= 2;
	}

	/* Add left-over byte, if any */
	if (length > 0)
		sum += *(unsigned char *)data;

	/* Fold 32-bit sum to 16 bits */
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

#if 0
static void print_ip(char *info, uint32_t addr, uint16_t port)
{
	addr = ntohl(addr);
	uint8_t ip[4];
	memcpy(&ip, &addr, sizeof(ip));

	printf("%s IP: %u.%u.%u.%u:%u\n", info, ip[3], ip[2], ip[1], ip[0], ntohs(port));
}
#endif

static void print_ip(char *info, uint32_t addr, uint16_t port)
{
	char str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &addr, str, INET_ADDRSTRLEN);
	printf("%s IP: %s:%u\n", info, str, ntohs(port));
}

static uint16_t udp_checksum(struct iphdr *ip, struct udphdr *udp, int len)
{
	uint16_t csum;
	int total_len;

	struct pseudo_header {
		uint32_t source_address;
		uint32_t dest_address;
		uint8_t placeholder;
		uint8_t protocol;
		uint16_t length;
	};

	struct {
		struct pseudo_header hdr;
		unsigned char l4[1480];
	} buffer;

	/* Fill pseudo header */
	buffer.hdr.source_address = ip->saddr;
	buffer.hdr.dest_address = ip->daddr;
	buffer.hdr.placeholder = 0;
	buffer.hdr.protocol = IPPROTO_UDP;
	buffer.hdr.length = htons(len);
	udp->check = 0;

	print_ip("source", ip->saddr, udp->source);
	print_ip("dest", ip->daddr, udp->dest);

	/* Allocate memory for the calculation */
	total_len = sizeof(struct pseudo_header) + len;

	/* Copy pseudo header, TCP header, and payload */
	memcpy(&buffer.l4[0], udp, len);

	/* Calculate checksum */
	csum = ip_checksum(&buffer, total_len);

	return csum;
}


int main(int argc, char *argv[])
{
	struct iphdr ip = { 0 };
	uint32_t udp[10] = { htonl(0xcc6a1451), htonl(0x0028f29f), htonl(0xa002faf0), htonl(0xc2fa1294), htonl(0x00000000), htonl(0x020405b4), htonl(0x0402080a), htonl(0x994b6f2f), htonl(0x00000000), htonl(0x01030307) };
	uint16_t csum;

	ip.saddr = htonl(0xc0a801b7);
	ip.daddr = htonl(0x6684c98d);

	csum = udp_checksum(&ip, (struct udphdr*)&udp, sizeof(udp));

	printf("csum: 0x%x\n", ntohs(csum));
}

#if 0
           <...>-520314  [002] b..1. 1229445.657995: bpf_trace_printk: tcp-udp: 0xc0a801b7:52330 > 0x6684c98d:5201 csum:0xf29f ulen:40 dlen:40 ilen:60
           <...>-520314  [002] b..1. 1229445.658007: bpf_trace_printk: tcp-udp: hex: 0xcc6a1451
           <...>-520314  [002] b..1. 1229445.658008: bpf_trace_printk: tcp-udp: hex: 0x0028f29f
           <...>-520314  [002] b..1. 1229445.658008: bpf_trace_printk: tcp-udp: hex: 0xa002faf0
           <...>-520314  [002] b..1. 1229445.658009: bpf_trace_printk: tcp-udp: hex: 0xc2fa1294
           <...>-520314  [002] b..1. 1229445.658010: bpf_trace_printk: tcp-udp: hex: 0x00000000
           <...>-520314  [002] b..1. 1229445.658011: bpf_trace_printk: tcp-udp: hex: 0x020405b4
           <...>-520314  [002] b..1. 1229445.658012: bpf_trace_printk: tcp-udp: hex: 0x0402080a
           <...>-520314  [002] b..1. 1229445.658013: bpf_trace_printk: tcp-udp: hex: 0x994b6f2f
           <...>-520314  [002] b..1. 1229445.658013: bpf_trace_printk: tcp-udp: hex: 0x00000000
          iperf3-520314  [002] b..1. 1229445.658014: bpf_trace_printk: tcp-udp: hex: 0x01030307
          iperf3-520314  [002] b..1. 1229445.658021: bpf_trace_printk: tcp-udp: csum: full:0x9ba5, diff:0xf2d2, len:40, seq:3271168660, ack_seq:0, s:1, a:0, f:0, r0, p:0, err:0

16:36:49.770507 20:7c:14:f3:d2:72 > 20:97:27:08:a8:f3, ethertype IPv4 (0x0800), length 74: (tos 0x0, ttl 64, id 11585, offset 0, flags [DF], proto UDP (17), length 60)
    192.168.1.183.52330 > 102.132.201.141.5201: [bad udp cksum 0xf2d2 -> 0x0028!] UDP, length 32

    computed csum: 0x9ba5
#endif
