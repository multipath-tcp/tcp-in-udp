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
	uint32_t udp[10] = { htonl(0x891a1451), htonl(0x00281b8d), htonl(0xa002faf0), htonl(0x0fc7da45), htonl(0x00000000), htonl(0x020405b4), htonl(0x0402080a), htonl(0xe994d5ca), htonl(0x00000000), htonl(0x01030307) };
	uint16_t csum;

	ip.saddr = htonl(0xc0a800bd);
	ip.daddr = htonl(0x6684c98d);

	csum = udp_checksum(&ip, (struct udphdr*)&udp, sizeof(udp));

	printf("csum: 0x%x\n", ntohs(csum));
}
