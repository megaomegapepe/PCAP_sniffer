#include <stdio.h>
#include <pcap.h>

/* Ethernet адреса состоят из 6 байт */
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet
{
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type;					/* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip
{
	u_char ip_vhl;				   /* version << 4 | header length >> 2 */
	u_char ip_tos;				   /* type of service */
	u_short ip_len;				   /* total length */
	u_short ip_id;				   /* identification */
	u_short ip_off;				   /* fragment offset field */
#define IP_RF 0x8000			   /* reserved fragment flag */
#define IP_DF 0x4000			   /* don't fragment flag */
#define IP_MF 0x2000			   /* more fragments flag */
#define IP_OFFMASK 0x1fff		   /* mask for fragmenting bits */
	u_char ip_ttl;				   /* time to live */
	u_char ip_p;				   /* protocol */
	u_short ip_sum;				   /* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp
{
	u_short th_sport; /* source port */
	u_short th_dport; /* destination port */
	tcp_seq th_seq;	  /* sequence number */
	tcp_seq th_ack;	  /* acknowledgement number */
	u_char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
	u_short th_win; /* window */
	u_short th_sum; /* checksum */
	u_short th_urp; /* urgent pointer */
};
#define SIZE_ETHERNET 14

const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ip *ip;			   /* The IP header */
const struct sniff_tcp *tcp;		   /* The TCP header */
const char *payload;				   /* Packet payload */

u_int size_ip;
u_int size_tcp;

void mycallback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip;			   /* The IP header */
	const struct sniff_tcp *tcp;		   /* The TCP header */
	const u_char *payload;				   /* Packet payload */

	int size_ethernet = sizeof(struct sniff_ethernet);
	int size_ip = sizeof(struct sniff_ip);
	int size_tcp = sizeof(struct sniff_tcp);

	ethernet = (struct sniff_ethernet *)(packet);
	ip = (struct sniff_ip *)(packet + size_ethernet);
	tcp = (struct sniff_tcp *)(packet + size_ethernet + size_ip);
	payload = (u_char *)(packet + size_ethernet + size_ip + size_tcp);

	FILE *file = fopen("output", "ab");
	if (file == NULL)
	{
		printf("error opening file");
	}

	fwrite(&payload, sizeof(u_char), 1, file);
	//fprintf(file, "Packet handled:%s; Packet type: %d\n", &payload, ethernet->ether_type);
	printf("Packet handled:%s; Packet type: %d\n", (char *)payload, ethernet->ether_type);
	fclose(file);
}

int main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return (2);
	}
	printf("Device: %s\n", dev);

	pcap_t *handle;

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return (2);
	}

	struct pcap_pkthdr header;
	const u_char *packet; /* Пакет */

	pcap_loop(handle, -1, mycallback, NULL);

	pcap_close(handle);
	return (0);
}