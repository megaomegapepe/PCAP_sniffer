#include <stdio.h>
#include <pcap.h>

/* Ethernet адреса состоят из 6 байт */
#define ETHER_ADDR_LEN 6

/* Заголовки Ethernet всегда состоят из 14 байтов */
#define SIZE_ETHERNET 14

/* Заголовок Ethernet */
struct sniff_ethernet
{
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Адрес назначения */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Адрес источника */
	u_short ether_type;					/* IP? ARP? RARP? и т.д. */
};

/* IP header */
struct sniff_ip
{
	u_char ip_vhl;				   /* версия << 4 | длина заголовка >> 2 */
	u_char ip_tos;				   /* тип службы */
	u_short ip_len;				   /* общая длина */
	u_short ip_id;				   /* идентефикатор */
	u_short ip_off;				   /* поле фрагмента смещения */
#define IP_RF 0x8000			   /* reserved флаг фрагмента */
#define IP_DF 0x4000			   /* dont флаг фрагмента */
#define IP_MF 0x2000			   /* more флаг фрагмента */
#define IP_OFFMASK 0x1fff		   /* маска для битов фрагмента */
	u_char ip_ttl;				   /* время жизни */
	u_char ip_p;				   /* протокол */
	u_short ip_sum;				   /* контрольная сумма */
	struct in_addr ip_src, ip_dst; /* адрес источника и адрес назначения */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp
{
	u_short th_sport; /* порт источника */
	u_short th_dport; /* порт назначения */
	tcp_seq th_seq;	  /* номер последовательности */
	tcp_seq th_ack;	  /* номер подтверждения */
	u_char th_offx2;  /* смещение данных, rsvd */
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
	u_short th_win; /* окно */
	u_short th_sum; /* контрольная сумма */
	u_short th_urp; /* экстренный указатель */
};

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	static int count = 1;
	const struct sniff_ethernet *ethernet; /* Заголовок Ethernet */
	const struct sniff_ip *ip;			   /* Заголовок IP */
	const struct sniff_tcp *tcp;		   /* Заголовок TCP */
	u_char *payload = 0;				   /* Данные пакета */

	u_int size_ip;
	u_int size_tcp;

	ethernet = (struct sniff_ethernet *)(packet);
	ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20)
	{
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	if (size_tcp < 20)
	{
		//printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	if (ethernet->ether_type != 8)
	{
		printf("HANDLED PACKET INFO:\nIP dir:%s\nIP source:%s\nIP type:%d\ncount:%d\n", ethernet->ether_dhost, ethernet->ether_shost, ethernet->ether_type, count);
	}
	//printf("HANDLED PACKET INFO:\nIP dir:%s\nIP source:%s\nIP type:%d\ncount:%d\n", ethernet->ether_dhost, ethernet->ether_shost, ethernet->ether_type, count);
	//printf("PACKET HANDLED:%s", payload);

	//printf("PACKET CATHED:\ntime:%d\nCaplen:%d\nLen:%d\n", pkthdr->ts, (int)(pkthdr->caplen), (int)(pkthdr->len));
	count++;
}

int main(int argc, char *argv[])
{

	const struct sniff_ethernet *ethernet; /* Заголовок Ethernet */
	const struct sniff_ip *ip;			   /* Заголовок IP */
	const struct sniff_tcp *tcp;		   /* Заголовок TCP */
	u_char *payload = 0;				   /* Данные пакета */

	u_int size_ip;
	u_int size_tcp;

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

	pcap_loop(handle, -1, callback, NULL);

	pcap_close(handle);
	return (0);
}