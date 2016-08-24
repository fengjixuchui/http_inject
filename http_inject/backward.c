#include "header.h"
#include "function.h"
#include <Winsock2.h>
#include "pcap.h"

int packet_handler_backward(pcap_t *fp, u_char *pkt_data, struct pcap_pkthdr *header)
{
	struct ether_header *eh;
	eh = (struct ether_header *)(pkt_data);
	struct ip_header *ih;							// IP 구조체 선언
	ih = (struct ip_header *)(pkt_data + 14);
	struct tcp_header *tcp;							// tcp 구조체 선언
	tcp = (struct tcp_header *)(pkt_data + 34);

	if (pkt_data == NULL || tcp == 0xccccccee)		// 패킷도 안가져와 놓고 이 함수로 오면 다 튕겨냄
		return 0;
	if (ntohs(tcp->dst_port) != 0x0050)				// http 통신이 아니면 버림
		return 0;
	char get_buf[12];										// Get문자를 담는 임시 배열
	memcpy(get_buf, (pkt_data + 54), sizeof(get_buf));
	get_buf[11] = '\0';
	if (strncmp(get_buf, "GET / HTTP/", sizeof(get_buf) - 1))	// HTTP의 GET 인지 확인
		return 0;

	char *Data = "blocked\0";
	/* IP checksum */
	u_char *p = (u_char *)ih;
	ip_checksum_backward(ih);

	/* Change Ethernet Address */
	change_MAC_Addr_backward(eh);

	struct pseudo_header *psh;						// pseudo_header 구조체 선언
	psh = (struct pseudo_header *)malloc(sizeof(pseudo_header));
	psh->ip_dst_addr, ih->ip_dst_addr;								// IP 도착지
	psh->ip_src_addr = ih->ip_src_addr;								// IP 시작지
	psh->placeholder = 0x00;										// Reserve 항상 0
	psh->protocol = ih->ip_protocol;								// IP 프로토콜	
	psh->tcp_length = sizeof(tcp_header) + (u_short)strlen(Data); // TCP header + Data len
																  /* TCP checksum */
	tcp_checksum_backward(tcp, psh, header);

	/* Packet Make */
	u_char *packet;
	int packet_size;
	packet_size = 54 + strlen(Data);						// 61 bytes
	packet = (u_char *)malloc(packet_size);
	memcpy(packet, pkt_data, 14);							// Ethernet
	memcpy(packet + 14, p, 20);		// IP
	memcpy(packet + 34, tcp, 20);	// TCP
	memcpy(packet + 54, Data, strlen(Data));				// Data

															/* Send packet */
	pcap_sendpacket(fp, packet, packet_size);
	free(packet);
	free(psh);
	return 0;
}

void ip_checksum_backward(struct ip_header *ih)
{
	struct in_addr temp;
	temp = ih->ip_src_addr;
	/* chagne IP addr */
	ih->ip_src_addr = ih->ip_dst_addr;
	ih->ip_dst_addr = temp;

	ih->ip_total_length = 0x2F00;		// 0x2F00 추후에 ntohs수정

	u_short *p = (u_short *)ih;
	u_int sum = 0;
	for (u_int i = 0; i < 9; i++)
		sum += ntohs(*p++);
	sum += ntohs(*p++);

	sum = (sum >> 16) + (sum & 0xffff);
	sum = ~sum;
}

void tcp_checksum_backward(struct tcp_header *tcp, struct pseudo_header *psh, struct pcap_pkthdr *header)
{
	u_short *tcp_data = (u_short *)tcp;
	u_short *psh_data = (u_short *)psh;
	u_int sum = 0;
	u_int i;

	/* port change */
	u_short port_temp;
	port_temp = tcp->source_port;
	tcp->source_port = tcp->dst_port;
	tcp->dst_port = port_temp;

	/* seq, ack change */
	u_int temp = tcp->acknowledge;
	tcp->acknowledge = ntohl(tcp->sequence) + (header->len - 54);
	tcp->acknowledge = htonl(tcp->acknowledge);
	tcp->sequence = temp;

	/* Flag and Checksum*/
	tcp->checksum = 0;
	tcp->flags = 0x11;
	for (i = 0; i < 5; i++)
		sum += ntohs(*psh_data++);
	sum += ntohs(*psh_data);			// psh_data 주소가 이상한 값으로 가는 거 방지

	for (i = 0; i < 9; i++)
		sum += ntohs(*tcp_data++);

	sum += ntohs(*tcp_data);			// tcp_data 주소가 이상한 값으로 가는 거 방지	
	sum = (sum >> 16) + (sum & 0xffff);
	sum = ~sum;
	tcp->checksum = (u_short)sum;
}

void change_MAC_Addr_backward(struct ether_header *eh)
{
	u_char temp[6];
	/* chagne MAC Addr */
	memcpy(temp, eh->dst_addr, sizeof(eh->dst_addr));
	memcpy(eh->dst_addr, eh->src_addr, sizeof(eh->dst_addr));
	memcpy(eh->src_addr, temp, sizeof(eh->dst_addr));
}