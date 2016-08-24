#include <Winsock2.h>
#include "pcap.h"
#include <stdlib.h>

/* backward */
int packet_handler_backward(pcap_t *fp, u_char *pkt_data, struct pcap_pkthdr *header);
void ip_checksum_backward(struct ip_header *ih);
void tcp_checksum_backward(struct tcp_header *tcp, struct pseudo_header *psh, struct pcap_pkthdr *header);
void change_MAC_Addr_backward(struct ether_header *eh);

/* forward*/
int packet_handler_foward(pcap_t *fp, u_char *pkt_data, struct pcap_pkthdr *header);
void ip_checksum_foward(struct ip_header *ih);
void tcp_checksum_foward(struct tcp_header *tcp, struct pseudo_header *psh, struct pcap_pkthdr *header);
