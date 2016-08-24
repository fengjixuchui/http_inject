#include "pcap.h"
#pragma comment (lib, "wpcap.lib")  
#pragma comment(lib, "Ws2_32.lib")

typedef struct tcp_header
{
	u_short source_port;
	u_short dst_port;
	u_int sequence;
	u_int acknowledge;
	u_char th_off;
	u_char flags;
	u_short win;
	u_short checksum;
	u_short urqptr;
}tcp_header;

typedef struct ip_header
{
	u_char ip_version;
	u_short ip_total_length;
	u_short ip_id;
	u_char flag;
	u_short frag_offset;
	u_char ip_ttl;
	u_char ip_protocol;
	//u_short ip_checksum;
	struct in_addr ip_src_addr;
	struct in_addr ip_dst_addr;
}ip_header;

typedef struct pseudo_header {
	struct in_addr ip_src_addr;
	struct in_addr ip_dst_addr;
	u_char placeholder;
	u_char protocol;
	u_short tcp_length;
}pseudo_header;

typedef struct ether_header						// 이더넷 구조체
{
	u_char dst_addr[6];
	u_char src_addr[6];
	u_short ether_type;
}ether_header;