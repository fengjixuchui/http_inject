#include <stdio.h>
#include "pcap.h"
#include <Winsock2.h>
#include "remote-ext.h" 
#include "function.h"

#pragma comment (lib, "wpcap.lib")  
#pragma comment(lib, "Ws2_32.lib")
//#pragma warning( disable : 4996)			// scnaf_s 안씀

int main()
{
	struct pcap_pkthdr *header;
	u_char *pkt_data;
	pcap_t *fp;		// Device
	pcap_if_t *alldevs;			// 디바이스 목록 리스트
	pcap_if_t *d;				// 선택한 디바이스
	int choice;					// 디바이스 선택 번호
	int i = 0;
	u_int BlockType;
	u_int res;

	char errbuf[PCAP_ERRBUF_SIZE];
	// 디바이스 리스트 가져옴

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	/* Backwrad? Forward? */
	printf("Forward : 1, Backward : 2 : ");
	scanf_s("%d", &BlockType);
	if (BlockType == 2)
		printf("Backward start\n\n");
	else if (BlockType == 1)
		printf("Forward start\n\n");
	else
	{
		fprintf(stderr, "error!\n");
		exit(1);
	}

	// 디바이스 리스트 출력
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");		// 디바이스 출력 오류
	}

	// 디바이스 리스트 없을 시 
	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	// 디바이스 선택
	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &choice);

	// 이상한 값을 넣었나 안넣었나
	if (choice < 1 || choice > i)
	{
		printf("\nInterface number out of range.\n");
		// 반환
		pcap_freealldevs(alldevs);
		return -1;
	}

	// 선택한 장치로
	for (d = alldevs, i = 0; i< choice - 1; d = d->next, i++);

	// 네트워크 디바이스 오픈
	if ((fp = pcap_open_live(d->name, 65536, 1, 1, errbuf)) == NULL)		// 패킷 받을 준비
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("\nlistening on %s...\n", d->description);

	/* 캡처 시작 */
	while ((res = pcap_next_ex(fp, &header, (const u_char **)&pkt_data)) >= 0)
	{
		if(BlockType >> 1)
			packet_handler_backward(fp, pkt_data, header);
		else
			packet_handler_foward(fp, pkt_data, header);
	}
	pcap_close(fp);    // 네트워크 디바이스 핸들 종료  
	return 0;
}

