#include <stdio.h>
#include "pcap.h"
#include <Winsock2.h>
#include "remote-ext.h" 
#include "function.h"

#pragma comment (lib, "wpcap.lib")  
#pragma comment(lib, "Ws2_32.lib")
//#pragma warning( disable : 4996)			// scnaf_s �Ⱦ�

int main()
{
	struct pcap_pkthdr *header;
	u_char *pkt_data;
	pcap_t *fp;		// Device
	pcap_if_t *alldevs;			// ����̽� ��� ����Ʈ
	pcap_if_t *d;				// ������ ����̽�
	int choice;					// ����̽� ���� ��ȣ
	int i = 0;
	u_int BlockType;
	u_int res;

	char errbuf[PCAP_ERRBUF_SIZE];
	// ����̽� ����Ʈ ������

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

	// ����̽� ����Ʈ ���
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");		// ����̽� ��� ����
	}

	// ����̽� ����Ʈ ���� �� 
	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	// ����̽� ����
	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &choice);

	// �̻��� ���� �־��� �ȳ־���
	if (choice < 1 || choice > i)
	{
		printf("\nInterface number out of range.\n");
		// ��ȯ
		pcap_freealldevs(alldevs);
		return -1;
	}

	// ������ ��ġ��
	for (d = alldevs, i = 0; i< choice - 1; d = d->next, i++);

	// ��Ʈ��ũ ����̽� ����
	if ((fp = pcap_open_live(d->name, 65536, 1, 1, errbuf)) == NULL)		// ��Ŷ ���� �غ�
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("\nlistening on %s...\n", d->description);

	/* ĸó ���� */
	while ((res = pcap_next_ex(fp, &header, (const u_char **)&pkt_data)) >= 0)
	{
		if(BlockType >> 1)
			packet_handler_backward(fp, pkt_data, header);
		else
			packet_handler_foward(fp, pkt_data, header);
	}
	pcap_close(fp);    // ��Ʈ��ũ ����̽� �ڵ� ����  
	return 0;
}

