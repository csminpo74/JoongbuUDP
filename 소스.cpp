#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <WS2tcpip.h>
#include "windivert.h"
#include <iostream>

#define MAXBUF  0xFFFF
/*
typedef struct
{
	WINDIVERT_IPHDR ip;
	WINDIVERT_TCPHDR tcp;
} TCPPACKET, *PTCPPACKET;
*/
int __cdecl main(int argc, char **argv)
{
	HANDLE handle;
	INT16 priority = 0;
	unsigned char packet[MAXBUF];
	UINT packet_len;
	WINDIVERT_ADDRESS recv_addr;
	PWINDIVERT_IPHDR ip_header;
	UINT payload_len;
	switch (argc)
	{
	case 3:
		priority = (INT16)atoi(argv[2]);
		break;
	default:
		fprintf(stderr, "usage: %s windivert-filter [priority]\n",
			argv[0]);
		fprintf(stderr, "examples:\n");
		fprintf(stderr, "\t%s true\n", argv[0]);
		fprintf(stderr, "\t%s \"outbound and tcp.DstPort == 80\" 1000\n",
			argv[0]);
		fprintf(stderr, "\t%s \"inbound and tcp.Syn\" -4000\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	handle = WinDivertOpen(argv[1], WINDIVERT_LAYER_NETWORK, priority, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			fprintf(stderr, "error: filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	while (TRUE) {
		if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_addr, &packet_len)) {
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}
		WinDivertHelperParsePacket(packet, packet_len, &ip_header,
			NULL, NULL, NULL, NULL,
			NULL, NULL, &payload_len);
		if (ip_header == NULL) {
			continue;
		}
		
		UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;	//xxx.121	쏘는사람
		UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;	//xxx.71	원래 받는사람
		
		printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u \n",
			src_addr[0], src_addr[1], src_addr[2], src_addr[3],
			dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
		inet_pton(AF_INET, "10.100.111.219", src_addr);
		inet_pton(AF_INET, "10.100.111.121", dst_addr);
		
		printf(">>ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u\n",
			src_addr[0], src_addr[1], src_addr[2], src_addr[3],
			dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
		if (*(UINT32 *)src_addr == *(UINT32 *)&ip_header->SrcAddr){
			WinDivertHelperCalcChecksums(packet, packet_len, 0);
			if (!WinDivertSend(handle, packet, packet_len, &recv_addr, NULL)) {
				std::cout << '!' << std::endl;
			}
		}
	}
}
