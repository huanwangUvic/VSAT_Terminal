#include "global.h"
#include "config.h"
#include "CRC.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <string.h>
#include <pthread.h>

#define SOCKADDR_LEN sizeof(struct sockaddr)
#define DEBUG_ERROR

extern void updateFreeData(unsigned char);

int udpSockId;
int serverSockId;
struct sockaddr_in serverAddr;

int tcpServerInit()
{
	int status;          /* 记录函数的执行状态,返回值 */
    int reuse = 0;
	struct sockaddr_in si;
	
	//udp init
	udpSockId = socket(AF_INET, SOCK_DGRAM, 0);	//发送udpsockid
	if (udpSockId < 0)
	{
		printf("server: socket is wrong.\n");
		return 0;
	}
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(send_port);
	inet_aton(send_ip, &serverAddr.sin_addr);
	
	
    serverSockId = socket(AF_INET, SOCK_DGRAM, 0);	//接收udpsockId

    if (serverSockId == 0)
    {
        perror("socket:server open is wrong.\n");
        return TRUE;
    }

    bzero((char *)&si, SOCKADDR_LEN);
    si.sin_addr.s_addr = inet_addr(recv_localIp);
    si.sin_family = AF_INET;
    si.sin_port = htons(recv_localPort);
    
    status = bind(serverSockId, (struct sockaddr *)&si, SOCKADDR_LEN);
    #ifdef DEBUG_ERROR
    if (status == -1)
    {
        perror("bind is wrong. process will exit\n");
        close(serverSockId);
        exit(1);
    }
    #endif
	
	return 1;
}

int send_frame(unsigned char * buf, int slotNum)
{
	int CRC_Start = 1 + frameLen - 2;
	unsigned short nCRC = crc_ccitt(buf + 1, frameLen - 2);
	buf[CRC_Start] = nCRC >> 8;
	buf[CRC_Start + 1] = nCRC & 0xFF;
	
	buf[0] = slotNum;
	
	sendto(udpSockId , buf , frameLen + 2, 0 , (struct sockaddr *)&serverAddr, sizeof(serverAddr));

	updateFreeData(0);
	
	return 0;	
}


int send_slotInform(int allSlotNum)
{
	unsigned char buf[9];
	
	buf[0] = allSlotNum;
	*((long long *)(buf + 1)) = initial_slottime;
	
	sendto(udpSockId, buf, 9, 0, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
	
	return 0;
}
