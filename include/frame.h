#ifndef MESG_FRAME_H
#define MESG_FRAME_H
#include "global.h"
#include "config.h"

#define BURST1		0 //��ƬIP������Ƭ���м�Ƭ����֡��ʱ�� ���ɺ�������ָʾƬ��00
#define BURST2  	1 //��ƬIP������Ƭ��֡��ʱ 01
#define NOBURST 	3//����Ƭ 11
#define grpLen  frameLen - 10

typedef struct msgframehead
{
	u_int8_t qosMsg;//qos�����Ϣ��qos���񼶱��й�
	u_int8_t remoteNed;//Զ��վͨ�������ʾ��ǰ������������ݴ��������Ҫ��ͻ��ʱ϶��Ŀ��
}msgFrameHead;

typedef struct sarmark//��Ϣ����
{
	u_int16_t d:1,	//Qos���񼶱��Ӷ��б��	
			c:4,		//Qos���񼶱�
			b:2,
			a:1,
			cutCount:6,		//��Ƭ����
			cutMark2:1,		
			cutMark1:1;	
			
	#define	SAR_MORE	0x01
	#define	SAR_END		0x02
	#define	SAR_LEN		0x04
	
}sarMark;

extern int CutToMsgFrameAndSend(char *);
extern int fd;
fd_set readfds;
struct timeval tv;

#endif