#ifndef MESG_FRAME_H
#define MESG_FRAME_H
#include "global.h"
#include "config.h"

#define BURST1		0 //分片IP包的首片或中间片（在帧首时） ，由后续计数指示片号00
#define BURST2  	1 //分片IP包的首片在帧中时 01
#define NOBURST 	3//不分片 11
#define grpLen  frameLen - 10

typedef struct msgframehead
{
	u_int8_t qosMsg;//qos相关信息和qos服务级别有关
	u_int8_t remoteNed;//远端站通信需求表示当前传输队列中数据传输可能需要的突发时隙数目。
}msgFrameHead;

typedef struct sarmark//信息分组
{
	u_int16_t d:1,	//Qos服务级别子队列编号	
			c:4,		//Qos服务级别
			b:2,
			a:1,
			cutCount:6,		//分片计数
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