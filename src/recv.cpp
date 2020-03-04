/**
 * 该文件是接收主站数据的处理线程
 */

#include "config.h"
#include "global.h"
#include "HDLCFrame.h"
#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#define bufLength	1024 * 32

using namespace std;

bool isFrameSendCountInit = 0;
int iGetMySlottime = 0;
int inNetState = 0;
unsigned int superFrameNum;		//当前超帧号
unsigned short powerAdjust;		//功率调整
unsigned short symbolShitf;		//符号偏移
unsigned int rateShift;			//频率偏移
unsigned char sysMessage[13] = {0};	//12字节系统信息,13字节表示数组是否已经填充
unsigned int myTimeStatus[3];
unsigned char tunnel0_buf[500];
unsigned char myRmotSlotNum;		//远端站分配时隙时的编号

extern int serverSockId;
extern struct highPriorityFrame highpframe;
extern unsigned int frameRecvCount;
extern unsigned int frameSendCount;
extern pthread_cond_t inNet_Condvar;
extern pthread_mutex_t inNet_Mutex;
extern struct frameQueue queue_resources;

#ifdef __cplusplus
extern "C" {
#endif
extern void updateFreeData(unsigned char);
extern void send_applyFrame();
extern int toTun(const unsigned char *);
extern int reAccept();
extern void send_freeFrame(int);
extern int send_frame(unsigned char *, int);
extern int send_slotInform(int);
extern int isEmptyQue();
extern int isFullQue();
extern int DeQueue();
extern int EnQueue();
extern void buildFrameHead2(unsigned char *);
extern void dealTcp(unsigned char *, unsigned char);
extern pthread_mutex_t ccb_link_lock;
#ifdef __cplusplus
}
#endif

extern "C" void * recv_loop();
static void goHandleFrame(const unsigned char *p,int len);
 
static unsigned int getIntValue(const unsigned char *p)
{
	return ntohl(*((unsigned int *)(p)));
}

static unsigned short getShortValue(const unsigned char *p)
{
	return ntohs(*((unsigned short *)(p)));
}

static bool isCtrlFrame(const unsigned char * buf)
{
	if((*((uint32_t *)(buf)) == htonl(0xFFFF7FFC)) && ((*(uint32_t *)(buf + 4))==0))
	{
		return true;
	}

	return false;
}

//本周期内主站共为我分配了多少个时隙
static int howManySlotIget(const unsigned char * pSlotStart)
{
	int i, count = 0;
	
	for(i = 0; i < 62; i++)
	{
		if(*pSlotStart == myRmotSlotNum)
		{
			count++;
		}
		pSlotStart++;
	}
	
	return count;
}

static bool getNextSlot(const unsigned char * pSlotStart, int *nowSlotNum)
{
	int i = *nowSlotNum;
	
	while(i--)
	{
		pSlotStart++;
	}
	
	for(i = *nowSlotNum; i < 62; i++)
	{
		if(*pSlotStart == myRmotSlotNum)
		{
			*nowSlotNum = ++i;
			return true;
		}
		pSlotStart++;
	}
	
	return false;
}

//发送c6重置发送帧计数
static void send_c6()
{
	unsigned char * pFrame;
	
	if(highpframe.flag & c6_ready)
	{
		PEP_DEBUG("no room for c6 frame");
		return ;
	}
	
	pFrame = highpframe.pframe[1];
	pFrame += 1;
	
	{
		*(pFrame++) = 0;
		*(pFrame++) = 1;
		*(pFrame++) = myRemtId83;
		*(pFrame++) = myRemtId2;
		*(pFrame++) = 0xc6;
	}
	
	highpframe.flag |= c6_ready;
	
	return ;
}

//接收主站数据线程
void * recv_loop()
{
	int readBytes;
	int recvFrameLen;
	CHDLCFrame * hdlcWork = new CHDLCFrame(1);
	struct sockaddr_in clientAddr;
	socklen_t fromLen = sizeof(struct sockaddr_in);
	unsigned char * mainBuf = new unsigned char[bufLength];
	
	for(;;)
	{
		readBytes = recvfrom(serverSockId, mainBuf, bufLength, 0, (struct sockaddr *)&clientAddr, &fromLen);

		if(readBytes <= 0)
		{
			PEP_DEBUG("system abortion going to exit");
			exit(0);
		}
		else
		{
			while (hdlcWork->GetDataBlock(mainBuf, readBytes))
			{
				if (hdlcWork->bCurFrameCorrect && (hdlcWork->DataLen > 2))
				{
					recvFrameLen = hdlcWork->DataLen - 2;
					goHandleFrame(hdlcWork->Data,recvFrameLen);
				}
			}
		}
	}
	
	pthread_exit(NULL);
}

static void goHandleFrame(const unsigned char *pbuf, int recvFrameLen)
{	
	int ipStart;
	IP_HEADER *iph;
	
	if(pbuf[0] == myRemtId83 && pbuf[1] == myRemtId2)//开头就是站址号，这是一个数据帧,或是压缩的tcp帧
	{
		if((pbuf[2] & 0xF0) == 0x00)//tcp
		{
			frameRecvCount++;
		}
		
		if((pbuf[2] == 0xf6) && (inNetState > 0))//如果收到83ebf6帧，表明发送帧计数已经错乱，则发送c6帧来请求主站重置
		{
			PEP_DEBUG("recv f6");
			isFrameSendCountInit = false;
			send_c6();
		} 
		else if(((pbuf[2] & 0xF0) == 0xc0) && isFrameSendCountInit == false)//重新读取发送帧计数
		{
			isFrameSendCountInit = true;
			frameSendCount = (pbuf[4] & 0x3f)*256 + pbuf[5];
			PEP_DEBUG("send count 赋值成功 %d", frameSendCount);
		}
		
		if(recvFrameLen == 14 && inNetState > 0)	//14字节短帧，进入tcp处理函数
		{
			if(pbuf[6] == 0x89 && pbuf[7] == 0x04)
			{
				pthread_mutex_lock(&ccb_link_lock);
				dealTcp((unsigned char *)pbuf, hub_14);
				pthread_mutex_unlock(&ccb_link_lock);
			}	
		}
		//所有的正常ip数据包
		else if(((pbuf[2] & 0xF0) == 0xc0 || (pbuf[2] & 0xF0) == 0x00) && inNetState > 0)
		{
			if ((pbuf[6] == 0x45 && pbuf[7] == 0) || (pbuf[6] == 0x46 && pbuf[7] == 0)) 
			{
				ipStart = 6;
			}
			else if((pbuf[8] == 0x45 && pbuf[9] == 0) || (pbuf[8] == 0x46 && pbuf[9] == 0)) 
			{
				ipStart = 8;
			}
			else
			{
				return ;
			}
			//包长度检测
			if(recvFrameLen < (getShortValue(pbuf + ipStart + 2) + ipStart))
			{
				return ;
			}
			
			//到达此处的都是标准的IP包
			
			iph = (IP_HEADER *)(pbuf + ipStart);
			
			if(iph->proto == 06)//进入tcp处理函数
			{
				pthread_mutex_lock(&ccb_link_lock);
				dealTcp((unsigned char *)(pbuf + ipStart), hub_normal);
				pthread_mutex_unlock(&ccb_link_lock);
			}
			else
			{
				toTun(pbuf + ipStart);//通过虚拟网卡下发数据
			}
		}
	}
	
	else if(isCtrlFrame(pbuf))
	{
		switch(pbuf[9])
		{
			case 0xDD:
			{	
				int i, iPos = 38, slotNumResrv, nowSlotNum = 0, iGetRemotAdjustHint = 0;	//slotNumResrv表示剩余时隙数，后一个参数目前无实际意义
				int slotStart = iPos + 16 + pbuf[13] * 12;
				
				if(inNetState == 0)
				{
					if(howManySlotIget(pbuf + slotStart) > 0)//如果获得了时隙分配，入网成功，inNetState = 1
					{
						inNetState++;
						WAKEUP_WAITERS_INNEXT(inNet_Condvar);
					}
					else if(sysMessage[12] && iGetMySlottime)//否则继续发送f4帧，sysMessage[12]表示是否已经读取到了主站的0x40帧，iGetMySlottime表示上个周期收到了主站的入网提示
					{
						send_applyFrame();
						PEP_DEBUG("send apply success");
					}
				}
				
				if(inNetState == 1)
				{
					slotNumResrv = howManySlotIget(pbuf + slotStart);	//得到了多少个时隙分配
					
					if(slotNumResrv == 0)
					{
						inNetState = 0;		//没有获得时隙分配，此时已经离网
						goto next;
					}
					
					send_slotInform(slotNumResrv);
					
					pthread_mutex_lock(&highpframe.lock);
					while(getNextSlot(pbuf + slotStart, &nowSlotNum))
					{
						if(highpframe.flag & icmp_ready)		//有icmp需要发送
						{
							buildFrameHead2(highpframe.pframe[0] + 1);
							send_frame(highpframe.pframe[0], nowSlotNum);
							highpframe.flag &= ~icmp_ready;		//清除icmp_ready标识
							continue;
						}
						
						if(highpframe.flag & c6_ready)			//高优先级数组中有c6帧需要发送
						{
							send_frame(highpframe.pframe[1], nowSlotNum);
							highpframe.flag &= ~c6_ready;		//清除c6_ready标识				
							continue;
						}
						
						QUEUE_LOCK_READ();
						if(!isEmptyQue())
						{	
							QUEUE_UNLOCK_READ();
							buildFrameHead2(queue_resources.headOfQueue[queue_resources.front] + 1);	//填充帧头的两个计数字段,以及时隙
							send_frame(queue_resources.headOfQueue[queue_resources.front], nowSlotNum);
							
							QUEUE_LOCK_WRITE();
							DeQueue();
							QUEUE_UNLOCK_WRITE();
							continue;
						}
						QUEUE_UNLOCK_READ();
						
						send_freeFrame(nowSlotNum);
					}
					pthread_mutex_unlock(&highpframe.lock);
				}
				
next:				
				iGetMySlottime = 0;			//本周期内是否获得了入网提示的标识
				
				superFrameNum = ntohl(*((unsigned int *)(pbuf + 26)));	//获取本周期的超帧号
				updateFreeData(1);			//更新一次空闲帧
				
				if(pbuf[12] == 0x80)		//
				{
					if(getIntValue(pbuf+iPos) == myRemtId)	//
					{
						iPos += 4; 
						myRmotSlotNum = pbuf[iPos + 2];	//在分配时隙时本小站的编号
						iPos += 12;
						iGetMySlottime = 1;
					}
					else
					{
						iPos += 16;
					}
				}
				
				for(i=0; i < pbuf[13]; i++)
				{
					if(getIntValue(pbuf + iPos + i*12) == hardwareID)
					{
						powerAdjust = getShortValue(pbuf + iPos + i*12 + 4);
						symbolShitf = getShortValue(pbuf + iPos + i*12 + 6);
						rateShift = getIntValue(pbuf + iPos + i*12 + 8);	//这是主站提示的本小站的频率偏移
						iGetRemotAdjustHint = 1;
						
						break;
					}
				}

				break;
			}
			case 0x40:
			{
				memcpy(sysMessage, pbuf + 66, 12);	//系统信息字段
				sysMessage[12] = 1;					//增加了一个字节用来标识是否收到了系统信息字段
				break;
			}
			case 0xFD:
			{
				break;
			}
			case 0xFE:
			{
				break;
			}
		}
	}
	else
	{
		//未知
	}
	
	return ;
}

