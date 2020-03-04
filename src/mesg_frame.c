/**
 * 该文件用来构造IP包的链路层,生成上行信道突发信息帧
 */
#include "frame.h"
#include "global.h"
#include <stdlib.h>
#include <sys/time.h> 
#include <sys/types.h> 
#include <unistd.h>

typedef int	bool; 

unsigned short frameSendCount = 0;
unsigned short frameRecvCount = 0;
unsigned char sarCount = 0;

static int qosLv;
static int qosQueue;
static int getQosLv();
static int getQosQueue();
int buildFrameHead(unsigned char * pFrame, IP_HEADER *iph);
struct frameQueue queue_resources;
void buildSar(unsigned char *pgrp, int num, unsigned char flag);
extern pthread_mutex_t ccb_link_lock;

struct highPriorityFrame highpframe;

bool frame_queue_init()		//为队列中的所有帧做初始化
{
	int i;
	struct frameQueue * pq = &queue_resources;
	
	pq->headOfQueue = (unsigned char **)malloc(maxSizeOfQue * sizeof(char *));
	if(pq->headOfQueue == NULL)
	{
		return false;
	}
	queue_resources.front = 0;
	queue_resources.rear = 0;
	
	for(i = 0; i < maxSizeOfQue; i++)
	{
		pq->headOfQueue[i] = (unsigned char *)malloc(lenOfPkg);
		if(pq->headOfQueue[i] == NULL)
		{
			return false;
		}
	}
	pthread_rwlock_init(&queue_resources.lock, NULL);
	
	highpframe.pframe[0] = (unsigned char *)malloc(lenOfPkg);
	highpframe.pframe[1] = (unsigned char *)malloc(lenOfPkg);
	highpframe.flag = 0;
	pthread_mutex_init(&highpframe.lock, NULL);

	return true;
}

bool isEmptyQue()	//判断队空
{
	if(queue_resources.rear == queue_resources.front)
	{
		return true;
	}	
	else
	{
		return false;
	}
}

bool isFullQue()	//判断队满
{
	struct frameQueue * pq = &queue_resources;
	
	if((pq->rear + 1) % maxSizeOfQue == pq->front)//队满
	{
		return true;
	}
	
	return false;
}

bool EnQueue()	//入队操作
{
	struct frameQueue * pq = &queue_resources;
	
	if(isFullQue())
	{
		return false;
	}
	
	pq->rear = (pq->rear + 1) % maxSizeOfQue;

	return true;
}

bool DeQueue()	//出队操作
{
	struct frameQueue * pq = &queue_resources;

	if(pq->rear == pq->front)//队空
	{
		return false;
	}
	
	pq->front = (pq->front + 1) % maxSizeOfQue;

	return true;
}

int encap_frame(char *ip_pck)
{
	int i, icmpOfHub = 0;	//icmpOfHub表示该帧是否是对主站发的icmp在网探测帧的响应
	int frameCapacity, frameNed, queSpaceleft;	//frameCapacity表示单帧最大承载数据的容量，frameNed表示该ip包需要几帧才能完成封装
	unsigned char * pFrame = NULL;	//帧长指针
	IP_HEADER *iph = (IP_HEADER *)ip_pck;	//IP头指针
	uint16_t ipLen = ntohs(iph->total_len);	//ip包长
	
	if(iph->proto == 06)	//如果是tcp包进入tcp处理流程
	{
		pthread_mutex_lock(&ccb_link_lock);
		if(dealTcp(iph, local) == 0)
		{
			pthread_mutex_unlock(&ccb_link_lock);
			return 0;
		}
		pthread_mutex_unlock(&ccb_link_lock);
	}
	else if(iph->proto == 01)	//如果是对主站发送的icmp管理帧的应答则置位标识
	{
		if(strcmp(ip_eth1, inet_ntoa(*(struct in_addr *)(&(iph->sourceIP)))) == 0)
		{
			icmpOfHub = 1;
		}
	}
	
	sarCount++;	//该计数每个ip包到来加1即可，主要用来填充后面的sar标识字段
	
	frameCapacity = grpLen - 2;	//grpLen是信息分组的长度，减去两个字节的crccheck就是帧的最大数据承载量
	
	
	/*
		这里请注意：存在三种情况：
		现在帧的最大承载容量为394字节，
		1 如果ipLen%394 == 0的话，则最后一帧就满帧填充，不再有长度字段，sar第二字节的前两个bit为10
		2 如果0 < ipLen%394 <= 392,则是最普通的正常填充，尾帧sar第二字节的前两bit为11
		3 如果ipLen%394 == 393，这种情况就比较尴尬，如果尾帧填充长度字段2字节，帧长就不够用，如果不填充长度字段，又无法判断帧何时结束。
		这种情况需要把这393字节分两次封装，前一帧封装392字节，后一帧封装1字节。第一帧sarbit标识为01，第二帧为11。
	*/
	
	frameNed  = ipLen / frameCapacity;
	
	if(((ipLen % frameCapacity) <= (frameCapacity - 2)) && (ipLen % frameCapacity != 0))	//0 < ipLen%394 <= 392
	{
		frameNed++;
	}
	else if((ipLen % frameCapacity) == (frameCapacity - 1))	//ipLen%394 == 393
	{
		frameNed += 2;
	}
	
	QUEUE_LOCK_READ();	
	if(queue_resources.rear >= queue_resources.front)
	{
		queSpaceleft = maxSizeOfQue - (queue_resources.rear - queue_resources.front);
	}
	else
	{
		queSpaceleft = queue_resources.front - queue_resources.rear;
	}
	if(queSpaceleft < frameNed)		//队列中剩余的空帧个数不够本次数据发送
	{
		return 0;
	}
	QUEUE_UNLOCK_READ();
	
	for(i = 0; i < frameNed; i++)
	{
		if(icmpOfHub == 0)
		{
			pFrame = queue_resources.headOfQueue[queue_resources.rear];//如果是普通数据包，从队列中取出一个空帧进行封装
		}
		else
		{
			pthread_mutex_lock(&highpframe.lock);
			if(highpframe.flag & icmp_ready)
			{
				pthread_mutex_unlock(&highpframe.lock);
				PEP_DEBUG("no room for icmp frame");
				return 0;
			}
			pthread_mutex_unlock(&highpframe.lock);
			pFrame = highpframe.pframe[0];	//否则取出高优先级数组填充
		}
		
		pFrame += 1;	//跳过一字节时隙
		buildFrameHead(pFrame, iph);	//build帧头，该次帧头的构建仅仅是一个大概的构建，在发送的时候再填上发送帧计数和接收帧计数
		pFrame += 8;
		
		if(frameNed == 1)//jump out
		{
			if(ipLen == frameCapacity)
			{
				buildSar(pFrame, 0, SAR_END);
				pFrame += 2;
			}
			else
			{
				buildSar(pFrame, 0, SAR_END + SAR_LEN);
				pFrame += 2;
				*(unsigned short *)(pFrame) = htons(ipLen);
				pFrame += 2;
			}
			memcpy(pFrame, ip_pck, ipLen);
			pFrame += ipLen;
		}
		else
		{
			if(ipLen < (frameCapacity - 1))//剩余ip包长度小于393
			{
				buildSar(pFrame, i, SAR_MORE + SAR_END + SAR_LEN);
				pFrame += 2;
				*(unsigned short *)(pFrame) = htons(ipLen);
				pFrame += 2;
				memcpy(pFrame, ip_pck, ipLen);
				pFrame += ipLen;
			}
			else if(ipLen == (frameCapacity - 1))//剩余ip包长等于393
			{
				buildSar(pFrame, i, SAR_MORE + SAR_LEN);
				pFrame += 2;
				*(unsigned short *)(pFrame) = htons(ipLen - 1);
				pFrame += 2;
				memcpy(pFrame, ip_pck, ipLen - 1);
				pFrame += ipLen - 1;
				ip_pck += ipLen - 1;
				ipLen = 1;
			}
			else if(ipLen == frameCapacity)//jump out 剩余ip包长等于394
			{
				buildSar(pFrame, i, SAR_MORE + SAR_END);
				pFrame += 2;
				memcpy(pFrame, ip_pck, ipLen);
				pFrame += ipLen;
			}
			else//剩余ip包长度大于394
			{
				buildSar(pFrame, i, SAR_MORE);
				pFrame += 2;
				memcpy(pFrame, ip_pck, frameCapacity);
				pFrame += frameCapacity;
				ip_pck += frameCapacity;
				ipLen -= frameCapacity;
			}
		}
		
		//最后一帧的末尾，数据填充完毕之后两个字节填充00
		pFrame[0] = 0;
		pFrame[1] = 0;
		
		if(icmpOfHub == 0)
		{
			QUEUE_LOCK_WRITE();
			EnQueue();
			QUEUE_UNLOCK_WRITE();
		}
		else
		{	
			pthread_mutex_lock(&highpframe.lock);
			highpframe.flag |= icmp_ready;
			pthread_mutex_unlock(&highpframe.lock);
		}
	}
	
	return 0;
}

int buildFrameHead(unsigned char *frameBuffer, IP_HEADER *iph)
{
	frameBuffer[0] = 0;
	frameBuffer[1] = 1;
	
	frameBuffer[2] = myRemtId83;
	frameBuffer[3] = myRemtId2;
	
	frameBuffer[4] = iph->proto;
	
	return 0;
}

void buildFrameHead2(unsigned char *frameBuffer)
{
	unsigned char proto, temp;
	
	proto = frameBuffer[4];
	
	*(unsigned short *)(frameBuffer + 6) = htons(frameRecvCount);
	
	if(proto == 06)
	{
		*(unsigned short *)(frameBuffer + 4) = htons(frameSendCount++);
	}
	else
	{
		*(unsigned short *)(frameBuffer + 4) = 0;
	}
	
	PEP_DEBUG("recv:%d send:%d--sendType %d", frameRecvCount, frameSendCount, proto);
	
	temp = frameBuffer[5] & 0x03;
	temp = temp << 6;
	temp &= 0xc0;
	
	frameBuffer[6] &= 0x3F;
	
	frameBuffer[6] = frameBuffer[6] | temp;

	*(unsigned short *)(frameBuffer + 4) = htons(ntohs((*(unsigned short *)(frameBuffer + 4))) >> 2);
	
	frameBuffer[4] &= 0x0F;
	
	if(proto != 6 && proto != 8)
	{
		frameBuffer[4] |= 0xc0;
	}
	else if(proto == 8)//短帧
	{
		frameBuffer[4] |= 0x80;
	}
	
	return ;
}

void buildSar(unsigned char *pgrp, int num, unsigned char flag) //flag 0001 是否分片 0010 本帧是否是结束帧 0100 本帧是否带有帧长指示
{
	sarMark *psar = (sarMark *)pgrp;
	
	if(flag & SAR_MORE)	//是否分片 如果分片sar第一字节如此填充
	{
		psar->a = 1;
		psar->b = 0;
		psar->c = sarCount;
		psar->d = 1;
	}
	else
	{
		pgrp[0] = 0;//否则填0
	}
	
	if(flag & SAR_END)	//是结束帧
	{
		psar->cutMark1 = 1;
	}
	else
	{
		psar->cutMark1 = 0;
	}
	
	if(flag & SAR_LEN)	//需要带有长度指示
	{
		psar->cutMark2 = 1;
	}
	else
	{
		psar->cutMark2 = 0;
	}
	
	psar->cutCount = num;	//帧编号，sar最后6bit

	return ;
}
