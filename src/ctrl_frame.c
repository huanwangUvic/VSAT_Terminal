/**
 * 该文件是部分控制帧的构造和发送函数
 */

#include "frame.h"
#include "config.h"

 struct statedata
 {
	uint8_t MN;
	uint8_t PQ;
	uint16_t counter;
 };

 void updateFreeData(uint8_t flag);
 static void applyFrame_init();
 static void freeFrame_init();
 
 static uint8_t frameFreeBuf[410];
 static uint8_t applyFrameBuf[410];
 static struct statedata freeData;
 extern unsigned char sysMessage[];
 extern unsigned int rateShift;
 extern unsigned int superFrameNum;

/*
 * 空闲帧0x7ff8
 * 说明	信息帧头	远端站ID	 控制帧标识	  控制信息或状态数据	  帧校验
 * 长度	0x00 00	     2字节	    0x7F F8 00 00	     ……	            2字节CRC+填充
 */
 
 void ctrlInit()
 {
	freeFrame_init();
	applyFrame_init();
 }
 
static void freeFrame_init()
 {
	int index = 0;
	
	index += 1;
	frameFreeBuf[index++] = 0;
	frameFreeBuf[index++] = 1;
	*(uint16_t *)(frameFreeBuf + index) = htons(myRemtId | 0x8000);
	index += 2;
	*(uint16_t *)(frameFreeBuf + index) = htons(frameFreeMark);
	index += 2;
	frameFreeBuf[index++] = 0;
	frameFreeBuf[index++] = 0;
	
	freeData.MN = 0xaa;
	freeData.PQ = 0x10;
	freeData.counter = 4;
	
	return ;
 }
 
 void updateFreeData(uint8_t flag)//flag = 0 仅仅更新时隙,flag=1更新超帧
 {
	if(flag == 0)
	{
		freeData.PQ += 0x11;	
	}
	else
	{
		freeData.MN++;
		freeData.PQ = 0x10;
	}	
 }
 
 void send_freeFrame(int slotNum)
 {
	int i = 1 + 8, j;
	
	while(i < frameLen)
	{
		j = frameLen - i;
		switch(j)
		{
			case 1:
			{
				frameFreeBuf[i] = freeData.MN;
				break;
			}
			case 2:
			{
				frameFreeBuf[i] = freeData.MN;
				if(i < 24)
				{
					frameFreeBuf[i + 1] = freeData.PQ;
				}
				else
				{
					frameFreeBuf[i + 1] = freeData.PQ + 1;
				}
				break;
			}
			case 3:
			{
				frameFreeBuf[i] = freeData.MN;
				if(i < 24)
				{
					frameFreeBuf[i + 1] = freeData.PQ;
				}
				else
				{
					frameFreeBuf[i + 1] = freeData.PQ + 1;
				}
				frameFreeBuf[i + 2] = freeData.counter >> 8;
				break;
			}
			default :
			{
				frameFreeBuf[i] = freeData.MN;
				if(i < 24)
				{
					frameFreeBuf[i + 1] = freeData.PQ;
				}
				else
				{
					frameFreeBuf[i + 1] = freeData.PQ + 1;
				}
				frameFreeBuf[i + 2] = freeData.counter >> 8;
				frameFreeBuf[i + 3] = freeData.counter & 0x00FF;
				break;
			}
		}
		i += 4;
	}

	send_frame(frameFreeBuf, slotNum);
	freeData.counter++;

	return ;
 }
 
/*
 * 入网捕获申请帧 0x7ff4
 * 说明	信息帧头	远端站ID	 控制帧标识	  控制信息或状态数据	  帧校验
 * 长度	0x00 00	     2字节	    0x7F F8 00 00	     ……	            2字节CRC+填充
 */
 static void applyFrame_init()
 {
	int index = 0;
	
	index += 1;
	
	applyFrameBuf[index++] = 0;
	applyFrameBuf[index++] = 1;
	*(uint16_t *)(applyFrameBuf + index) = htons(myRemtId | 0x8000);
	index += 2;
	
	*(uint16_t *)(applyFrameBuf + index) = htons(frameApplyMark);
	index += 2;
	
	applyFrameBuf[index++] = 0;
	applyFrameBuf[index++] = 0;
	*((uint32_t *)(applyFrameBuf + index)) = htonl(0x0000012e);
	index += 4;
	*((uint32_t *)(applyFrameBuf + index)) = 0;
	index += 4;
	/*跳过频率偏移字段*/
	index += 4;
	*((uint32_t *)(applyFrameBuf + index)) = 0;
	
	return ;
 }
 
 void send_applyFrame()
 {
	unsigned char * pStart = applyFrameBuf + 1;
	
	*(uint32_t *)(pStart + 16) = htonl(rateShift);
	memcpy(pStart + 24, sysMessage, 12);
	*(uint32_t *)(pStart + 36) = htonl(superFrameNum);
	
	send_frame(applyFrameBuf, applySlot);
	
	return ;
 }
 