#ifndef CONFIG_H
#define CONFIG_H

#define myRemtId			0x03eb
#define myRemtId03			0x03
#define myRemtId83			0x83
#define myRemtId2			0xeb

#define hardwareID			0x0068B558
#define initial_slottime	0
#define frameFreeMark 		0x7ff8
#define frameApplyMark 		0x7ff4
#define frameReportMark		0x7fe0
#define maxSizeOfQue 		1000
#define lenOfPkg			410

#define onlyOneSlotSend		//只有一个时隙可供发送
#undef onlyOneSlotSend
#define applySlot			63

#ifdef	onlyOneSlotSend
#define which_slot_to_send	applySlot	//时隙2可供发送
#endif

#define ip_eth1				"182.168.1.1"

/* recv from HUB */
#define recv_localPort		10797
#define recv_localIp		"192.168.1.1"

/* send to modulator */
#define send_port			9387
#define	send_ip				"192.168.1.2"

#endif