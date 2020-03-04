#ifndef GLOBAL_HEADER_H
#define GLOBAL_HEADER_H
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>

#include <stdlib.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pthread.h>


#define IP_SIZE				sizeof(IP_HEADER)			
#define UDP_SIZE 			sizeof(UDP_HEADER)		
#define TCP_SIZE			sizeof(TCP_HEADER)

#define	false	0
#define	true	1 

#define PEP_ERRBUF_SZ 1024

#define MAX_PKG_SIZE 80 /* ip header = 20 ~ 40, tcp header = 20 ~ 40; max = 80 */   

#define MAX_PSD_SIZE 52 /* psd header = 12, tcp header = 20 ~ 40; max = 52 tcp伪首部长度 */


#define pep_error(fmt, args...)                     \
    __pep_error(__FUNCTION__, __LINE__, fmt, ##args)
	
#define PEP_DEBUG(fmt, args...)                     \
    if (DEBUG) {                                    \
        fprintf(stderr, "[DEBUG] %s(): " fmt "\n",  \
                __FUNCTION__, ##args);              \
    }
	
extern int DEBUG;

#define TRUE	1
#define FALSE 	0

#define local		0
#define hub_normal 	1
#define hub_14		2

typedef int BOOL;

#define WAKEUP_WAITERS_INNEXT(CONVAR) 		pthread_cond_signal(&CONVAR)
#define WAITING_FOR_INNET(CONVAR, MUTEX)	pthread_cond_wait(&CONVAR, &MUTEX)

#define QUEUE_LOCK_READ()		pthread_rwlock_rdlock(&queue_resources.lock)
#define QUEUE_LOCK_WRITE()   	pthread_rwlock_wrlock(&queue_resources.lock)
#define QUEUE_UNLOCK_READ()  	pthread_rwlock_unlock(&queue_resources.lock)
#define QUEUE_UNLOCK_WRITE() 	pthread_rwlock_unlock(&queue_resources.lock)

struct highPriorityFrame 
{
	uint8_t * pframe[2];		//buf[0] for icmp ack, buf[1] for c6 reset frameSendCount
	uint8_t flag;
	#define icmp_ready	0x01
	#define c6_ready	0x02	
	pthread_mutex_t lock;
};

struct frameQueue 
{	
	unsigned char **headOfQueue;
	int front, rear;
	pthread_rwlock_t lock;
	
};

struct Addr{
	uint32_t ip;
	uint16_t port;
};

/* 用于计算TCP校验和的伪头部 */  
struct psdhdr{  
    uint32_t saddr; /* ip头部源地址 */  
    uint32_t daddr; /* ip头部目的地址 */  
    uint8_t mbz; /* 补全字段，需为0 */  
    uint8_t protocol; /* ip头部协议 */  
    uint16_t tcpl; /* tcp长度，包括头部和数据部分 */  
};

struct connectCtrlBlk
{
	uint8_t conn_state;	//lock
	
	uint16_t l_num;		//tcp连接编号 本端 主机字节序
	uint16_t f_num;		//tcp连接编号 对端 网络字节序
	uint16_t f_window;
	uint32_t seq;
	//记录hub端连接另一方的seq
	uint32_t fin_seq;	//记录Fin的序列号//开始用该变量来记录 synseq lock
	uint8_t	fin_direct;	//记录fin的方向	0 代表本端 1代表对端	lock
	
	struct Addr f_addr; //该字段表明连接的目的地址
	struct Addr l_addr; //src地址
	unsigned char * ptemplate;	//应答tcp模板
	
	struct connectCtrlBlk * next;//lock
};     

typedef struct _etherhdr
{
	uint8_t srcMac[6];
	uint8_t dstMac[6];
	uint16_t type;
}E_HEADER;

typedef struct _iphdr //定义IP首部 
{ 
    unsigned char h_verlen; //4位首部长度+4位IP版本号 
    unsigned char tos; //8位服务类型TOS 
    unsigned short total_len; //16位总长度（字节） 
    unsigned short ident; //16位标识 
    unsigned short frag_off; 
    unsigned char ttl; //8位生存时间 TTL 
    unsigned char proto; //8位协议 (TCP, UDP 或其他) 
    unsigned short checksum; //16位IP首部校验和 
    unsigned int sourceIP; //32位源IP地址 
    unsigned int destIP; //32位目的IP地址 
}IP_HEADER; 

typedef struct _udphdr //定义UDP首部
{
    unsigned short uh_sport;    //16位源端口
    unsigned short uh_dport;    //16位目的端口
    unsigned int uh_len;//16位UDP包长度
    unsigned int uh_sum;//16位校验和
}UDP_HEADER;

typedef struct _tcphdr //定义TCP首部 
{ 
    unsigned short th_sport; //16位源端口 
    unsigned short th_dport; //16位目的端口 
    unsigned int th_seq; //32位序列号 	
    unsigned int th_ack; //32位确认号 
	
	#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4;       /** (unused) */
    u_int8_t th_off:4;      /** data offset */
	#  endif
	#  if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4;      /** data offset */
    u_int8_t th_x2:4;       /** (unused) */
	#  endif

    unsigned char th_flag; //6位标志位
	#define	TH_FIN	0x01
	#define	TH_SYN	0x02
	#define	TH_RST	0x04
	#define	TH_PUSH	0x08
	#define	TH_ACK	0x10
	#define	TH_URG	0x20
    unsigned short th_win; //16位窗口大小
    unsigned short th_sum; //16位校验和
    unsigned short th_urp; //16位紧急数据偏移量
}TCP_HEADER;


#ifndef INCLUDE_FRAME_LEN
extern unsigned short frameLen;
#endif

#endif
