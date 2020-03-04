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

#define MAX_PSD_SIZE 52 /* psd header = 12, tcp header = 20 ~ 40; max = 52 tcpα�ײ����� */


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

/* ���ڼ���TCPУ��͵�αͷ�� */  
struct psdhdr{  
    uint32_t saddr; /* ipͷ��Դ��ַ */  
    uint32_t daddr; /* ipͷ��Ŀ�ĵ�ַ */  
    uint8_t mbz; /* ��ȫ�ֶΣ���Ϊ0 */  
    uint8_t protocol; /* ipͷ��Э�� */  
    uint16_t tcpl; /* tcp���ȣ�����ͷ�������ݲ��� */  
};

struct connectCtrlBlk
{
	uint8_t conn_state;	//lock
	
	uint16_t l_num;		//tcp���ӱ�� ���� �����ֽ���
	uint16_t f_num;		//tcp���ӱ�� �Զ� �����ֽ���
	uint16_t f_window;
	uint32_t seq;
	//��¼hub��������һ����seq
	uint32_t fin_seq;	//��¼Fin�����к�//��ʼ�øñ�������¼ synseq lock
	uint8_t	fin_direct;	//��¼fin�ķ���	0 ������ 1����Զ�	lock
	
	struct Addr f_addr; //���ֶα������ӵ�Ŀ�ĵ�ַ
	struct Addr l_addr; //src��ַ
	unsigned char * ptemplate;	//Ӧ��tcpģ��
	
	struct connectCtrlBlk * next;//lock
};     

typedef struct _etherhdr
{
	uint8_t srcMac[6];
	uint8_t dstMac[6];
	uint16_t type;
}E_HEADER;

typedef struct _iphdr //����IP�ײ� 
{ 
    unsigned char h_verlen; //4λ�ײ�����+4λIP�汾�� 
    unsigned char tos; //8λ��������TOS 
    unsigned short total_len; //16λ�ܳ��ȣ��ֽڣ� 
    unsigned short ident; //16λ��ʶ 
    unsigned short frag_off; 
    unsigned char ttl; //8λ����ʱ�� TTL 
    unsigned char proto; //8λЭ�� (TCP, UDP ������) 
    unsigned short checksum; //16λIP�ײ�У��� 
    unsigned int sourceIP; //32λԴIP��ַ 
    unsigned int destIP; //32λĿ��IP��ַ 
}IP_HEADER; 

typedef struct _udphdr //����UDP�ײ�
{
    unsigned short uh_sport;    //16λԴ�˿�
    unsigned short uh_dport;    //16λĿ�Ķ˿�
    unsigned int uh_len;//16λUDP������
    unsigned int uh_sum;//16λУ���
}UDP_HEADER;

typedef struct _tcphdr //����TCP�ײ� 
{ 
    unsigned short th_sport; //16λԴ�˿� 
    unsigned short th_dport; //16λĿ�Ķ˿� 
    unsigned int th_seq; //32λ���к� 	
    unsigned int th_ack; //32λȷ�Ϻ� 
	
	#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4;       /** (unused) */
    u_int8_t th_off:4;      /** data offset */
	#  endif
	#  if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4;      /** data offset */
    u_int8_t th_x2:4;       /** (unused) */
	#  endif

    unsigned char th_flag; //6λ��־λ
	#define	TH_FIN	0x01
	#define	TH_SYN	0x02
	#define	TH_RST	0x04
	#define	TH_PUSH	0x08
	#define	TH_ACK	0x10
	#define	TH_URG	0x20
    unsigned short th_win; //16λ���ڴ�С
    unsigned short th_sum; //16λУ���
    unsigned short th_urp; //16λ��������ƫ����
}TCP_HEADER;


#ifndef INCLUDE_FRAME_LEN
extern unsigned short frameLen;
#endif

#endif
