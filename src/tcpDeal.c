/**
 * 该文件用来对主站小站之间的tcp加速进行协议转换
 */
 
#include "global.h"
#include "frame.h"

extern struct frameQueue queue_resources;
unsigned short connNum = 1;
struct connectCtrlBlk *ccbHead;
pthread_mutex_t ccb_link_lock = PTHREAD_MUTEX_INITIALIZER;

int tcpDealInit()
{	
	ccbHead = (struct connectCtrlBlk *)malloc(sizeof(struct connectCtrlBlk));
	ccbHead->next = NULL;
	
	return 1;
}

struct connectCtrlBlk * alloc_ccb()
{
	IP_HEADER * iph;
	TCP_HEADER *tcph;
	
	struct connectCtrlBlk * ccb = (struct connectCtrlBlk *)malloc(sizeof(struct connectCtrlBlk));
	if(ccb == NULL)
	{
		PEP_DEBUG("failed to allocate");
		return NULL;
	}
	
	ccb->conn_state = 0;
	ccb->fin_seq = 0;
	ccb->fin_direct = 0;
	ccb->ptemplate = (unsigned char *)malloc(60);
	if(ccb->ptemplate == NULL)
	{
		PEP_DEBUG("alloc_ccb wrong");
		return NULL;
	}
	
	iph = (IP_HEADER *)(ccb->ptemplate);
	iph->h_verlen = 0x45;
	iph->tos = 0;
	iph->total_len = htons(40);
	iph->ident = htons(0x3c0a);
	iph->frag_off = htons(0x4000);
	iph->ttl = 0x7d;
	iph->proto = 06;
	iph->checksum = 0;
	
	tcph = (TCP_HEADER *)(ccb->ptemplate + 20);
	tcph->th_off = 5;
	tcph->th_x2 = 0;
	tcph->th_flag = TH_ACK;
	tcph->th_urp = 0;
	
	return ccb;
}

static void release_blk(struct connectCtrlBlk ** pccb)
{	
	struct connectCtrlBlk * ccb = ccbHead;
	
	while(ccb != NULL)
	{
		if(ccb->next == *pccb)
		{
			ccb->next = (*pccb)->next;
			free((*pccb)->ptemplate);
			free(*pccb);
			break;
		}
	}
	
	*pccb = NULL;
	
	return ;
}

static int matchAddr(struct connectCtrlBlk * p, unsigned char *buf)
{
	IP_HEADER * ip = (IP_HEADER *)buf;
	TCP_HEADER * th = (TCP_HEADER *)(buf + (ip->h_verlen & 0x0f)*4);
	
	if(ip->sourceIP == p->l_addr.ip && ip->destIP == p->f_addr.ip)
	{
		if(th->th_sport == p->l_addr.port && th->th_dport == p->f_addr.port)
		{
			return 1;
		}
	}
	if(ip->sourceIP == p->f_addr.ip && ip->destIP == p->l_addr.ip)
	{
		if(th->th_sport == p->f_addr.port && th->th_dport == p->l_addr.port)
		{
			return 1;
		}
	}
	
	return 0;
}

struct connectCtrlBlk * find_blk(unsigned char *buf, int num)
{
	struct connectCtrlBlk * cb = ccbHead->next;
	
	if(num != 0)
	{
		while(cb != NULL)
		{
			if(cb->f_num == num)
			{
				break;
			}
			cb = cb->next;
		}
	}
	else
	{
		while(cb != NULL)
		{
			if(matchAddr(cb, buf))
			{
				break;
			}
			cb = cb->next;
		}
	}
	
	return cb;
}

static unsigned short fin_state(struct connectCtrlBlk * ccb, TCP_HEADER *tcph, unsigned char dirct)
{
	uint16_t temp;
	
	switch(ccb->conn_state)
	{
		case 2:
		{
			ccb->fin_seq = ntohl(tcph->th_seq);
			ccb->fin_direct = dirct;
			ccb->conn_state++;
			break;
		}
		case 3:
		{
			if(ccb->fin_direct != dirct)
			{
				if(ccb->fin_seq == ntohl(tcph->th_ack) + 1)
				{
					ccb->fin_seq = ntohl(tcph->th_seq);
					ccb->fin_direct = dirct;
					ccb->conn_state = 5;
				}
			}
			
			break;
		}
		case 4:
		{
			if(ccb->fin_direct != dirct)
			{
				ccb->fin_seq = ntohl(tcph->th_seq);
				ccb->fin_direct = dirct;
				ccb->conn_state++;
			}
			
			break;
		}
		case 5:
		{
			if(ccb->fin_direct != dirct)
			{
				if(ccb->fin_seq == ntohl(tcph->th_ack) + 1)
				{
					ccb->conn_state = 6;
					temp = ccb->l_num;
					release_blk(&ccb);
					return temp;
				}
			}
			
			break;
		}
		default:
		{
			break;
		}
	}
	
	return 0;
}

static int sendFrame8Byte()
{
	unsigned char *pFrame;
	
	QUEUE_LOCK_READ();
	if(isFullQue() == 1)		//队列满 无法继续入队
	{
		return 0; 
	}
	pFrame = queue_resources.headOfQueue[queue_resources.rear];
	QUEUE_UNLOCK_READ();
	
	pFrame += 1;	//5820头
	pFrame[0] = 0;
	pFrame[1] = 1;
	pFrame[2] = myRemtId83;
	pFrame[3] = myRemtId2;
	pFrame[4] = 0x08;
	
	QUEUE_LOCK_WRITE();
	EnQueue();
	QUEUE_UNLOCK_WRITE();
	
	return 1;		
}

int dealTcp(unsigned char *buf, uint8_t flag)
{
	IP_HEADER *iph;
	TCP_HEADER *tcph;
	int tcpDataLen;
	unsigned char * pFrame;
	unsigned short connum;
	unsigned int acknum;
	struct connectCtrlBlk * ccb = NULL;
	
	switch(flag)
	{
		case hub_normal:
		{
			iph = (IP_HEADER *)buf;
			tcph = (TCP_HEADER *)(buf + (iph->h_verlen & 0x0f)*4);

			if(tcph->th_flag & TH_SYN)
			{
				if(!(tcph->th_flag & TH_ACK))//syn
				{
					ccb = find_blk(buf, 0);
					if(ccb != NULL)
					{
						if(ccb->conn_state > 2)
						{
							release_blk(&ccb);
						}
						else
						{
							tcph->th_sum = calculate_tcp_csum(buf);
							toTun(buf);
							return 0;
						}
					}
					ccb = alloc_ccb();
					if(!ccb)
					{
						PEP_DEBUG("failed to allocate ccb");
						exit(1);
					}
					ccb->f_addr.ip = iph->sourceIP;
					ccb->f_addr.port = tcph->th_sport;
					ccb->l_addr.ip = iph->destIP;
					ccb->l_addr.port = tcph->th_dport;
					ccb->f_num = tcph->th_sum;
					ccb->conn_state = 1;
					ccb->f_window = tcph->th_win;
					ccb->seq = ntohl(tcph->th_seq);
					
					ccb->next = ccbHead->next;
					ccbHead->next = ccb;
					
					tcph->th_sum = calculate_tcp_csum(buf);
					
				}
				else//syn ack
				{
					if((ccb = find_blk(buf, 0)) == NULL) 
					{
						PEP_DEBUG("unexpected syn ack, cannot find cblk");
						tcph->th_sum = calculate_tcp_csum(buf);
						toTun(buf);
						return 0;
					}
					if(ccb->conn_state < 1 || ccb->conn_state > 2)
					{
						PEP_DEBUG("unexpected syn ack");
					}
					ccb->fin_seq = ntohl(tcph->th_seq);	//这里用finseq变量记录了synseq 复用了变量
					ccb->f_num = tcph->th_sum;
					ccb->f_window = tcph->th_win;
					ccb->seq = ntohl(tcph->th_seq);

					if(ccb->conn_state == 1)
					{
						ccb->conn_state++;
					}
					
					tcph->th_sum = calculate_tcp_csum(buf);
				}
			}
			else if(tcph->th_flag & TH_FIN)
			{
				ccb = find_blk(buf, 0);
				if(ccb == NULL)
				{
					tcph->th_sum = calculate_tcp_csum(buf);
					PEP_DEBUG("unexpected fin");
					toTun(buf);
					return 0;
				}
				if(ccb->conn_state < 2)
				{
					PEP_DEBUG("unexpected fin");
				}
				ccb->f_window = tcph->th_win;
				fin_state(ccb, tcph, 1);
				
				tcph->th_sum = calculate_tcp_csum(buf);
			}
			else
			{
				if((ccb = find_blk(NULL, tcph->th_sum)) == NULL)
				{
					PEP_DEBUG("can not find cblk");
					tcph->th_sum = calculate_tcp_csum(buf);
					toTun(buf);
					return 0;
				}
				
				if(ccb->conn_state < 2) 
				{
					PEP_DEBUG("unexpected tcp pack");
					tcph->th_sum = calculate_tcp_csum(buf);
					toTun(buf);
					return 0;
				}
				
				if(ccb->fin_direct != 1 && (ccb->conn_state == 3 || ccb->conn_state == 5))
				{
					if(ntohl(tcph->th_ack) == ccb->fin_seq + 1)
					{
						ccb->conn_state++;
						if(ccb->conn_state == 6)
						{
							release_blk(&ccb);
						}
					}
				}
				if(ccb != NULL)
				{
					tcpDataLen = ntohs(iph->total_len) - (iph->h_verlen & 0x0f)*4 - 4*tcph->th_off;
					if(tcpDataLen == 0)
					{
						sendFrame8Byte();
					}
					ccb->seq = ntohl(tcph->th_seq) + tcpDataLen;
					ccb->f_window = tcph->th_win;
				}
				
				tcph->th_sum = calculate_tcp_csum(buf);	
			}
			
			toTun(buf);
			break;
		}
		case hub_14:
		{
			connum = *(uint16_t *)(buf + 8);
			acknum = *(uint32_t *)(buf + 10);
			
			if((ccb = find_blk(NULL, connum)) == NULL)
			{
				PEP_DEBUG("cant find cblk, drop..");
				return 0;
			}
			
			IP_HEADER *ip = (IP_HEADER *)(ccb->ptemplate);
			TCP_HEADER *tcp = (TCP_HEADER *)(ccb->ptemplate + 20);
			ip->sourceIP = ccb->f_addr.ip;
			ip->destIP = ccb->l_addr.ip;
			ip->checksum = 0;
			ip->checksum = htons(csum(ccb->ptemplate, 20));
			
			tcp->th_sport = ccb->f_addr.port;
			tcp->th_dport = ccb->l_addr.port;
			tcp->th_seq = htonl(ccb->seq);
			tcp->th_ack = acknum;
			tcp->th_win = ccb->f_window;

			tcp->th_sum = calculate_tcp_csum(ccb->ptemplate);
			sendFrame8Byte();
			
			toTun(ccb->ptemplate);
			
			break;
		}
		case local:
		{
			iph = (IP_HEADER *)buf;
			tcph = (TCP_HEADER *)(buf + (iph->h_verlen & 0x0F)*4);
			uint16_t temp_l_num;
			
			if(tcph->th_flag & TH_SYN)
			{
				if(!(tcph->th_flag & TH_ACK))	//syn
				{
					ccb = find_blk(buf, 0);
					if(ccb != NULL)
					{
						if(ccb->conn_state > 2)
						{
							release_blk(&ccb);
						}
						else
						{
							tcph->th_sum = ccb->l_num;
							return 1;
						}	
					}
					ccb = alloc_ccb();
					if(!ccb)
					{
						PEP_DEBUG("failed to allocate ccb");
						exit(0);
					}
					ccb->f_addr.ip = iph->destIP;
					ccb->f_addr.port = tcph->th_dport;
					ccb->l_addr.ip = iph->sourceIP;
					ccb->l_addr.port = tcph->th_sport;
					
					ccb->l_num = htons(++connNum);
					ccb->conn_state = 1;
					tcph->th_sum = ccb->l_num;
					
					ccb->next = ccbHead->next;
					ccbHead->next = ccb;
				}
				else	//synack
				{
					if((ccb = find_blk(buf, 0)) == NULL) 
					{
						PEP_DEBUG("unexpected syn ack, can not find cblock");
						return 1;
					}
					if(ccb->conn_state == 1)
					{
						ccb->l_num = htons(++connNum);
						ccb->conn_state++;
					}
					
					tcph->th_sum = ccb->l_num;
				}
				
				return 1;
			}
			else if(tcph->th_flag & TH_FIN)
			{
				ccb = find_blk(buf, 0);
				if(ccb == NULL)
				{
					return 1;
				}
				
				temp_l_num = fin_state(ccb, tcph, 1);
				
				if(temp_l_num == 0)
				{
					tcph->th_sum = ccb->l_num;
				}
				else
				{
					tcph->th_sum = temp_l_num;
				}
				
				return 1;
			}
			else
			{	
				int flag = 0;
				
				if((ccb = find_blk(buf, 0)) == NULL) 
				{
					PEP_DEBUG("cant find conn cblk");
					return 1;
				}
				if(ccb->conn_state < 2)
				{
					PEP_DEBUG("unexpected tcp conn_state");
					return 1;
				}
				if(ccb->fin_direct != 0 && (ccb->conn_state == 3 || ccb->conn_state == 5))
				{
					if(ntohl(tcph->th_ack) == ccb->fin_seq + 1)
					{
						flag = 2;	//应答fin的ack
						ccb->conn_state++;
						if(ccb->conn_state == 6)
						{
							temp_l_num = ccb->l_num;
							release_blk(&ccb);
						}
					}
				}
				if(ntohl(tcph->th_ack) == (ccb->fin_seq + 1) && (ccb->fin_seq != 0) && ccb->conn_state == 2)	//这里用fin_seq来记了syn seq的值，因为状态值不同 不会混淆
				{
					flag = 1;//应答syn 的ack
					ccb->fin_seq = 0;
				}
				tcpDataLen = ntohs(iph->total_len) - (iph->h_verlen & 0x0f)*4 - 4*tcph->th_off;
				
				if(flag == 1 || flag == 2)
				{
					sendFrame8Byte();
					return 0;
				}
				
				else if((tcpDataLen == 0) && (tcph->th_flag == TH_ACK) && flag == 0)	//转成14字节，放入队列
				{
					QUEUE_LOCK_READ();
					if(isFullQue() == 1)		//队列满 无法继续入队
					{
						PEP_DEBUG("queue full.. drop");
						return 0; 
					}
					pFrame = queue_resources.headOfQueue[queue_resources.rear];
					QUEUE_UNLOCK_READ();
					
					pFrame += 1;
					buildFrameHead(pFrame, iph);
					pFrame += 8;
					buildSar(pFrame, 0, SAR_END + SAR_LEN);
					pFrame += 2;
					*(unsigned short *)pFrame = htons(8);
					pFrame += 2;
					*(unsigned short *)pFrame = htons(0x8904);
					pFrame += 2;
					if(ccb != NULL)
					{
						*(unsigned short *)pFrame = ccb->l_num;
					}
					pFrame +=2;
					*(unsigned int *)pFrame = tcph->th_ack;
					pFrame +=4;
					*(unsigned short *)pFrame = 0;
					
					QUEUE_LOCK_WRITE();
					EnQueue();
					QUEUE_UNLOCK_WRITE();
					
					return 0;
				}
				else	//有负载的tcp，其他ack，添加编号字段，放入队列中
				{	
					if(ccb == NULL)
					{
						tcph->th_sum = temp_l_num;
					}
					else
					{
						tcph->th_sum = ccb->l_num;
					}

					return 1;
				}
			}
			
			break;
		}
		default:
		{
			break;
		}
	}
	
	return 1;
}