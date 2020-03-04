#include "global.h"

uint16_t csum(unsigned char *buf, int size)  
{  
    unsigned int cksum = 0; 
	unsigned char *p = (unsigned char *)(malloc(size));
	
	memcpy(p, buf, size);
	unsigned short *buffer = (unsigned short *)(p);
	
    while(size > 1)
    {  
		*buffer = htons(*buffer);
	    cksum += *buffer++;  
        size -= sizeof(uint16_t);  
    }  
  
    if(size)  
    {  
        cksum += *(unsigned char*)buffer;  
    }  
  
	while(cksum>>16)
	{
		cksum = (cksum>>16) + (cksum & 0xffff);
	}
	
	free(p);
	
    return (uint16_t)(~cksum);  
}

unsigned short calculate_tcp_csum(unsigned char *pbuf)
{	
	IP_HEADER * iph = (IP_HEADER *)pbuf;
	int ipHlen = (iph->h_verlen & 0x0f)*4;
	TCP_HEADER * tcph = (TCP_HEADER *)(pbuf + ipHlen);
	
	unsigned char psdheader[MAX_PSD_SIZE] = {0};
	struct psdhdr *psdh = (struct psdhdr*)psdheader; 
	struct _tcphdr *tcph_psd = (struct _tcphdr*)(psdheader + sizeof(struct psdhdr));
	uint16_t tcplen = ntohs(iph->total_len) - ipHlen;
	
	tcph->th_sum = 0;
	psdh->saddr = *((unsigned int *) (&(iph->sourceIP)));  
    psdh->daddr = *((unsigned int *) (&(iph->destIP)));  
    psdh->mbz = 0;  
    psdh->protocol = iph->proto;  
    psdh->tcpl = htons(tcplen);
	memcpy(psdheader + sizeof(struct psdhdr), pbuf + ipHlen, tcplen);
	
	return htons(csum(psdheader, sizeof(struct psdhdr) + tcplen));
}
