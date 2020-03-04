/**
 * 该文件是tuntap虚拟网卡相关函数，用来初始化虚拟网卡，向虚拟网卡传递IP数据包
 */

#include "global.h"
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include<net/if.h> 
#include <string.h>  
#include <unistd.h>  
#include <netinet/in.h>  
#include <netinet/ip_icmp.h>  
#include <sys/ioctl.h>

int tun_fd;

static int tun_create(char *dev, int flags)
{
	 struct ifreq ifr;
	 int tun_fd, err;

	 if ((tun_fd = open("/dev/net/tun", O_RDWR)) < 0)
		 return tun_fd;

	 memset(&ifr, 0, sizeof(ifr));
	 ifr.ifr_flags |= flags;
	 if (*dev != '\0')
		 strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	 if ((err = ioctl(tun_fd, TUNSETIFF, (void *)&ifr)) < 0) {
		 close(tun_fd);
		 return err;
	 }
	 strcpy(dev, ifr.ifr_name);

	 return tun_fd;
}

int tun_init()
{
	char tun_name[IFNAMSIZ];

	tun_name[0] = '\0';
	tun_fd = tun_create(tun_name, IFF_TUN | IFF_NO_PI);
	if (tun_fd < 0) 
	{
		perror("tun_create");
		return 0;
	}
	PEP_DEBUG("TUN %s create successful\n", tun_name);
	system("ifconfig tun0 0.0.0.0 up");
	
	return 1;
}

int toTun(const unsigned char * buf)//用户数据包交给内核
{
	int bufLen, ret;

	if(!((buf[0] == 0x45 && buf[1] == 0) || (buf[0] == 0x46 && buf[1] == 0)))
	{	
		PEP_DEBUG("wrong IP style!");
		return 0;
	}
	
	bufLen = ntohs(*((unsigned short *)(buf + 2)));
	ret = write(tun_fd, buf, bufLen);

	return ret;
}
