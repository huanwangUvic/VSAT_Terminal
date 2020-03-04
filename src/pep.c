#include "config.h"
#include "global.h"
#define IPQUEUE_OLD 0
#define QUEUER_BUF_SIZE PAGE_SIZE
#define INCLUDE_FRAME_LEN
#include <unistd.h>
#include <assert.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/user.h>
#include<sys/time.h>
#include<sys/resource.h>

#define __USE_XOPEN_EXTENDED
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netdb.h>
#include <getopt.h>
#include <linux/netfilter.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <sys/poll.h>
#include <string.h>
#include <time.h>
#include <signal.h>

#if (IPQUEUE_OLD)
#include <libipq/libipq.h>
#else
#include <libnetfilter_queue/libnetfilter_queue.h>
#endif

int DEBUG = 0;
unsigned short frameLen = 0;
static int nice_value = -20;//进程优先级
static int background = 0;
static int queuenum = 0;
static pthread_t queuer_postRouting;
static pthread_t receiver;
pthread_cond_t inNet_Condvar = PTHREAD_COND_INITIALIZER;
pthread_mutex_t	inNet_Mutex = PTHREAD_MUTEX_INITIALIZER;

extern tcpSockFd;
extern inNetState;
extern void * recv_loop();
#define pep_error(fmt, args...)                     \
    __pep_error(__FUNCTION__, __LINE__, fmt, ##args)

#define pep_warning(fmt, args...)                   \
    __pep_warning(__FUNCTION__, __LINE__, fmt, ##args)

#define PEP_DEBUG(fmt, args...)                     \
    if (DEBUG) {                                    \
        fprintf(stderr, "[DEBUG] %s(): " fmt "\n",  \
                __FUNCTION__, ##args);              \
    }

#define PEP_DEBUG_DP(proxy, fmt, args...)                           \
    if (DEBUG) {                                                    \
        char __buf[17];                                             \
        toip(__buf, (proxy)->src.addr);                             \
        fprintf(stderr, "[DEBUG] %s(): {%s:%d} " fmt "\n",          \
                __FUNCTION__, __buf, (proxy)->src.port, ##args);    \
    }
	
void __pep_error(const char *function, int line, const char *fmt, ...)
{
    va_list ap;
    char buf[PEP_ERRBUF_SZ];
    int err = errno;
    size_t len;

    va_start(ap, fmt);

    len = snprintf(buf, PEP_ERRBUF_SZ, "[ERROR]: ");
    len += vsnprintf(buf + len, PEP_ERRBUF_SZ - len, fmt, ap);
    if (err && (PEP_ERRBUF_SZ - len) > 1) {
        snprintf(buf + len, PEP_ERRBUF_SZ - len,
                 "\n      ERRNO: [%s:%d]", strerror(err), err);
    }

    fprintf(stderr, "%s\n         AT: %s:%d\n", buf, function, line);
    va_end(ap);
    exit(EXIT_FAILURE);
}

int postRoutingCb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
	(void)nfmsg;
	(void)data;
	u_int32_t id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	unsigned char *pbuf = NULL; 
	int pdata_len;

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph)
	{
		id = ntohl(ph->packet_id);
	}
	pdata_len = nfq_get_payload(nfa, (char**)&pbuf);
	if(pdata_len == -1)
	{
		pdata_len = 0;
	}
	
	if(inNetState > 0)
	{
		encap_frame(pbuf);
	}
	
	goto DROP;
	

ACCEPT:
	return nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)pdata_len, pbuf);
DROP:
	return nfq_set_verdict(qh, id, NF_DROP, (u_int32_t)pdata_len, pbuf);
}

static void *queuer_loop_postRouting(void __attribute__((unused)) *unused)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int rv;
	int fd;
	char buf[QUEUER_BUF_SIZE];
	
	WAITING_FOR_INNET(inNet_Condvar, inNet_Mutex);
	
	h = nfq_open();
	if (!h)
	{
		exit(1);
	}

	if (nfq_unbind_pf(h, AF_INET) < 0)
	{
		exit(1);
	}

	if (nfq_bind_pf(h, AF_INET) < 0)
	{
		exit(1);
	}

	PEP_DEBUG("binding this socket to queue %d\n", queuenum);
	qh = nfq_create_queue(h, queuenum, &postRoutingCb, NULL);
	if (!qh)
	{
		exit(1);
	}

	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		exit(1);
	}

	nh = nfq_nfnlh(h);
	fd = nfnl_fd(nh);
	
	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) 
	{	
		nfq_handle_packet(h, buf, rv);
	}
	nfq_destroy_queue(qh);
	
	nfq_close(h);
	pthread_exit(NULL);
}

static void init_pep_threads(void)
{
    int ret;
	
	PEP_DEBUG("Creating queuer thread");
    ret = pthread_create(&queuer_postRouting, NULL, queuer_loop_postRouting, NULL);
    if (ret) {
        pep_error("Failed to create the queuer_postRouting thread! [RET = %d]", ret);
    }

    PEP_DEBUG("Creating recv_loop (for HUB) thread");
    ret = pthread_create(&receiver, NULL, recv_loop, NULL);
    if (ret) {
        pep_error("Failed to create the recv_loop for HUB thread! [RET = %d]", ret);
    }
}

int main(int argc, char *argv[])
{
    int c, ret, numfds;
    void *valptr;
    sigset_t sigset;
	
    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
			{"daemon", 1, 0, 'd'},
            {"verbose", 1, 0, 'v'},
			{"queue", 1, 0, 'q'},
            {"version", 0, 0, 'V'},
			{"frameLen",1,0,'f'},
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "dvVhq:f:",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'd':
                background = 1;
                break;
            case 'v':
                DEBUG = 1;
				break;
			case 'q':
				queuenum = atoi(optarg);
				break;
			case 'f':	
				frameLen = atoi(optarg);
				if(!(frameLen==441 || frameLen == 546 || frameLen ==676 || frameLen == 3249))
				{
					PEP_DEBUG("frameLen could only be 441,676,546,3249!\n");
					exit(0);
				}
				frameLen /= 8;
				break;
            case 'V':
                PEP_DEBUG("PPSal ver. %s\n", "1.0");
                exit(0);	
        }
    }

	setpriority(0, 0, nice_value);			//进程优先级
	
    if (background) {
        PEP_DEBUG("Daemonizing...");
        if (daemon(0, 1) < 0) {
            pep_error("daemon() failed!");
        }
    }
	
	ret = tcpServerInit();
	if(!ret)
	{
		pep_error("Failed to initialize tcpServer");
	}
	
	ret = tun_init();
	if(!ret)
	{
		pep_error("Failed to initialize tun/tap");
	}
	ctrlInit();
	
	ret = frame_queue_init();
	if(!ret)
	{
		pep_error("Failed to initialize frame queue");
	}
	ret = tcpDealInit();
	if(!ret)
	{
		pep_error("Failed to initialize tcp connection ctrlBlock");
	}
	
    init_pep_threads();
	
    PEP_DEBUG("Pepsal started...");
	pthread_join(queuer_postRouting, &valptr);
	pthread_join(receiver, &valptr);
    printf("exiting...\n");
	
    return 0;
}
