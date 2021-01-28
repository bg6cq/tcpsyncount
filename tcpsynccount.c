/* tcpsynccount: count tcpsync
	  by james@ustc.edu.cn 2021.01.28

Output:
port IN OUT


*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <stdarg.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

#if !defined(PCAP_NETMASK_UNKNOWN)
/*
 * Value to pass to pcap_compile() as the netmask if you don't know what
 * the netmask is.
 */
#define PCAP_NETMASK_UNKNOWN    0xffffffff
#endif

#define MAXLEN 			2048
#define MAX_PACKET_SIZE		65535
#define MAXPORT 65535

struct _EtherHeader {
	uint16_t destMAC1;
	uint32_t destMAC2;
	uint16_t srcMAC1;
	uint32_t srcMAC2;
	uint32_t VLANTag;
	uint16_t type;
	int32_t payload;
} __attribute__ ((packed));

typedef struct _EtherHeader EtherPacket;

int debug = 0;
int daemon_proc = 0;
int timeout = 0;
int print_all = 0;
char dev_name[MAXLEN];
char filter_string[MAXLEN];

struct {
	int port;
	unsigned int in;
	unsigned int out;
} portcount [MAXPORT+1];

void TimeOut(int signum)
{
	if (debug)
		printf("Timer ran out! exit -1\n");
	int p;
	for(p=0;p< MAXPORT+1; p++) {
		if(portcount[p].in + portcount[p].out !=0) 
			printf("%d %d %d\n", p, portcount[p].in ,portcount[p].out);
	}
	exit(0);
}

void err_doit(int errnoflag, int level, const char *fmt, va_list ap)
{
	int errno_save, n;
	char buf[MAXLEN];

	errno_save = errno;	/* value caller might want printed */
	vsnprintf(buf, sizeof(buf), fmt, ap);	/* this is safe */
	n = strlen(buf);
	if (errnoflag)
		snprintf(buf + n, sizeof(buf) - n, ": %s", strerror(errno_save));
	strcat(buf, "\n");

	if (daemon_proc) {
		syslog(level, "%s", buf);
	} else {
		fflush(stdout);	/* in case stdout and stderr are the same */
		fputs(buf, stderr);
		fflush(stderr);
	}
	return;
}

void err_msg(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(0, LOG_INFO, fmt, ap);
	va_end(ap);
	return;
}

void Debug(const char *fmt, ...)
{
	va_list ap;
	if (debug) {
		va_start(ap, fmt);
		err_doit(0, LOG_INFO, fmt, ap);
		va_end(ap);
	}
	return;
}

void err_quit(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(0, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}

void err_sys(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(1, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}

char *stamp(void)
{
	static char st_buf[200];
	struct timeval tv;
	struct timezone tz;
	struct tm *tm;

	gettimeofday(&tv, &tz);
	tm = localtime(&tv.tv_sec);

	snprintf(st_buf, 200, "%02d%02d %02d:%02d:%02d.%06ld", tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, tv.tv_usec);
	return st_buf;
}

void printPacket(EtherPacket * packet, ssize_t packetSize, char *message)
{
	printf("%s ", stamp());

	if ((ntohl(packet->VLANTag) >> 16) == 0x8100)	// VLAN tag
		printf("%s #%04x (VLAN %d) from %04x%08x to %04x%08x, len=%d\n",
		       message, ntohs(packet->type),
		       ntohl(packet->VLANTag) & 0xFFF, ntohs(packet->srcMAC1),
		       ntohl(packet->srcMAC2), ntohs(packet->destMAC1), ntohl(packet->destMAC2), (int)packetSize);
	else
		printf("%s #%04x (no VLAN) from %04x%08x to %04x%08x, len=%d\n",
		       message, ntohl(packet->VLANTag) >> 16,
		       ntohs(packet->srcMAC1), ntohl(packet->srcMAC2), ntohs(packet->destMAC1), ntohl(packet->destMAC2), (int)packetSize);
	fflush(stdout);
}

int IPIsUSTCnetIP(__u32 ip)
{    
	__u32 hip;
	hip=ntohl(ip);
	if( (hip & 0xFFFFE000l) == 0xCA264000l) return 1;
	if( (hip & 0xFFFFF000l) == 0xD22D4000l) return 1;
	if( (hip & 0xFFFFF000l) == 0xD22D7000l) return 1;
	if( (hip & 0xFFFFF000l) == 0xD3569000l) return 1;
	if( (hip & 0xFFFFE000l) == 0xDEC34000l) return 1;
	if( (hip & 0xFFFFE000l) == 0x72D6A000l) return 1;
	if( (hip & 0xFFFFC000l) == 0x72D6C000l) return 1;
     return 0;
}


void process_packet(const unsigned char *buf, int len)
{
	unsigned char *packet;

	if (debug)
		printf("pkt, len=%d\n", len);
	if (len < 54)
		return;
	packet = (unsigned char *)(buf + 12);	// skip ethernet dst & src addr
	len -= 12;
	if (debug)
		printf("proto: 0x%02X%02X\n", packet[0], packet[1]);

	if ((packet[0] == 0x81) && (packet[1] == 0x00)) {	// skip 802.1Q tag 0x8100
		if (debug)
			printf("802.1Q pk\n");
		packet += 4;
		len -= 4;
	}


	if ((packet[0] == 0x81) && (packet[1] == 0x00)) {	// skip 802.1Q tag 0x8100
		packet += 4;
		len -= 4;
	}
	if ((packet[0] == 0x08) && (packet[1] == 0x00)) {	// IPv4 packet 0x0800
		packet += 2;
		len -= 2;

		// now packet point to iphdr

		struct iphdr *ip = (struct iphdr *)packet;
		if (ip->version != 4)
			return;	// check ipv4
		if (ntohs(ip->frag_off) & 0x1fff)
			return;	// not the first fragment
		if (ip->protocol != IPPROTO_TCP)
			return;	// not tcp packet
		if (ntohs(ip->tot_len) > len)
			return;	// tot_len should < len 

		struct tcphdr *tcph = (struct tcphdr *)(packet + ip->ihl * 4);
		if (!tcph->syn || tcph->ack)
			return;

		unsigned sport = ntohs(tcph->source);
		unsigned dport = ntohs(tcph->dest);

		int srcisustc= IPIsUSTCnetIP(ip->saddr);

		if (debug) {
			Debug("ipv4 tcp syn %s %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d", 
				srcisustc?"from USTC": "to  USTC", 
				packet[12], packet[13], packet[14], packet[15],sport,
				packet[16], packet[17], packet[18], packet[19],dport);
		}
		if(srcisustc)
			portcount[dport].out ++;
		else
			portcount[dport].in ++;

	}
}

void process_pcap_packet(void)
{
	pcap_t *handle;
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	const unsigned char *buf;
	int len;
	handle = pcap_open_live(dev_name, MAX_PACKET_SIZE, 0, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "pcap open %s error %s\n", dev_name, errbuf);
		exit(0);
	}
	if (filter_string[0]) {
		struct bpf_program pgm;
		if (pcap_compile(handle, &pgm, filter_string, 1, PCAP_NETMASK_UNKNOWN) == -1) {
			fprintf(stderr, "pcap_filter compile error\n");
			exit(0);
		}
		if (pcap_setfilter(handle, &pgm) == -1) {
			fprintf(stderr, "pcap_setfilter error\n");
			exit(0);
		}
	}
	while (1) {
		int r = pcap_next_ex(handle, &header, (const u_char **)&buf);
		if (r == 0)
			continue;
		if (r < 0)
			exit(0);
		len = header->len;
		if (len <= 0)
			continue;
		process_packet(buf, len);
	}
}

void usage(void)
{
	printf("Usage:\n");
	printf("./tcpsyncount [ -d ] [ -x timeout ] -i ifname \n");
	printf(" options:\n");
	printf("    -d               enable debug\n");
	printf("    -i ifname        interface to monitor\n");
	printf("    -x timeout       exit -1 when timeout\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	int c;
	while ((c = getopt(argc, argv, "dx:i:")) != EOF)
		switch (c) {
		case 'd':
			debug = 1;
			break;
		case 'i':
			strncpy(dev_name, optarg, MAXLEN);
			break;
		case 'x':
			timeout = atoi(optarg);
			break;
		}
	sprintf(filter_string, "tcp and ((tcp[tcpflags] & (tcp-syn) != 0) && (tcp[tcpflags] & (tcp-ack) == 0))");
	if (dev_name[0] == 0)
		usage();
	int p;
	for(p=0;p< MAXPORT+1; p++)
		portcount[p].port = p;
	if (debug) {
		printf("         debug = 1\n");
		printf("       pcap if = %s\n", dev_name);
		printf("       timeout = %d\n", timeout);
		printf("\n");
	}

	if (timeout > 0) {
		signal(SIGALRM, TimeOut);
		alarm(timeout);
	}

	process_pcap_packet();

	return 0;
}
