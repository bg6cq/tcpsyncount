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
#define MAXSUBNET		50

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
int timeout = 3;
int print_all = 0;
char dev_name[MAXLEN];
char filter_string[MAXLEN];
char prefix[MAXLEN];
int TDengine = 0;

int checkports = 0;
int Ports[65536];
int total_subnets = 0;

struct {
	int port;
	unsigned int in;
	unsigned int out;
} portcount[MAXPORT + 1];

struct {
	__u32 ip;
	__u32 mask;
} local_subnets[MAXSUBNET];

void TimeOut(int signum)
{
	if (debug)
		printf("Timer ran out! exit -1\n");
	int p;
	for (p = 0; p < MAXPORT + 1; p++) {
		if (portcount[p].in + portcount[p].out != 0) {
			if (TDengine) {
				printf("INSERT INTO tcpsyncount.tcpsyncount_p%d USING tcpsyncount.tcpsyncount TAGS (%d) VALUES(now, %d, %d);\n",
				       p, p, portcount[p].in, portcount[p].out);
			} else if (prefix[0]) {
				printf("%s,port=%d in=%d,out=%d\n", prefix, p, portcount[p].in, portcount[p].out);
			} else
				printf("%d %d %d\n", p, portcount[p].in, portcount[p].out);
		}
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
		fputs(buf, stdout);
		fflush(stdout);
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

void load_localsubnets(char *name)
{
	FILE *fp;
	char buf[1024];
	char *p;
	fp = fopen(name, "r");
	if (fp == NULL) {
		printf("open local subnets file %s error\n", name);
		exit(0);
	}
	while (fgets(buf, 1024, fp)) {
		if (total_subnets == MAXSUBNET - 1) {
			printf("too many local subnets\n");
			exit(0);
		}
		p = buf;
		while (*p && isblank(*p))
			p++;
		if (*p == 0)
			continue;
		if (*p == '#')
			continue;
		if (inet_aton(p, (struct in_addr *)&local_subnets[total_subnets].ip) == 0)
			continue;

		while (*p && !isblank(*p))
			p++;
		if (*p == 0)
			continue;
		while (*p && isblank(*p))
			p++;
		if (inet_aton(p, (struct in_addr *)&local_subnets[total_subnets].mask) == 0)
			continue;
		local_subnets[total_subnets].ip = (local_subnets[total_subnets].ip & local_subnets[total_subnets].mask);
		__u32 ip, mask;
		ip = local_subnets[total_subnets].ip;
		mask = local_subnets[total_subnets].mask;
		if (debug)
			printf("Local subnet: %d %d.%d.%d.%d/%d.%d.%d.%d\n", total_subnets, (ip & 0xff), (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff,
			       mask & 0xff, (mask >> 8) & 0xff, (mask >> 16) & 0xff, (mask >> 24) & 0xff);
		total_subnets++;
	}
	fclose(fp);
}

int IPislocal_subnets(__u32 ip)
{
	int i;
	for (i = 0; i < total_subnets; i++)
		if (local_subnets[i].ip == ((local_subnets[i].mask & ip)))
			return 1;
	return 0;
}

void process_packet(const unsigned char *buf, int len)
{
	unsigned char *packet;

	// if (debug)
	//      printf("pkt, len=%d\n", len);
	if (len < 54)
		return;
	packet = (unsigned char *)(buf + 12);	// skip ethernet dst & src addr
	len -= 12;
	// if (debug)
	//      printf("proto: 0x%02X%02X\n", packet[0], packet[1]);

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

		int srcislocal = IPislocal_subnets(ip->saddr);

		if (debug) {
			Debug("ipv4 tcp syn %s %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
			      srcislocal ? "from Local" : "to   Local",
			      packet[12], packet[13], packet[14], packet[15], sport, packet[16], packet[17], packet[18], packet[19], dport);
		}
		if (checkports && (Ports[dport] == 0)) {
			if (debug)
				Debug("ignoreed\n");
			return;
		}

		if (srcislocal)
			portcount[dport].out++;
		else
			portcount[dport].in++;

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
	printf("./tcpsyncount [ -d ] [ -t ] [ -x timeout ] [ -p 80,22,23 ] [ -l filename ] -i ifname \n");
	printf(" options:\n");
	printf("    -d               enable debug\n");
	printf("    -t               TDengine output\n");
	printf("    -x timeout       exit -1 when timeout, default is 3\n");
	printf("    -p ports         count ports\n");
	printf("    -i ifname        interface to monitor\n");
	printf("    -P prefix        influxdb prefix\n");
	printf("    -l filename      local subnets file, default is localsubnets.txt\n");
	exit(0);
}

void get_ports(char *s)
{
	char *p = s;
	while (*p) {
		while (*p && (!isdigit(*p)))
			p++;	// skip blank
		if (*p == 0)
			break;
		int port = atoi(p);
		if ((port >= 0) && (port <= 65535))
			Ports[port] = 1;
		while (*p && isdigit(*p))
			p++;	// skip port
	}
}

int main(int argc, char *argv[])
{
	int c;
	while ((c = getopt(argc, argv, "dtx:i:p:P:l:")) != EOF)
		switch (c) {
		case 'd':
			debug = 1;
			break;
		case 't':
			TDengine = 1;
			break;
		case 'i':
			strncpy(dev_name, optarg, MAXLEN);
			break;
		case 'x':
			timeout = atoi(optarg);
			break;
		case 'p':
			checkports = 1;
			get_ports(optarg);
			break;
		case 'P':
			strcpy(prefix, optarg);
			break;
		case 'l':
			load_localsubnets(optarg);
			break;
		}

	if (total_subnets == 0)
		load_localsubnets("localsubnets.txt");
	sprintf(filter_string, "tcp and ((tcp[tcpflags]&(tcp-syn)!=0)&&(tcp[tcpflags]&(tcp-ack)==0))");
	if (dev_name[0] == 0)
		usage();
	int p;
	for (p = 0; p < MAXPORT + 1; p++)
		portcount[p].port = p;
	if (debug) {
		printf("         debug = 1\n");
		printf("       pcap if = %s\n", dev_name);
		printf("       timeout = %d\n", timeout);
		printf("    checkports = %d\n", checkports);
		printf("\n");
	}

	if (timeout > 0) {
		signal(SIGALRM, TimeOut);
		alarm(timeout);
	}

	process_pcap_packet();

	return 0;
}
