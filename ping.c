/*  On terminal 
  $ gcc -o ping pinger.c 
  $ sudo su
  # ./ping 127.0.0.1 
   OR
  # ./ping google.com */

/*Include required libs*/
#include <stdio.h>

#include <signal.h>

#include <arpa/inet.h>

#include <sys/types.h>

#include <sys/socket.h>

#include <unistd.h>

#include <netinet/in.h>

#include <netinet/ip.h>

#include <netinet/ip_icmp.h>

#include <netdb.h>

#include <setjmp.h>

#include <errno.h>

#include <string.h>

/* Change packet size here, wait time, delay between requests and max packets*/
#define PACKET_SIZE     64

#define MAX_WAIT_TIME   12

#define MAX_NO_PACKETS 0 //Change to value > 1 stop infinite pinging

#define DELAY_BW_REQ 1

char sendpacket[PACKET_SIZE];

char recvpacket[PACKET_SIZE];

int sockfd, datalen = PACKET_SIZE;

int nsend = 0, nreceived = 0;

struct sockaddr_in dest_addr;

pid_t pid;

struct sockaddr_in from;

struct timeval tvrecv;


/*Declarations here*/
void statistics(int signo);

unsigned short cal_checksum(unsigned short *addr, int len);

int pack(int pack_no);

void send_packet(void);

void recv_packet(void);

int unpack(char *buf, int len);

void tv_sub(struct timeval *out, struct timeval *in);


/*Stats function to show packet stats*/
void statistics(int signo)

{

    printf("\n--------------------Ping Report-------------------\n");

    printf("%d packets transmitted, %d received , %d%% lost\n", nsend,nreceived, (nsend -nreceived) / nsend * 100);

    close(sockfd);

    exit(1);

} 


/*Checksum Function*/
unsigned short cal_checksum(unsigned short *addr, int len)

{

    int nleft = len;

    int sum = 0;

    unsigned short *w = addr;

    unsigned short answer = 0;





    while (nleft > 1)

    {

        sum +=  *w++;

        nleft -= 2;

    }



    if (nleft == 1)

    {

        *(unsigned char*)(&answer) = *(unsigned char*)w;

        sum += answer;

    }

    sum = (sum >> 16) + (sum &0xffff);

    sum += (sum >> 16);

    answer = ~sum;

    return answer;

}





int pack(int pack_no)

{

    int i, packsize;

    struct icmp *icmp;

    struct timeval *tval;

    icmp = (struct icmp*)sendpacket;

    icmp->icmp_type = ICMP_ECHO;

    icmp->icmp_code = 0;

    icmp->icmp_cksum = 0;

    icmp->icmp_seq = pack_no;

    icmp->icmp_id = pid;

    packsize = 8+datalen;

    tval = (struct timeval*)icmp->icmp_data;

    gettimeofday(tval, NULL); 

    icmp->icmp_cksum = cal_checksum((unsigned short*)icmp, packsize); 

    return packsize;

}





void send_packet()

{

    int packetsize;

    if (MAX_NO_PACKETS > 0){
    	while (nsend < MAX_NO_PACKETS)

   	{

        nsend++;

        packetsize = pack(nsend); 

	        if (sendto(sockfd, sendpacket, packetsize, 0, (struct sockaddr*)
	
	            &dest_addr, sizeof(dest_addr)) < 0)

        	{

	            perror("Error while sending...");

	            continue;

        	} 

	recv_packet();
	
	sleep(DELAY_BW_REQ); 

    		}

	}

    else{
    	while (1==1) //An infinite ping

   	{

        nsend++;

        packetsize = pack(nsend); 

	        if (sendto(sockfd, sendpacket, packetsize, 0, (struct sockaddr*)
	
	            &dest_addr, sizeof(dest_addr)) < 0)

        	{

	            perror("Error while sending...");

	            continue;

        	} 

	recv_packet();
	
	sleep(DELAY_BW_REQ); 

    		}

	}
}




void recv_packet()

{

    int n, fromlen;

    extern int errno;

    signal(SIGALRM, statistics);

    fromlen = sizeof(from);

    while (nreceived < nsend)

    {


        alarm(MAX_WAIT_TIME);

        if ((n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, (struct

            sockaddr*) &from, &fromlen)) < 0)

        {

            if (errno == EINTR)

                continue;

            perror("Error while receiving...");

            continue;

        } gettimeofday(&tvrecv, NULL); 

        if (unpack(recvpacket, n) ==  - 1)

            continue;

        nreceived++;

    }

}





int unpack(char *buf, int len)

{

    int i, iphdrlen;

    struct ip *ip;

    struct icmp *icmp;

    struct timeval *tvsend;

    double rtt;

    ip = (struct ip*)buf;

    iphdrlen = ip->ip_hl << 2; 

    icmp = (struct icmp*)(buf + iphdrlen);

    len -= iphdrlen; 

    if (len < 8)

    

    {

        printf("Packet\'s length is <8\n");

        return  - 1;

    } 



    if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid))

    {

        tvsend = (struct timeval*)icmp->icmp_data;

        tv_sub(&tvrecv, tvsend); 

        rtt = tvrecv.tv_sec * 1000+tvrecv.tv_usec / 1000;

            

        printf("%d byte from %s: icmp_seq=%u TTL=%d RTT=%.3f ms\n", len,

            inet_ntoa(from.sin_addr), icmp->icmp_seq, ip->ip_ttl, rtt);

    }

    else

        return  - 1;

}



main(int argc, char *argv[])

{

  struct addrinfo hints, *res, *res0;
  int error;
  int s;
  const char *cause = NULL;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

    struct hostent *host;

    struct protoent *protocol;

    unsigned long inaddr = 0l;

    int waittime = MAX_WAIT_TIME;

    int size = 50 * 1024;

    if (argc < 2)

    {

        printf("Usage:%s hostname/IP address\n", argv[0]);

        exit(1);

    } 

   
   if ((protocol = getprotobyname("icmp")) == NULL)

    {

        perror("Error in protocol");

        exit(1);

    }



    if ((sockfd = socket(AF_INET, SOCK_RAW, protocol->p_proto)) < 0)

    {

        perror("Socket Error (Make sure you run this program as an admin)");

        exit(1);

    }



    setuid(getuid());



    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

    bzero(&dest_addr, sizeof(dest_addr));

    dest_addr.sin_family = AF_INET;



    if (inaddr = inet_addr(argv[1]) == INADDR_NONE)

    {

        if ((host = gethostbyname(argv[1])) == NULL)
//Can migrate to getaddrinfo() to handle all types of families and protocols
       

        {

            perror("Invalid Hostname");

            exit(1);

        }

        memcpy((char*) &dest_addr.sin_addr, host->h_addr, host->h_length);

    }

    else

        dest_addr.sin_addr.s_addr = inet_addr(argv[1]);


    pid = getpid();

    printf("Pinging %s(%s): %d bytes data...\n", argv[1], inet_ntoa

        (dest_addr.sin_addr), datalen);

    send_packet(); 

    recv_packet(); 

    statistics(SIGALRM); 

    return 0;

}

void tv_sub(struct timeval *out, struct timeval *in)

{

    if ((out->tv_usec -= in->tv_usec) < 0)

    {

        --out->tv_sec;

        out->tv_usec += 1000000;

    } out->tv_sec -= in->tv_sec;

}



 /*------------- The End -----------*/
