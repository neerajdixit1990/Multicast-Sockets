#include "unp.h"
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<linux/if_arp.h>
#include<unistd.h>
#include<stdlib.h>
#include<netinet/in_systm.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<time.h>

#define MAX_LIST_SIZE  5000
#define MULTICAST_ADDRESS  "224.110.1.150"
#define MULTICAST_PORT      5187
#define	PROTOCOL_NO			129
#define MCAST_SERVER_PORT   51867
#define PAYLOAD_SIZE        1000
#define IP_HEADER_SIZE      20
#define UNIQUE_ID           532
#define BUFFER_SIZE         6144 
#define	ARP_PATH			"/tmp/ndixit_arp"
#define	TOUR_PATH		    "/tmp/ndixit_tour"
#define ETH0            	"eth0"
#define	PROTOCOL_NO_PF		51824

#define BUFSIZE          	1500
#define IP_HEADER_SIZE 	    20  // IPv4 header length
#define ICMP_HEADER_SIZE    8  // ICMP header length for echo request, excludes data
#define PF_PACKET_HEADER	14

#define	IF_NAME		16	/* same as IFNAMSIZ    in <net/if.h> */
#define	IF_HADDR	 6	/* same as IFHWADDRLEN in <net/if.h> */
#define	IP_ALIAS  	 1	/* hwa_addr is an alias */

pthread_mutex_t 		socket_mutex = PTHREAD_MUTEX_INITIALIZER;


typedef enum visit_vm_status_	{
	NOT_VISIT,
	VISIT,
	VISIT_NONE
}visit_vm_status;


typedef enum mutlicast_status_	{
	MCAST_NOT_SENT,
	MCAST_SENT,
	MCAST_NONE
}mutlicast_status;

typedef enum ping_end_status_	{
	PING_NOT_END,
	PING_END
	
}ping_end_status;

struct hwa_info {
	char    if_name[IF_NAME];		/* interface name, null terminated */
	char    if_haddr[IF_HADDR];		/* hardware address */
	int     if_index;				/* interface index */
	short   ip_alias;				/* 1 if hwa_addr is an alias IP address */
	struct  sockaddr  *ip_addr;		/* IP address */
	struct  hwa_info  *hwa_next;	/* next of these structures */
};




typedef struct ping_ip_table_ {

long    		current_ip;
char    		list_ip[500];

}ping_ip_table;





visit_vm_status visit_flag = NOT_VISIT;
mutlicast_status multicast_visit_flag = MCAST_NOT_SENT;
ping_end_status  ping_end_flag = PING_NOT_END;
struct sockaddr_in multiaddr_send;

/* globals */
char    sendbuf[BUFSIZE];
int     datalen;
char   *host;
int     nsent;
pid_t   pid;
int     sockfd;
long    ping_source_ip;
long    ping_dest_ip;
int     current_vm_ptr;
int     datalen = 56;
int     count_mcast_msg = 0;
char    payload_ping[PAYLOAD_SIZE] = {0};
ping_ip_table  ping_table[10];
int current_list_count = 0;




/* function prototypes */
struct hwa_info	*get_hw_addrs();
struct hwa_info	*Get_hw_addrs();
void   free_hwa_info(struct hwa_info *);
unsigned char 		dest_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; 

struct hwa_info *
get_hw_addrs()	{
	struct hwa_info	*hwa, *hwahead, **hwapnext;
	int		sockfd, len, lastlen, alias, nInterfaces, i;
	char	*buf, lastname[IF_NAME], *cptr;
	struct ifconf	ifc;
	struct ifreq	*ifr, *item, ifrcopy;
	struct sockaddr	*sinptr;

	sockfd = Socket(AF_INET, SOCK_DGRAM, 0);

	lastlen = 0;
	len = 100 * sizeof(struct ifreq);	/* initial buffer size guess */
	for ( ; ; ) {
		buf = (char*) Malloc(len);
		ifc.ifc_len = len;
		ifc.ifc_buf = buf;
		if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
			if (errno != EINVAL || lastlen != 0)
				err_sys("ioctl error");
		} else {
			if (ifc.ifc_len == lastlen)
				break;		/* success, len has not changed */
			lastlen = ifc.ifc_len;
		}
		len += 10 * sizeof(struct ifreq);	/* increment */
		free(buf);
	}

	hwahead = NULL;
	hwapnext = &hwahead;
	lastname[0] = 0;
    
	ifr = ifc.ifc_req;
 	nInterfaces = ifc.ifc_len / sizeof(struct ifreq);
	for(i = 0; i < nInterfaces; i++)  {
		item = &ifr[i];
 		alias = 0; 
		hwa = (struct hwa_info *) Calloc(1, sizeof(struct hwa_info));
		memcpy(hwa->if_name, item->ifr_name, IF_NAME);		/* interface name */
		hwa->if_name[IF_NAME-1] = '\0';
				/* start to check if alias address */
		if ( (cptr = (char *) strchr(item->ifr_name, ':')) != NULL)
			*cptr = 0;		/* replace colon will null */
		if (strncmp(lastname, item->ifr_name, IF_NAME) == 0) {
			alias = IP_ALIAS;
		}
		memcpy(lastname, item->ifr_name, IF_NAME);
		ifrcopy = *item;
		*hwapnext = hwa;		/* prev points to this new one */
		hwapnext = &hwa->hwa_next;	/* pointer to next one goes here */

		hwa->ip_alias = alias;		/* alias IP address flag: 0 if no; 1 if yes */
                sinptr = &item->ifr_addr;
		hwa->ip_addr = (struct sockaddr *) Calloc(1, sizeof(struct sockaddr));
	        memcpy(hwa->ip_addr, sinptr, sizeof(struct sockaddr));	/* IP address */
		if (ioctl(sockfd, SIOCGIFHWADDR, &ifrcopy) < 0)
                          perror("SIOCGIFHWADDR");	/* get hw address */
		memcpy(hwa->if_haddr, ifrcopy.ifr_hwaddr.sa_data, IF_HADDR);
		if (ioctl(sockfd, SIOCGIFINDEX, &ifrcopy) < 0)
                          perror("SIOCGIFINDEX");	/* get interface index */
		memcpy(&hwa->if_index, &ifrcopy.ifr_ifindex, sizeof(int));
	}
	free(buf);
	return(hwahead);	/* pointer to first structure in linked list */
}

void
free_hwa_info(struct hwa_info *hwahead)	{
	struct hwa_info	*hwa, *hwanext;

	for (hwa = hwahead; hwa != NULL; hwa = hwanext) {
		free(hwa->ip_addr);
		hwanext = hwa->hwa_next;	/* can't fetch hwa_next after free() */
		free(hwa);			/* the hwa_info{} itself */
	}
}
/* end free_hwa_info */

struct hwa_info *
Get_hw_addrs()	{
	struct hwa_info	*hwa;

	if ( (hwa = get_hw_addrs()) == NULL)
		err_quit("get_hw_addrs error");
	return(hwa);
}

int
fill_source_mac(char	*dest,
				int		if_index)	{
	struct hwa_info		*hwa;
	int					status = 1;
	
	
	hwa = Get_hw_addrs();
	for (; hwa != NULL; hwa = hwa->hwa_next) {
		if(hwa->if_index == if_index) {
			memcpy((void*)dest, (void*)hwa->if_haddr, ETH_ALEN);
			status = 0;
			break;
		}
	}
	return status;
}

uint16_t
in_cksum (uint16_t * addr, int len)
  {
      int     nleft = len;
      uint32_t sum = 0;
      uint16_t *w = addr;
      uint16_t answer = 0;

      /*
       * Our algorithm is simple, using a 32 bit accumulator (sum), we add
      * sequential 16 bit words to it, and at the end, fold back all the
      * carry bits from the top 16 bits into the lower 16 bits.
      */
     while (nleft > 1) {
         sum += *w++;
         nleft -= 2;
     }
         /* mop up an odd byte, if necessary */
     if (nleft == 1) {
         * (unsigned char *) (&answer) = * (unsigned char *) w;
         sum += answer;
     }

         /* add back carry outs from top 16 bits to low 16 bits */
     sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
     sum += (sum >> 16);     /* add carry */
     answer = ~sum;     /* truncate to 16 bits */
     return (answer);
 }


  void
  tv_sub (struct timeval *out, struct timeval *in)
  {
      if ((out->tv_usec -= in->tv_usec) < 0) {     /* out -= in */
          --out->tv_sec;
          out->tv_usec += 1000000;
      }
     out->tv_sec -= in->tv_sec;
 }



int
count_digits(int	number) {
	int		count = 0;
	while(number != 0) {
		number = number/10;
		count++;
	}
	return count;
}

int
count_digits_long(long	number) {
	int		count = 0;
	while(number != 0) {
		number = number/10;
		count++;
	}
	return count;
}

int
fill_packet_data(char	*packet,
				 int	data,
				 int	data_size) {
	int		no_digit = count_digits(data);
	int		iter;
	
	iter = data_size - 1;
	for(; iter >= 0; iter --) {
		packet[iter] = data%10 + 48;
		data = data/10;
	}
	
	for(iter = 0; iter < data_size - no_digit; iter ++) {
		packet[iter] = 48;
	}
	return 0;
}

int
fill_packet_data_long(char	*packet,
					  long	data,
					  int	data_size) {
	int		no_digit = count_digits_long(data);
	int		iter;
	
	iter = data_size - 1;
	for(; iter >= 0; iter --) {
		packet[iter] = data%10 + 48;
		data = data/10;
	}
	
	for(iter = 0; iter < data_size - no_digit; iter ++) {
		packet[iter] = 48;
	}
	return 0;
}

int
get_packet_data(char	*packet,
				int		data_size,
				int		*ret) {
	char	number[30];
	int		iter;
	
	for (iter = 0; iter < data_size; iter++) {
		number[iter] = packet[iter];
	}
	number[iter] = '\0';
	*ret = atoi(number);
	return 0;
}

int
get_packet_data_long(char	*packet,
					 int	data_size,
					 long		*ret) {
	char	number[30];
	int		iter;
	
	for (iter = 0; iter < data_size; iter++) {
		number[iter] = packet[iter];
	}
	number[iter] = '\0';
	*ret = atol(number);
	return 0;
}

/*Minimum Calculation of Reciver window, Congestion Window, Window Size*/
int 
max_socket_fd_set(int  sockfd_rt,
				  int  sockfd_pg,	
				  int  soc_multi_recv)	{
				  
				 
	
	if(sockfd_rt > sockfd_pg && sockfd_rt > soc_multi_recv)	{
		return(sockfd_rt);
	} else if(sockfd_pg > sockfd_rt && sockfd_pg > soc_multi_recv)	{
		return(sockfd_pg);
	} else {
		return(soc_multi_recv);
	}
} 

int fill_IP_list( int argc,
                  char **argv,
                  char *Ip_list){

	int 				status;
	int 				i;
	int                 Ip_location = 0 ;
	char				selfhostname[5];
    struct hostent 		*host_IP = NULL;
	struct in_addr 		**addr_list = NULL;    
	
	status=gethostname(selfhostname, 5);
	if (status < 0) {
		printf("\nUnable to get hostname of the machine !!!");
		return -1;
	}
	
	host_IP = gethostbyname(selfhostname);
	if (host_IP == NULL) { 
		printf("\nNo IP address associated with %s\n", selfhostname);
        return(-1);			
		} else {
			addr_list = (struct in_addr **)host_IP->h_addr_list;
	}
	
	status = fill_packet_data_long(Ip_list+Ip_location, (**addr_list).s_addr, 10);
	if (status != 0) {
		printf("\nFailed to fill sequence in packet !!!");
		return (-1);
	}
		
	Ip_location = 10;
	
	for(i= 1; i < argc; i++){

		if( (strncmp(argv[i],selfhostname,4)) == 0){
			printf("\n Incorrect Command Line Argument<Same Source  node Cannot Be Entered>\n ");
			return(-1);
		} 
		
		if( (strncmp(argv[i],argv[i-1],4)) == 0){
			printf("\n Incorrect Command Line Argument<Consequetive Enteries Cannot Be Entered>\n ");
			return(-1);
		}
			
		host_IP = gethostbyname(argv[i]);
		if (host_IP == NULL) { 
			printf("\nNo IP address associated with %s\n", argv[i]);
            return(-1);			
		} else {
				addr_list = (struct in_addr **)host_IP->h_addr_list;
		}
		
        if((strncmp("vm",argv[i],2)) != 0){
			printf("\n Incorrect Command Line Argument<Incorrect data entered>\n ");
		    return(-1);
		}
        		
		status = fill_packet_data_long(Ip_list+Ip_location, (**addr_list).s_addr, 10);
		if (status != 0) {
			printf("\nFailed to fill sequence in packet !!!");
			return (-1);
		}
		
        Ip_location = Ip_location + 10;	
    }
	return 0;
}				  

int
print_IP_list( int argc,
               char **argv,
               char *Ip_list)
{
    int 	status;
	long 	current_ip;
	char 	ip[50];
    int 	i;
	int     Ip_location = 0 ; 
	int     port;
	
	
	printf("\nPacket payload consists of following IP address:");
	for(i= 1; i < argc+2; i++){
		
		status = get_packet_data_long(Ip_list+Ip_location, 10, &current_ip);
		if (status != 0) {
			printf("\nStatus = %d, Unable to get IP's !!! Exiting ...",status);
			return (-1);
		}
		
		inet_ntop(AF_INET, &(current_ip), (ip), INET_ADDRSTRLEN);
		Ip_location = Ip_location + 10;
		printf("\n%s",ip);   
    }
	
	status = get_packet_data(Ip_list+Ip_location, 5, &port);
	if (status != 0) {
		printf("\nStatus = %d, Unable to get port number !!! Exiting ...",status);
		return (-1);
	}
	printf("\nPort number:\t%d\n",port); 
	return 0;	
}

int fill_ping_table(long source_ip,
                    long dest_ip){

	int status;
	       if(current_list_count == 0){
		       ping_table[0].current_ip =0;
				ping_table[0].current_ip= source_ip;
			    status = fill_packet_data_long((ping_table[0].list_ip)+current_list_count, dest_ip, 10);
			    if (status != 0) {
					printf("\nFailed to ping Data in packet !!!");
					return (-1);
				} 	
			
			
			}else{
			
				status = fill_packet_data_long((ping_table[0].list_ip)+current_list_count, dest_ip, 10);
				if (status != 0) {
					printf("\nFailed to fill  ping data  !!!");
					return (-1);
				}
			}
			current_list_count = current_list_count+ 10;
		   
	
    return 0;
}

int check_ping_table(long source_ip,
                    long dest_ip) {

	long temp_dst_ip;
	int  status, i;
	char ip_s[50],ip_d[50];
	
	inet_ntop(AF_INET, &(source_ip), (ip_s), INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(dest_ip), (ip_d), INET_ADDRSTRLEN);
	
	if(current_list_count != 0){
    
			if (ping_table[0].current_ip == source_ip) {
				for(i = 0; i < current_list_count; i = i+10)
				{	 
					status = get_packet_data_long((ping_table[0].list_ip+i), 10, &temp_dst_ip);
					if (status != 0) {
						printf("\nStatus = %d, Unable to get ping Data !!! Exiting ...",status);
						return (-1);
					}
					if(temp_dst_ip==dest_ip){
				    printf("\nNode with Ip: %s and  Node with Ip: %s have Been already Pinged\n",ip_s,ip_d); 
					sleep(1);
					return 1;
					}	   
				
       
				}
			}
			
	}
	return 0;	

}



void 
get_vmname(long ip,
			char	*dest) {
			
	struct hostent 		*hesrc = NULL;
	struct in_addr 		ipsrc;
	socklen_t			len = 0;
	
	ipsrc.s_addr = ip;
	len = sizeof(ipsrc);
    hesrc = gethostbyaddr((const char *)&ipsrc, len, AF_INET);
	strncpy(dest, hesrc->h_name, strlen(hesrc->h_name));
}

int
get_previous_ip(char	*payload,
				long	*prev_ip) {
	int		status, current_vm;
	
	status = get_packet_data(payload, 5, &current_vm);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill IP address of Destination !!! Exiting ...",status);
		return (-1);
	}

	/* Get previous vm's IP address */
	status = get_packet_data_long((payload+5)+((current_vm-1)*10), 10, prev_ip);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill IP address of Destination !!! Exiting ...",status);
		return (-1);
	}
	return 0;
}

int
areq(char				*payload,
	 unsigned char		*destmac)	{
		 
	int					unix_sockfd, i, soc_option, status;
	struct sockaddr_un 	addr;
	char				*ptr;
    long prev_ip;
    char ip_d[50]; 	
	/* Create unix domain socket */
    unix_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(unix_sockfd < 0) {
		printf("\nError in creating UNIX domain socket !!!\nExiting client ...\n");
		return 0;
	}

	soc_option = 1;
	status = setsockopt(unix_sockfd, SOL_SOCKET, SO_REUSEADDR, &soc_option, sizeof(int));
	if (status != 0) {
		fflush(stdout);
		printf("Status = %d, Unable to set echo port to REUSE_ADDR mode !!! Continuing ...",status);
		return -1;
	}
	
    bzero(&addr, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, TOUR_PATH);
	unlink(addr.sun_path);
	
	Bind(unix_sockfd, (struct sockaddr *)&addr, sizeof(addr));

    bzero(&addr, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, ARP_PATH);
	
	
	
	Connect(unix_sockfd, (struct sockaddr *)&addr, sizeof(addr));
	get_previous_ip(payload, &prev_ip);
	inet_ntop(AF_INET, &(prev_ip), (ip_d), INET_ADDRSTRLEN);
	printf("\nRequest Hardware adress : %s\n",ip_d);
	Send(unix_sockfd, payload, strlen(payload), 0);
					
	Recv(unix_sockfd, destmac, 6, 0);
	
	fflush(stdout);
	printf("\nARP resolved MAC for %s : ", ip_d);
	ptr = (char *)destmac;
	i = IF_HADDR;
	do {
		printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
	} while (--i > 0);
	printf("\n");
	
	close(unix_sockfd);
	return 0;
}


void
 send_ping_data (unsigned char *dest_mac){

 
 char 				ppayload[PAYLOAD_SIZE]={0};
 char 				ip_hddr[IP_HEADER_SIZE]={0};
 char               icmp_hddr[100]={0};    
 char               eth_hdr[PF_PACKET_HEADER]={0};  
    
 int                len,status,packet_soc_fd = 0;
    
	

 struct sockaddr_ll 	pack_addr;
 struct  iphdr 	*ip_h = (struct iphdr *) ip_hddr;
 struct  icmp   *icmp_h = (struct icmp *) icmp_hddr;
 struct  ethhdr *eh =   (struct ethhdr *) eth_hdr;
 
    memcpy((void*)eth_hdr, (void*)dest_mac, ETH_ALEN);
	status = fill_source_mac(eth_hdr+ETH_ALEN,2);
    if (status != 0) {
		printf("\nStatus = %d, Unable to fill source mac of Destination !!! Exiting ...",status);
		exit(0);
	}
	eh->h_proto = htons(ETH_P_IP);
    memcpy((void*)ppayload, (void*)eth_hdr, sizeof(struct ethhdr));
	
	len = 8 + datalen;           /* checksum ICMP header and data */
	
	ip_h->ihl = 5;
    ip_h->version = 4;
    ip_h->tos = 0;
	ip_h->tot_len =htons(20+len);
    ip_h->ttl = 255;
	ip_h->frag_off=0;
    ip_h->protocol = IPPROTO_ICMP;
    ip_h->id = htons(0);
    ip_h->saddr = ping_source_ip;
    ip_h->daddr = ping_dest_ip ;
    ip_h->check = 0;
	ip_h->check = in_cksum ((uint16_t *) ip_h, IP_HEADER_SIZE);
	
	
	icmp_h->icmp_type = ICMP_ECHO;
	icmp_h->icmp_code = 0;
	icmp_h->icmp_id = pid;
	icmp_h->icmp_seq = nsent++;
      
   
    
    memset (icmp_h->icmp_data, 0xa5, datalen); /* fill with pattern */
	Gettimeofday ((struct timeval *) icmp_h->icmp_data, NULL);
    icmp_h->icmp_cksum = 0;
	icmp_h->icmp_cksum = in_cksum ((u_short *) icmp_h, len);
	

   	memcpy((void*)ppayload+PF_PACKET_HEADER, (void*)ip_hddr, sizeof(struct iphdr));
	memcpy((void*)ppayload+PF_PACKET_HEADER+IP_HEADER_SIZE, (void*) icmp_hddr,len);
	
	packet_soc_fd = socket(AF_PACKET, SOCK_RAW, PROTOCOL_NO_PF);
	if (packet_soc_fd < 0) {
		printf("\nError in creating socket !!!");
        exit(0);	
	}
	
	pack_addr.sll_family   = PF_PACKET;
	pack_addr.sll_protocol = htons(ETH_P_IP);
	pack_addr.sll_ifindex  = 2;
	pack_addr.sll_hatype   = ARPHRD_ETHER;
	pack_addr.sll_pkttype  = PACKET_OTHERHOST;
	pack_addr.sll_halen    = ETH_ALEN;
	
	pack_addr.sll_addr[0]  = dest_mac[0];
	pack_addr.sll_addr[1]  = dest_mac[1];
	pack_addr.sll_addr[2]  = dest_mac[2];
	pack_addr.sll_addr[3]  = dest_mac[3];
	pack_addr.sll_addr[4]  = dest_mac[4];
	pack_addr.sll_addr[5]  = dest_mac[5];
	pack_addr.sll_addr[6]  = 0x00;
	pack_addr.sll_addr[7]  = 0x00;
	
	status = sendto(packet_soc_fd,ppayload , 200, 0,
					(struct sockaddr *)&pack_addr, sizeof(pack_addr));
	if (status <= 0) {
		printf("\nError in sending payload !!!\n");
		exit(0);
	}
	fflush(stdout);
 
 
 }
 
 
 void
 sig_alrm (int signo)
 {    
  if(ping_end_flag == PING_NOT_END)
  { 
    
	send_ping_data(dest_mac);
    
    alarm(1);
    return;
 }
} 
 
  
  void
  proccess_ping (char *ptr, ssize_t len,struct timeval *tvrecv)
  {
    int     hlenl, icmplen;
    double  rtt;
    struct iphdr *ip;
    struct icmp *icmp;
	char   iprec[50];
    struct timeval *tvsend;
	

     ip = (struct iphdr *) ptr;      /* start of IP header */
     hlenl = ip->ihl << 2;      /* length of IP header */
     if (ip->protocol != IPPROTO_ICMP)
         return;                  /* not ICMP */

     icmp = (struct icmp *) (ptr + hlenl);   /* start of ICMP header */
     if ( (icmplen = len - hlenl) < 8)
         return;                  /* malformed packet */

        if (icmp->icmp_type == ICMP_ECHOREPLY) {
         if (icmp->icmp_id != pid)
             return;                /* not a response to our ECHO_REQUEST */
         if (icmplen < 16)
             return;                /* not enough data to use */
        printf("\nPing Received: ");
			 
			 
         tvsend = (struct  timeval  *) icmp->icmp_data;
         tv_sub (tvrecv, tvsend);
         rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;
          
	
         inet_ntop(AF_INET, &(ip->saddr), ( iprec), INET_ADDRSTRLEN);
         printf ("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",
                 icmplen,iprec,icmp->icmp_seq, ip->ttl, rtt);
     
	 } 
 
 }
 
int 
 receive_ping(int sockfd){
	int     size;
	char    payload[BUFSIZE];
	struct sockaddr_in	recvaddr;
	socklen_t           len;
	int   status;
	struct timeval tval;

	fflush(stdout);
	size = 60 * 1024;        
	setsockopt (sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof (size));

	status = recvfrom(sockfd, payload, 500, 0, (struct sockaddr *)&recvaddr, &len);
			if (status < 0) {
				printf("\nError in receiving packet from UNIX domain socket !!!\n");
	            return(-1);		
			}
			
	Gettimeofday (&tval, NULL);
    proccess_ping(payload, status, &tval);

	return(0);		
 }
 

 
 
 




int ping_start(char	*Ip_list){


    long 				dest_ip;
    long                source_ip; 
    int  				current_vm;
    struct hostent 		*host_IP = NULL;
	struct in_addr 		**addr_list = NULL;
	char                 ip[50];
    int                  status;
	char 	dest_name[100] = {0};
	ping_source_ip = 0;
    ping_dest_ip   = 0;
	status = get_packet_data(Ip_list, 5, &current_vm);
	if (status != 0) {
		printf("\nStatus = %d, Unable to get current pointer !!! Exiting ...",status);
		return (-1);
	}
    
	status = get_packet_data_long((Ip_list+5)+((current_vm-1)*10), 10, &dest_ip);
	if (status != 0) {
		printf("\nStatus = %d, Unable to get destination IP  !!! Exiting ...",status);
		return (-1);
	}
	
	status = get_packet_data_long((Ip_list+5)+((current_vm)*10), 10, &source_ip);
	if (status != 0) {
		printf("\nStatus = %d, Unable to get source  ip !!! Exiting ...",status);
		return (-1);
	}
	
	status = check_ping_table(source_ip,dest_ip);
	if (status < 0) {
		printf("\nStatus = %d, Unable to check ping table  !!! Exiting ...",status);
		return (-1);
	}
	if(status == 1)
	{
		
		return 0;
	
	}
	status = fill_ping_table(source_ip,dest_ip);
	if (status < 0) {
		printf("\nStatus = %d, Unable to fill ping table  !!! Exiting ...",status);
		return (-1);
	}
	
	pthread_mutex_lock(&socket_mutex);
	ping_dest_ip = dest_ip;
	ping_source_ip = source_ip;
	
	 
		
	memcpy((void*)payload_ping,(void*)Ip_list, strlen(Ip_list));
	 /* Address resolution of previous vm */
	status = areq(Ip_list, dest_mac);
	if (status != 0) {
		fflush(stdout);
		printf("\nStatus = %d, Unable to perform ARP resolution", status);
	}
    pthread_mutex_unlock(&socket_mutex);
	
	

	
	
	get_vmname( ping_dest_ip, dest_name);
	
	
	fflush(stdout);

	host_IP = gethostbyname(dest_name);
	if (host_IP == NULL) { 
		printf("\nNo IP address associated with %s\n",dest_name);
        return(-1);			
		} else {
			addr_list = (struct in_addr **)host_IP->h_addr_list;
	    }
	
	
	
	pid = getpid() & 0Xffff;
	inet_ntop(AF_INET, & ((**addr_list).s_addr), (ip), INET_ADDRSTRLEN);
	printf("\n---------------------------------------------------------");
	printf("\n PING %s (%s): %d data bytes ",host_IP->h_name,ip,datalen);	
    printf("\n---------------------------------------------------------");
    printf("\n");
	sig_alrm (SIGALRM);         /* send first packet */
  
	

    
	return 0; 
	
	
    	
	
    
	  	

}
void *
ping_routine(void 	*data)	{

int 	sockfd_pg = *(int *)data;
int     status;
struct timeval 		timeout;
 
while(1) {
		
		fd_set 		mon_fd;
        FD_ZERO(&mon_fd);
		FD_SET(sockfd_pg, &mon_fd);
		
		timeout.tv_sec = 5;
	    timeout.tv_usec = 0;
		
		status = select(sockfd_pg + 1, &mon_fd, NULL, NULL, &timeout);
	    if (status < 0) {
			if (errno == EINTR) continue;
			printf("\nStatus = %d, Unable to monitor sockets !!! Exiting ...",status);
			exit(0);
		}

		if (FD_ISSET(sockfd_pg, &mon_fd)) {
		    
            if(ping_end_flag == PING_NOT_END) {  			
			status = receive_ping( sockfd_pg);
			if(status<0) {
				printf("Could not receive Ping");
				exit(0);
			}
			
			}
		 
		}
	}

}

int
multicast_group_join(int	soc_multi_recv){
					 
	socklen_t           multi_len;
	multi_len = sizeof(multiaddr_send);
	
	if(visit_flag == NOT_VISIT){
		/*join to group*/
		visit_flag = VISIT ;
        printf("\nJoining  the Multicast Group\n");
		Mcast_join(soc_multi_recv,(struct sockaddr *)&multiaddr_send,  multi_len, NULL, 0);
		Mcast_set_ttl(soc_multi_recv, 1);	
		fflush(stdout);
	} else {
		fflush(stdout);
 	  	printf("\nThis node has already joined the Multicast Group\n");
	}
	
  	return(0);									
}

int
send_multi_cast_msg(char *msg,
                    int  soc_multi_send){

	int		status;
	char	selfhostname[5];
	int     sleep_time_left;
   	status = gethostname(selfhostname, 5);
	if (status < 0) {
		printf("\nUnable to get hostname of the machine !!!");
		return -1;
	}
    	
	msg[strlen(msg)]='\0';
	sleep_time_left = sleep(5);
	if(sleep_time_left != 0){
	     sleep(sleep_time_left);
	
	}
	status = sendto(soc_multi_send, msg , strlen(msg),0,(struct sockaddr *)&multiaddr_send, sizeof(multiaddr_send));
	if (status <= 0) {
		printf("\nError in sending multi cast message!!!\n");
		return -1;
	}
	
    
	fflush(stdout);	
	printf("\n---------------------------------------------"); 
	printf("\nNode %s: Sent Muticast Message %s",selfhostname, msg);
    printf("\n---------------------------------------------"); 
	return 0;
}




int 
receive_multi_cast_msg(int soc_mult_recv){

	struct sockaddr_in	multiaddr_recv;
	char                multi_cast_msg[MAXLINE]= {0};
	char				selfhostname[5];
    int					status;	
    socklen_t           len;
    
    len = sizeof(multiaddr_recv);	
	
	status = gethostname(selfhostname, 5);
	if (status < 0) {
		printf("\nUnable to get hostname of the machine !!!");
		return -1;
	}

	status = recvfrom(soc_mult_recv, multi_cast_msg, 500, 0, (struct sockaddr *)&multiaddr_recv, &len);
	if (status <= 0) {
		printf("\nError in receiving packet from multicast socket !!!\n");
		return(-1);
	}
    
	
	printf("\n---------------------------------------------------------------------"); 
	printf("\nNode %s: %s",selfhostname, multi_cast_msg);
	//printf("\n----------------------------------------------------------------------"); 
		
    return(0);

}


int
send_IP_route_packet(int sockfd_rt,
                     char *Ip_list){

	char 				payload[PAYLOAD_SIZE];
	char 				headdr[IP_HEADER_SIZE];
	struct sockaddr_in	sendaddr;
	struct 	iphdr 		*ip_header = (struct iphdr *) headdr;					 
	long 				dest_ip,source_ip;	
    int  				current_vm;
    char 				src_name[100] = {0};
	char				dest_name[100] = {0};
    int                 status; 	
	
	status = get_packet_data(Ip_list, 5, &current_vm);
	if (status != 0) {
		printf("\nStatus = %d, Unable to get current pointer !!! Exiting ...",status);
		return (-1);
	}	
	
	status = get_packet_data_long((Ip_list+5)+((current_vm-1)*10), 10, &source_ip);
	if (status != 0) {
		printf("\nStatus = %d, Unable to get source ip !!! Exiting ...",status);
		return (-1);
	}			 
    
    status = get_packet_data_long(Ip_list+(current_vm*10)+5, 10, &dest_ip);
	if (status != 0) {
		printf("\nStatus = %d, Unable to get Destination ip !!! Exiting ...",status);
		return (-1);
	}
	
	ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
	ip_header->tot_len = htons(20 + strlen(Ip_list));
    ip_header->ttl = 255;
	ip_header->frag_off=0;
    ip_header->protocol = PROTOCOL_NO;
    ip_header->id = htons(UNIQUE_ID);
    ip_header->check = 0;
    ip_header->saddr = source_ip;
    ip_header->daddr = dest_ip;
	get_vmname(dest_ip, dest_name);
	get_vmname(source_ip, src_name);

	
    bzero(&sendaddr, sizeof(sendaddr));
    sendaddr.sin_family = AF_INET;	
	sendaddr.sin_addr.s_addr = dest_ip;
		
    memcpy((void*)payload,(void*)headdr, sizeof(headdr));	
    memcpy((void*)payload+IP_HEADER_SIZE,(void*)Ip_list, strlen(Ip_list));	
	payload[IP_HEADER_SIZE+strlen(Ip_list)] = '\0';	
  
	status=sendto(sockfd_rt,payload , PAYLOAD_SIZE,0, (struct sockaddr *)&sendaddr, sizeof(sendaddr));
	if (status < 0) {
		printf("\nError in sending IP Packet!!!\n");
		return -1;
	 }
	printf("\n-------------------------------------------------------");
	printf("\nRoute traversal from node %s to %s", src_name, dest_name);
    printf("\n-------------------------------------------------------");
	fflush(stdout);
	
	return 0;	
}

int
check_if_last_vm_packet(char	*payload_list,
						int     soc_multi_send){

    char				Ip_list[MAX_LIST_SIZE];
	int					status;  
	struct sockaddr_in 	multi_addr;
	long				multicast_addr;
	int					current_vm;
	char				msg[100],selfhostname[5];

	inet_pton(AF_INET, MULTICAST_ADDRESS, &(multi_addr.sin_addr)); 	
    memcpy((void*)Ip_list,(void*)payload_list,strlen(payload_list));
  
   	status = gethostname(selfhostname, 5);
	if (status < 0) {
		printf("\nUnable to get hostname of the machine !!!");
		return -1;
	}
	status = get_packet_data(Ip_list, 5, &current_vm);
	if (status != 0) {
		printf("\nStatus = %d, Unable to get packet data !!! Exiting ...",status);
		return (-1);
	}
    
	status = get_packet_data_long(Ip_list+5+((current_vm+1)*10), 10, &multicast_addr);
	if (status != 0) {
		printf("\nStatus = %d, Unable to get  address muti_cast_addr!!! Exiting ...",status);
		return (-1);
	}
    
    if(multi_addr.sin_addr.s_addr == multicast_addr) {		
		
		
	    snprintf(msg, sizeof(msg), "%s %s%s","<<<<This is node ", selfhostname,
	    ". Tour has ended.Group members please identify your Self.>>>>" );
		 
		status = send_multi_cast_msg(msg,soc_multi_send);
        if (status < 0) {
			printf("\nStatus = %d, Unable to send Multi_cast_data !!! Exiting ...",status);
			return (-1);
		}
		
		
	
		return (1); 
	} 
    return 0;
}

int
forward_IP_route_packet(int		sockfd_rt,
                        char	*payload_list,
						int     soc_multi_send) {
  
 
	char				Ip_list[MAX_LIST_SIZE];
	int					status;  
	int					current_vm;
	
 
    
  
    memcpy((void*)Ip_list,(void*)payload_list,strlen(payload_list));
  
   
    status = ping_start(Ip_list);
	if (status < 0) {
			printf("\nError in Pinging !!!\n");
			return 0;
		}	
	
    status = get_packet_data(Ip_list, 5, &current_vm);
	if (status != 0) {
		printf("\nStatus = %d, Unable to get IP data !!! Exiting ...",status);
		return (-1);
	}
    
	status = check_if_last_vm_packet(payload_list, soc_multi_send);
	if (status < 0 ) {
		printf("\nStatus = %d, Unable to check last_vm address !!! Exiting ...",status);
		return (-1);
	} else if(status == 0){ 
     
		status = fill_packet_data(Ip_list, current_vm+1,5 );
		if (status != 0) {
			printf("\nFailed to fill data in packet !!!");
			return (-1);
		}
	
		status = send_IP_route_packet(sockfd_rt, Ip_list);
		if (status < 0) {
			printf("\nError in sending IP_route_packet !!!\n");
			return (-1);
		}
	}		
	return 0;						
}						


int
valid_packet(int	sockfd_rt,
             char	*payload,
			 int	soc_multi_recv,
			 int	soc_multi_send) {
	int  	status;
	int		current_vm;  
	long    source_ip; 
    char 	src_name[100] = {0};
 	    
    status = get_packet_data(payload+20, 5, &current_vm);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill IP address of Destination !!! Exiting ...",status);
		return (-1);
	}	
    
	status = get_packet_data_long((payload+25)+((current_vm-1)*10), 10, &source_ip);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill IP address of Destination !!! Exiting ...",status);
		return (-1);
	}	
	  
	get_vmname(source_ip, src_name);
	
	printf("\n");
	printf("\nReceived source routing packet from : %s",src_name);
	printf("\n");
	fflush(stdout);
	
	status = multicast_group_join(soc_multi_recv);	
    if (status < 0) {
		printf("\nError in joining multicast group !!!\n");
		return 0;
	} 
	
	status = forward_IP_route_packet(sockfd_rt, payload+20,
                                     soc_multi_send);
	if(status <0) {
		printf("\nFailed to Forward Packet");
		return(-1);
	}
	return 0;			

	
	}						

int
main (int argc,
	  char **argv)	{

	int 				status;
	int     			sockfd_rt,sockfd_pg;
	int					soc_multi_recv,soc_multi_send;
	int                 max_soc_fd;
	socklen_t           len;
	const int			soc_rset = 1;
    const int           soc_rset_on =  1; 	
	int 				list_size;
	char 				Ip_list[MAX_LIST_SIZE] ;
	struct sockaddr_in 	multi_addr;
	int                 current_vm_pointer; 
	struct sockaddr_in	recvaddr;
	char 				payload[PAYLOAD_SIZE];
	char 				headdr[IP_HEADER_SIZE];
	struct 	iphdr 		*ip_header_recv = (struct iphdr *) headdr;
	int                 data_size;
	char                selfhostname[10];
	pthread_t           ping_th;
    char                send_msg[100] = {0};
    struct timeval 		timeout;	
	
	

	inet_pton(AF_INET, MULTICAST_ADDRESS, &(multi_addr.sin_addr));
    status = gethostname(selfhostname, 10);
	if (status < 0) {
		printf("\nUnable to get hostname of the machine !!!");
		return -1;
	}
     	
	sockfd_rt = socket(AF_INET, SOCK_RAW, PROTOCOL_NO);
	if(sockfd_rt < 0) {
		printf("\nError in creating RT socket !!!\nExiting client ...\n");
		return 0;
	}
	
    soc_multi_send =  socket(AF_INET, SOCK_DGRAM, 0);
	if( soc_multi_send < 0) {
		printf("\nError in creating UDP socket !!!\nExiting client ...\n");
		return 0;
	}
	
	if (setsockopt(sockfd_rt, IPPROTO_IP, IP_HDRINCL, &soc_rset, sizeof(soc_rset)) < 0){
		printf("\nError in setting Option IP_HDRINCL  for RT socket !!!\nExiting client ...\n");
		return 0;
    }   
	
    sockfd_pg = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(sockfd_rt < 0) {
		printf("\nError in creating  PG socket !!!\nExiting client ...\n");
		return 0;
	}
	
    soc_multi_recv =  socket(AF_INET, SOCK_DGRAM, 0);;
	if( soc_multi_recv < 0) {
		printf("\nError in creating RT socket !!!\nExiting client ...\n");
		return 0;
	}
	
	bzero(&multiaddr_send, sizeof(multiaddr_send));
	multiaddr_send.sin_family = AF_INET;
	multiaddr_send.sin_port = htons(MULTICAST_PORT);
	Inet_pton(AF_INET, MULTICAST_ADDRESS, &multiaddr_send.sin_addr);
	
	
	
	if (setsockopt(soc_multi_recv , SOL_SOCKET, SO_REUSEADDR, &soc_rset_on, sizeof(soc_rset_on)) < 0){
		printf("\nError in setting Option IP_HDRINCL  for RT socket !!!\nExiting client ...\n");
		return 0;
    
	}
	
	status = bind(soc_multi_recv, (struct sockaddr *) &multiaddr_send, sizeof(multiaddr_send));
	if (status < 0) {
		printf("\nError in UDP socket bind for Multicast !!!\nExiting ...\n");
		return 0;
	}
	
	if(argc > 1) {
    
		current_vm_pointer = 1;	
		status = fill_packet_data(Ip_list, current_vm_pointer,5);
		if (status != 0) {
			printf("\nFailed to fill data in packet !!!");
			return (-1);
		}
	
		status = fill_IP_list(argc ,argv, Ip_list+5);
		if (status < 0) {
			printf("\nError in Creating IP_list_Invalid Arguments !!!\n");
			return 0;
		}

		list_size=argc*10; 
		
		
		status = fill_packet_data_long(Ip_list+list_size+5, multi_addr.sin_addr.s_addr, 10);
		if (status != 0) {
			printf("\nFailed to fill data in packet !!!");
			return (-1);
		}
		list_size=(argc+1)*10;
	
		status = fill_packet_data(Ip_list+list_size+5, MULTICAST_PORT, 5);
		if (status != 0) {
			printf("\nFailed to fill data in packet !!!");
			return (-1);
		}
		
		list_size=list_size+5;	
		Ip_list[list_size+5]= '\0';
	
		status = print_IP_list(argc ,argv, Ip_list+5);
		if (status < 0) {
			printf("\nError in Printing IP_list !!!\n");
			return 0;
		}
		
		/* source node joining to MULTICAST GROUP */
		status = multicast_group_join(soc_multi_recv); 	
		if (status < 0) {
			printf("\nError in joining multicast group !!!\n");
			return 0;
		}	 
	
		status = send_IP_route_packet(sockfd_rt, Ip_list);
		if (status < 0) {
			printf("\nError in sending IP_route_packet !!!\n");
			return 0;
		}
	} 
   
    data_size = BUFFER_SIZE;		/* OK if setsockopt fails */
	if (setsockopt(sockfd_rt, IPPROTO_IP, SO_RCVBUF, &data_size, sizeof(data_size))<0){
		printf("\nError in setting Option SO_RCVBUF  for RT socket !!!\nExiting client ...\n");
		return 0;
   	}
	
	pthread_create(&ping_th, NULL, ping_routine, (void *)&sockfd_pg);
	while(1) {
		fd_set 		mon_fd;
        FD_ZERO(&mon_fd);
		
      	FD_SET(sockfd_rt, &mon_fd);
		FD_SET(soc_multi_recv, &mon_fd);
		if(count_mcast_msg == 0){
			timeout.tv_sec = 5000;
			timeout.tv_usec = 0;
		} else
		{
		    timeout.tv_sec = 5;
			timeout.tv_usec = 0;
		
		}
		max_soc_fd = max_socket_fd_set(sockfd_rt,-10000,soc_multi_recv); 
		
		
		
		status = select(max_soc_fd + 1, &mon_fd, NULL, NULL,&timeout);
	    if (status < 0) {
            if (errno == EINTR) continue;    
			printf("\nStatus = %d, Unable to monitor sockets !!! Exiting ...",status);
			return 0;
		}
		
		if (FD_ISSET(sockfd_rt, &mon_fd)) {
			len = sizeof(recvaddr);
			status = recvfrom(sockfd_rt, payload, PAYLOAD_SIZE, 0, (struct sockaddr *)&recvaddr, &len);
			if (status <= 0) {
				printf("\nError in receiving packet from Raw socket !!!\n");
			}	
			memcpy((void*)headdr,(void*)payload, 20);	  
			
			if((ip_header_recv->id)== htons(UNIQUE_ID)){
	            Signal(SIGALRM, sig_alrm);	
				status = valid_packet(sockfd_rt, payload, soc_multi_recv, 
									soc_multi_send);
				if (status < 0) {
					printf("\nFailed to  Forward  valid Packet....");
				} 
				continue;
			} else {
				printf("\n This Payload is ignored...\n");
				continue;
			}
		} else if (FD_ISSET(soc_multi_recv, &mon_fd)) {
		    
			ping_end_flag = PING_END;	
			fflush(stdout);
		    status = receive_multi_cast_msg(soc_multi_recv);
			if (status <0) {
				printf("\nFailed to receive Muticast... Exiting !!!\n");
				return 0; 
			}
		     
			
			
			if( multicast_visit_flag == MCAST_NOT_SENT){
			   	
			   status = gethostname(selfhostname, 5);
	           if (status < 0) {
		       printf("\nUnable to get hostname of the machine !!!");
		       return -1;
	           }
				
				snprintf(send_msg, sizeof(send_msg), "%s%s%s","<<<<This is node ", selfhostname,
	            ".I am member of the group.>>>>" );
				
			   status = send_multi_cast_msg(send_msg, soc_multi_send);
				if (status <0) {
					printf("\nStatus = %d, Unable to send multicast !!! Exiting ...",status);
					return (-1);
				}
				multicast_visit_flag = MCAST_SENT;
		        count_mcast_msg = 1;
                			
			}
			
	   
	    }  else {
			fflush(stdout);
			printf("\n\nAll multicast messages received, Exiting Tour ...\n");
			exit(0);
	    } 
  
    }
    
	
	exit(0);
}