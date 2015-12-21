#include "unp.h"
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<linux/if_arp.h>
#include<unistd.h>
#include<stdlib.h>


#define	IF_NAME		16	/* same as IFNAMSIZ    in <net/if.h> */
#define	IF_HADDR	 6	/* same as IFHWADDRLEN in <net/if.h> */
#define	IP_ALIAS  	 1	/* hwa_addr is an alias */

#define	ARP_PATH		"/tmp/ndixit_arp"
#define	TOUR_PATH		"/tmp/ndixit_tour"
#define	PROTOCOL_NO		51838
#define PF_PACKET_HEADER	14 
#define ETH0            "eth0"
#define	BACKLOG_LIMIT		20

struct hwa_info {
	char    if_name[IF_NAME];		/* interface name, null terminated */
	char    if_haddr[IF_HADDR];		/* hardware address */
	int     if_index;				/* interface index */
	short   ip_alias;				/* 1 if hwa_addr is an alias IP address */
	struct  sockaddr  *ip_addr;		/* IP address */
	struct  hwa_info  *hwa_next;	/* next of these structures */
};

typedef struct arp_cache_ {
	long			ip;
	char    		if_haddr[IF_HADDR];
	int				if_index;
	int				socfd;
	unsigned short	hatype;
	int				status;
}arp_cache;

typedef enum arp_type_ {
	ARP_REQUEST,
	ARP_REPLY,
	ARP_NONE
}arp_type;

arp_cache		arp_table[50];

/* Count digits in the number */
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

/*Function Reterives Details from Packet Header Recieved*/
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

/*Function Reterives Details from Packet Header Recieved*/
int
get_packet_data_long(char	*packet,
					int		data_size,
					long	*ret) {
	char	number[30];
	int		iter;
	
	for (iter = 0; iter < data_size; iter++) {
		number[iter] = packet[iter];
	}
	number[iter] = '\0';
	*ret = atol(number);
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
		hwa = (struct hwa_info *)Calloc(1, sizeof(struct hwa_info));
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
	free_hwa_info(hwa);
	return status;
}

int
gen_arp_request(int		packet_soc_fd,
				long	destip,
				long	my_ip,
				char	*source_mac,
				int		if_index) {
	char				packet[500], myvm[10], destaddr[50], srcaddr[50];
	struct ethhdr 		*eh = (struct ethhdr *)packet;
	struct sockaddr_ll 	pack_addr;
	unsigned char 		dest_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	int					status, i;
	char				*ptr;
	
	pack_addr.sll_family   = PF_PACKET;
	pack_addr.sll_protocol = htons(PROTOCOL_NO);
	pack_addr.sll_ifindex  = if_index;
	pack_addr.sll_hatype   = ARPHRD_ETHER;
	pack_addr.sll_pkttype  = PACKET_OTHERHOST;
	pack_addr.sll_halen    = ETH_ALEN;
	
	pack_addr.sll_addr[0]  = 0xFF;
	pack_addr.sll_addr[1]  = 0xFF;
	pack_addr.sll_addr[2]  = 0xFF;
	pack_addr.sll_addr[3]  = 0xFF;
	pack_addr.sll_addr[4]  = 0xFF;
	pack_addr.sll_addr[5]  = 0xFF;
	pack_addr.sll_addr[6]  = 0x00;
	pack_addr.sll_addr[7]  = 0x00;
	
	memcpy((void*)packet, (void*)dest_mac, ETH_ALEN);
	memcpy((void*)(packet+ETH_ALEN), (void*)source_mac, ETH_ALEN);
	eh->h_proto = PROTOCOL_NO;
	
	status = fill_packet_data(packet+PF_PACKET_HEADER, ARP_REQUEST, 5);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill packet type !!! Exiting ...",status);
		return -1;
	}
	
	status = fill_packet_data_long(packet+PF_PACKET_HEADER+5, destip, 10);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill destination IP !!! Exiting ...",status);
		return -1;
	}
	
	status = fill_packet_data_long(packet+PF_PACKET_HEADER+15, my_ip, 10);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill source IP !!! Exiting ...",status);
		return -1;
	}

	packet[PF_PACKET_HEADER+25] = '\0';
	get_vmname(my_ip, myvm);
	inet_ntop(AF_INET, &(destip), destaddr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(my_ip), srcaddr, INET_ADDRSTRLEN);
	
	fflush(stdout);
	printf("\n=========================================");
	printf("\nARP at node %s sending ARP REQUEST", myvm);
	printf("\nDestination MAC: ");
	ptr = packet;
	i = IF_HADDR;
	do {
		printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
	} while (--i > 0);
	
	printf("\tSource MAC: ");
	ptr = packet+ETH_ALEN;
	i = IF_HADDR;
	do {
		printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
	} while (--i > 0);
	printf("\nDestination IP: %s", destaddr);
	printf("\t\tSource IP: %s", srcaddr);
	printf("\n=========================================");
	
	status = sendto(packet_soc_fd, packet, 500, 0, 
					(struct sockaddr *)&pack_addr, sizeof(pack_addr));
	if (status <= 0) {
		printf("\nError in sending ARP request !!!\n");
		return -1;
	}	

	return 0;
}

int
get_arp_entry(char		*payload,
			  long		my_ip,
			  int		packet_soc_fd,
			  char		*source_mac,
			  int		if_index,
			  long		destip) {
	int		status, current_vm, iter;
	long	ip;
	char	ip_d[100];
	
	status = get_packet_data(payload, 5, &current_vm);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill IP address of Destination !!! Exiting ...",status);
		return (-1);
	}

	/* Get previous vm's IP address */
	status = get_packet_data_long((payload+5)+((current_vm-1)*10), 10, &ip);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill IP address of Destination !!! Exiting ...",status);
		return (-1);
	}
	
	for(iter = 0; iter < 50; iter++) {
		if (arp_table[iter].ip == destip
			/*arp_table[iter].status == 1*/) {
			/* Found ARP entry */
			//memcpy((void *)ret, (void *)arp_table[iter].if_haddr, IF_HADDR);
			inet_ntop(AF_INET, &(destip), (ip_d), INET_ADDRSTRLEN);
			printf("\nRequest Hardware adress for Ip: %s\n",ip_d);

			fflush(stdout);
			printf("\nARP entry for %s exists in ARP cache, not sending ARP request ...\n", ip_d);
			return 0;
		}
	}
	
	/* Send ARP Request */
	status = gen_arp_request(packet_soc_fd, ip, my_ip,
							 source_mac, if_index);
	if (status != 0) {
		printf("\nStatus = %d, Unable to generate ARP request !!!", status);
		return -1;
	}
	return 1;
}

int
update_arp_table(int				pack_type,
				 char				*packet, 
				 struct sockaddr_ll	*pack_addr,
				 int				socfd) {
	int		status, iter, valid = 0, i;
	long	ip1, ip2, check_ip = -1;
	char	addr[INET_ADDRSTRLEN], *ptr;

	/* Destination address */
	status = get_packet_data_long(packet+PF_PACKET_HEADER+5, 10, &ip1);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill IP address of Destination !!! Exiting ...",status);
		return (-1);
	}

	/* Source address */
	status = get_packet_data_long(packet+PF_PACKET_HEADER+15, 10, &ip2);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill IP address of Destination !!! Exiting ...",status);
		return (-1);
	}
	
	if (pack_type == ARP_REQUEST) {
		check_ip = ip2;
	} else if (pack_type == ARP_REPLY) {
		check_ip = ip1;
	}
	
	/* Check for update function */
	for(iter = 0; iter < 50; iter++) {
		if (arp_table[iter].ip == check_ip) {
			if (pack_type == ARP_REQUEST) {
				memcpy((void *)arp_table[iter].if_haddr, (void *)packet+ETH_ALEN, ETH_ALEN);
				arp_table[iter].ip = ip2;
			} else if (pack_type == ARP_REPLY) {
				memcpy((void *)arp_table[iter].if_haddr, (void *)packet+ETH_ALEN, ETH_ALEN);
				arp_table[iter].ip = ip1;
			}
	
			arp_table[iter].if_index = pack_addr->sll_ifindex;
			arp_table[iter].socfd = socfd;
			arp_table[iter].hatype = pack_addr->sll_hatype;
			//arp_table[iter].status = 1;
			valid = 1;
			break;
		}
	}
	
	/* Create new entry */
	if (valid == 0) {
		for(iter = 0; iter < 50; iter++) {
			if (arp_table[iter].status == 0) {
				if (pack_type == ARP_REQUEST) {
					memcpy((void *)arp_table[iter].if_haddr, (void *)packet+ETH_ALEN, ETH_ALEN);
					arp_table[iter].ip = ip2;
				} else if (pack_type == ARP_REPLY) {
					memcpy((void *)arp_table[iter].if_haddr, (void *)packet+ETH_ALEN, ETH_ALEN);
					arp_table[iter].ip = ip1;
				}
	
				arp_table[iter].if_index = pack_addr->sll_ifindex;
				arp_table[iter].socfd = socfd;
				arp_table[iter].hatype = pack_addr->sll_hatype;
				arp_table[iter].status = 1;
				valid = 1;
				break;
			}
		}
	}
	
	fflush(stdout);
	printf("\n\t\t=== ARP Cache ===");
	printf("\n=====================================================================");
	printf("\nIP Address\tMAC Address\t\tIF-INDEX");
	printf("\n=====================================================================");
	for(iter = 0; iter < 50; iter++) {
		if (arp_table[iter].status == 1) {
			inet_ntop(AF_INET, &(arp_table[iter].ip), addr, INET_ADDRSTRLEN);
			printf("\n%s\t", addr);
			
			ptr = arp_table[iter].if_haddr;
			i = IF_HADDR;
			do {
				printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
			} while (--i > 0);
	
			printf("\t%d\t", arp_table[iter].if_index);
		
			
		}
	}
	fflush(stdout);
	printf("\n=====================================================================");
	return 0;
}

int
send_unix_reply(int			unix_sockfd,
				long		ip) {
	char				packet[6];
	int					iter;

	for(iter = 0; iter < 50; iter++) {
		//if (arp_table[iter].status == 1 &&
		if(arp_table[iter].ip == ip) {
			memcpy((void *)packet, (void *)arp_table[iter].if_haddr, ETH_ALEN);
			break;
		}
	}

	Send(unix_sockfd, packet, 6, 0);
	
	close(unix_sockfd);
	return 0;
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
send_arp_reply(char					*packet,
			   int					packet_soc_fd,
			   struct sockaddr_ll	*pack_addr,
			   char					*source_mac,
			   long					my_ip) {
	int					status, i;
	char				temp[10], *ptr;
	struct ethhdr 		*eh = (struct ethhdr *)packet;
	long				destip;
	char				myvm[10], destaddr[50], srcaddr[50];
	
	memcpy((void *)temp, (void *)packet+ETH_ALEN, ETH_ALEN);
	
	memcpy((void*)packet, (void*)temp, ETH_ALEN);
	memcpy((void*)(packet+ETH_ALEN), (void*)source_mac, ETH_ALEN);
	eh->h_proto = PROTOCOL_NO;
	
	status = fill_packet_data(packet+PF_PACKET_HEADER, ARP_REPLY, 5);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill ARP packet type !!! Exiting ...",status);
		return -1;
	}

	/* Source address */
	status = get_packet_data_long(packet+PF_PACKET_HEADER+15, 10, &destip);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill IP address of Destination !!! Exiting ...",status);
		return (-1);
	}

	get_vmname(my_ip, myvm);
	inet_ntop(AF_INET, &(destip), destaddr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(my_ip), srcaddr, INET_ADDRSTRLEN);

	fflush(stdout);
	printf("\n=========================================");
	printf("\nARP at node %s sending ARP REPLY", myvm);
	printf("\nDestination MAC: ");
	ptr = packet;
	i = IF_HADDR;
	do {
		printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
	} while (--i > 0);
	
	printf("\tSource MAC: ");
	ptr = packet+ETH_ALEN;
	i = IF_HADDR;
	do {
		printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
	} while (--i > 0);
	printf("\nDestination IP: %s", destaddr);
	printf("\t\tSource IP: %s", srcaddr);
	printf("\n=========================================");

	status = sendto(packet_soc_fd, packet, 500, 0, 
					(struct sockaddr *)pack_addr, sizeof(*pack_addr));
	if (status <= 0) {
		printf("\nError in sending ARP reply !!!\n");
		return -1;
	}	

	return 0;	
}

int main() {
	int     			unix_sockfd, status, packet_sockfd;
	int					if_index = 2;
    struct sockaddr_un 	servaddr;
	char				selfhostname[10];
	struct hwa_info		*hwa;
	struct sockaddr		*sa;
	char   				*ptr;
	int    				i, prflag;
	long				my_ip, prev_ip;
	struct sockaddr_in *temp;
	char    			source_mac[IF_HADDR];
	char				source_addr[INET_ADDRSTRLEN];
	char				packet[500], payload[500];
	long				packip = 0;
	socklen_t			len = 0;
	struct sockaddr_ll 	pack_addr;
	struct sockaddr_un 	recv;
	struct sockaddr_storage	in_data;
	int					temp_fd = -1, pack_type;
	
    status = gethostname(selfhostname, 10);
	if (status < 0) {
		printf("\nUnable to get hostname of the machine !!!");
	}
	
	/* Create unix domain socket */
    unix_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(unix_sockfd < 0) {
		printf("\nError in creating UNIX domain socket !!!\nExiting client ...\n");
		return 0;
	}
	
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_UNIX;
    strcpy(servaddr.sun_path, ARP_PATH);
	unlink(servaddr.sun_path);

    status = bind(unix_sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
	if (status < 0) {
		printf("\nError in UNIX domain bind !!!\nExiting ...\n");
		return 0;
	}
	
	/* Create packet socket */
    packet_sockfd = socket(AF_PACKET, SOCK_RAW, PROTOCOL_NO);
	if (packet_sockfd < 0) {
		printf("\nError in creating packet socket !!!");
	}

	hwa = Get_hw_addrs();
	for (; hwa != NULL; hwa = hwa->hwa_next) {
		
		status = strncmp(hwa->if_name, ETH0, strlen(ETH0));
		if(status == 0)	{
			temp = (struct sockaddr_in *)hwa->ip_addr;
			my_ip = temp->sin_addr.s_addr;
			memcpy((void*)source_mac, (void*)hwa->if_haddr, ETH_ALEN);
			if_index = hwa->if_index;
			//inet_pton(AF_INET, &(temp->sin_addr), &my_ip);
		}
		
		printf("%s :%s", hwa->if_name, ((hwa->ip_alias) == IP_ALIAS) ? " (alias)\n" : "\n");
		
		if ( (sa = hwa->ip_addr) != NULL)
			printf("         IP addr = %s\n", Sock_ntop_host(sa, sizeof(*sa)));
				
		prflag = 0;
		i = 0;
		do {
			if (hwa->if_haddr[i] != '\0') {
				prflag = 1;
				break;
			}
		} while (++i < IF_HADDR);

		if (prflag) {
			printf("         HW addr = ");
			ptr = hwa->if_haddr;
			i = IF_HADDR;
			do {
				printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
			} while (--i > 0);
		}
		printf("\n         interface index = %d\n\n", hwa->if_index);
	}
	
	inet_ntop(AF_INET, &(my_ip), source_addr, INET_ADDRSTRLEN);
	fflush(stdout);
	printf("\nSource IP address: %s", source_addr);
	printf("\nSource MAC address = ");
	ptr = source_mac;
	i = IF_HADDR;
	do {
		printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
	} while (--i > 0);
	fflush(stdout);
	printf("\nSource if_index = %d", if_index);

	/* Listen echo socket, check for errors */
    status = listen(unix_sockfd, BACKLOG_LIMIT);
	if (status != 0) {
		printf("\nStatus = %d, Unable to listen echo service socket !!!",status);
		return 0;			
	}

	while(1) {
		fd_set 		mon_fd;

		FD_ZERO(&mon_fd);
		FD_SET(unix_sockfd, &mon_fd);
		FD_SET(packet_sockfd, &mon_fd);
		
		if (unix_sockfd > packet_sockfd) {
			status = select(unix_sockfd + 1, &mon_fd, NULL, NULL, NULL);
		} else {
			status = select(packet_sockfd + 1, &mon_fd, NULL, NULL, NULL);
		}
		if (status < 0) {
			printf("\nStatus = %d, Unable to monitor sockets !!! Exiting ...",status);
			return 0;
		}

		if (FD_ISSET(unix_sockfd, &mon_fd)) {
			len = sizeof(in_data);
           	temp_fd = accept(unix_sockfd, (struct sockaddr *)&in_data, &len);
			if (temp_fd < 0) {
				printf("\nStatus = %d, Unable to accept connections on socket !!! Exiting ...",temp_fd);
				return 0;
			}
			
			len = sizeof(recv);
			Read(temp_fd, payload, 500);
			
			status = get_previous_ip(payload, &prev_ip);
			if (status != 0) {
				printf("\nStatus = %d, Unable to get previous IP data", status);
			}
			
			status = get_arp_entry(payload, my_ip, packet_sockfd,
									source_mac, if_index, prev_ip);
			if (status == 0) {
				/* Entry found, send reply */
				status = send_unix_reply(temp_fd, prev_ip);
			}
			
		} else if (FD_ISSET(packet_sockfd, &mon_fd)) {
			len = sizeof(pack_addr);
			status = recvfrom(packet_sockfd, packet, 500, 0,
							(struct sockaddr *)&pack_addr, &len);
			if (status <= 0) {
				printf("\nError in packet socket recvfrom !!!\n");
			}
			
			status = get_packet_data(packet+PF_PACKET_HEADER, 5, &pack_type);
			if (status != 0) {
				printf("\nStatus = %d, Unable to get packet !!! Exiting ...",status);
				return 0;
			}
			
			if (pack_type == ARP_REQUEST) {

				status = update_arp_table(pack_type, packet, &pack_addr, temp_fd);
				if (status != 0) {
					printf("\nStatus = %d, Unable to update ARP table !!!", status);
				}
				
				status = get_packet_data_long(packet+PF_PACKET_HEADER+5, 10, &packip);
				if (status != 0) {
					printf("\nStatus = %d, Unable to get destination IP address !!! Exiting ...",status);
					return 0;
				}
				
				if (packip == my_ip) {
					status = send_arp_reply(packet, packet_sockfd, &pack_addr,
											source_mac, my_ip);
					if (status != 0) {
						fflush(stdout);
						printf("\nStatus = %d, Unable to send ARP reply !!!", status);
					}
				}
			} else if (pack_type == ARP_REPLY) {
				
				status = update_arp_table(pack_type, packet, &pack_addr, temp_fd);
				if (status != 0) {
					printf("\nStatus = %d, Unable to update ARP table !!!", status);
				}
				
				status = send_unix_reply(temp_fd, prev_ip);
			} else {
				fflush(stdout);
				printf("\nUn-expected ARP packet type !!!");
			}
		} else {
			// Select timeout
		}
	}
	
	return 0;
}