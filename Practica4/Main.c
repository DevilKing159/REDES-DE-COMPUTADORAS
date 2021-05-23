//interfaz 3
#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>

/* prototype of the packet handler */

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct ip_header{
	u_char ver_ihl; // Version (4 bits) + IP header length (4 bits)
	u_char tos; // Type of service
	u_short tlen; // Total length
	u_short identification; // Identification
	u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
	u_char ttl; // Time to live
	u_char proto; // Protocol
	u_short crc; // Header checksum
	ip_address saddr; // Source address
	ip_address daddr; // Destination address
	u_int op_pad; // Option + Padding
}ip_header;

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	
	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the device */
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	printf("\nlistening on %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	
	/* start the capture */
	pcap_loop(adhandle, 50, packet_handler, NULL);
	
	pcap_close(adhandle);
	return 0;
}


/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	/*
	 * unused parameters
	 */
	(VOID)(param);
	(VOID)(pkt_data);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	//ltime=localtime(&local_tv_sec);
	//strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	
	//printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	
	unsigned short tipo = (pkt_data[12]*256)+pkt_data[13];
	if (tipo==2048){
		puts("*------------------------------------*");
		printf("Paquete IP..\n");
		ip_header *ih;
		u_int ip_len;
		/* retireve the position of the ip header */
		ih = (ip_header *) (pkt_data + 14); //length of ethernet header
		
		//Version
		printf("Version: %.2x  ",(ih->ver_ihl)&0xf0>>3);
		if(((ih->ver_ihl)&0xf0>>3) == 4)
			puts("IP Version 4");
		else 
			puts("IP Version 6");
		
		//IHL
		printf("IHL: %.2d \n",(ih->ver_ihl)&0x0f);
		printf("Tam: %d\n", ((ih->ver_ihl)&0x0f)*4);
		//Tipo de servicio
		//printf("DEBUG: %.2x \n",(ih->tos));
		printf("Tipo de servicio: %d  ",((ih->tos)>>5)&0x07);
		switch (((ih->tos)>>5)&0x07)
		{
		case 0:
			puts("Routine");
			break;
		case 1:
			puts("Priority");
			break;
		case 2:
			puts("Immediate");
			break;
		case 3:
			puts("Flash");
			break;
		case 4:
			puts("Flash Overdrive");
			break;
		case 5:
			puts("CRITIC/ECP");
			break;
		case 6:
			puts("Internetwork Control");
			break;	
		case 7:
			puts("Network Control");
			break;					
		default:
			puts("");
			break;
		}

		//ENC
		printf("ENC: %d  ",(ih->tos)&0x03);
		switch ((ih->tos)&0x03)
		{
		case 0:
			puts("Sin capacidad ECN");
			break;
		case 1:
			puts("Capacidad de transporte ENC(0)");
			break;
		case 2:
			puts("Capacidad de transporte ENC(1)");
			break;
		case 3:
			puts("Congestion encontrada");
			break;
					
		default:
			puts("");
			break;
		}
		
		//Banderas
		printf("Banderas: %d  ", (ih->flags_fo>>13)&0x07);
		switch ((ih->flags_fo>>13)&0x07)
		{
		case 0:
			puts("Fragmentacion permitida, Ultimo fragmento del paquete");
			break;
		case 1:
			puts("Fragmentacion permitida, a espera de mas fragmentos");
			break;
		case 2:
			puts("Paquete sin fragmentacion");
			break;
		default:
			break;
		}
		
		//Fragment offset
		printf("Offset de fragmento: %d\n", (ih->flags_fo)&0x1FFF);
		
		
		
		//ttl
		printf("TTL: %d\n", ih->ttl);
		//Protocolo
		printf("Protocolo: %d   ->   ", ih->proto);
		switch (ih->proto)
		{
		case 0:
			puts("RESERVADO");
			break;
		case 1:
			puts("ICMP");
			break;
		case 2:
			puts("IGMP");
			break;
		case 3:
			puts("GGP");
			break;
		case 4:
			puts("IP");
			break;
		case 5:
			puts("ST");
			break;
		case 6:
			puts("TCP");
			break;
		case 7:
			puts("UCL");
			break;
		case 8:
			puts("EGP");
			break;
		case 17:
			puts("UDP");
			break;
		default:
			break;
		}
		
		//checksum
		printf("Cheksum: %d\n", ih->crc);
		
		//options
		printf("Opciones: %.2x %.2x %.2x", ih->op_pad&0xFF000000>>24, ih->op_pad&0xFF0000>>26, ih->op_pad&0xFF00>>8, ih->op_pad&0xFF);
		

		puts("\n");
		/* print ip addresses and udp ports */
		printf("Source Address: %d.%d.%d.%d\n", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
		printf("Destination Address: %d.%d.%d.%d\n", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
		
		
		
		
		
		puts("\n\n*------------------------------------*\n\n");
	}
		

	
	
	
    
}


