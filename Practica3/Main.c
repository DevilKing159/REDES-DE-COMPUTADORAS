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
	pcap_loop(adhandle, 1000, packet_handler, NULL);
	
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
	
	int j = 0, tab = 1, bit = 1, aux;
	
	
	//Para convertir un hex de dos bytes a int (pkt_data[0]*256)+pkt_data[1];
	//Formateo de codigo
	
	aux = (pkt_data[12]*256) + pkt_data[13];
	if(aux == 2054){
		//Formato de trama a 16 bytes
		puts("\n------------------------------------------------");
		puts("Tipo: ARP");
		while(j<32){
		if(tab < 8)
		printf("%.2X ",pkt_data[j]);
		else{
			printf("%.2X ",pkt_data[j]);
			puts("");
			tab = 0;
			}   
			tab++;
			j+=1;
		}

		//Tipo de hardware
		aux = (pkt_data[14]*256) + pkt_data[15];
		printf("Tipo de hardware: ");
		switch (aux)
		{
		case 1:
			printf("%.2x Ethernet\n", aux);
			break;
		case 6:
			printf("%.2x IEEE 802 Networks\n", aux);
			break;
		case 7:
			printf("%.2x ARCTNET\n", aux);
			break;
		case 15:
			printf("%.2x Frame Relay\n", aux);
			break;
		default:
			puts("");
			break;
		}

		//Tipo de protocolo
		aux = (pkt_data[16]*256) + pkt_data[17];
		printf("Tipo de protocolo: ");
		switch (aux)
		{
		case 2048:
			printf("%.2x %.2x IPV4\n", pkt_data[16], pkt_data[17]);
			break;
		case 2054:
			printf("%.2x %.2x ARP\n", pkt_data[16], pkt_data[17]);
			break;
		case 2056:
			printf("%.2x %.2x Frame Relay ARP\n", pkt_data[16], pkt_data[17]);
			break;
		case 2058:
			printf("%.2x %.2x Point-to-Point Tunneling Protocol (PPTP)\n", pkt_data[16], pkt_data[17]);
			break;
		default:
			puts("");
			break;
		}

		//Tamaño de hardware
		printf("Tam de hardware: %d\n", pkt_data[18]);
		
		//Tamaño de protocolo
		printf("Tam de protocolo: %d\n", pkt_data[29]);

		//OP code
		
		aux = (pkt_data[20]*256) + pkt_data[21];
		printf("OP code: %d ",aux);
		switch (aux)
		{
		case 1:
			printf("ARP Request\n");
			break;
		case 2:
			printf("ARP REPLY\n");
			break;
		case 3:
			printf("ARP Request Reverse\n");
			break;
		case 4:
			printf("ARP Reply Reverse\n");
			break;
		default:
			puts("");
			break;
		}

		//Hardware addres
		printf("Direccion MAC de emisor: ");
		int ad = 0;
		while(ad<5){
			printf("%.2X:",pkt_data[22+ad]);
			ad+=1;
		}
		printf("%.2X",pkt_data[22+ad]);
		puts("");

		//IP address
		printf("Direccion IP de emisor: ");
		ad = 0;
		while(ad<3){
			printf("%d.",pkt_data[28+ad]);
			ad+=1;
		}
		printf("%d",pkt_data[28+ad]);
		puts("");
		
		//MAC destino:
		printf("Direccion MAC de receptor: ");
		ad = 0;
		while(ad<5){
			printf("%.2X:",pkt_data[32+ad]);
			ad+=1;
		}
		printf("%.2X",pkt_data[32+ad]);
		puts("");

		//MAC destino:
		printf("Direccion IP de receptor: ");
		ad = 0;
		while(ad<3){
			printf("%d.",pkt_data[38+ad]);
			ad+=1;
		}
		printf("%d",pkt_data[38+ad]);
		puts("\n------------------------------------------------\n\n");

	}
    
}


