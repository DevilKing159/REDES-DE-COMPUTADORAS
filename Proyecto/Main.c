#include <stdio.h>
#include <stdlib.h>
#include "C:\\Users\\JP\\Desktop\\escuela\\NPCAP\\npcap-sdk-1.06\\Include\\pcap.h"
#include <pcap.h>
#define LINE_LEN 16
#define RUTA "C:\\Users\\JP\\Desktop\\escuela\\Redes\\Proyecto\\paquetes3.pcap"
#define 	PCAP_OPENFLAG_PROMISCUOUS   1
#define 	PCAP_SRC_FILE   2
#define 	PCAP_BUF_SIZE   1024

//Version de prueba 1
void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
void tipoI(unsigned char, unsigned char, int);
void tipoS(unsigned char, unsigned char, int);
void tipoU(unsigned char);
void printfBin(unsigned char);

int main(int argc, char **argv)
{
pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
char source[PCAP_BUF_SIZE];

   /* if(argc != 2){

        printf("usage: %s filename", argv[0]);
        return -1;

    }*/

    /* Create the source string according to the new WinPcap syntax */
    if ( pcap_createsrcstr( source,         // variable that will keep the source string
                            PCAP_SRC_FILE,  // we want to open a file
                            NULL,           // remote host
                            NULL,           // port on the remote host
                            RUTA, //argv[1],        // name of the file we want to open
                            errbuf          // error buffer
                            ) != 0)
    {
        fprintf(stderr,"\nError creating a source string\n");
        return -1;
    }
    
    /* Open the capture file */
    if ( (fp= (pcap_t *)pcap_open(source,         // name of the device
                        65536,          // portion of the packet to capture
                                        // 65536 guarantees that the whole packet will be captured on all the link layers
                         PCAP_OPENFLAG_PROMISCUOUS,     // promiscuous mode
                         1000,              // read timeout
                         NULL,              // authentication on the remote machine
                         errbuf         // error buffer
                         ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the file %s\n", source);
        return -1;
    }

    // read and dispatch packets until EOF is reached
    pcap_loop(fp, 0, dispatcher_handler, NULL);

    return 0;
}


//Dispatcher handler como main
void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    u_int i=0;
    int ext, j; //Extendido / No extendido
    int tipo; // 0 = I; 1 = S; 2 = U;
    unsigned int T_L, aux; 
	unsigned char i_g;
	unsigned char c_r;
    int opcion = 0;

    while(opcion != 4){
        printf("Interfaz de inicio para el analizador de tramas\n");
        printf("1)Analizador ARP\n2)IP\n3)IEEE\n4)Salir\n");
        scanf("%d", &opcion);

        switch (opcion)
        {
        case 1:
            arp(&temp1,&header,&pkt_data);
            break;

        case 2:
            ip(&temp1,&header,&pkt_data);
            break;

        case 3:
            ieee(&temp1,&header,&pkt_data);
            break;

        case 4:
            exit(0);
            break;

        default:
            puts("Opcion no valida");
            break;
        }
        puts("\n");
    }
   

}

void arp(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data){
    
    u_int i=0;
    int ext, j; //Extendido / No extendido
    int tipo; // 0 = I; 1 = S; 2 = U;
    unsigned int T_L, aux; 
	unsigned char i_g;
	unsigned char c_r;
    int opcion = 0;



    return;
}

void ip(const u_char *pkt_data){
    printf("IP\n");
    return;
}

void ieee(const u_char *pkt_data){
    printf("IEEE\n");
    return;
}
