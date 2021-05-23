#include <stdio.h>
#include <stdlib.h>
#include "C:\\Users\\JP\\Desktop\\escuela\\NPCAP\\npcap-sdk-1.06\\Include\\pcap.h"
#include <pcap.h>
#define LINE_LEN 16
#define RUTA "C:\\Users\\JP\\Desktop\\escuela\\Redes\\P2\\paquetes3.pcap"
#define 	PCAP_OPENFLAG_PROMISCUOUS   1
#define 	PCAP_SRC_FILE   2
#define 	PCAP_BUF_SIZE   1024


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



void dispatcher_handler(u_char *temp1, 
                        const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    u_int i=0;
    int ext, j; //Extendido / No extendido
    int tipo; // 0 = I; 1 = S; 2 = U;
    unsigned int T_L, aux; 
	unsigned char i_g;
	unsigned char c_r;
	
	

    /*
     * Unused variable
     */
    (VOID)temp1;
	printf("---------------------------------------- Analisis de la trama ---------------------------\n");
    /* print pkt timestamp and pkt len */
    printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);          
    
    /* Print the packet */
    for (i=1; (i < header->caplen + 1 ) ; i++)
    {
        printf("%.2x ", pkt_data[i-1]);
        if ( (i % LINE_LEN) == 0) printf("\n");
    }
    
    printf("\n\n");     
    
    printf("MAC Destino: ");
    for(j = 0; j<6; j++){
        printf("%.2x ", pkt_data[j]);
    }
    puts("");

    printf("MAC Origen: ");
    for(j = 6; j<12; j++){
        printf("%.2x ", pkt_data[j]);
    }
    puts("");
	
	T_L = (pkt_data[12]*256)+pkt_data[13];
	printf("Longitud/tipo:\n(%.2x %.2x)Hex = (%d)Dec\n", pkt_data[12], pkt_data[13], T_L);
    
    if(T_L <= 1500){
        i_g = pkt_data[14]&0x01;
        printf("\n");
        printf("DSAP: %i\n", i_g);

        c_r = pkt_data[15]&0x01;
        printf("\n");
        printf("SSAP: %i\n", c_r);  
        puts("");
        
        if(i_g==0)
            printf("el destinatario es un protocolo individual");
        else
            printf("el destinatario es un conjunto de protocolos");
        
        c_r = pkt_data[15]&0x01;
        printf("\n");
        
        if(c_r==0)
            printf("el mensaje es de comando");
        else
            printf("el mensaje es de respuesta");
        
        printf("\n");

        //Modo extendido o no extendido mas logitud del campo de control
        printf("campo de control: ");
        if(T_L<1500 && T_L>3)
        {
            printf("2 bytes, Extendido\n");
            ext = 1;
        }
        else if(T_L==3 || T_L < 3){
            printf("1 byte\n"); 
            ext = 0;
        }

		puts("");
        //chequeo de tipo de trama
        aux = pkt_data[16]&0x01; //mascara para el ultimo bit 
        if(aux == 0){
            tipo = 0;
            puts("Trama tipo I");
            tipoI(pkt_data[16], pkt_data[17], ext);
            
        }
        else{
            aux = pkt_data[16]&0x03;
            if(aux == 1){
                tipo = 1;
                puts("Trama tipo S");
                tipoS(pkt_data[16], pkt_data[17], ext);
            }
            else{ 
                tipo = 2;
                puts("Trama tipo U");
                tipoU(pkt_data[16]);
            }
        }

        printf("-----------------------------------------------------------------------------------------\n");

        printf("\n\n\n");     

    }
    else
        puts("Secuencia de Ethernet");
}

void tipoI(unsigned char pkt_dataA, unsigned char pkt_dataB, int ext){
    unsigned char aux;
    if(ext){
        aux = ((pkt_dataA)>>1)&0x127;
        printf("Numero de secuencia de envio: %.2x\n", aux);
        aux = ((pkt_dataB)>>1)&0x127;
        printf("Numero de secuencia de recibo: %.2x\n", aux);
        aux = pkt_dataB&0x01;
        printf("P/F: %.1x\n", aux);
    }
    else{
        aux = ((pkt_dataA)>>5)&0x07;
        printf("Numero de secuencia de envio: %.2x\n", aux);
        aux = ((pkt_dataA)>>1)&0x07;
        printf("Numero de secuencia de recibo: %.2x\n", aux);
        aux = pkt_dataB>>4&0x01;
        printf("P/F: %.1x\n", aux);
    }
}

void tipoS(unsigned char pkt_dataA, unsigned char pkt_dataB, int ext){
    unsigned char aux;
    if(ext){
        aux = (pkt_dataA&0x01>>2)&0x03;
        printf("SS: %.2x\n", aux);
        switch (aux)
        {
        case 0x00:
            puts("listo para recibir");
            break;
        case 0x01:
            puts("Rechazo");
            break;
        case 0x02:
            puts("Receptor no listo para recibir");
            break;
        case 0x03:
            puts("Rechazo Selectivo");
            break;
        
        default:
            break;
        }
        aux = (pkt_dataB>>1)&0x127;
        printf("Numero de acuse: %.2x\n", aux);
    }
    else{
        aux = (pkt_dataA>>2)&0x03;
        printf("SS: %.2x\n", aux);
        switch (aux)
        {
        case 0x00:
            puts("listo para recibir");
            break;
        case 0x01:
            puts("Rechazo");
            break;
        case 0x02:
            puts("Receptor no listo para recibir");
            break;
        case 0x03:
            puts("Rechazo Selectivo");
            break;
        
        default:
            break;
        }
        aux = (pkt_dataA>>5)&0x03;
        printf("Numero de acuse: %.2x\n", aux);
    }
}

void tipoU(unsigned char pkt_dataA){
    unsigned char aux1, aux2;
    int i;
    aux1 = (pkt_dataA>>2)&0x03;  //Ultimos 2 bits
    aux2 = (pkt_dataA>>5)&0x07; //Ultimos 3 bits
    printf("Secuencia de 5 bits: ");
    for(i = 0; i<3; i++){
        if(aux2&0x01)
            printf("1 ");
        else    
            printf("0 ");
        aux2 = aux2>>1;
    }

    for(i = 0; i<2; i++){
        if(aux1&0x01)
            printf("1 ");
        else    
            printf("0 ");
        aux1 = aux1>>1;
    }
    puts("");
    aux1= pkt_dataA>>3&0x01;
    printf("P/F: %.1x\n", aux1);
}
