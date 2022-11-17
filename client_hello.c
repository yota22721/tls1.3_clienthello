#include<stdint.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<unistd.h>
#include<netdb.h>
#include <arpa/inet.h>

#define DEV_RANDOM "/dev/urandom"
typedef uint8_t opaque;

typedef uint8_t ProtocolVersion;
typedef uint8_t Random[32];

typedef uint8_t CipherSuite;  /*Cryptgraphic suite selector */

typedef struct{
    ProtocolVersion legacy_version[2]; //tls v1.2 : 0x0303 tls v1.3 : 0x0304(default 0x0303)
    Random random;      //32bit random value 
    opaque legacy_session_id;   // pre-tlsv1.3 : <0...32> tlsv1.3 : 0x00
    CipherSuite cipher_suites[14];  //<2..2^16-2>
    opaque legacy_compression_methods;  //prior to tlsv1.3 : <1..2^8-1>  tls v1.3 : 0x00
    opaque extensions;   //<8..2^16-1>

}ClientHello;

//basic vector
typedef struct 
{
    uint8_t* data;
    int size;
}Vector;

Vector *v;

uint8_t get_random( uint8_t *buf,const int buflen)
{
    int fd = open(DEV_RANDOM,O_RDONLY);

    if(fd == -1){
        fprintf(stderr,"Error : failed to load /dev/urandom../ :(");
        return -1;
    }
    int r = read(fd,buf,32);
    if(r < 0){
        fprintf(stderr,"Error : Failed to read /dev/urandom.\n");
        return -1;
    }
    if (buflen != 32)
    {
        fprintf(stderr,"Error can not read(%d != %d)",r,32);
        return -1;
    }
    
    return 0;
}


void CharToHex(char origin[],uint8_t dest[]){
    int num;
    int j=0,i=0,k=0;

    char hex[] ="0123456789abcdef";
    char digits[3];

    for( i=0; origin[i] !='\0';i++){
    
        j = origin[i] %16;
        num = origin[i] / 16;
       
        digits[k]=hex[num];
        digits[++k]=hex[j];

        dest[i] = (uint8_t)strtol(digits,(char**)NULL,16) &0xff;
        if(k == 1) k= 0;
        
    }

}

int append(uint8_t n,Vector *source){
    uint8_t byte = sizeof(uint8_t);
    if(source->size == 0){
        source->data = (uint8_t*)malloc(sizeof(uint8_t));
    }
    int capa = source->size + 1;
    uint8_t size = byte *capa;
    uint8_t *tmp = realloc(source->data,size);
    if(!tmp){
        return -1;
    }
    source->data = tmp;
    source->size = capa;
    source->data[size -1] = n;


    return 0;

}

void addTolast(uint8_t lst[],uint8_t len,Vector *source,int is_stack){

    if(is_stack == 0){
        for(int i =0;i<len;i++){
            append(lst[i],source);
        }
    }else{
        for(int i = 0;i<len;i++){
        append(lst[len-i-1],source);
        }
    }
    
}


void addServerName(Vector *source){
  
    char ServerName[] = "www.google.com";
    uint8_t length = sizeof(ServerName)/sizeof(ServerName[0])-1;
    uint8_t name_data[length];
    
    uint8_t head[9] = {
        0x00,0x00,
        0x00,(length + 5)&0xff,
        0x00,(length + 3)&0xff,
        0x00,
        0x00,length&0xff
        };
    CharToHex(ServerName,name_data); 
    addTolast(head,9,source,0);
    addTolast(name_data,length,source,0);   
}

void addSupportedGroups(Vector *source){
    uint8_t groups[]={
            0x00, 0x1d,//x25519
            0x00, 0x17,//secp256r1
            0x00, 0x1e,//x448
            0x00, 0x19,//secp521r1
            0x00, 0x18,//secp384r1 
            0x01, 0x00,//ffdhe2048
            0x01, 0x01,//ffdhe3072
            0x01, 0x02,//ffdhe4096
            0x01, 0x03,//ffdhe6144
            0x01, 0x04,//ffdhe8192
    };
    uint8_t size = sizeof(groups);
    uint8_t head[6] = {
        0x00,0x0a,
        0x00,(size+2)&0xff,
        0x00,size&0xff
    };
    addTolast(head,sizeof(head),source,0);
    addTolast(groups,size,source,0);
}

void addSignatureAlgorithms(Vector *source){
    uint8_t algorithms[]={
        0x04,0x03,//ecdsa_secp256r1_sha256
        0x05,0x03,//ecdsa_secp384r1_sha384
        0x06,0x03,//ecdsa_secp521r1_sha512

        0x08,0x07,//ed25519
        0x08,0x08,//ed448

        0x08,0x09,//rsa_pss_pss_sha256
        0x08,0x0a,//rsa_pss_pss_sha384
        0x08,0x0b,//rsa_pss_pss_sha512

        0x08,0x04,//rsa_pss_rsae_sha256
        0x08,0x05,//rsa_pss_rsae_sha384
        0x08,0x06,//rsa_pss_rsae_sha512

        0x04,0x01,//rsa_pkcs1_sha256
        0x05,0x01,//rsa_pkcs1_sha384
        0x06,0x01,//rsa_pkcs1_sha512
    };
    uint8_t size = sizeof(algorithms);
    uint8_t head[6] ={
        0x00,0x0d,
        0x00,(size+2)&0xff,
        0x00,size&0xff
    };
    addTolast(head,sizeof(head),source,0);
    addTolast(algorithms,size,source,0);
}


void addSupportedVersions(Vector *source){
    uint8_t data[7] ={
        0x00,0x2b,
        0x00,0x03,
        0x02,
        0x03,0x04
    };
    addTolast(data,sizeof(data),source,0);
}

void GenerateKey(uint8_t *key){
    //this field will be used for key generation.

}
void addKeyShare(Vector *source){
    uint8_t generated_key[32] ={
        0x00,0x01,
        0x02,0x03,
        0x04,0x05,
        0x06,0x07,
        0x08,0x09,
        0x0a,0x0b,
        0x0c,0x0d,
        0x0e,0x0f,
        0x10,0x11,
        0x12,0x13,
        0x14,0x15,
        0x16,0x17,
        0x18,0x19,
        0x1a,0x1b,
        0x1c,0x1d,
        0x1e,0x1f,
    };

    uint8_t head[10] = {
        0x00,0x33,
        0x00,0x26,
        0x00,0x24,
        0x00,0x1d,//x25519
        0x00,0x20
    };
    //GenerateKey(generated_key);
    addTolast(head,sizeof(head),source,0);
    addTolast(generated_key,32,source,0);
}

void addExtension(Vector *source)
{
    source->size = 0;
    addSupportedGroups(source);
    addSignatureAlgorithms(source);
    addSupportedVersions(source);
    addKeyShare(source);

}


void InitClientHello(ClientHello *data)
{
    uint8_t random[32];
    int i;

    data->legacy_version[0]= 0x03;
    data->legacy_version[1]= 0x03;

    if(get_random(random,32) == 0){
        for(int i = 0;i< sizeof(random);i++){ 
            data->random[i] = random[i];
        }
    }
    
    data->legacy_session_id = 0x00;

    uint8_t suites[]= {
        0x00,0x0c,//bytes of cipher suite data
        0x13,0x02,//TLS_AES_256_GCM_SHA384
        0x13,0x03,//TLS_CHACHA20_POLY1305_SHA256
        0x13,0x01,//TLS_AES_128_GCM_SHA256
        0x13,0x04,//TLS_AES_128_CCM_SHA256 
        0x13,0x05,//TLS_AES_128_COM_SHA256  
        0x00,0xff//TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        };
    for(i =0; i< sizeof(suites);i++){
        data->cipher_suites[i] = suites[i];
    }

    data->legacy_compression_methods = 0x00;

}


void addClientHello(ClientHello *ch,Vector *clienthello,uint8_t exts_size)
{
    Vector stack;
    stack.size = 0;
    clienthello->size = 0;

    //Extensions Length
    append(exts_size,&stack);
    append(0x00,&stack);

    //Legacy Compression Methods
    append(0x00,&stack);
    append(0x01,&stack);

    //Cipher Suites
    addTolast(ch->cipher_suites,sizeof(ch->cipher_suites),&stack,1);
   
    //Legacy Session ID
    append(ch->legacy_session_id,&stack);
    append(0x01,&stack);  

    //Client Random
    addTolast(ch->random,32,&stack,1);

    //Legacy version
    addTolast(ch->legacy_version,2,&stack,0);
 
    //Handshake Header
    append((stack.size + exts_size)&0xff,&stack);
    uint8_t handshake_header[] ={0x00,0x00};
    addTolast(handshake_header,2,&stack,0);
    append(0x01,&stack);
 
    //Record Header
    uint8_t record[] ={
        (stack.size + exts_size)&0xff,0x00,
        0x01,0x03,
        0x16
    };
    addTolast(record,5,&stack,0);
    
    int size = stack.size;
    for(int i = 0;i<size;i++){
        append(stack.data[size-1-i],clienthello);
    }

}

int main(){
    ClientHello ch;
    Vector clienthello;
    Vector extensions;

    InitClientHello(&ch);

    addExtension(&extensions);

    addClientHello(&ch,&clienthello,(uint8_t)extensions.size&0xff);
    
    addTolast(extensions.data,extensions.size,&clienthello,0);
    
    unsigned char *raw;
    raw = (unsigned char*)clienthello.data;

    clienthello.data = NULL;
    extensions.data = NULL;

#ifdef OUTPUT_CH

    int sock;
    char *hostname = "www.google.com";
    char *service = "https";
    struct addrinfo hints, *res0,*res;
    int err;
    int send_size,recv_size;
    unsigned char recv_buf[256];

    memset(&hints,0,sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = PF_UNSPEC;

    if(err = getaddrinfo(hostname,service,&hints,&res0) !=0){
        printf("error %d\n",err);
        return 1;
    }

    for (res=res0; res!=NULL; res=res->ai_next) {
        sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock < 0) {
            continue;
        }
 
        if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
        close(sock);
        continue;
        }    

        break;
    }

    if(res == NULL){
        printf("Failed\n");
        return 1;
    }
    freeaddrinfo(res0);

    printf("[*]connection succeeded!\n");

#else



    int sock;
    int port = 4043;
    char ip_addr[] = "127.0.0.2";
    
    int send_size,recv_size;
    unsigned char recv_buf[256];
    struct sockaddr_in addr;

    sock = socket(AF_INET,SOCK_STREAM,0);
    if(sock == -1){
        printf("socket error\n");
        return -1;
    }

    memset(&addr,0,sizeof(struct sockaddr_in));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip_addr);

    printf("[*]Start connecting...\n");
    if(connect(sock,(struct sockaddr *)&addr,sizeof(addr)) == -1)
    {
        printf("[!]connection error\n");
        close(sock);
        return -1;
    }
    printf("[*]connection succeeded!\n");
#endif
    
    send_size = send(sock,raw,clienthello.size,0);
    
    if(send_size == -1){
        printf("[!]Send error\n");
        return -1;
    }
    printf("[*]sent buffer...\n");
    recv_size = recv(sock,recv_buf,256,0);
    if(recv_size == -1){
        printf("[!]recv error\n");
        return -1;
    }
    if(recv_size == 0){
        printf("[!]connection ended.\n");
        return -1;
    }
    if(recv_buf == 0){
        printf("[!]Finish connection\n");
        return -1;
    }
    printf("server response : ");
    for(int i = 0;i<256;i++){
        printf(" %02x",recv_buf[i]);
    }
    printf("\n");
    
    close(sock);

    return 0;
}



