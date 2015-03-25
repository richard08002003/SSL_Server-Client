/* SSL_Client.c */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
/**開啟socket來連線*/
int OpenConnection( const char *hostname , int port )
{
    struct hostent *host ;
    struct sockaddr_in addr ;
    if ( ( host = gethostbyname(hostname) ) == NULL ) {
        printf("hostname error ! \n") ;
        exit(1) ;
    }
    //Socket()
    int sd = socket( PF_INET , SOCK_STREAM , 0 ) ;
    if ( sd < 0 ) {
        printf("Could not create a socket ! \n") ;
        exit(1) ;
    }
        printf("Socket Create ! \n") ;
    bzero( &addr , sizeof(addr) ) ;
    addr.sin_family = AF_INET ;
    addr.sin_port = htons(port) ;
    addr.sin_addr.s_addr = *(long*)(host->h_addr) ;
    //Connect()
    if ( connect( sd , (struct sockaddr*)&addr , sizeof(addr) ) < 0 ) {
        printf("Connect Failed ! \n") ;
        exit(1) ;
    }
        printf("Connect() Success ! \n") ;
    return sd ;
}

int main( int n , char *s[])
{
    char *hostname , *portnum ;
    if ( n != 3 ) {
        printf("Usage : %s <hostname> <portnum> \n" , s[0] ) ;
        exit(1) ;
    }
    hostname = s[1] ;     //設定第一個參數：ip address
    portnum = s[2] ;      //設定第二個參數：port

    SSL_library_init() ; // SSL庫的初始化
    /** 初始化SSL */
    OpenSSL_add_all_algorithms() ; //裝載&註冊所有密碼的資訊
    SSL_load_error_strings() ; //載入所有錯誤信息
    // 創建一個名為"ctx"並且使用SSLv23_client_method的SSL_CTX
    SSL_CTX *ctx = SSL_CTX_new( SSLv23_client_method() ) ;
    if ( ctx == NULL ) {
        printf("Create SSL_CTX Failed ! \n") ;
        exit(1) ;
    }
    //呼叫OpenConnection()，帶入兩個參數，並且開始連線至Server
    int server = OpenConnection( hostname , atoi(portnum) ) ;
    SSL *ssl = SSL_new(ctx) ;   // 設定一個新的使用ctx的SSL
    SSL_set_fd( ssl , server ) ; //設定連線用戶的socket加入到SSL
    //SSL_connect()
    int client = SSL_connect( ssl ) ;
    if ( client < 0 ) {
        printf("SSL_connect() Failed ! \n") ;
        exit(1) ;
    }
        /**成功連線，並且開始進行SSL通訊*/
        printf("Connect To Server ! \n") ;
        //傳送資料
        char data[1024] = {0} ;
        char  buf [1024] ={0} ;
        while(1) {
            printf("Please enter the data : ") ;
            fgets( data , sizeof(data) , stdin ) ;
            char *ptr = strrchr( data , '\n' ) ;
            if( NULL != ptr ) {
                *ptr = 0 ;
            }
            int snd = SSL_write( ssl , data , strlen(data) ) ;
            if ( snd < 0 ) {
                printf("Send data Failed ! \n") ;
                break ;
            }
                printf("Send Success ! \n") ;
            // 讀取資料
            int val = SSL_read( ssl , buf , sizeof(buf) ) ;
            if ( val < 0 ) {
                printf("\nReceive messages Failed!! \n") ;
                break ;
            }else if ( val == 0 ) {
                printf("\nDisconnected to Server . . . \n") ;
                break ;
            } else {
                buf[val] = 0 ;
                printf("Receive the Server's reply --> %s \n", buf ) ;
                printf("-------------------------------------------------\n") ;
            }
        }
        SSL_free(ssl) ;
        close(server) ;
        SSL_CTX_free(ctx) ;

    return 0 ;
}
