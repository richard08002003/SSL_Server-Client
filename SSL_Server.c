/* SSL_Server.c : 可接受多人連線
*   Complie ： gcc -Wall -o SSL_Server SSL_Server.c -lcrypto -lssl
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
/**開啟Socket來監聽*/
 int OpenListener( int port )
 {
    struct sockaddr_in addr ;
    //Create Socket()
    int sd = socket( PF_INET , SOCK_STREAM , 0 ) ;
    if ( sd < 0 ) {
        printf("Could not create a socket ! \n") ;
        exit(1) ;
    }
        printf("Socket Create ! \n") ;
    bzero( &addr , sizeof(addr) ) ;
    addr.sin_family = AF_INET ;
    addr.sin_port = htons(port) ;
    addr.sin_addr.s_addr = INADDR_ANY ;
    //Bind()
    int reuseaddr = 1 ;
    socklen_t reuseaddr_len ;
    setsockopt(sd , SOL_SOCKET , SO_REUSEADDR , &reuseaddr , reuseaddr_len) ;
    if ( bind( sd , (struct sockaddr*)&addr , sizeof(addr) ) < 0 ) {
        printf("Bind Failed ! \n") ;
        exit(1) ;
    }
        printf("Bind Successed ! \n") ;
    //Listen()
    if (listen( sd , 10 ) < 0 ) {
        printf("Can't configure listening port ! \n") ;
        exit(1) ;
    }
        printf("Listen Successed ! \n") ;
    printf("Connect Port : %d \n" , port ) ;
    printf("Waiting for connection . . . \n\n") ;
    return sd ;
 }

 int main()
 {
    SSL_library_init() ; // SSL庫的初始化
    /** 初始化SSL */
    SSL_CTX *ctx ;
    OpenSSL_add_all_algorithms() ; //裝載&註冊所有密碼的資訊
    SSL_load_error_strings() ; //載入所有錯誤信息
    ctx = SSL_CTX_new( SSLv23_server_method() ) ; // 創建一個名為"ctx"並使用SSLv23_server_method的SSL_CTX
    if ( ctx == NULL ) {
            printf("Create SSL_CTX Failed ! \n") ;
            exit(1) ;
    }
    /**載入憑證&驗證憑證 */
    char CertFile[] = "/home/richard/Richard/Server&Client For C/SSL_Server&Client/myca/mycert.pem" ;
    char KeyFile[] = "/home/richard/Richard/Server&Client For C/SSL_Server&Client/myca/mycert.pem" ;
    //載入用戶數位簽章，此憑證用來發給client端，包含公鑰( public key )
    if ( SSL_CTX_use_certificate_file( ctx , CertFile , SSL_FILETYPE_PEM ) <= 0 ) {
        printf("設定憑證(Certificate)失敗！\n") ;
        exit(1) ;
    }
    //載入用戶的的私鑰( private key )
    if( SSL_CTX_use_PrivateKey_file( ctx , KeyFile , SSL_FILETYPE_PEM ) <= 0 ) {
        printf("設定私鑰(Private Key)失敗！\n") ;
        exit(1) ;
    }
    //檢查用戶私鑰( private key )是否正確
    if ( !SSL_CTX_check_private_key(ctx) ) {
        printf("用戶的私鑰不符合！\n") ;
        exit(1) ;
    }
    //載入憑證(用戶的憑證)
    if ( SSL_CTX_load_verify_locations( ctx , CertFile , NULL ) <= 0 ) {
        printf("SSL_CTX_load_verify_location() Failed ! \n") ;
        exit(1) ;
    }
    //用來驗證client端的憑證（server端會驗證client端的憑證）
    SSL_CTX_set_verify( ctx , SSL_VERIFY_PEER , NULL ) ;
    //設定最大的驗證用戶憑證的數目
    SSL_CTX_set_verify_depth( ctx , 10 ) ;

    //呼叫OpenListenet()，並且帶入參數(port : 7979)
    int server = OpenListener(7979) ;

    while(1) {
        struct sockaddr_in addr ;
        SSL *ssl ; // Create SSL ，繼承SSL_CTX的所有設定
        socklen_t len = sizeof(addr) ;
        //accept() : 接受client端的連線
        int client = accept( server , (struct sockaddr*)&addr , (socklen_t*)&len ) ;
        if ( client < 0 ) {
            printf("accept Failed ! \n") ;
            exit(1) ;
        }
        printf("Connect IP : %s\n" , inet_ntoa(addr.sin_addr) ) ;
        ssl = SSL_new(ctx) ;  // 設定一個新的使用ctx的SSL
        SSL_set_fd( ssl , client ) ; //設定連線用戶的socket加入到SSL

        /*fork：讓多個Client來連線*/
        pid_t fpid ;
        fpid = fork() ;
        if ( fpid < 0 ) {
            printf("fork() is Error ! \n") ;
            exit(1) ;
        } else if ( fpid == 0 ) {
            //Child proccess 子行程 -> 進行讀寫
            /* int SSL_accept(SSL *ssl) ; */
            int act = SSL_accept( ssl ) ;
            if ( act < 0 ) {
                printf("SSL_accept() Failed ! \n") ;
                exit(1) ;
            }
            char buf[1024] ={0} ;
            //char str[] = "Hello 123" ;
            while(1) {
                /** 讀取資料*/
                int val = SSL_read( ssl , buf , sizeof(buf) ) ;
                if ( val < 0 ) {
                    printf("\nReceive the \"%s\"Client's messages Failed!! \n" , inet_ntoa(addr.sin_addr) ) ;
                    break ;
                }else if ( val == 0 ) {
                    printf("\nDisconnected to \"%s\" Client . . . \n" , inet_ntoa(addr.sin_addr) ) ;
                    break ;
                } else {
                    buf[val] = 0 ;
                    printf("[%s]：%s \n", inet_ntoa(addr.sin_addr) , buf ) ;
                    /**回傳資料*/
                    int snd = SSL_write( ssl , buf , strlen(buf) ) ;
                    if ( snd < 0 ) {
                        printf("Send reply Failed！\n") ;
                        exit(1) ;
                    }
                        printf("Send reply success！\n") ;
                        printf("-------------------------------------------------\n") ;
                }
            }
            int sd = SSL_get_fd( ssl ) ; // 給定一個sd 使用連線socket的ssl
            SSL_free(ssl) ; // 釋放ssl
            close(sd) ;  //關閉sd socket
        } else {
            //parent process 父行程
            continue ;
        }
    }
    close(server) ;
    SSL_CTX_free(ctx) ;
    return 0 ;
 }
