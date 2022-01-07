#include <stdio.h>      // for printf() and fprintf() 
#include <sys/socket.h> // for socket(), connect(), send(), and recv() 
#include <arpa/inet.h>  // for sockaddr_in and inet_addr() 
#include <stdlib.h>     // for atoi() and exit() 
#include <string.h>     // for memset() 
#include <unistd.h>     // for close() 

#include <openssl/ssl.h>
#include <openssl/err.h>

#define STRBUFSIZE 1024 // Size of receive buffer 

int main(int argc, char *argv[])
{
    int sock;                        // Socket descriptor 
    struct sockaddr_in echoServAddr; // Echo server address 
    unsigned short echoServPort;     // Echo server port 
    char *servIP;                    // Server IP address (dotted quad)
    char echoString[STRBUFSIZE];     // Buffer for echo string  
    char echoBuffer[STRBUFSIZE];     // Buffer for echo string 
    unsigned int echoStringLen;      // Length of string to echo 
    int bytesRcvd, totalBytesRcvd;   // Bytes read in single recv() and total bytes read 

    if ( ( argc < 2 ) || (argc > 3 ) )    // Test for correct number of arguments 
    {
       fprintf( stderr, "Usage: %s <Server IP> [<Echo Port>]\n", argv[0] );
       exit(1);
    }

    servIP = argv[1];             // First arg: server IP address (dotted quad) 

    if ( argc == 3 )
    {
        // Use given port, if any 
        echoServPort = atoi(argv[2]); 
    }
    else
    {
        // 7 is the well-known port for the echo service
        echoServPort = 7;  
    } 

    // Create a reliable, stream socket using TCP 
    if ( ( sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP ) ) < 0 )
    {
        perror("socket() failed");
        exit(1);
    }
    
    // Construct the server address structure 
    memset(&echoServAddr, 0, sizeof(echoServAddr));     // Zero out structure 
    echoServAddr.sin_family      = AF_INET;             // Internet address family 
    echoServAddr.sin_addr.s_addr = inet_addr(servIP);   // Server IP address 
    echoServAddr.sin_port        = htons(echoServPort); // Server port 

    // Establish the connection to the echo server 
    if ( connect( sock, (struct sockaddr *) &echoServAddr, sizeof( echoServAddr ) ) < 0 )
    {
        perror( "connect() failed" );
        exit(1);
    }
    
    // Initialize OpenSSL
    SSL_load_error_strings();   
    OpenSSL_add_ssl_algorithms();
    
    const SSL_METHOD *method;
    method = TLS_client_method();
    SSL_CTX *ctx;
    ctx = SSL_CTX_new( method );
    
    if( !ctx )
    {
        perror( "Unable to create SSL context" );
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    
    SSL *ssl = SSL_new( ctx );
    SSL_set_fd( ssl, sock );
    
    if ( SSL_connect( ssl ) < 0 )
    {
        perror( "Unable to setup an SSL connection" );
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    
    while ( 1 )
    {
        bzero( echoString, STRBUFSIZE );
        bzero( echoBuffer, STRBUFSIZE );
        
        printf("Enter(q for exit): \n"); 
        
        fgets( echoString, STRBUFSIZE, stdin ); 
        
        echoStringLen = strlen( echoString );
        
        if ( echoStringLen == 2 && echoString[0] == 'q' && echoString[1] == '\n' )
        {
            break;
        }
        
        if ( SSL_write(ssl, echoString, echoStringLen) != echoStringLen )
        {
            perror( "send() sent a different number of bytes than expected");
            ERR_print_errors_fp(stderr);
            exit(1);
        }
        
        printf("Received"); 
        
        if ( ( bytesRcvd = SSL_read( ssl, echoBuffer, STRBUFSIZE) ) <= 0 )
        {
            perror("recv() failed or connection closed prematurely");
            ERR_print_errors_fp(stderr);
            exit(1);
        }
        printf( "(%d): ", bytesRcvd );
        printf( "%s", echoBuffer);      // Print the echo buffer 
        
    }
    
    printf("\n");    // Print a final linefeed 
    
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx); 
    return 0;
}