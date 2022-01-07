#include <stdio.h>          // for printf() and fprintf() 
#include <sys/socket.h>     // for socket(), bind(), and connect() 
#include <arpa/inet.h>      // for sockaddr_in and inet_ntoa() 
#include <stdlib.h>         // for atoi() and exit() 
#include <string.h>         // for memset() 
#include <unistd.h>         // for close() 
#include <sys/time.h>       // for struct timeval {} 
#include <fcntl.h>          // for fcntl() 
#include <sys/types.h>
#include <unistd.h>

#include <sys/epoll.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


#define MAXPENDING 5        // Maximum outstanding connection requests
#define MAXCLIENT  100	    // Maximum users
#define RCVBUFSIZE 1000	    // Buffer Size

SSL_CTX *ctx;

int CreateTCPServerSocket(unsigned short port)
{
    int sock;                        // socket to create 
    struct sockaddr_in echoServerAddr; // Local address 

    // Create socket for incoming connections 
    if ( ( sock = socket( PF_INET, SOCK_STREAM, IPPROTO_TCP ) ) < 0 )
    {
        perror( "socket() failed" );
        exit(1);
    }
      
    // Construct local address structure 
    memset( &echoServerAddr, 0, sizeof( echoServerAddr ) );	// Zero out structure 
    echoServerAddr.sin_family = AF_INET;                      	// Internet address family 
    echoServerAddr.sin_addr.s_addr = inet_addr( "0.0.0.0" );   // Any incoming interface 
	// echoServerAddr.sin_addr.s_addr = htonl( INADDR_ANY );
                                                                // # define INADDR_ANY ((unsigned long int) 0x00000000)
    echoServerAddr.sin_port = htons( port );                  	// Local port 

    // Bind to the local address 
    if ( bind(sock, (struct sockaddr *) &echoServerAddr, sizeof( echoServerAddr ) ) < 0 )
    {
        perror( "bind() failed" );
        exit(1);
    }
    
    // Mark the socket so it will listen for incoming connections 
    if ( listen( sock, MAXPENDING ) < 0 )
    {
        perror( "listen() failed" );
        exit(1);
    }
    
    return sock;
}

int AcceptTCPClient( int serverSock, struct sockaddr_in *echoClientAddr )
{
	int clientSock;        				// Socket descriptor for client
    unsigned int        clientLen;     	// Length of client address data structure 
    
    // Wait for a client to connect 
    if ( ( clientSock = accept( serverSock, (struct sockaddr *) echoClientAddr, &clientLen ) ) < 0 )
    {
        perror("accept() failed");
        exit(1);
    }
    
    return clientSock;
}

int HandleTCPClient( SSL *ssl )
{
    char    echoBuffer[RCVBUFSIZE] = {0};  // Buffer for echo string 
    int     recvMsgSize;                   // Size of received message 
    
    // Receive message from client 
    if ( ( recvMsgSize = SSL_read( ssl, echoBuffer, RCVBUFSIZE ) ) < 0 )
    {
        perror("SSL_read failed");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // Send received string and receive again until end of transmission 
    if ( recvMsgSize > 0 )      // zero indicates end of transmission 
    {
        printf( "From FD (%d) recv %d bytes:\n\tData:", SSL_get_fd( ssl ), recvMsgSize );
        
        for( int i = 0 ; i < recvMsgSize ; i++ )
        {
            printf( "%02X ", echoBuffer[i] );
        }
        printf( "\n" );
        
        // Echo message back to client 
        if ( SSL_write( ssl, echoBuffer, recvMsgSize ) != recvMsgSize )
        {
            perror( "SSL_write() failed" );
            ERR_print_errors_fp(stderr);
            exit(1);
        }
    }
    
    return recvMsgSize;
}


int main( int argc, char *argv[] )
{
    int	serverSock;	// Socket descriptor for server 
    
    if ( argc != 2 )     
    {
        fprintf( stderr, "Usage:  %s port\n", argv[0]);
        exit(1);
    }
    
    serverSock = CreateTCPServerSocket( atoi( argv[1] ) );
    
    int                     epfd;                   // EPOLL File Descriptor. 
    struct epoll_event      ev;                     // Used for EPOLL.
    struct epoll_event      events[MAXCLIENT + 2];  // Used for EPOLL.
    int                     noEvents;               // EPOLL event number.
    
    epfd = epoll_create1( 0 );		
    
    // Add the server socket to the epoll
    ev.data.fd = serverSock;
    ev.events = EPOLLIN | EPOLLET;
    epoll_ctl( epfd, EPOLL_CTL_ADD, serverSock, &ev );
    
    // Add STDIN into the EPOLL set.
    ev.data.fd = STDIN_FILENO;
    ev.events = EPOLLIN | EPOLLET;
    epoll_ctl( epfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev );     
    
    // Initialize OpenSSL
    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();
    
    const SSL_METHOD *method;
    
    method = TLS_server_method();
    ctx = SSL_CTX_new( method );
    
    SSL_CTX_set_ecdh_auto(ctx, 1);
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "server.pem", SSL_FILETYPE_PEM) <= 0) 
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0 ) 
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    if( !ctx )
    {
        perror( "Unable to create SSL context" );
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    
    int running = 1;    
    while( running )
    {
        noEvents = epoll_wait( epfd, events, MAXCLIENT + 2 , ( 5 * 1000 ) );
        
        if ( noEvents <= 0 ) 
        {
            printf("No echo requests for 5 secs...Server still alive\n" );
            continue; 
        }
        
        for( int i = 0 ; i < noEvents ; i++ )
        {
            if( events[i].events & EPOLLIN && STDIN_FILENO == events[i].data.fd )
            {
                printf("Shutting down server\n");
                getchar();
                running = 0;
                continue;
            }
            else if ( events[i].events & EPOLLIN && serverSock == events[i].data.fd )
            {
                // Accept new connections
                int clientSock; 			// Socket descriptor for client
                struct sockaddr_in echoClientAddr; 	// client address
                unsigned int        clientLen;     	// Length of client address data structure 
    
                clientSock = AcceptTCPClient( serverSock, &echoClientAddr );
                printf("Connected Client --> IP: %s, Port: %d, FD: %d\n", inet_ntoa( echoClientAddr.sin_addr ), htons( echoClientAddr.sin_port ), clientSock );
                
                SSL *ssl = SSL_new( ctx );
                SSL_set_fd( ssl, clientSock );
                
                if ( SSL_accept( ssl ) <= 0 ) 
                {
                    perror( "SSL Accept fail" );
                    ERR_print_errors_fp(stderr);
                    continue;
                }
                
                ev.data.ptr = ssl;
                ev.events = EPOLLIN | EPOLLET;
                epoll_ctl( epfd, EPOLL_CTL_ADD, clientSock, &ev ); 
            }
            else if ( events[i].events & EPOLLIN )
            {
                if( HandleTCPClient( events[i].data.ptr ) == 0 )
                {
                    printf( "Connection %d Shudown.\n", SSL_get_fd( (SSL *)( events[i].data.ptr ) ) );
                    SSL_shutdown( (SSL *)( events[i].data.ptr ) );
                    close( SSL_get_fd( (SSL *)( events[i].data.ptr ) ) );
                    SSL_free( (SSL *)( events[i].data.ptr ) );
                }
            }
        }
    }
    
    close( serverSock );
    SSL_CTX_free(ctx);
    
    return 0;
}
