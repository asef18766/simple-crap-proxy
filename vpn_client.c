#include <stdio.h>
#include <stdlib.h>

#include <net/if.h>         // struct ifreq
#include <sys/types.h>      // open
#include <sys/stat.h>       // open
#include <fcntl.h>          // open
#include <arpa/inet.h>      // inet
#include <sys/ioctl.h>      // ioctl
#include <linux/if_tun.h>   // tun/tap
#include <errno.h>
#include <unistd.h>        // close

#include <sys/epoll.h>

#include <string.h>
#include <openssl/err.h>

#include "utils.h"

#define CLIENT_PING "PING"
#define CLIENT_OK "OK!"


int tun_alloc( char *dev, int flags )
{
    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";

    if( ( fd = open( clonedev , O_RDWR ) ) < 0 ) 
    {
        perror( "Opening /dev/net/tun" );
        return fd;
    }

    memset( &ifr, 0, sizeof( ifr ) );

    ifr.ifr_flags = flags;
    
    // Set the interface name.
    if ( strlen( dev ) > 0 ) 
    {
        strncpy( ifr.ifr_name, dev, IFNAMSIZ );
    }

    if( ( err = ioctl( fd, TUNSETIFF, (void *)&ifr ) ) < 0 ) 
    {
        perror( "ioctl(TUNSETIFF)" );
        close( fd );
        return err;
    }

    return fd;
}

int set_ip( char *dev, char *ipaddr, char *netmask )
{
    struct ifreq ifr;
    int err;
    
    // ioctl needs one fd as an input.
    // Request kernel to give me an unused fd. 
    int fd = socket( PF_INET, SOCK_DGRAM, IPPROTO_IP );
    
    // Set the interface name.
    if ( *dev ) 
    {
        strncpy( ifr.ifr_name, dev, IFNAMSIZ );
    }
    ifr.ifr_addr.sa_family = AF_INET;
    
    // Set IP address
    // The structure of ifr.ifr_addr.sa_data is "struct sockaddr"
    // struct sockaddr
    // {
    //      unsigned short    sa_family;
    //      char              sa_data[14];
    // }
    // This is why +2 is used.
    if( ( err = inet_pton( AF_INET, ipaddr, ifr.ifr_addr.sa_data + 2 ) ) != 1 )
    {
        perror( "Error IP address." );
        close( fd );
        return err;
    }
    if( ( err = ioctl( fd, SIOCSIFADDR, &ifr ) ) < 0 )
    {
        perror( "IP: ioctl(SIOCSIFADDR)" );
        close( fd );
        return err;
    }
    
    // Set netmask
    if( ( err = inet_pton( AF_INET, netmask, ifr.ifr_addr.sa_data + 2 ) ) != 1 )
    {
        perror( "Error IP address." );
        close( fd );
        return err;
    }
    if( ( err = ioctl( fd, SIOCSIFNETMASK, &ifr ) ) < 0 )
    {
        perror( "Netmask: ioctl(SIOCSIFNETMASK)" );
        close( fd );
        return err;
    }
    
    // Enable the interface
    // Get the interface flag first and add IFF_UP | IFF_RUNNING.
    if( ( err = ioctl( fd, SIOCGIFFLAGS, &ifr ) ) < 0 )
    {
        perror( "ioctl(SIOCGIFFLAGS)" );
        close( fd );
        return err;
    }
    ifr.ifr_flags |= ( IFF_UP | IFF_RUNNING );
    if( ( err = ioctl( fd, SIOCSIFFLAGS, &ifr ) ) < 0 )
    {
        perror( "ioctl(SIOCSIFFLAGS)" );
        close( fd );
        return err;
    }
    
    close( fd );
    
    return 1;
}

typedef struct _ssl_bundle{
    int sock;
    SSL *ssl;
    SSL_CTX *ctx;
} ssl_bundle;

ssl_bundle create_tls_connection(int netsock)
{
    ssl_bundle ssl_connection;
    ssl_connection.sock = netsock;

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
    
    if ( ( ssl_connection.ssl = SSL_new( ctx ) ) == NULL )
    {
        perror( "Unable to new SSL" );
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if ( SSL_set_fd( ssl_connection.ssl, ssl_connection.sock ) == 0 )
    {
        perror( "Unable to set SSL fd" );
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    
    if ( SSL_connect( ssl_connection.ssl ) < 0 )
    {
        perror( "Unable to setup an SSL connection" );
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return ssl_connection;
}

int main( int argc, char *argv[] )
{
    char    ifname[IFNAMSIZ];
    char    *ipaddr  = NULL;
    char    *netmask = NULL;
    int     tapfd = -1;
    
    int                     epfd;       // EPOLL File Descriptor. 
    struct epoll_event      ev;         // Used for EPOLL.
    struct epoll_event      events[5];  // Used for EPOLL.
    int                     noEvents;   // EPOLL event number.
    
    int     i = 0, rcvlen = 0, running = 1;
    
    unsigned char   buffer[1024];   // Receive packet buffer.
    if (argc != 3)
    {
        printf("Usage:\n");
        printf("%s (server ip) (port)\n", argv[0]);
        return -1;
    }
    memset( ifname, 0, IFNAMSIZ );
    
    // Create epoll file descriptor.

    epfd = epoll_create1( 0 );
    
    // Add socket into the EPOLL set.

    struct sockaddr_in echoServAddr; // Echo server address 
    
    // Create a reliable, stream socket using TCP
    int netsock;
    if ( ( netsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP ) ) < 0 )
    {
        perror("socket() failed");
        exit(1);
    }
    
    // Construct the server address structure 
    memset(&echoServAddr, 0, sizeof(echoServAddr));     // Zero out structure 
    echoServAddr.sin_family      = AF_INET;             // Internet address family 
    echoServAddr.sin_addr.s_addr = inet_addr(argv[1]);   // Server IP address 
    echoServAddr.sin_port        = htons(atoi(argv[2])); // Server port 

    // Establish the connection to the echo server 
    if ( connect( netsock, (struct sockaddr *) &echoServAddr, sizeof( echoServAddr ) ) < 0 )
    {
        perror( "connect() failed" );
        exit(1);
    }

    ev.data.fd = netsock;
    ev.events = EPOLLIN;
    if (epoll_ctl( epfd, EPOLL_CTL_ADD, netsock, &ev ) == -1)
    {
        perror("[epoll_ctl]");
        return -1;
    }
    ssl_bundle ssl_info = create_tls_connection(netsock);
    SSL_write_with_check(ssl_info.ssl, CLIENT_PING, sizeof(CLIENT_PING));
    SSL_read_with_check(ssl_info.ssl, buffer, 1024);
    
    netmask = strtok(buffer, " ");
    ipaddr = strtok(NULL, " ");
    printf("assigned ip: %s\n", ipaddr);
    printf("assigned netmask: %s\n", netmask);

    // IFF_TUN is for TUN; IFF_TAP is for TAP
    //
    // TUN (namely network TUNnel) simulates a network layer device and it
    // operates with layer 3 packets like IP packets. 
    // TAP (namely network tap) simulates a link layer device and it operates 
    // with layer 2 packets like Ethernet frames.
    //
    // IFF_NO_PI tells the kernel to not provide packet information. 

    if( ( tapfd = tun_alloc( ifname, IFF_TAP | IFF_NO_PI ) ) < 0 )
    {
        printf( "Create TUN/TAP interface fail!!\n" );
    }
    set_ip( ifname, ipaddr, netmask );
    SSL_write_with_check(ssl_info.ssl, CLIENT_OK, sizeof(CLIENT_OK));

    ev.data.fd = tapfd;
    ev.events = EPOLLIN;
    if (epoll_ctl( epfd, EPOLL_CTL_ADD, tapfd, &ev ) == -1)
    {
        perror("[epoll_ctl]");
        return -1;
    }

    // Use Ctrl-C to interrupt the process.
    while( running )
    {
        noEvents = epoll_wait( epfd, events, 5 , 5000 );
        if (noEvents == 0)
        {
            printf("No echo requests for 5 secs...client still alive\n");
            continue;
        }
        else if(noEvents < 0)
        {
            perror("[epoll_wait]");
            exit(-1);
        }
        for( i = 0 ; i < noEvents; i++ )
        {
            if( events[i].events & EPOLLIN && tapfd == events[i].data.fd )
            {
                memset( buffer, 0, 1024 );
                if( ( rcvlen = read( tapfd, buffer, 1024 ) ) < 0 )
                {
                    perror( "Reading data" );
                    running = 0;
                }
                else
                {
                    // Since this is a TUN interface, we parse this as an IP packet.
                    // If TAP, buffer will be an ethernet frame.
                    /*
                    static int frame_ctr = 0;
                    
                    printf("==== new ethernet frame ====\n");
                    printf("index: %d\n", frame_ctr);
                    printf("frame len: %d\n", rcvlen);
                    printhex( buffer, rcvlen );
                    putchar('\n');
                    frame_ctr++;
                    */
                   SSL_write_with_check(ssl_info.ssl, buffer, rcvlen);
                }
            }
            if( events[i].events & EPOLLIN && ssl_info.sock == events[i].data.fd )
            {
                int data_sz = SSL_read_with_check(ssl_info.ssl, buffer, 1024);
                if (write(tapfd, buffer, data_sz) != data_sz)
                    perror("[write to tun failure]");
            }
        }
    }
    
    close( tapfd );
    
    return 0;
}