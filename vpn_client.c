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

#include "utils.h"

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

int main( int argc, char *argv[] )
{
    char    ifname[IFNAMSIZ];
    char    ipaddr[16];
    char    netmask[16];
    int     tunfd = 0;
    
    int                     epfd;       // EPOLL File Descriptor. 
    struct epoll_event      ev;         // Used for EPOLL.
    struct epoll_event      events[5];  // Used for EPOLL.
    int                     noEvents;   // EPOLL event number.
    
    int     i = 0, rcvlen = 0, running = 1;
    
    unsigned char   buffer[1024];   // Receive packet buffer.
    
    memset( ifname, 0, IFNAMSIZ );
    memset( ipaddr, 0, 16 );
    memset( netmask, 0, 16 );
    
    if( argc == 3 )
    {
        strncpy( ipaddr, argv[1], 15 );
        strncpy( netmask, argv[2], 15 );
    }
    else if( argc == 4 )
    {
        strncpy( ifname, argv[1], IFNAMSIZ - 1 );
        strncpy( ipaddr, argv[2], 15 );
        strncpy( netmask, argv[3], 15 );
    }
    else
    {
        printf( "Usage:\n" );
        printf( "%s (interface name) [server ip] [netmask]\n", argv[0] );
        return 0;
    }
    
    printf( "IF Name: %s\n", ifname );
    printf( "IP Address: %s\n", ipaddr );
    printf( "Netmask: %s\n", netmask );
    
    // IFF_TUN is for TUN; IFF_TAP is for TAP
    //
    // TUN (namely network TUNnel) simulates a network layer device and it
    // operates with layer 3 packets like IP packets. 
    // TAP (namely network tap) simulates a link layer device and it operates 
    // with layer 2 packets like Ethernet frames.
    //
    // IFF_NO_PI tells the kernel to not provide packet information. 
    
    if( ( tunfd = tun_alloc( ifname, IFF_TAP | IFF_NO_PI ) ) < 0 )
    {
        printf( "Create TUN/TAP interface fail!!\n" );
    }
    set_ip( ifname, ipaddr, netmask );
    
    // Create epoll file descriptor.

    epfd = epoll_create1( 0 );
    
    // Add socket into the EPOLL set.
    
    ev.data.fd = tunfd;
    ev.events = EPOLLIN | EPOLLET;
    epoll_ctl( epfd, EPOLL_CTL_ADD, tunfd, &ev );  
    
    // Use Ctrl-C to interrupt the process.
    while( running )
    {
        noEvents = epoll_wait( epfd, events, FD_SETSIZE , -1 );
        
        for( i = 0 ; i < noEvents; i++ )
        {
            if( events[i].events & EPOLLIN && tunfd == events[i].data.fd )
            {
                memset( buffer, 0, 1024 );
                if( ( rcvlen = read( tunfd, buffer, 1024 ) ) < 0 )
                {
                    perror( "Reading data" );
                    running = 0;
                }
                else
                {
                    // Since this is a TUN interface, we parse this as an IP packet.
                    // If TAP, buffer will be an ethernet frame.
                    print_ip_packet( buffer, rcvlen );
                }
            }
        }
    }
    
    close( tunfd );
    
    return 0;
}