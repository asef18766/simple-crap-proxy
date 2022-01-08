#include "utils.h"
#include <stdio.h>
#include <openssl/err.h>

void print_ip_packet( unsigned char *packet, int size )
{
    int ipheaderlen = 0;
    int protocol = 0;
    int i = 0, offset = 0;
    
    if( size < 20 )
    {
        printf( "Size < IP Header!!\n" );
        return;
    }
    
    if( ( packet[0] & 0xF0 ) != 0x40 )
    {
        printf( "We only print IPv4 Packets!!\n" );
        return;
    }
    
    ipheaderlen = ( packet[0] & 0x0F ) * 4;
    protocol = packet[9];
    
    printf( "=========================================\n" );
    printf( "IP Header:\n\t" );
    
    for( i = 0 ; i < ipheaderlen ; i++ )
    {
        printf( "%02X ", packet[i] );
        
        if( i % 4 == 3 )
        {
            printf( "\n\t" );
        }
    }
    
    printf( "\n" );
    
    offset = ipheaderlen;
    
    if( protocol == 6 )
    {
        printf( "TCP Header:\n\t" );
        
        for( i = 0 ; i < 20 ; i++ )
        {
            printf( "%02X ", packet[offset + i] );
        
            if( i % 4 == 3 )
            {
                printf( "\n\t" );
            }
        }
        
        offset += 20;
        printf( "\n" );
    }
    else if( protocol == 17 )
    {
        printf( "UDP Header:\n\t" );
        
        for( i = 0 ; i < 8 ; i++ )
        {
            printf( "%02X ", packet[offset + i] );
        
            if( i % 4 == 3 )
            {
                printf( "\n\t" );
            }
        }
        
        offset += 8;
        printf( "\n" );
    }
    
    printf( "Data Payload:\n\t" );

    for( i = offset ; i < size ; i++ )
    {
        printf( "%02X ", packet[i] );
        
        if( i % 8 == ( ( offset - 1) % 8 ) )
        {
            printf( "\n\t" );
        }
    }
    
    printf( "\n" );
    printf( "=========================================\n" );
}
void printhex(unsigned char *packet, int size)
{
    for (int i = 0; i != size; ++i)
    {
        printf("%02x ", packet[i]);
        if (i % 16 == 15)
            putchar('\n');
    }
}
void SSL_write_with_check(SSL* ssl, void *echoString, ssize_t echoStringLen)
{
    if ( SSL_write(ssl, echoString, echoStringLen) != echoStringLen )
    {
        perror( "send() sent a different number of bytes than expected");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
}
int SSL_read_with_check(SSL* ssl, void *echoBuffer, ssize_t echoBufferLen)
{
    int bytesRcvd;
    if ( ( bytesRcvd = SSL_read( ssl, echoBuffer, echoBufferLen) ) <= 0 )
    {
        perror("recv() failed or connection closed prematurely");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return bytesRcvd;
}