#include "utils.h"
#include <stdio.h>
#include <openssl/err.h>

#include <arpa/inet.h>
#include <pcap.h>

#include <netinet/ip.h>
#include <linux/if_arp.h>
#include <net/ethernet.h>

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

unsigned short print_ethernet_packet(const unsigned char *packet_content)
{
	unsigned char *mac_string;				//
	struct ether_header *ethernet_protocol = (struct ether_header *)packet_content;
    unsigned short ethernet_type = ntohs(ethernet_protocol->ether_type);//獲得乙太網的型別
	
    printf("----------------------------------------------------\n");
	mac_string = (unsigned char *)ethernet_protocol->ether_shost;//獲取源mac地址
	printf("mac src: %02x:%02x:%02x:%02x:%02x:%02x\n",
    mac_string[0],\
    mac_string[1],\
    mac_string[2],\
    mac_string[3],\
    mac_string[4],\
    mac_string[5]);

	mac_string = (unsigned char *)ethernet_protocol->ether_dhost;//獲取目的mac
	printf("mac dst: %02x:%02x:%02x:%02x:%02x:%02x\n",\
    mac_string[0],\
    mac_string[1],\
    mac_string[2],\
    mac_string[3],\
    mac_string[4],\
    mac_string[5]);

    printf("Ethernet type is :%04x\n",ethernet_type);
    switch(ethernet_type)
	{
		case ETHERTYPE_IP:printf("The network layer is IP protocol\n");break;//ip
		case ETHERTYPE_ARP:printf("The network layer is ARP protocol\n");break;//arp
		default:break;
	}
    printf("----------------------------------------------------\n");
    return ethernet_type;
}

void print_ip(const unsigned char *packet_content)
{
    struct ip *ip = (struct ip *)(packet_content + ETHER_HDR_LEN);
    u_int version = ip->ip_v;
    u_int header_len = ip->ip_hl << 2;
    u_char tos = ip->ip_tos;
    u_int16_t total_len = ntohs(ip->ip_len);
    u_int16_t id = ntohs(ip->ip_id);
    u_int16_t offset = ntohs(ip->ip_off);
    u_char ttl = ip->ip_ttl;
    u_char protocol = ip->ip_p;
    u_int16_t checksum = ntohs(ip->ip_sum);

    //TODO: finish printing
    perror("not implemented !!");
    exit(-1);
}

void print_arp(const unsigned char *packet_content)
{
    struct arphdr* arpheader = (struct arphdr*)(packet_content + ETHER_HDR_LEN);
    
}