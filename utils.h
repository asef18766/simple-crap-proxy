#pragma once
#include <openssl/ssl.h>
void print_ip_packet( unsigned char *packet, int size );
void printhex(unsigned char *packet, int size);
void SSL_write_with_check(SSL* ssl, void *echoString, ssize_t echoStringLen);
int SSL_read_with_check(SSL* ssl, void *echoBuffer, ssize_t echoBufferLen);