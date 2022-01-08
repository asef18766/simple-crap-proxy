#pragma once
#include <stddef.h>
#include <openssl/ssl.h>
#include <arpa/inet.h>      // inet

const in_addr_t VPN_STR_IP = 0x3f070804; // 4.8.7.63
#define VPN_NETMASK "255.255.255.0"

class client_state
{
    private:
    enum state{
        no_ip,
        assigned_ip,
        ready
    };
    client_state::state cur_state;
    SSL *ssl;

    public:
    client_state(SSL* _ssl);
    ~client_state();

    void recv(void *buf, size_t len);
    void send(void *buf, size_t len);
};
