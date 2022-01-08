#include "vpn_client_state.hpp"
#include "client_manager.hpp"

#include <stdexcept>
#include <string>

#include <string.h>
#include "utils.h"

client_state::client_state(SSL* _ssl)
{
    this->cur_state = this->no_ip;
    this->ssl = _ssl;
    client_manager::get_instance()->add_client(this);
}
client_state::~client_state()
{
    client_manager::get_instance()->delete_client(this);
}
void send_ip(SSL *ssl)
{
    static unsigned int ctr = 0;
    in_addr dst_raw;
    dst_raw.s_addr = \
        (VPN_STR_IP & 0x00ffffff) | \
        ((VPN_STR_IP >> 24) + ctr << 24);
    char *dst_ip = inet_ntoa(dst_raw);
    
    std::string buf = "255.255.255.0 ";
    buf += dst_ip;
    SSL_write_with_check(ssl, (void*)buf.c_str(), buf.length());
    ctr ++;
}
void client_state::recv(void *buf, size_t len)
{
    switch (this->cur_state)
    {
        case this->no_ip:
            printf("try to send client ip...\n");
            send_ip(this->ssl);
            this->cur_state = this->assigned_ip;
            break;
        case this->assigned_ip:
            #define CLIENT_RET "OK!"
            printf("auth code:\n");
            printhex((unsigned char *)buf, len);
            putchar('\n');
            if (strncmp(CLIENT_RET, (char *)buf, sizeof(CLIENT_RET)) != 0)
                throw std::invalid_argument((char*)buf);
            this->cur_state = this->ready;
            break;
        case this->ready:
            printf("broadcasting packets except FD(%d)\n", SSL_get_fd(this->ssl));
            printf("=== data ===\n");
            printhex((unsigned char*)buf, len);
            printf("\n");
            
            client_manager::get_instance()->broadcast(this, buf, len);
            break;
        default:
            throw std::invalid_argument("encounter undefined state");
    }
}
void client_state::send(void *buf, size_t len)
{
    SSL_write_with_check(this->ssl, buf, len);
}
bool client_state::is_ready()
{
    return this->cur_state == this->ready;
}