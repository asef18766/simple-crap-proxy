#pragma once
#include <vector>
#include "vpn_client_state.hpp"

class client_manager
{
    private:
        client_manager();
        std::vector<client_state*> clients;
        static client_manager* instance;
    public:
        static client_manager* get_instance();
        void add_client(client_state* cptr);
        void delete_client(client_state *cptr);
        void broadcast(client_state* except, void* msg, size_t msglen);
        ~client_manager();
};