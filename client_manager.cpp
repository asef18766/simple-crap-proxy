#include "client_manager.hpp"
#include <algorithm>
client_manager* client_manager::instance = NULL;

client_manager::client_manager() {}
client_manager* client_manager::get_instance()
{
    if (instance == NULL)
        instance = new client_manager();
    return instance;
}
void client_manager::add_client(client_state* cptr)
{
    this->clients.push_back(cptr);
}
void client_manager::delete_client(client_state *cptr)
{
    auto idx = std::find(this->clients.begin(), this->clients.end(), cptr);
    this->clients.erase(idx);
}
void client_manager::broadcast(client_state* except, void* msg, size_t msglen)
{
    for (auto i = this->clients.begin() ; i != this->clients.end(); ++i)
    {
        if (*i == except || (!(*i)->is_ready()))
            continue;
        (*i)->send(msg, msglen);
    }
}
client_manager::~client_manager()
{
    instance = NULL;
}