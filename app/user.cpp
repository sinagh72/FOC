#include "user.h"
#include <cstddef>


//constructors
User::User(){
    
}
User::User(string username, string IP, unsigned short port, int client_socket):
    username{username}, IP{IP}, port{port}, client_socket{client_socket}, 
    server_client_key{nullptr}, clients_key{nullptr}, clients_pubk{nullptr},
    clients_pubk_char{nullptr}, client_server_pubk{nullptr}, 
    client_server_pubk_char{nullptr}, server_pubk{nullptr}, server_pubk_char{nullptr},
    peer_pubk{nullptr}, peer_pubk_char{nullptr}, server_counter{0}, 
    client_counter{0}, peer_username{nullptr}{
}
User::User(const User &source):
    username(source.username), IP(source.IP), port(source.port), client_socket(source.client_socket),
    server_client_key(source.server_client_key), clients_key(source.clients_key), clients_pubk(source.clients_pubk),
    clients_pubk_char(source.clients_pubk_char), client_server_pubk(source.client_server_pubk), 
    client_server_pubk_char(source.client_server_pubk_char), server_pubk(source.server_pubk), server_pubk_char(source.server_pubk_char),
    peer_pubk(source.peer_pubk), peer_pubk_char(source.peer_pubk_char), server_counter(source.server_counter), 
    client_counter(source.client_counter), peer_username(source.peer_username)
    {
    
}

//serialize the object
void User::serialize(){
}

bool User::replay_check(bool from_server, uint16_t received_counter){
    bool returned = false;
    if (from_server)
        if (received_counter - this->get_server_counter() != 1){//the difference between them should be always 1
            cerr<< "Replay Attack! This message is discarded!" <<endl;
            return false;
        }
        else {
            this->increment_server_counter();
            return true;
        }
    else{
        if (received_counter - this->get_client_coutner() != 1){//the difference between them should be always 1
            cerr<< "Replay Attack! This message is discarded!" <<endl;
            return false;
        }
        else {
            this->increment_client_counter();
            return true;
        }
    }
    cerr<< "Error: Problem in replay check!" <<endl;
    return false;
}

User::~User(){
    if(this->peer_pubk_char)
        free(this->peer_pubk_char);
    if(this->clients_pubk_char)
        free(this->clients_pubk_char);
}
