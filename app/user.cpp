#include "user.h"
#include <cstddef>


//constructors
User::User(){
    
}
User::User(string username, string password, string IP, unsigned short port, int socket){
    // username{username}, IP{IP}, port{port}, socket{socket}, password{password}, 
    // server_client_key{nullptr}, clients_key{nullptr}, clients_pubk{nullptr},
    // clients_pubk_char{nullptr}, client_server_pubk{nullptr}, 
    // client_server_pubk_char{nullptr}, server_pubk{nullptr}, server_pubk_char{nullptr},
    // peer_pubk{nullptr}, peer_pubk_char{nullptr}, received_counter{0}, 
    // sent_counter{0}, peer_username{nullptr}{
        this->username.assign(username);
        this->password.assign(password);
        this->IP.assign(IP);
        this->port = port;
        this->socket = socket;

}
User::User(const User &source):
    username(source.username), IP(source.IP), port(source.port), socket(source.socket),
    server_client_key(source.server_client_key), clients_key(source.clients_key), clients_pubk(source.clients_pubk),
    clients_pubk_char(source.clients_pubk_char), client_server_pubk(source.client_server_pubk), 
    client_server_pubk_char(source.client_server_pubk_char), server_pubk(source.server_pubk), server_pubk_char(source.server_pubk_char),
    peer_pubk(source.peer_pubk), peer_pubk_char(source.peer_pubk_char), received_counter(source.received_counter), 
    sent_counter(source.sent_counter), peer_username(source.peer_username), password(source.password)
    {
    
}

//serialize the object
void User::serialize(){
}

bool User::replay_check(bool from_server, uint16_t received_counter){
    bool returned = false;
    if (from_server)
        if (received_counter - this->get_received_counter() != 1){//the difference between them should be always 1
            cerr<< "Replay Attack! This message is discarded!" <<endl;
            return false;
        }
        else {
            this->increment_received_counter();
            return true;
        }
    else{
        if (received_counter - this->get_sent_counter() != 1){//the difference between them should be always 1
            cerr<< "Replay Attack! This message is discarded!" <<endl;
            return false;
        }
        else {
            this->increment_sent_counter();
            return true;
        }
    }
    cerr<< "Error: Problem in replay check!" <<endl;
    return false;
}

void User::clear(){
    this->IP.clear();
    this->port = 0;
    this->socket = 0;
    this->client_server_pubk = nullptr;
    this->clients_pubk = nullptr;
    this->peer_username.clear();
    this->sent_counter = 0;
    this->received_counter = 0;
    this->status = OFFLINE; 
    this->peer_pubk = nullptr;
    this->server_pubk = nullptr;
    this->server_pubk_char = nullptr;
    if(this->peer_pubk_char)
        free(this->peer_pubk_char);
    if(this->clients_pubk_char)
        free(this->clients_pubk_char);
    if(this->clients_key)
        free(this->clients_key);
    if(this->client_server_pubk_char)
        free(client_server_pubk_char);
    if(this->server_client_key)
        free(server_client_key);

}
User::~User(){
    if(this->peer_pubk_char)
        free(this->peer_pubk_char);
    if(this->clients_pubk_char)
        free(this->clients_pubk_char);
    if(this->clients_key)
        free(this->clients_key);
    if(this->client_server_pubk_char)
        free(client_server_pubk_char);    
    if(this->server_client_key)
        free(server_client_key);
}

