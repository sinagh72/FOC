#include "user.h"
#include <openssl/ossl_typ.h>

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
// User::User(const User &source):
//     username(source.username), IP(source.IP), port(source.port), socket(source.socket),
//     clients_key(source.clients_key), clients_pubk(source.clients_pubk),
//     clients_pubk_char(source.clients_pubk_char), client_server_pubk(source.client_server_pubk), 
//     client_server_pubk_char(source.client_server_pubk_char), server_pubk(source.server_pubk), server_pubk_char(source.server_pubk_char),
//     peer_pubk(source.peer_pubk), peer_pubk_char(source.peer_pubk_char), received_counter(source.received_counter), 
//     sent_counter(source.sent_counter), peer_username(source.peer_username), password(source.password), 
//     server_client_key(source.server_client_key)
//     {
//         this->set_server_client_key(source.server_client_key, 16);
    
// }

User::User(const User &source){
    //===================copy called
    cout <<"=========================================copy called" <<endl;
    this->username.assign(source.username);
    this->password.assign(source.password); 
    this->IP.assign(source.IP);
    this->port = source.port;
    this->socket = source.socket;
    this->set_clients_key(source.clients_key, 16);
    //this->set_server_client_key(source.server_client_key, 16);
    this->set_clients_pubk(source.clients_pubk);
    this->set_clients_pubk_char(source.clients_pubk_char);
    this->set_client_server_pubk(source.client_server_pubk);
    this->set_client_server_pubk_char(source.client_server_pubk_char);
    this->set_server_pubk(source.server_pubk);
    this->set_server_pubk_char(source.server_pubk_char);
    this->set_peer_pubk(source.peer_pubk);
    this->set_peer_pubk_char(source.peer_pubk_char);
    this->received_counter = source.received_counter;
    this->sent_counter = source.sent_counter;
    this->peer_username.assign(source.peer_username);
    this->status = source.status;
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
    set_peer_pubk_char(nullptr);
    set_clients_pubk_char(nullptr);
    set_client_server_pubk_char(nullptr);
    set_clients_key(nullptr, 0);
    set_server_client_key(nullptr, 0);

}
User::~User(){
    set_peer_pubk_char(nullptr);
    set_clients_pubk_char(nullptr);
    set_client_server_pubk_char(nullptr);
    set_clients_key(nullptr, 0);
    set_server_client_key(nullptr, 0); 
}

