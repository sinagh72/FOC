#include "user.h"


//methods
//set the username
User::User(string username, string IP, unsigned short port, EVP_PKEY* pubkey, int client_socket):
    IP{IP},username{username},port{port},pub_key{pubkey}, server_counter{0}, client_counter{0}, client_socket{client_socket}{
        this->pub_key_char = Security::EVP_PKEY_to_chars(pubkey);
}
User::User(const User &source):
    username(source.username),IP(source.IP),port(source.port),pub_key(source.pub_key), 
    server_counter(source.server_counter), client_counter(source.client_counter), client_socket(source.client_socket){
    
}

//serialize the object
void User::serialize(){
}

bool User::replay_check(bool from_server, unsigned short received_counter){
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

