#include "user.h"


//methods
//set the username
User::User(string username, string IP, unsigned short port, EVP_PKEY* dh_pubk, int client_socket):
    IP{IP},username{username},port{port},dh_pubk{dh_pubk}, server_counter{0}, client_counter{0}, client_socket{client_socket}{
        BIO *bio{nullptr};
        Security::EVP_PKEY_to_chars(bio, dh_pubk, &this->dh_pubk_char);
}
User::User(const User &source):
    username(source.username),IP(source.IP),port(source.port),dh_pubk(source.dh_pubk), 
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

