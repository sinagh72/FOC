#include "user.h"


//constructors
User::User(){
    
}
User::User(string username, string IP, unsigned short port, int client_socket):
    username{username}, IP{IP}, port{port}, client_socket{client_socket}{
}
User::User(const User &source):
    username(source.username),IP(source.IP),port(source.port),client_socket(source.client_socket){
    
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

