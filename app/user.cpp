#include "user.h"


//methods
//set the username
User::User(tring username, string IP, unsigned short port, EVP_PKEY* pubkey, int client_socket):
    IP{IP},username{username},port{port},pub_key{pubkey}, server_counter{0}, client_counter{0}, client_socket{client_socket}{
}
User::User(const User &source):
    username(source.username),IP(source.IP),port(source.port),key(source.key), 
    server_counter(source.server_counter), client_counter(source.client_counter), client_socket(source.client_socket){
    
}

//serialize the object
void User::serialize(){
    

}

