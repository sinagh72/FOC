#include "user.h"


//methods
//set the username
User::User(string username_val, string IP_val, unsigned short port_val):
    IP{IP_val},username{username_val},port{port_val},key{nullptr}, server_counter{0}, client_counter{0}, client_socket{0}{
}
User::User(const User &source):
    username(source.username),IP(source.IP),port(source.port),key(source.key), 
    server_counter(source.server_counter), client_counter(source.client_counter), client_socket(source.client_socket){
    
}

//serialize the object
void User::serialize(){
    

}

