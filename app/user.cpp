#include "user.h"


//methods
//set the identifier
User::User(string identifier_val, string IP_val, string port_val):
    IP{IP_val},identifier{identifier_val},port{port_val},key{nullptr}, server_counter{0}, client_counter{0}{
}
User::User(const User &source):
    IP(source.IP),identifier(source.identifier),port(source.port),key(source.key), 
    server_counter(source.server_counter), client_counter(source.client_counter){
    
}

//serialize the object
void User::serialize(){
    

}

