#ifndef APP_USER_H
#define APP_USER_H

#include <string>


using namespace std;
class User{
private:
    string username;
    string IP;
    unsigned short port;
    unsigned char* key;
    unsigned short server_counter;
    unsigned short client_counter;
    int client_socket;
    
public:
    //constructor
    User(string username, string IP, unsigned short port);
    //copy constructor
    User(const User &source);
    //methods
    //set the username
    void set_username(string username){
        this->username = username;
    }
    //set the ip
    void set_IP(string IP){
        this->IP = IP;
    }
    //set the port
    void set_port(unsigned short port){
        this->port = port;
    }
    //set the key
    void set_key(unsigned char * key){
        this->key = key;
    }

    //set server socket with that client (user)
    void set_client_socket(int socket) {
        this->client_socket = socket;
    }

    //increment the server counter
    unsigned short increment_server_counter(){
        this->server_counter++;
        return this->server_counter;
    }
    //increment the client counter
    unsigned short increment_client_counter(){
        this->client_counter++;
        return client_counter;
    }
    //set the client counter to zero
    void clear_client_counter(){
         this->client_counter = 0;
    }
    //ser the server counter to zero
    void clear_server_counter(){
        this->server_counter = 0;
    }
    //return the username
    string get_username() const{
        return this->username;
    }
    //return the ip
    string get_IP() const{
        return this->IP;
    }
    //return the port
    unsigned short get_port() const{
        return this->port;
    }
    //return the key
    unsigned char * get_key() const{
        return this->key;
    }
    //return the server counter
    unsigned short get_server_counter() const{
        return this->server_counter;
    }
    //return the client counter
    unsigned short get_client_coutner() const{
        return this->client_counter;
    }
    // get the client socket
    int get_client_socket() const{
        return this->client_socket;
    }
    //serialize the object
    void serialize();
    //Destructor
    ~User();
};
#endif