#ifndef _CHATTING_HPP_
#define _CHATTING_HPP_

#include <string>


using namespace std;
class User{
private:
    string identifier;
    string IP;
    string port;
    unsigned char* key;
    unsigned short server_counter;
    unsigned short client_counter;
    
public:
    //constructor
    User(string identifier, string IP, string port);
    //copy constructor
    User(const User &source);
    //methods
    //set the identifier
    void set_identifier(string identifier){
        this->identifier = identifier;
    }
    //set the ip
    void set_IP(string IP){
        this->IP = IP;
    }
    //set the port
    void set_port(string port){
        this->port = port;
    }
    //set the key
    void set_key(unsigned char * key){
        this->key = key;
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
    //return the identifier
    string get_identifier() const{
        return this->identifier;
    }
    //return the ip
    string get_IP() const{
        return this->IP;
    }
    //return the port
    string get_port() const{
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
    //serialize the object
    void serialize();
    //Destructor
    ~User();
};
#endif