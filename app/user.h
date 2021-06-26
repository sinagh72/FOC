#ifndef APP_USER_H
#define APP_USER_H

#include <string>
#include <openssl/evp.h>
#include <iostream>
#include "Security.h"

using namespace std;


enum STATUS {CONNECTING, ONLINE, CHATTING};

class User{
private:
    STATUS status;
    string username;
    string IP;
    unsigned short port;
    unsigned char* sim_key;
    EVP_PKEY* pub_key;
    char * pub_key_char;
    unsigned short server_counter{0};//server to client counter: #messages that the user has received from the server
    unsigned short client_counter{0};//client to server counter: #messages that the user has sent to the server
    int client_socket;


    
public:
    //constructor
    User(string username, string IP, unsigned short port, EVP_PKEY* pubkey, int client_socket);
    //copy constructor
    User(const User &source);
    //methods
    //set the username

    void set_status(STATUS status) {
        this->status = status;
    }

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
        this->sim_key = key;
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
    //set the server counter to zero
    void clear_server_counter(){
        this->server_counter = 0;
    }
    //set public key
    void set_pub_key(EVP_PKEY*pub_key){
        this->pub_key = pub_key;
    }
    //set public key char
    void set_pub_key_char(char*pub_key_char){
        this->pub_key_char = pub_key_char;
    }

    //return the status
    STATUS get_status() {
        return this->status;
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
        return this->sim_key;
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
    // get the public key
    EVP_PKEY* get_pub_key() const{
        return this->pub_key;
    }
    // get the public key char
    char* get_pub_key_char() const{
        return this->pub_key_char;
    }
    //serialize the object
    void serialize();
    //check for replay attack
    bool replay_check(bool from_server, unsigned short received_counter);
    //Destructor
    ~User();
};
#endif