#ifndef APP_USER_H
#define APP_USER_H

#include <cstdint>
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
    unsigned char* client_server_key; // the key between the server and the client
    unsigned char* clients_key; // the key between two clients
    EVP_PKEY* dh_pubk;
    unsigned char * dh_pubk_char;
    EVP_PKEY* peer_dh_pubk;
    unsigned char *peer_dh_pubk_char;
    uint16_t server_counter{0};//server to client counter: #messages that the user has received from the server
    uint16_t client_counter{0};//client to server counter: #messages that the user has sent to the server
    int client_socket;


    
public:
    //constructor
    User(string username, string IP, unsigned short port, EVP_PKEY* dh_pubkey, int client_socket);
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
    //set the key between client and server
    void set_client_server_key(unsigned char * key){
        this->client_server_key = key;
    }
    //set the key between clients
    void set_clientskey(unsigned char * key){
        this->clients_key = key;
    }

    //set server socket with that client (user)
    void set_client_socket(int socket) {
        this->client_socket = socket;
    }

    //increment the server counter
    uint16_t increment_server_counter(){
        this->server_counter++;
        return this->server_counter;
    }
    //increment the client counter
    uint16_t increment_client_counter(){
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
    void set_dh_pubk(EVP_PKEY*dh_pubk){
        this->dh_pubk = dh_pubk;
    }
      //set public key
    void set_peer_dh_pubk(EVP_PKEY*peer_dh_pubk){
        this->peer_dh_pubk = peer_dh_pubk;
    }
    //set public key char
    void set_dh_pubk_char(unsigned char*dh_pubk_char){
        this->dh_pubk_char = dh_pubk_char;
    }
     //set public key char
    void set_peer_dh_pubk_char(unsigned char*peer_dh_pubk_char){
        this->peer_dh_pubk_char = peer_dh_pubk_char;
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
    //return the key between client and server
    unsigned char * get_client_server_key() const{
        return this->client_server_key;
    }
    //return the key between clients
    unsigned char * get_clients_key() const{
        return this->clients_key;
    }
    //return the server counter
    uint16_t get_server_counter() const{
        return this->server_counter;
    }
    //return the client counter
    uint16_t get_client_coutner() const{
        return this->client_counter;
    }
    // get the client socket
    int get_client_socket() const{
        return this->client_socket;
    }
    // get the public key
    EVP_PKEY* get_dh_pubk() const{
        return this->dh_pubk;
    }
    // get the public key char
    unsigned char* get_dh_pubk_char() const{
        return this->dh_pubk_char;
    }
     // get the peer public key
    EVP_PKEY* get_peer_dh_pubk() const{
        return this->peer_dh_pubk;
    }
    // get the peer public key char
    unsigned char* get_peer_dh_pubk_char() const{
        return this->peer_dh_pubk_char;
    }
    //serialize the object
    void serialize();
    //check for replay attack
    bool replay_check(bool from_server, uint16_t received_counter);
    //Destructor
    ~User();
};
#endif