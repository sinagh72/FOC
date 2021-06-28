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
    unsigned char* server_client_key; // the key between the server and the client
    unsigned char* clients_key; // the key between two clients
    EVP_PKEY* clients_pubk; // dh pub key for generating a'
    unsigned char * clients_pubk_char; // dh pub key for generating a' in characters
    EVP_PKEY* client_server_pubk; //dh pub key for generating a
    unsigned char * client_server_pubk_char;// dh pub key for generating a in characters
    EVP_PKEY* server_pubk;// dh pub key of the server or g^b
    unsigned char *server_pubk_char;//h pub key of the server or g^b in characters
    EVP_PKEY* peer_pubk;// dh pub key of other peer or g^b'
    unsigned char *peer_pubk_char;// dh pub key of other peer or g^b' in characters
    uint16_t server_counter{0};//server to client counter: #messages that the user has received from the server
    uint16_t client_counter{0};//client to server counter: #messages that the user has sent to the server
    int client_socket;
    string peer_username;//the username of the user that we are communicating with


    
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
    void set_server_client_key(unsigned char * key){
        this->server_client_key = key;
    }
    //set the key between clients
    void set_clients_key(unsigned char * key){
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
    //set public key for the client_client communication 
    void set_clients_pubk(EVP_PKEY*dh_pubk){
        this->clients_pubk = dh_pubk;
    }
    //set public key for the server_client communication 
    void set_clients_pubk_char(unsigned char*dh_pubk_char){
        this->clients_pubk_char = dh_pubk_char;
    }
        //set public key for the client_client communication 
    void set_client_server_pubk_char(unsigned char*dh_pubk_char){
        this->client_server_pubk_char = dh_pubk_char;
    }
    //set public key for the server_client communication 
    void set_client_server_pubk(EVP_PKEY*dh_pubk){
        this->client_server_pubk = dh_pubk;
    }
      //set public key
    void set_peer_pubk(EVP_PKEY*peer_pubk){
        this->peer_pubk = peer_pubk;
    }
     //set public key char
    void set_peer_pubk_char(unsigned char*peer_pubk_char){
        this->peer_pubk_char = peer_pubk_char;
    }
          //set public key
    void set_server_pubk(EVP_PKEY*pubk){
        this->server_pubk = pubk;
    }
     //set public key char
    void set_server_pubk_char(unsigned char*pub_key_char){
        this->server_pubk_char = pub_key_char;
    }
    void set_peer_username(string username){
        this->peer_username = username;
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
    unsigned char * get_server_client_key() const{
        return this->server_client_key;
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
    EVP_PKEY* get_clients_pubk() const{
        return this->clients_pubk;
    }
    // get the public key char
    unsigned char* get_clients_pubk_char() const{
        return this->clients_pubk_char;
    }
     // get the peer public key
    EVP_PKEY* get_peer_pubk() const{
        return this->peer_pubk;
    }
    // get the public key char
    unsigned char* get_pubk_char() const{
        return this->peer_pubk_char;
    }
     // get the peer public key
    EVP_PKEY* get_client_server_pubk() const{
        return this->client_server_pubk;
    }
    // get the peer public key char
    unsigned char* get_client_server_pubk_char() const{
        return this->client_server_pubk_char;
    }
    EVP_PKEY* get_server_pubk() const{
        return this->server_pubk;
    }
    // get the peer public key char
    unsigned char* get_server_pubk_char() const{
        return this->server_pubk_char;
    }
    //get peer username
    string get_peer_username(){
        return this->username;
    }
    //serialize the object
    void serialize();
    //check for replay attack
    bool replay_check(bool from_server, uint16_t received_counter);
    //Destructor
    ~User();
};
#endif