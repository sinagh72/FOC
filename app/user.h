#ifndef APP_USER_H
#define APP_USER_H

#include "Security.h"
#include <cstddef>

using namespace std;


enum STATUS {CONNECTING, ONLINE, CHATTING, RTT, OFFLINE};

class User{
private:
    STATUS status;
    string username;
    string IP;
    uint16_t port;
    string password;
    int socket;
    unsigned char* server_client_key{nullptr}; // the key between the server and the client
    unsigned char* clients_key{nullptr}; // the key between two clients
    size_t server_client_key_len = 0;
    size_t clients_key_len = 0;
    EVP_PKEY* clients_pubk{nullptr}; // dh pub key for generating a'
    unsigned char * clients_pubk_char{nullptr}; // dh pub key for generating a' in characters
    EVP_PKEY* client_server_pubk{nullptr}; //dh pub key for generating a
    unsigned char * client_server_pubk_char{nullptr};// dh pub key for generating a in characters
    EVP_PKEY* server_pubk{nullptr};// dh pub key of the server or g^b
    unsigned char *server_pubk_char{nullptr};//h pub key of the server or g^b in characters
    EVP_PKEY* peer_pubk{nullptr};// dh pub key of other peer or g^b'
    unsigned char *peer_pubk_char{nullptr};// dh pub key of other peer or g^b' in characters
    uint16_t server_counter{0};//server to client counter: #messages that the user has received from the server
    uint16_t client_counter{0};//client to server counter: #messages that the user has send to the server
    uint16_t send_counter{0};//#messages that the user has received from the other user
    uint16_t receive_counter{0};//#messages that the user has send to the other user
    string peer_username;//the username of the user that we are communicating with


    
public:
    //constructor
    User();
    User(string username, string password, string IP, uint16_t port, int socket);
    //copyructor
    User(const User &source);
    //methods
    //set the username

    void set_status(STATUS status) {
        this->status = status;
    }

    void set_username(string username){
        this->username.assign(username);
    }
    //set the ip
    void set_IP(string IP){
        this->IP.assign(IP);
    }
    //set the port
    void set_port(uint16_t port){
        this->port = port;
    }
    //set the key between client and server
    void set_server_client_key(unsigned char * key, size_t key_len){
        if(!key){
            if(this->server_client_key != nullptr){
                #pragma optimize("", off)
                memset(this->server_client_key, 0, server_client_key_len);
                #pragma optimize("", on)
                free(this->server_client_key);
            } 
            this->server_client_key = nullptr;
            return;
        }
        if(!this->server_client_key){
            this->server_client_key = (unsigned char*)malloc(key_len);
        }
        this->server_client_key_len = key_len;
        memcpy(this->server_client_key, key, key_len);
    }
    //set the key between clients
    void set_clients_key(unsigned char * key, size_t key_len){
        if(!key){
            if(this->clients_key != nullptr){
                #pragma optimize("", off)
                memset(this->clients_key, 0, clients_key_len);
                #pragma optimize("", on)
                free(this->clients_key);
            }
            this->clients_key = nullptr;
            return;
        }
        if(!this->clients_key){
            this->clients_key = (unsigned char*)malloc(key_len);
        }
        this->clients_key_len = key_len;
        memcpy(this->clients_key, key, key_len);
    }

    //set server socket with that client (user)
    void set_socket(int socket) {
        this->socket = socket;
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
     //increment the send counter
    uint16_t increment_send_counter(){
        this->send_counter++;
        return this->send_counter;
    }
    //increment the receive counter
    uint16_t increment_receive_counter(){
        this->receive_counter++;
        return receive_counter;
    }
    //set the send counter to zero
    void clear_send_counter(){
         this->send_counter = 0;
    }
    //set the receive counter to zero
    void clear_receive_counter(){
        this->receive_counter = 0;
    }
    //set public key for the client_client communication 
    void set_clients_pubk(EVP_PKEY*dh_pubk){
        this->clients_pubk = dh_pubk;
    }
    //set public key for the server_client communication 
    void set_clients_pubk_char(unsigned char*dh_pubk_char){
        if(!dh_pubk_char){
            if(this->clients_pubk_char != nullptr) free(this->clients_pubk_char);
                clients_pubk_char = nullptr;
            return;
        }

        if(!this->clients_pubk_char){
            this->clients_pubk_char = (unsigned char*)malloc(DH_PUBK_LENGTH);
        }
        memcpy(this->clients_pubk_char,dh_pubk_char,DH_PUBK_LENGTH);
    }
        //set public key for the client_client communication 
    void set_client_server_pubk_char(unsigned char*dh_pubk_char){
        if(!dh_pubk_char){
            if(this->client_server_pubk_char != nullptr) free(this->client_server_pubk_char);
                client_server_pubk_char = nullptr;

            return;
        }

        if(!this->client_server_pubk_char){
            this->client_server_pubk_char = (unsigned char*)malloc(DH_PUBK_LENGTH);
        }
        memcpy(this->client_server_pubk_char, dh_pubk_char, DH_PUBK_LENGTH);
    }
    //set public key for the server_client communication 
    void set_client_server_pubk(EVP_PKEY*dh_pubk){
        // RSA *rsa = EVP_PKEY_get1_RSA(dh_pubk); // Get the underlying RSA key
        // RSA *dup_rsa = RSAPrivateKey_dup(rsa); // Duplicate the RSA key
        // RSA_free(rsa); // Decrement reference count
        // EVP_PKEY_set1_RSA(this->client_server_pubk, dup_rsa);
        this->client_server_pubk = dh_pubk;

    }
      //set public key
    void set_peer_pubk(EVP_PKEY*peer_pubk){
        this->peer_pubk = peer_pubk;
    }
     //set public key char
    void set_peer_pubk_char(unsigned char*peer_pubk_char){
        if(!peer_pubk_char){
            if(!this->peer_pubk_char) 
                free(this->peer_pubk_char);
            return;
        }
        if(!this->peer_pubk_char){
            this->peer_pubk_char = (unsigned char*)malloc(DH_PUBK_LENGTH);
        }
        memcpy(this->peer_pubk_char,peer_pubk_char,DH_PUBK_LENGTH);
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
        if(username.empty()){
            this->peer_username.clear();
        }else
            this->peer_username.assign(username);
    }

    void set_password(string password){
        this->password.assign(password);
        
    }
    //return the status
    STATUS get_status() {
        return this->status;
    }

    //return the username
    string get_username(){
        return this->username;
    }
    //return the ip
    string get_IP(){
        return this->IP;
    }
    //return the port
    uint16_t get_port(){
        return this->port;
    }
    //return the key between client and server
    unsigned char * get_server_client_key(){
        return this->server_client_key;
    }
    //return the key between clients
    unsigned char * get_clients_key(){
        return this->clients_key;
    }
    //return the server counter
    uint16_t get_server_counter(){
        return this->server_counter;
    }
    //return the client counter
    uint16_t get_client_counter(){
        return this->client_counter;
    }
    //return the send counter
    uint16_t get_send_counter(){
        return this->send_counter;
    }
    //return the receive counter
    uint16_t get_receive_counter(){
        return this->receive_counter;
    }
    // get the client socket
    int get_socket(){
        return this->socket;
    }
    // get the public key
    EVP_PKEY* get_clients_pubk(){
        return this->clients_pubk;
    }
    // get the public key char
    unsigned char* get_clients_pubk_char(){
        return this->clients_pubk_char;
    }
     // get the peer public key
    EVP_PKEY* get_peer_pubk(){
        return this->peer_pubk;
    }
    // get the public key char
    unsigned char* get_peer_pubk_char(){
        return this->peer_pubk_char;
    }
     // get the peer public key
    EVP_PKEY* get_client_server_pubk(){
        return this->client_server_pubk;
    }
    // get the peer public key char
    unsigned char* get_client_server_pubk_char(){
        return this->client_server_pubk_char;
    }
    EVP_PKEY* get_server_pubk(){
        return this->server_pubk;
    }
    // get the peer public key char
    unsigned char* get_server_pubk_char(){
        return this->server_pubk_char;
    }
    //get peer username
    string get_peer_username(){
        return this->peer_username;
    }
    string get_password(){
        return this->password;
        
    }
    //check for replay attack
    bool replay_check(bool from_server, uint16_t server_counter);
    //this method is called when the user has logged out in order to clear any data inside the client!
    void clear();
    //destructor
    ~User();
};
#endif