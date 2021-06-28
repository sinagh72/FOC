#ifndef APP_MESSAGE_SINA_H
#define APP_MESSAGE_SINA_H
#include <vector>
#include "user.h"
#include "Security.h"
#include <stdint.h>
#include <cstring>
#include <openssl/conf.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/pem.h>


class Message {

public:
    static unsigned int send_message_5(User* my_user, string dest_username);
    //===================================================================================================================  
    static int parse_message_5(char * message, string sender, vector<User>users);
    //===================================================================================================================  
    static unsigned int send_message_6(User* sender_user, string dest_username, vector<User>users);
    //===================================================================================================================  
    static int parse_message_6(char * message, User* my_user);
    //===================================================================================================================  
    /**
     * create a message of type 9
     * @param my_user the sender User
     * @param dest_username destination username
     * @param dest_dh_pubk the dh pubkey of the receiver of the message
     * @param dest_dh_pubk_char the dh pubkey of the receiver of the message type char*
     * @param clinets_key the established key between two clients
     * @param server_client_key the established key between server and the sender
     * @return the number of byte of the buffer
     */
    static unsigned int send_message_9(User* my_user,
                                    string dest_username,
                                    EVP_PKEY* dest_dh_pubk, char* dest_dh_pubk_char,
                                    unsigned char* clinets_key, unsigned char* server_client_key);
    //===================================================================================================================
    static int parse_message_9(char* message, 
                                    unsigned char* sender_server_key, 
                                    unsigned char* receiver_server_key, vector<User>users);
    //===================================================================================================================
    static unsigned int send_message_10(string source_username, string dest_username, string forwarding_message,
                                    unsigned char* key, vector<User>users);
    //===================================================================================================================
    static int parse_message_10(char* message, User* my_user);

    
};


#endif
