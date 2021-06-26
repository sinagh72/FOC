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
    /**
     * create a message of type 9
     * @param client_to_server_counter the counter from the client to the server such as counterAs
     * @param my_dh_pubk the dh pubkey of the sender of the message
     * @param my_dh_pubk_char the dh pubkey of the sender of the message type char*
     * @param peers_dh_pubk the dh pubkey of the receiver of the message 
     * @param peers_dh_pubk_char the dh pubkey of the receiver of the message type char*
     * @param dest_username the username of the receiver of the message
     * @param my_username the username of the sender of the message
     * @param clinets_key the established session key between two cilents
     * @param server_client_key the established session key between the server and the client
     * @return the number of byte of the buffer
     */
    static unsigned int send_message_9(User* my_user,
                                    string dest_username,
                                    EVP_PKEY* dest_dh_pubk, char* dest_dh_pubk_char,
                                    unsigned char* clinets_key, unsigned char* server_client_key);
    //===================================================================================================================
    static unsigned int parse_message_9(char* message, unsigned char* sender_key, unsigned char* receiver_key, vector<User>users);
    //===================================================================================================================
    static unsigned int send_message_10(string source_username, string dest_username, string forwarding_message,
                                    unsigned char* key, vector<User>users);
};


#endif
