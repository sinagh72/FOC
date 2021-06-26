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
     * create a message of type 0
     * @param username is the username of the user that want to sent that message
     *        to start communicating with the server
     * @param buffer is a pointer to pointer that will point to a buffer allocated inside the function
     * @return the number of byte of the buffer
     */
    static unsigned int create_message_9(unsigned short client_to_server_counter, 
                                        EVP_PKEY* my_dh_pubk, char* my_dh_pubk_char,
                                        EVP_PKEY* peers_dh_pubk, char* peers_dh_pubk_char,
                                        char* source_username, char* dest_username,
                                        string my_username,
                                        unsigned char* clinets_key, unsigned char* server_client_key);
    //===================================================================================================================
    static unsigned int create_message_10(char* username, char **buffer);
};


#endif
