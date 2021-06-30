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
#include <algorithm>

class Message {

public:
    ///TODO:remove **message_buf fom the functions
    static unsigned int send_message_5(char**message_buf, User* my_user, string receiver_username);
    //===================================================================================================================  
    static int handle_message_5(char * message, size_t message_len, User* sender, vector<User>users);
    //===================================================================================================================  
    ///TODO:remove **message_buf fom the functions
    static unsigned int send_message_6(char**message_buf, User* sender, vector<User>users);
    //===================================================================================================================
    static int handle_message_6(char * message, size_t message_len, User* my_user);
    //=================================================================================================================== 
    ///TODO:remove **message_buf fom the functions 
    static unsigned int send_message_7(char**message_buf, User* my_user);
    //=================================================================================================================== 
    ///TODO:remove **clients_ciphertext fom the functions
    static int handle_message_7(unsigned char ** clients_ciphertext, char * message, size_t message_len, User* sender, vector<User>users);
    //=================================================================================================================== 
    ///TODO:remove **message_buf fom the functions
    static unsigned int send_message_8(char**message_buf, User* sender, unsigned char * clients_ciphertext, int clients_ciphertext_len, vector<User>users);
    //=================================================================================================================== 
    static  int handle_message_8(char * message, size_t message_len, User* my_user);
    //===================================================================================================================
    ///TODO:remove **message_buf fom the functions     
    /**
     * create a message of type 9
     * @param my_user the User of that is sending the message!
     */
    static unsigned int send_message_9(char**message_buf, User* my_user);
    //===================================================================================================================
    ///TODO:remove **message_buf fom the functions
    static int handle_message_9(char**message_buf, char * message, User* sender, vector<User>users);
    //===================================================================================================================
    ///TODO:remove **message_buf fom the functions
    static unsigned int send_message_10(char**message_buf, User* sender, string clients_ciphertext, vector<User>users);
    //===================================================================================================================
    ///TODO:remove **message_buf fom the functions
    static int handle_message_10(char**message_buf, char* message, User* my_user);

    
};


#endif
