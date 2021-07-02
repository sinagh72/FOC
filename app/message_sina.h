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
    static int handle_message_5(char * message, size_t message_len, User* sender);
    //===================================================================================================================  
    ///TODO:remove **message_buf fom the functions
    static unsigned int send_message_6(char**message_buf, User* sender, User* receiver);
    //===================================================================================================================
    static int handle_message_6(char * message, size_t message_len, User* my_user);
    //=================================================================================================================== 
    ///TODO:remove **message_buf fom the functions 
    static unsigned int send_message_7(char**message_buf, User* my_user);
    //=================================================================================================================== 
    ///TODO:remove **clients_ciphertext fom the functions
    static int handle_message_7(unsigned char ** clients_ciphertext, char * message, size_t message_len, User* sender);
    //=================================================================================================================== 
    ///TODO:remove **message_buf fom the functions
    static unsigned int send_message_8(char**message_buf, User* sender, User* receiver, unsigned char * clients_ciphertext, int clients_ciphertext_len);
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
    static int handle_message_9(unsigned char ** clients_ciphertext, char * message, size_t message_len, User* sender);
    //===================================================================================================================
    ///TODO:remove **message_buf fom the functions
    static unsigned int send_message_10(char**message_buf, User* sender, User* receiver, unsigned char * clients_ciphertext, int clients_ciphertext_len);
    //===================================================================================================================
    ///TODO:remove **message_buf fom the functions
    static int handle_message_10(char * message, size_t message_len, User* my_user);
    //===================================================================================================================
    ///TODO:remove **message_buf fom the functions
    static unsigned int send_message_11(char**message_buf, User* my_user);
    //===================================================================================================================
    static int handle_message_11(char * message, size_t message_len, User* sender);
    //===================================================================================================================
    static unsigned int send_message_12(char**message_buf, User* sender, User* receiver);
    //===================================================================================================================
    static int handle_message_12(char* message, size_t message_len, User*my_user);
    //=================================================================================================================== 
    ///TODO:remove **message_buf fom the functions 
    static unsigned int send_message_13(char**message_buf, unsigned char* message, size_t message_len, User* my_user);
    //=================================================================================================================== 
    ///TODO:remove **message_buf fom the functions 
    static int handle_message_13(unsigned char ** clients_ciphertext, char * message, size_t message_len, User* sender);
    //=================================================================================================================== 
    ///TODO:remove **message_buf fom the functions 
    static unsigned int send_message_14(char**message_buf, User* sender, User* receiver, unsigned char * clients_ciphertext, int clients_ciphertext_len);
    //=================================================================================================================== 
    static int handle_message_14(char * message, size_t message_len, User* my_user);
    //===================================================================================================================
    ///TODO:remove **message_buf fom the functions
    static unsigned int send_message_17(char**message_buf, User* my_user);
    //===================================================================================================================
    static int handle_message_17(char * message, size_t message_len, User* sender);



    
};


#endif
