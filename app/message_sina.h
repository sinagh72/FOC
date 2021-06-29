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
    static unsigned int send_message_5(User* my_user, string receiver_username);
    //===================================================================================================================  
    static int parse_message_5(char * message, User* sender, vector<User>users);
    //===================================================================================================================  
    static unsigned int send_message_6(User* sender, string receiver_username, vector<User>users);
    //===================================================================================================================  
    static int parse_message_6(char * message, User* my_user);
    //===================================================================================================================  
    static unsigned int send_message_7(User* my_user);
    //=================================================================================================================== 
    static int parse_message_7(char * message, User* sender, vector<User>users);
    //=================================================================================================================== 
    static unsigned int send_message_8(User* sender, string clients_ciphertext, vector<User>users);
    //===================================================================================================================   
    static  int parse_message_8(char * message, User* my_user);
    //===================================================================================================================     
    /**
     * create a message of type 9
     * @param my_user the User of that is sending the message!
     */
    static unsigned int send_message_9(User* my_user);
    //===================================================================================================================
    static int parse_message_9(char * message, User* sender, vector<User>users);
    //===================================================================================================================
    static unsigned int send_message_10(User* sender, string clients_ciphertext, vector<User>users);
    //===================================================================================================================
    static int parse_message_10(char* message, User* my_user);

    
};


#endif
