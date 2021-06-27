//
// Created by lorenzo on 24/06/21.
//

#ifndef APP_MESSAGE_H
#define APP_MESSAGE_H
#include <vector>
#include "user.h"
#include "Security.h"
#include <stdint.h>
#include <cstring>
#include <openssl/conf.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

using namespace std;
class Message {

public:
    /**
     * create a message of type 0
     * @param username is the username of the user that want to sent that message
     *        to start communicating with the server
     * @param buffer is a pointer to pointer that will point to a buffer allocated inside the function
     * @return the number of byte of the buffer
     */
    static unsigned int create_message_0(char* username, char **buffer);

    /**
     * handle function for message type 0
     * @param buffer is the message buffer
     * @param client_socket is the socket with the client
     * @param ip : ip address of the client
     * @param port :port of the client
     * @param online_users : vector of Users that are online
     */
    static void handle_message_0(char* buffer, int client_socket, char* ip, uint16_t port, vector<User> online_users);
};


#endif
