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

    // message 3
    static unsigned int send_message_3(char** msg_buf, User* my_user);
    static int parse_message_3(char * message, size_t message_len, User* sender, vector<User>users);

    // message 4
    static unsigned int send_message_4(char** msg_buf, vector<User> * act_usr, User * dest_user);
    static int parse_message_4(char * message, size_t message_len, User* sender, vector<User>users);
};