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
    static unsigned int send_message_3(char ** msg_buf, User * my_user);
    static int handle_message_3(char * msg_buf, size_t msg_len, User * my_user);

    // message 4
    static unsigned int send_message_4(char ** msg_buf, vector<User> * act_usr, User * dest_user);
    static int handle_message_4(char * msg_buf, size_t msg_len, User * dest_user);
};