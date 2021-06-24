//
// Created by lorenzo on 24/06/21.
//
#include "Message.h"


int Message::create_message_0(char *username, char **buffer) {
    EVP_PKEY* pubkey= nullptr;
    Security::generate_dh_pubk(pubkey);
    *buffer=(char*) malloc(10);
    return 2;
}

void Message::handle_message_0(char *buffer, int client_socket, char *ip, uint16_t port, vector <User> online_users) {

}