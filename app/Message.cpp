//
// Created by lorenzo on 24/06/21.
//
#include "Message.h"


unsigned int Message::create_message_0(char *username, char **buffer) {
    EVP_PKEY* pubkey= nullptr;
    BIO* bio= BIO_new(BIO_s_mem());
    long int pubkey_serialized_len;
    char* serialized_pubkey = nullptr;

    Security::generate_dh_pubk(&pubkey);
    if (PEM_write_bio_PUBKEY(bio, pubkey)==0) {
        printf("Error establishing session with server: DH serialization problem");

    }
    pubkey_serialized_len = BIO_get_mem_data(bio, &serialized_pubkey);
    //printf("%s\n", serialized_pubkey);
    //printf("%ld\n", strlen(serialized_pubkey));

    unsigned    int message_len= pubkey_serialized_len + 32 +1;
    *buffer=(char*) malloc(message_len);
    memcpy(*buffer+32+1, serialized_pubkey, pubkey_serialized_len);
    memset(*buffer, 0, 1);
    if(strlen(username)+1>=32) {
        printf("Error establishing session with server: username too long (>31 char)");
    }
    memcpy(*buffer+1, username, strlen(username));

    EVP_PKEY_free(pubkey);
    BIO_free(bio);
    return message_len;
}

void Message::handle_message_0(char *buffer, int client_socket, char *ip, uint16_t port, vector <User> online_users) {

}