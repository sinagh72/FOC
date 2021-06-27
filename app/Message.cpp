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

    string ip_str(ip);
    //extract the username
    string username(buffer+1);

    //extract the DH serialized pubkey
    string dh_pubkey_peer(buffer+32);


    //find the user RSA pubkey
    FILE* pubkey_file = fopen("./users/"+username+"/rsa_pubkey.pem", "r");
    if(!pubkey_file) {
        printf("User %s not registered", username);
        return;
    }
    EVP_PKEY* evpPkey;
    evpPkey= PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
    if(!evpPkey) {
        printf("Error: pubkey of user %s not loaded correctly", username);
        return;
    }

    User *client = new User(username, ip, (unsigned short) port, evpPkey, client_socket);
    client->set_status(CONNECTING);
    online_users.insert(online_users.begin(), client);

    //load server certificate from file and serialize it
    FILE* cert_file = fopen("./certificates/ChatApp_cert.pem", "r");
    if(!cert_file)  {
        printf("Error opening server certificate file");
        return;
    }
    X509* cert;
    cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    if(!cert) {
        printf("Error loading server certificate")
        return;
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if(PEM_write_bio_X509(bio, cert)==1) {
        printf("Error serializing the certificate");
        return;
    }

    char* certificate_serialized= nullptr;
    long cert_size= BIO_get_mem_data(bio, &certificate_serialized);

    BIO_free(bio);


    //server DH pubkey serialization
    long dh_pubkey_server_size;
    char* dh_pubkey_server_serialized = nullptr;
    EVP_PKEY *dh_pubkey_server = nullptr;
    //generate our own DH pubkey
    Security::generate_dh_pubk(&pubkey);
    if (PEM_write_bio_PUBKEY(bio, pubkey)==0) {
        printf("Error establishing session with client: DH serialization problem");

    }
    dh_pubkey_server_size = BIO_get_mem_data(bio, &dh_pubkey_server_serialized);

    



}