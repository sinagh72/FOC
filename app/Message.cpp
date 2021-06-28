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
        fclose(pubkey_file);
        return;
    }
    fclose(pubkey_file);

    User *client = new User(username, ip, port, evpPkey, client_socket);
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
        printf("Error loading server certificate");
        fclose(cert_file);
        return;
    }
    fclose(cert_file);
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
    bio= BIO_new(BIO_s_mem());
    //generate our own DH pubkey
    Security::generate_dh_pubk(&dh_pubkey_server);
    if (PEM_write_bio_PUBKEY(bio, dh_pubkey_server)==0) {
        printf("Error establishing session with client: DH serialization problem");

    }
    dh_pubkey_server_size = BIO_get_mem_data(bio, &dh_pubkey_server_serialized);
    BIO_free(bio);
    //concatenate and sign DH pubkey
    char* dh_param_to_sign =(char*) malloc(dh_pubkey_server_size+dh_pubkey_peer.length()+1);
    if(!dh_param_to_sign) {

    }
    dh_param_to_sign[0] = '\0';
    strcat(dh_param_to_sign, dh_pubkey_peer.c_str());
    strcat(dh_param_to_sign, dh_pubkey_server);

    char* signature = nullptr;
    int signature_len = Security::signature("./users/"+username+"/rsa_privkey.pem", dh_param_to_sign,
                                            dh_pubkey_server_size+dh_pubkey_peer.length()+1, &signature);
    free(dh_param_to_sign);


    BIO* deserialize_bio = BIO_new(BIO_s_mem());
    BIO_write(deserialize_bio, dh_pubkey_peer.c_str(), dh_pubkey_peer.length()+1); //verificare il +1
    EVP_PKEY *peer_pubk = PEM_read_PUBKEY(deserialize_bio, NULL, NULL, NULL);
    BIO_free(deserialize_bio);

    char* shared_key= nullptr;
    Security::generate_dh_key(dh_pubkey_server, peer_pubk, &shared_key);
    client->set_server_client_key(shared_key);
    EVP_PKEY_free(dh_pubkey_server);
    EVP_PKEY_free(peer_pubk);

    //generate IV
    char* iv= nullptr;
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)) {
        cerr<<"Error generating IV for message type 1";
        return;
    }


    int aad_len = 1 + 2 + cert_size + dh_pubkey_server_size+Security::GCM_IV_LEN;
    char* aad = (char*)malloc(aad_len);
    if(!aad) {
        cerr<<"Error during space allocation for AAD";
        return;
    }

    memset(aad, 1, 1);
    uint16_t* counter_pointer= aad+1;
    *counter_pointer = client->get_server_counter();
    client->increment_server_counter();
    memcpy(aad+3, iv, Security::GCM_IV_LEN);
    strncpy(aad+3+Security::GCM_IV_LEN, certificate_serialized, cert_size);
    strncpy(aad+3+Security::GCM_IV_LEN+cert_size, dh_pubkey_server_serialized, dh_pubkey_server_size);

    char* ciphertext= nullptr;
    char* tag = nullptr;
    int ciphertext_len = Security::gcm_encrypt(aad, aad_len, signature, signature_len, shared_key,
                          iv, &ciphertext, &tag);

    char* buffer= (char*)malloc(aad_len+ciphertext_len+ Security::GCM_TAG_LEN);
    if(!buffer) {
        cerr<<"Error allocating buffer for sending message type 1";
    }
    memcpy(buffer, aad, aad_len);
    memcpy(buffer+aad_len, ciphertext, ciphertext_len);
    memcpy(buffer+aad_len+ciphertext_len, tag, Security::GCM_TAG_LEN);

    //send the message to the client
    send(client->get_client_socket(), buffer, aad_len+ciphertext_len+Security::GCM_TAG_LEN, 0);

    free(buffer);
    free(aad);
    free(ciphertext);
    free(certificate_serialized);
    free(dh_pubkey_server_serialized);
    free(tag);
    free(iv);

}