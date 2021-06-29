//this script should be merged and then removed

#include "message_sina.h"
#include "Security.h"
#include <cstdint>
#include <cstring>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <string.h>
#include <iostream>
#include <cstdlib>
#include <stdio.h>
#include "dimensions.h"

using namespace std;

User* find_user(string user, vector<User>users){
    for (auto &usr : users) // access by reference to avoid copying
    {  
        if (usr.get_username().compare(user)==0)
        {
           return &usr;
        }
    }
    cerr<< "Error: Receiver not found (find_dhpubk)!" <<endl;
    return NULL;
}
//sent by the client A
unsigned int Message::send_message_5(User* my_user, string receiver_username){
    //generating new dh pubk -> g^a'
    EVP_PKEY * newA{nullptr};
    if(Security::generate_dh_pubk(&newA) == -1){return 0;}
    my_user->set_clients_pubk(newA);
    //initialization vector
    unsigned char* iv{nullptr};
    if(Security::generate_iv(&iv, Security::GCM_IV_LEN)){my_user->set_clients_pubk(nullptr);EVP_PKEY_free(newA);return 0;}
    //creating aad: message type, client_to_server_counter, iv, generated dh public key
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH + 1;
    char * aad = (char*)malloc(aad_len);
    if(!aad){
        my_user->set_clients_pubk(nullptr);
        EVP_PKEY_free(newA);
        free(iv);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return 0;
    }
    aad[0] = 5;
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = my_user->get_client_coutner() + 1;
    //add iv to aad
    memcpy(aad + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    BIO* bio{nullptr};
    unsigned char*newA_char{nullptr};
    if(Security::EVP_PKEY_to_chars(bio, newA, &newA_char) == -1){ 
        my_user->set_clients_pubk(nullptr);
        EVP_PKEY_free(newA);
        free(iv);
        return 0;
    }
    my_user->set_clients_pubk_char(newA_char);
    BIO_free(bio);
    //add generated dh public key to aad
    memcpy(aad + COUNTER_LENGTH + Security::GCM_IV_LEN, newA_char, DH_PUBK_LENGTH);
    //generate the gcm plaintext: sender username||receiver username
    int gcm_plaintext_len = my_user->get_username().length() + receiver_username.length() + 1;
    unsigned char* gcm_plaintext = (unsigned char*)malloc(gcm_plaintext_len);
    strcpy((char*)gcm_plaintext, (my_user->get_username() + receiver_username).c_str());
    //GCM encryption
    unsigned char* gcm_ciphertext{nullptr};
    unsigned char* tag{nullptr};
    int gcm_ciphertext_len = 0;
    if(-1 == (gcm_ciphertext_len = Security::gcm_encrypt((unsigned char *)aad, aad_len , gcm_plaintext, gcm_plaintext_len, 
                                                        my_user->get_server_client_key(), iv, &gcm_ciphertext, &tag))){

        my_user->set_clients_pubk(nullptr);
        my_user->set_clients_pubk_char(nullptr);
        EVP_PKEY_free(newA);
        free(gcm_plaintext);    
        free(gcm_ciphertext);
        free(tag);
        free(iv);
        free(aad);
        return 0;
    }

    ///TODO:Send the data to the network!

    ////
    my_user->increment_client_counter();
    free(aad);
    free(iv);
    free(gcm_plaintext);
    free(gcm_ciphertext);
    free(tag);
    EVP_PKEY_free(newA);
    return gcm_ciphertext_len;
}
//recevied by the server 
int Message::parse_message_5(char * message, User* sender, vector<User>users){
    string msg (message);
    string tag = msg.substr(msg.length()-Security::GCM_TAG_LEN, msg.length());
    string ciphertext = msg.substr(msg.length()-Security::GCM_TAG_LEN -2*USERNAME_LENGTH, msg.length()-Security::GCM_TAG_LEN);
    string aad = msg.substr(0,MESSAGE_TYPE_LENGTH+COUNTER_LENGTH+Security::GCM_IV_LEN+DH_PUBK_LENGTH);
    string gcm_iv = msg.substr(MESSAGE_TYPE_LENGTH+COUNTER_LENGTH,MESSAGE_TYPE_LENGTH+COUNTER_LENGTH+Security::GCM_IV_LEN);
    unsigned char *decryptedtext{nullptr};
    if(-1==(Security::gcm_decrypt((unsigned char*)aad.c_str(), aad.length(), 
                                (unsigned char*)ciphertext.c_str(), ciphertext.length(),
                                sender->get_server_client_key(),(unsigned char*) gcm_iv.c_str(), &decryptedtext, 
                                (unsigned char*)tag.c_str()))){
        return -1;
    }
    string decryptedtext_str ((char*)decryptedtext);
    free(decryptedtext);
    uint16_t received_counter = 0;
    received_counter = message[1] << 8;  
    received_counter |= message[2];
    if(!sender->replay_check(false, received_counter)){
        return -1;
    }
    string dh_key = aad.substr(MESSAGE_TYPE_LENGTH+COUNTER_LENGTH+Security::GCM_IV_LEN,aad.length()); 
    sender->set_clients_pubk_char((unsigned char *)dh_key.c_str());
    send_message_6(sender, decryptedtext_str.substr(USERNAME_LENGTH,decryptedtext_str.length()), users);
    return 1;
}
//sent by the server to client B
unsigned int Message::send_message_6(User* sender, string receiver_username, vector<User>users){
    //
    User *receiver{nullptr};
    if(!(receiver = find_user(receiver_username, users))) return 0;
    //initialization vector
    unsigned char* iv{nullptr};
    if(Security::generate_iv(&iv, Security::GCM_IV_LEN)){return 0;}
    //creating aad: message type, client_to_server_counter, iv, generated dh public key
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH + 1;
    char * aad = (char*)malloc(aad_len);
    if(!aad){
        free(iv);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return 0;
    }
    //insert message type into aad
    aad[0] = 6;
    //insert counter into aad
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = sender->get_client_coutner() + 1;
    //insert the iv into aad
    memcpy(aad + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //insert the generated dh public key into the aad
    memcpy(aad + COUNTER_LENGTH + Security::GCM_IV_LEN, sender->get_clients_pubk_char(), DH_PUBK_LENGTH);
    //generate the gcm plaintext: sender username||receiver username
    int gcm_plaintext_len = sender->get_username().length() + receiver_username.length() + 1;
    unsigned char* gcm_plaintext = (unsigned char*)malloc(gcm_plaintext_len);
    strcpy((char*)gcm_plaintext, sender->get_username().c_str());
    strcat((char*)gcm_plaintext, receiver_username.c_str());
    //GCM encryption
    unsigned char* gcm_ciphertext{nullptr};
    unsigned char* tag{nullptr};
    int gcm_ciphertext_len = 0;
    if(-1 == (gcm_ciphertext_len = Security::gcm_encrypt((unsigned char *)aad, aad_len , gcm_plaintext, gcm_plaintext_len, 
                                                        receiver->get_server_client_key(), 
                                                        iv, &gcm_ciphertext, &tag))){

        free(gcm_plaintext);    
        free(gcm_ciphertext);
        free(tag);
        free(iv);
        free(aad);
        return gcm_ciphertext_len;
    }

    ///TODO:Send the data to the network!

    ////
    receiver->increment_server_counter();
    free(aad);
    free(iv);
    free(gcm_plaintext);
    free(gcm_ciphertext);
    free(tag);
    return gcm_ciphertext_len;
}
//received by the client B
int Message::parse_message_6(char* message, User*my_user){
    string msg (message);
    string tag = msg.substr(msg.length()-Security::GCM_TAG_LEN, msg.length());
    string ciphertext = msg.substr(msg.length()-Security::GCM_TAG_LEN -2*USERNAME_LENGTH, msg.length()-Security::GCM_TAG_LEN);
    string aad = msg.substr(0,MESSAGE_TYPE_LENGTH+COUNTER_LENGTH+Security::GCM_IV_LEN+DH_PUBK_LENGTH);
    string gcm_iv = msg.substr(MESSAGE_TYPE_LENGTH+COUNTER_LENGTH,MESSAGE_TYPE_LENGTH+COUNTER_LENGTH+Security::GCM_IV_LEN);
    unsigned char *decryptedtext{nullptr};
    if(-1==(Security::gcm_decrypt((unsigned char*)aad.c_str(), aad.length(), 
                                (unsigned char*)ciphertext.c_str(), ciphertext.length(),
                                my_user->get_server_client_key(),(unsigned char*) gcm_iv.c_str(), &decryptedtext, 
                                (unsigned char*)tag.c_str()))){
        return -1;
    }
    string decryptedtext_str ((char*)decryptedtext);
    free(decryptedtext);
    uint16_t received_counter = 0;
    received_counter = message[1] << 8;  
    received_counter |= message[2];
    if(!my_user->replay_check(true, received_counter)){
        return -1;
    }
    ///
    ///
    ///TODO: specify to user the to accept or reject this request
    ///
    //if we want to accept
    string dh_key = aad.substr(MESSAGE_TYPE_LENGTH+COUNTER_LENGTH+Security::GCM_IV_LEN,aad.length()); 
    my_user->set_peer_pubk_char((unsigned char *)dh_key.c_str());
    my_user->set_peer_username(decryptedtext_str.substr(0,USERNAME_LENGTH));
    send_message_7(my_user);
    return 1;

}
//sent by the client B
unsigned int Message::send_message_7(User* my_user){
    //generating new dh pubk g^b'
    EVP_PKEY * newB{nullptr};
    if(Security::generate_dh_pubk(&newB) == -1){return 0;}
    my_user->set_clients_pubk(newB);
    BIO * bio{nullptr};
    unsigned char *newB_char{nullptr};
    if(Security::EVP_PKEY_to_chars(bio, newB ,&newB_char) == -1){
        EVP_PKEY_free(newB);
        my_user->set_clients_pubk(nullptr);
        my_user->set_peer_pubk_char(nullptr);
        return 0;
    }
    my_user->set_clients_pubk_char(newB_char);
    BIO_free(bio);
    //convert peers pubk char into EVP_PKEY
    BIO * mio{nullptr};
    EVP_PKEY * peer_pubk;
    if(Security::chars_to_EVP_PKEY(mio, &peer_pubk , my_user->get_peer_pubk_char())==-1){
        EVP_PKEY_free(newB);
        my_user->set_clients_pubk(nullptr);
        my_user->set_clients_pubk_char(nullptr);
        my_user->set_peer_pubk_char(nullptr);
        return 0;
    }
    my_user->set_peer_pubk(peer_pubk);
    //concatenation g^a'||g^b'
    unsigned char* text_to_sign = (unsigned char*)malloc(2*DH_PUBK_LENGTH);
    if(!text_to_sign){
        cerr <<"malloc for concatenation returned NULL (text_to_sign is too big?)"<<endl;
        EVP_PKEY_free(newB);
        my_user->set_clients_pubk(nullptr);
        my_user->set_clients_pubk_char(nullptr);
        my_user->set_peer_pubk(nullptr);
        my_user->set_peer_pubk_char(nullptr);
        return 0;
    }
    //put g^a' into the buffer
    memcpy(text_to_sign, my_user->get_peer_pubk_char(), DH_PUBK_LENGTH);
    //put g^b' into the buffer
    memcpy(text_to_sign+DH_PUBK_LENGTH, my_user->get_clients_pubk_char(), DH_PUBK_LENGTH);
    //sign the concatenation
    unsigned char *signature{nullptr};
    int signature_len = 0;
    if((signature_len = Security::signature("./users/"+my_user->get_username()+"rsa_privkey.pem", text_to_sign, 
                            2*DH_PUBK_LENGTH, &signature)) == -1){
        EVP_PKEY_free(newB);
        free(text_to_sign);
        my_user->set_clients_pubk(nullptr);
        my_user->set_clients_pubk_char(nullptr);
        my_user->set_peer_pubk(nullptr);
        return 0;
    }
    //generating session key between two client
    unsigned char * clients_key{nullptr};
    if(Security::generate_dh_key(my_user->get_clients_pubk(), my_user->get_peer_pubk(), &clients_key) == -1){
        EVP_PKEY_free(newB);
        free(text_to_sign);
        my_user->set_clients_pubk(nullptr);
        my_user->set_clients_pubk_char(nullptr);
        my_user->set_peer_pubk(nullptr);
        free(signature);
        return 0;
    }
    my_user->set_clients_key(clients_key);
    //encrypt the signature with the session key
    unsigned char* ciphertext{nullptr};
    int ciphertext_len = 0;
    if((ciphertext_len = Security::encryption_AES(signature, signature_len, my_user->get_clients_key(), NULL, &ciphertext)) == -1){
        EVP_PKEY_free(newB);
        free(text_to_sign);
        my_user->set_clients_pubk(nullptr);
        my_user->set_clients_pubk_char(nullptr);
        my_user->set_peer_pubk(nullptr);
        my_user->set_clients_key(nullptr);
        free(signature);
        free(clients_key);
        return 0;
    }
     //initialization vector
    unsigned char* iv{nullptr};
    if(Security::generate_iv(&iv, Security::GCM_IV_LEN)){
        EVP_PKEY_free(newB);
        free(text_to_sign);
        my_user->set_clients_pubk(nullptr);
        my_user->set_clients_pubk_char(nullptr);
        my_user->set_peer_pubk(nullptr);
        my_user->set_clients_key(nullptr);
        free(signature);
        free(ciphertext);
        free(clients_key);
        return 0;
    }
    //creating aad: message type, client_to_server_counter, iv, generated dh public key,encrypted signature
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH + ciphertext_len + 1;
    char * aad = (char*)malloc(aad_len);
    if(!aad){
        EVP_PKEY_free(newB);
        free(text_to_sign);
        my_user->set_clients_pubk(nullptr);
        my_user->set_clients_pubk_char(nullptr);
        my_user->set_peer_pubk(nullptr);
        my_user->set_clients_key(nullptr);
        free(signature);
        free(iv);
        free(ciphertext);
        free(clients_key);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return 0;
    }
    //put message type into aad
    aad[0] = 7;
    //put counter into the aad
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = my_user->get_client_coutner() + 1;
    //put the iv into the aad
    memcpy(aad + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //put the generated dh public key into the aad
    memcpy(aad + COUNTER_LENGTH + Security::GCM_IV_LEN, my_user->get_clients_pubk_char(), DH_PUBK_LENGTH);
    //put the encryption of signature into the aad
    memcpy(aad + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH, ciphertext, ciphertext_len);
    //plain text for gcm: source username||destination username
    int gcm_plaintext_len = my_user->get_username().length() + my_user->get_peer_username().length() + 1;
    unsigned char* gcm_plaintext = (unsigned char*)malloc(gcm_plaintext_len);
    strcpy((char*)gcm_plaintext, (my_user->get_username()+my_user->get_peer_username()).c_str());
    //GCM encryption
    unsigned char* gcm_ciphertext{nullptr};
    unsigned char* tag{nullptr};
    int gcm_ciphertext_len = 0;
    if(-1 == (gcm_ciphertext_len = Security::gcm_encrypt((unsigned char *)aad, aad_len , gcm_plaintext, gcm_plaintext_len, 
                                                        my_user->get_server_client_key(), iv, &gcm_ciphertext, &tag))){

        EVP_PKEY_free(newB);
        free(text_to_sign);
        my_user->set_clients_pubk(nullptr);
        my_user->set_clients_pubk_char(nullptr);
        my_user->set_peer_pubk(nullptr);
        my_user->set_clients_key(nullptr);
        free(signature);
        free(iv);
        free(ciphertext);
        free(aad);
        free(clients_key);
        return 0;
    }

    ///TODO:Send the data to the network!

    ////
    EVP_PKEY_free(newB);
    free(text_to_sign);
    my_user->increment_client_counter();
    free(signature);
    free(iv);
    free(ciphertext);
    free(aad);
    free(gcm_ciphertext);
    free(clients_key);
    return gcm_ciphertext_len;
}
//recevied by the server 
int Message::parse_message_7(char * message, User* sender, vector<User>users){
    string msg (message);
    string tag = msg.substr(msg.length()-Security::GCM_TAG_LEN, msg.length());
    string gcm_ciphertext = msg.substr(msg.length()-Security::GCM_TAG_LEN -2*USERNAME_LENGTH, msg.length()-Security::GCM_TAG_LEN);
    string aad = msg.substr(0,msg.length() - gcm_ciphertext.length() - tag.length());
    string gcm_iv = msg.substr(MESSAGE_TYPE_LENGTH+COUNTER_LENGTH,MESSAGE_TYPE_LENGTH+COUNTER_LENGTH+Security::GCM_IV_LEN);
    string clients_ciphertext = aad.substr(MESSAGE_TYPE_LENGTH+COUNTER_LENGTH+Security::GCM_IV_LEN+DH_PUBK_LENGTH, aad.length());
    unsigned char *gcm_decryptedtext{nullptr};
    if(-1==(Security::gcm_decrypt((unsigned char*)aad.c_str(), aad.length(), 
                                (unsigned char*)gcm_ciphertext.c_str(), gcm_ciphertext.length(),
                                sender->get_server_client_key(),(unsigned char*) gcm_iv.c_str(), &gcm_decryptedtext, 
                                (unsigned char*)tag.c_str()))){
        return -1;
    }
    string gcm_decryptedtext_str ((char*)gcm_decryptedtext);
    free(gcm_decryptedtext);
    uint16_t received_counter = 0;
    received_counter = message[1] << 8;  
    received_counter |= message[2];
    if(!sender->replay_check(false, received_counter)){
        return -1;
    }
    sender->set_peer_username(gcm_decryptedtext_str.substr(USERNAME_LENGTH,gcm_decryptedtext_str.length()));
    string dh_key = aad.substr(MESSAGE_TYPE_LENGTH+COUNTER_LENGTH+Security::GCM_IV_LEN, MESSAGE_TYPE_LENGTH+COUNTER_LENGTH+Security::GCM_IV_LEN+DH_PUBK_LENGTH);
    sender->set_clients_pubk_char((unsigned char *)dh_key.c_str());
    send_message_8(sender, clients_ciphertext, users);
    return 1;
}
//sent by the server to client A
unsigned int Message::send_message_8(User* sender, string clients_ciphertext, vector<User>users){
    //
    User *receiver{nullptr};
    if(!(receiver = find_user(sender->get_peer_username(), users))) return 0;
    //initialization vector
    unsigned char* iv{nullptr};
    if(Security::generate_iv(&iv, Security::GCM_IV_LEN)){return 0;}
    //retrieve and send the rsa_public key of the sender
    // load rsa public key:
    string filename = "./users/"+sender->get_username() + "rsa_pubkey.pem";
    FILE* pubk_file = fopen(filename.c_str(), "r");
    if(!pubk_file){ cerr << "Error: cannot open file '" << filename << "' (missing?)\n"; exit(1); }
    EVP_PKEY* pubk = PEM_read_PUBKEY(pubk_file, NULL, NULL, NULL);
    fclose(pubk_file);
    if(!pubk){ cerr << "Error: PEM_read_PUBKEY returned NULL\n"; exit(1); }
    //serialize the public key
    BIO *bio;
    unsigned char *pk_buf{nullptr};
    int pk_buf_size = 0;
    if(-1==(pk_buf_size = Security::EVP_PKEY_to_chars(bio, pubk, &pk_buf))){
        free(iv);
        EVP_PKEY_free(pubk);
        return 0;
    }
    BIO_free(bio);
    //creating aad: message type, client_to_server_counter, iv, generated dh public key, rsa publick key, encrypted signature
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH + 
                    pk_buf_size + clients_ciphertext.length() + 1;
    char * aad = (char*)malloc(aad_len);
    if(!aad){
        free(iv);
        EVP_PKEY_free(pubk);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return 0;
    }
    //put the message type into aad
    aad[0] = 8;
    //put the counter into aad
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = sender->get_client_coutner() + 1;
    //put the iv into the aad
    memcpy(aad + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //put the generated dh public key into the aad
    memcpy(aad + COUNTER_LENGTH + Security::GCM_IV_LEN, sender->get_clients_pubk_char(), DH_PUBK_LENGTH);
    //put the rsa public key into the aad 
    memcpy(aad + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH, pk_buf, pk_buf_size);
    //put the encrypted signature into the aad
    memcpy(aad + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH + pk_buf_size, clients_ciphertext.c_str(),
                                                                                        clients_ciphertext.length());

    //plain text for gcm: source username||destination username
    int gcm_plaintext_len = sender->get_username().length() + receiver->get_username().length() + 1;
    unsigned char* gcm_plaintext = (unsigned char*)malloc(gcm_plaintext_len);
    strcpy((char*)gcm_plaintext, (sender->get_username()+receiver->get_username()).c_str());
    //GCM encryption
    unsigned char* gcm_ciphertext{nullptr};
    unsigned char* tag{nullptr};
    int gcm_ciphertext_len = 0;
    if(-1 == (gcm_ciphertext_len = Security::gcm_encrypt((unsigned char *)aad, aad_len , gcm_plaintext, gcm_plaintext_len, 
                                                        receiver->get_server_client_key(), 
                                                        iv, &gcm_ciphertext, &tag))){

        EVP_PKEY_free(pubk);
        free(gcm_plaintext);    
        free(gcm_ciphertext);
        free(tag);
        free(iv);
        free(aad);
        return gcm_ciphertext_len;
    }

    ///TODO:Send the data to the network!

    ////
    receiver->increment_server_counter();
    free(aad);
    free(iv);
    free(gcm_plaintext);
    free(gcm_ciphertext);
    free(tag);
    EVP_PKEY_free(pubk);
    receiver->set_peer_username(sender->get_username());
    return gcm_ciphertext_len;
}
//received by the client A
int Message::parse_message_8(char* message, User * my_user){
    string msg (message);
    string tag = msg.substr(msg.length()-Security::GCM_TAG_LEN, msg.length());
    string gcm_ciphertext = msg.substr(msg.length()-Security::GCM_TAG_LEN -2*USERNAME_LENGTH, msg.length()-Security::GCM_TAG_LEN);
    string aad = msg.substr(0,msg.length() - tag.length() - gcm_ciphertext.length());
    string gcm_iv = msg.substr(MESSAGE_TYPE_LENGTH+COUNTER_LENGTH,MESSAGE_TYPE_LENGTH+COUNTER_LENGTH+Security::GCM_IV_LEN);
    unsigned char *gcm_decryptedtext{nullptr};
    if(-1==(Security::gcm_decrypt((unsigned char*)aad.c_str(), aad.length(), 
                                (unsigned char*)gcm_ciphertext.c_str(), gcm_ciphertext.length(),
                                my_user->get_server_client_key(),(unsigned char*) gcm_iv.c_str(), &gcm_decryptedtext, 
                                (unsigned char*)tag.c_str()))){
        return -1;
    }
    string gcm_decryptedtext_str ((char*)gcm_decryptedtext);
    free(gcm_decryptedtext);
    uint16_t received_counter = 0;
    received_counter = message[1] << 8;  
    received_counter |= message[2];
    if(!my_user->replay_check(true, received_counter)){
        return -1;
    }
    string dh_key = aad.substr(MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN, 
                                MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH); 

    //generate the clients session key
    BIO *mbio;
    EVP_PKEY *peers_pubk{nullptr};
    if(Security::chars_to_EVP_PKEY(mbio, &peers_pubk,(unsigned char *) dh_key.c_str()) == -1){
        return -1;
    }
    BIO_free(mbio);
    unsigned char * clients_key{nullptr};
    if(-1 == Security::generate_dh_key(peers_pubk, my_user->get_clients_pubk(), &clients_key)){
        EVP_PKEY_free(peers_pubk);
        return -1;
    }
    //decrypt the clients cipher text
    string clients_ciphertext = aad.substr(MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH + SIGNATURE_LENGTH,
                                            aad.length());
    int clients_decryptext_len = 0;
    unsigned char * clients_decryptext{nullptr};
    if(-1 == (clients_decryptext_len = Security::decryption_AES((unsigned char *)clients_ciphertext.c_str(), clients_ciphertext.length(), 
                                            clients_key, NULL, &clients_decryptext))){
        
        EVP_PKEY_free(peers_pubk);
        return -1;
    }
    //extract the rsa public key
    string rsa_pubk = aad.substr(MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH, 
                                MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH + SIGNATURE_LENGTH).c_str();
    //desrialize the rsa public key
    BIO *bio;
    EVP_PKEY *pkey{nullptr};
    if(-1 == Security::chars_to_EVP_PKEY(bio, &pkey, (unsigned char *)rsa_pubk.c_str())){
        free(clients_decryptext);
        EVP_PKEY_free(peers_pubk);
        return -1;
    }
    BIO_free(bio);
    //generating the clear text for verification of the signature
    //concatenation g^a'||g^b'
    unsigned char* text_to_sign = (unsigned char*)malloc(2*DH_PUBK_LENGTH);
    if(!text_to_sign){
        cerr <<"malloc for concatenation returned NULL (text_to_sign is too big?)"<<endl;
        free(clients_decryptext);
        EVP_PKEY_free(peers_pubk);
        EVP_PKEY_free(pkey);
        return 0;
    }
    //put g^a' into the buffer
    memcpy(text_to_sign, my_user->get_clients_pubk_char(), DH_PUBK_LENGTH);
    //put g^b' into the buffer
    memcpy(text_to_sign+DH_PUBK_LENGTH,(unsigned char *)dh_key.c_str(), DH_PUBK_LENGTH);

    //verify the signature
    if(-1 == Security::verify_signature(pkey, clients_decryptext, clients_decryptext_len, text_to_sign,2*DH_PUBK_LENGTH)){
        free(clients_decryptext);
        EVP_PKEY_free(peers_pubk);
        free(text_to_sign);
        EVP_PKEY_free(pkey);
        return -1;
    }
    my_user->set_clients_key(clients_key);
    my_user->set_peer_pubk_char((unsigned char *)dh_key.c_str());
    my_user->set_peer_username(gcm_decryptedtext_str.substr(0,USERNAME_LENGTH));

    free(clients_decryptext);
    EVP_PKEY_free(peers_pubk);
    free(text_to_sign);
    EVP_PKEY_free(pkey);
    ///
    ///TODO: specify to user the to accept or reject this request
    ///
    ///
    send_message_9(my_user);
    return 1;
}
//sent by a client A
unsigned int Message::send_message_9(User* my_user){
    //generating the clear text for verification of the signature
    //concatenation g^b'||g^a'
    unsigned char* text_to_sign = (unsigned char*)malloc(2*DH_PUBK_LENGTH);
    if(!text_to_sign){
        cerr <<"malloc for concatenation returned NULL (text_to_sign is too big?)"<<endl;
        return 0;
    }
    //put g^b' into the buffer
    memcpy(text_to_sign, my_user->get_peer_pubk_char(), DH_PUBK_LENGTH);
    //put g^a' into the buffer
    memcpy(text_to_sign + DH_PUBK_LENGTH, my_user->get_clients_pubk_char(), DH_PUBK_LENGTH);
    //sign the concatenation {g^b'||g^a'}
    unsigned char* signature{nullptr};
    int signature_len = 0;
    if(-1 == (signature_len = 
                Security::signature("./users/"+my_user->get_username()+"/rsa_pubkey.pem", text_to_sign, 2*DH_PUBK_LENGTH, &signature))){
        //free(client_to_server_counter);
        free(text_to_sign);
        return 0;
    }
               
    //Encrypt the digital signature
    unsigned char* cipher_signature{nullptr};
    int cipher_signature_len = 0;
    if(-1 == (cipher_signature_len = Security::encryption_AES(signature, signature_len, my_user->get_clients_key(), NULL, &cipher_signature))){
        free(text_to_sign);
        free(signature);
        return 0;

    }
    //initialization vector
    unsigned char* iv{nullptr};
    if(Security::generate_iv(&iv, Security::GCM_IV_LEN)){
        // free(client_to_server_counter);
        free(text_to_sign);
        free(signature);
        free(cipher_signature);
        return 0;
    }
    //creating aad: message type, client_to_server_counter, iv, encrypted signature
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + cipher_signature_len + 1;
    char * aad = (char*)malloc(aad_len);
    if(!aad){ 
        // free(client_to_server_counter);
        free(text_to_sign);
        free(signature);
        free(cipher_signature);
        free(iv);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return 0;
    }
    //put message type into aad
    aad[0] = 9;
    //put counter into aad
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = my_user->get_client_coutner() + 1;
    //put iv into the aad
    memcpy(aad + MESSAGE_TYPE_LENGTH + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //put encrypted cipher text into the aad
    memcpy(aad + MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN, cipher_signature, cipher_signature_len);
    //
    int gcm_plaintext_len = my_user->get_username().length() + my_user->get_peer_username().length() + 1;
    unsigned char* gcm_plaintext = (unsigned char*)malloc(gcm_plaintext_len);
    strcpy((char*)gcm_plaintext, (my_user->get_username()+my_user->get_peer_username()).c_str());
    //GCM encryption
    unsigned char* gcm_ciphertext{nullptr};
    unsigned char* tag{nullptr};
    int gcm_ciphertext_len = 0;
    if(-1 == (gcm_ciphertext_len = Security::gcm_encrypt((unsigned char *)aad, aad_len , gcm_plaintext, gcm_plaintext_len, 
                                                        my_user->get_server_client_key(), iv, &gcm_ciphertext, &tag))){

        free(text_to_sign);
        free(signature);
        free(cipher_signature); 
        free(gcm_plaintext);    
        free(gcm_ciphertext);
        free(tag);
        free(iv);
        free(aad);
        return 0;
    }

    ///TODO:Send the data to the network!

    ////
    my_user->increment_client_counter();
    //remove the public keys
    my_user->set_peer_pubk_char(nullptr);
    my_user->set_clients_pubk(nullptr);
    my_user->set_clients_pubk_char(nullptr);
    free(aad);
    free(iv);
    free(text_to_sign);
    free(signature);
    free(gcm_plaintext);
    free(gcm_ciphertext);
    free(tag);
    return gcm_ciphertext_len;
}
//received by the server
int Message::parse_message_9(char * message, User* sender, vector<User>users){

    //extract the tag from the message
    string msg (message);
    string tag = msg.substr(msg.length()-Security::GCM_TAG_LEN, msg.length());
     //calculate the inner encryption length
    string aad = msg.substr(0, msg.length() - tag.length() - 2*USERNAME_LENGTH);
    string ciphertext = msg.substr(aad.length(), msg.length()-tag.length());
    string gcm_iv = msg.substr(MESSAGE_TYPE_LENGTH+COUNTER_LENGTH,MESSAGE_TYPE_LENGTH+COUNTER_LENGTH+Security::GCM_IV_LEN);
    unsigned char*decryptedtext{nullptr};
    int decryptedtext_len = 0;
    if(-1 == (decryptedtext_len = Security::gcm_decrypt((unsigned char*)aad.c_str(), aad.length(), 
                        (unsigned char*)ciphertext.c_str(), ciphertext.length(),
                        sender->get_server_client_key(), 
                        (unsigned char*)gcm_iv.c_str(), &decryptedtext,
                        (unsigned char*)tag.c_str()))) return -1;

    string str_ ((char*)decryptedtext);
    free(decryptedtext);
    //message[0] is the message type
    unsigned short received_counter = 0;
    received_counter = message[1] << 8;  
    received_counter |= message[2];
    //check for replay
    if (!sender->replay_check(false, received_counter)){ return 0; }
    //find pubkey of the receiver
    string receiver = str_.substr(USERNAME_LENGTH,2*USERNAME_LENGTH);
    string clients_ciphertext = aad.substr(MESSAGE_TYPE_LENGTH+COUNTER_LENGTH+Security::GCM_IV_LEN, aad.length());
    //send the message type 10
    int gcm_ciphertext_len;
    if(0 == (gcm_ciphertext_len = send_message_10(sender, clients_ciphertext, users))){
        cerr <<"Erro: sending message 10 failed";
        return -1;
    }
    return gcm_ciphertext_len;

}
//sent by the server to client B
unsigned int Message::send_message_10(User* sender, string clients_ciphertext, vector<User>users){
     //
    User *receiver{nullptr};
    if(!(receiver = find_user(sender->get_peer_username(), users))) return 0;
    //initialization vector
    unsigned char* iv{nullptr};
    if(Security::generate_iv(&iv, Security::GCM_IV_LEN)){return 0;}
    //retrieve and send the rsa_public key of the sender
    // load rsa public key:
    string filename = "./users/"+sender->get_username() + "rsa_pubkey.pem";
    FILE* pubk_file = fopen(filename.c_str(), "r");
    if(!pubk_file){ cerr << "Error: cannot open file '" << filename << "' (missing?)\n"; exit(1); }
    EVP_PKEY* pubk = PEM_read_PUBKEY(pubk_file, NULL, NULL, NULL);
    fclose(pubk_file);
    if(!pubk){ cerr << "Error: PEM_read_PUBKEY returned NULL\n"; exit(1); }
    //serialize the rsa public key
    BIO *bio;
    unsigned char *pk_buf{nullptr};
    int pk_buf_size = 0;
    if(-1==(pk_buf_size = Security::EVP_PKEY_to_chars(bio, pubk, &pk_buf))){
        free(iv);
        EVP_PKEY_free(pubk);
        return 0;
    }
    BIO_free(bio);
    //creating aad: message type, client_to_server_counter, iv, rsa public key, encrypted signature
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + 
                    pk_buf_size + clients_ciphertext.length() + 1;
    char * aad = (char*)malloc(aad_len);
    if(!aad){
        free(iv);
        EVP_PKEY_free(pubk);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return 0;
    }
    //put the message type into aad
    aad[0] = 10;
    //put the counter into aad
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = sender->get_client_coutner() + 1;
    //put the iv into the aad
    memcpy(aad + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //put the rsa public key into the aad 
    memcpy(aad + COUNTER_LENGTH + Security::GCM_IV_LEN , pk_buf, pk_buf_size);
    //put the encrypted signature into the aad
    memcpy(aad + COUNTER_LENGTH + Security::GCM_IV_LEN + pk_buf_size, clients_ciphertext.c_str(),
                                                                        clients_ciphertext.length());

    //plain text for gcm: source username||destination username
    int gcm_plaintext_len = sender->get_username().length() + receiver->get_username().length() + 1;
    unsigned char* gcm_plaintext = (unsigned char*)malloc(gcm_plaintext_len);
    strcpy((char*)gcm_plaintext, (sender->get_username()+receiver->get_username()).c_str());
    //GCM encryption
    unsigned char* gcm_ciphertext{nullptr};
    unsigned char* tag{nullptr};
    int gcm_ciphertext_len = 0;
    if(-1 == (gcm_ciphertext_len = Security::gcm_encrypt((unsigned char *)aad, aad_len , gcm_plaintext, gcm_plaintext_len, 
                                                        receiver->get_server_client_key(), 
                                                        iv, &gcm_ciphertext, &tag))){

        EVP_PKEY_free(pubk);
        free(gcm_plaintext);    
        free(gcm_ciphertext);
        free(tag);
        free(iv);
        free(aad);
        return gcm_ciphertext_len;
    }

    ///TODO:Send the data to the network!

    ////
    receiver->increment_server_counter();
    free(aad);
    free(iv);
    free(gcm_plaintext);
    free(gcm_ciphertext);
    free(tag);
    EVP_PKEY_free(pubk);
    //remove the dh public keys from users stored inside the server for client to client communication 
    //removing g^a' and g^b'
    receiver->set_peer_pubk_char(nullptr);
    sender->set_peer_pubk_char(nullptr);

    return gcm_ciphertext_len;
}
//received by a client B
int Message::parse_message_10(char* message, User* my_user){
    string msg (message);
    string tag = msg.substr(msg.length()-Security::GCM_TAG_LEN, msg.length());
    string gcm_ciphertext = msg.substr(msg.length()-Security::GCM_TAG_LEN -2*USERNAME_LENGTH, msg.length()-Security::GCM_TAG_LEN);
    string aad = msg.substr(0,msg.length() - tag.length() - gcm_ciphertext.length());
    string gcm_iv = msg.substr(MESSAGE_TYPE_LENGTH+COUNTER_LENGTH,MESSAGE_TYPE_LENGTH+COUNTER_LENGTH+Security::GCM_IV_LEN);
    unsigned char *gcm_decryptedtext{nullptr};
    if(-1==(Security::gcm_decrypt((unsigned char*)aad.c_str(), aad.length(), 
                                (unsigned char*)gcm_ciphertext.c_str(), gcm_ciphertext.length(),
                                my_user->get_server_client_key(),(unsigned char*) gcm_iv.c_str(), &gcm_decryptedtext, 
                                (unsigned char*)tag.c_str()))){
        return -1;
    }
    string gcm_decryptedtext_str ((char*)gcm_decryptedtext);
    free(gcm_decryptedtext);
    uint16_t received_counter = 0;
    received_counter = message[1] << 8;  
    received_counter |= message[2];
    if(!my_user->replay_check(true, received_counter)){
        return -1;
    }
    //decrypt the clients cipher text
    string clients_ciphertext = aad.substr(MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + SIGNATURE_LENGTH,
                                            aad.length());
    int clients_decryptext_len = 0;
    unsigned char * clients_decryptext{nullptr};
    if(-1 == (clients_decryptext_len = Security::decryption_AES((unsigned char *)clients_ciphertext.c_str(), clients_ciphertext.length(), 
                                            my_user->get_clients_key(), NULL, &clients_decryptext))){
        
        return -1;
    }
    //extract the rsa public key
    string rsa_pubk = aad.substr(MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN, 
                                MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + SIGNATURE_LENGTH).c_str();
    //desrialize the rsa public key
    BIO *bio;
    EVP_PKEY *pkey{nullptr};
    if(-1 == Security::chars_to_EVP_PKEY(bio, &pkey, (unsigned char *)rsa_pubk.c_str())){
        free(clients_decryptext);
        return -1;
    }
    BIO_free(bio);
    //generating the clear text for verification of the signature
    //concatenation g^a'||g^b'
    unsigned char* text_to_sign = (unsigned char*)malloc(2*DH_PUBK_LENGTH);
    if(!text_to_sign){
        cerr <<"malloc for concatenation returned NULL (text_to_sign is too big?)"<<endl;
        free(clients_decryptext);
        EVP_PKEY_free(pkey);
        return 0;
    }
    //put g^b' into the buffer
    memcpy(text_to_sign, my_user->get_clients_pubk_char(), DH_PUBK_LENGTH);
    //put g^a' into the buffer
    memcpy(text_to_sign+DH_PUBK_LENGTH,my_user->get_peer_pubk_char(), DH_PUBK_LENGTH);

    //verify the signature
    if(-1 == Security::verify_signature(pkey, clients_decryptext, clients_decryptext_len, text_to_sign,2*DH_PUBK_LENGTH)){
        free(clients_decryptext);
        EVP_PKEY_free(pkey);
        free(text_to_sign);
        return -1;
    }
    free(clients_decryptext);
    EVP_PKEY_free(pkey);
    free(text_to_sign);
    //removing the public keys
    my_user->set_peer_pubk(nullptr);
    my_user->set_peer_pubk_char(nullptr);
    my_user->set_clients_pubk(nullptr);
    my_user->set_clients_pubk_char(nullptr);
    return 1;
                                        
}
