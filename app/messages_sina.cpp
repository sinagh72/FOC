//this script should be merged and then removed

#include "message_sina.h"
#include "Security.h"
#include <cstdint>
#include <cstring>
#include <openssl/ossl_typ.h>
#include <string.h>
#include <iostream>
#include <cstdlib>
#include <stdio.h>
#include "dimensions.h"

using namespace std;

//convert unsigned short to unsigned char
void short_to_char(unsigned short input, unsigned char **array){
    *array = (unsigned char*)malloc(sizeof(input));
    if(!*array){ cerr<< "Error: malloc for converting short to char returned NULL (too big short?)\n"; return;}
    (*array)[0] = (input >> 8);
    (*array)[1] = (input & 0xFF);
    (*array)[2] = '\0';
}
User* find_user(string user, vector<User>users){
    bool returned = false;
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
//confirmation message that the session key is received and generated sucessfully
//sent by a client 
unsigned int Message::send_message_9(User* my_user,
                                    string dest_username,
                                    EVP_PKEY* dest_dh_pubk, char* dest_dh_pubk_char,
                                    unsigned char* clinets_key, unsigned char* server_client_key){
    //convert unsigned short to unsigned char                                 
    // unsigned char* client_to_server_counter{nullptr};
    // short_to_char(my_user->get_client_coutner() + 1, &client_to_server_counter);
    //
    int text_to_sign_len =  dest_username.length() + strlen(dest_dh_pubk_char) + 1;
    unsigned char * text_to_sign = (unsigned char*)malloc(text_to_sign_len);
    if(!text_to_sign){
        //free(client_to_server_counter);
        cerr<< "Error: malloc for DH pubks signature returned NULL (too big signature?)\n"; return 0;
    }
    //concatenating the two dh pubks {g^b'||g^a'}
    strcpy((char*)text_to_sign, dest_dh_pubk_char);
    strcat((char*)text_to_sign, (char*)my_user->get_dh_pubk_char());
    //sign the concatenation {g^b'||g^a'}
    unsigned char* signature{nullptr};
    int signature_len = 0;
    if(-1 == (signature_len = 
                Security::signature("./users/"+my_user->get_username()+"/rsa_pubkey.pem", text_to_sign, text_to_sign_len, &signature))){
        //free(client_to_server_counter);
        free(text_to_sign);
        return 0;
    }
                
    //Encrypt the digital signature
    unsigned char* cipher_signature{nullptr};
    int cipher_signature_len = 0;
    if(-1 == (cipher_signature_len = Security::encryption_AES(signature, signature_len, clinets_key, NULL, &cipher_signature))){
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
    aad[0] = 9;
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = my_user->get_client_coutner();
    memcpy(aad + MESSAGE_TYPE_LENGTH + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    memcpy(aad + MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN, cipher_signature, cipher_signature_len);
    // strcpy(aad, "9");
    // strcat(aad,(const char*)client_to_server_counter);
    // strcat(aad,(char*)iv);
    // strcat(aad,(char*)cipher_signature); 
    //
    int gcm_plaintext_len = my_user->get_username().length() + dest_username.length() + 1;
    unsigned char* gcm_plaintext = (unsigned char*)malloc(gcm_plaintext_len);
    strcpy((char*)gcm_plaintext, my_user->get_username().c_str());
    strcat((char*)gcm_plaintext, dest_username.c_str());
    //GCM encryption
    unsigned char* gcm_ciphertext{nullptr};
    unsigned char* tag{nullptr};
    int gcm_ciphertext_len = 0;
    if(-1 == (gcm_ciphertext_len = Security::gcm_encrypt((unsigned char *)aad, aad_len , gcm_plaintext, gcm_plaintext_len, 
                                                        server_client_key, iv, &gcm_ciphertext, &tag))){

        // free(client_to_server_counter);
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
    free(aad);
    free(iv);
    free(text_to_sign);
    free(signature);
    // free(client_to_server_counter);
    free(gcm_plaintext);
    free(gcm_ciphertext);
    free(tag);
    return gcm_ciphertext_len;
}
//received by the server
int Message::parse_message_9(char* message, 
                            unsigned char* sender_server_key, 
                            unsigned char* receiver_server_key, vector<User>users){

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
                        sender_server_key, 
                        (unsigned char*)gcm_iv.c_str(), &decryptedtext,
                        (unsigned char*)tag.c_str()))) return -1;

    string str_ ((char*)decryptedtext);
    free(decryptedtext);
    //message[0] is the message type
    unsigned short received_counter = 0;
    received_counter = message[1] << 8;  
    received_counter |= message[2];
    //check for replay
    User*sender;
    if (!(sender = find_user(str_.substr(0,USERNAME_LENGTH), users))) return 0;
    if (!sender->replay_check(false, received_counter)){ delete sender; return 0; }
    //find pubkey of the receiver
    string receiver = str_.substr(USERNAME_LENGTH,2*USERNAME_LENGTH);
    string forwarding_message = aad.substr(MESSAGE_TYPE_LENGTH+COUNTER_LENGTH+Security::GCM_IV_LEN, aad.length());
    //send the message type 10
    int gcm_ciphertext_len;
    if(0 == (gcm_ciphertext_len = send_message_10(sender->get_username(), receiver, forwarding_message, receiver_server_key, users))){
        cerr <<"Erro: sending message 10 failed";
        delete sender;
        return -1;
    }
    delete sender;
    return gcm_ciphertext_len;

}
//sent by the server
unsigned int Message::send_message_10(string source_username, string dest_username, string forwarding_message,
                                    unsigned char* key, vector<User>users){
    User* receiver;
    if(!(receiver = find_user(dest_username, users))) return 0;
    //convert unsigned short to unsigned char                                 
    // unsigned char* server_to_client_counter{nullptr};
    // short_to_char(receiver->get_server_counter() + 1, &server_to_client_counter);
    //initialization vector
    unsigned char* iv{nullptr};
    if(Security::generate_iv(&iv, Security::GCM_IV_LEN)) {
        delete receiver;
        // free(server_to_client_counter);
        return 0;
    }
    //creating aad: message type, server_to_client_counter, iv, public key of receiver, encrypted signature
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH +
                    forwarding_message.length() + 1;
    char * aad = (char*)malloc(aad_len);
    if(!aad){ 
        delete receiver;
        free(iv);
        // free(server_to_client_counter);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return 0;
    }
    aad[0] = 10;
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = receiver->get_server_counter();
    memcpy(aad + MESSAGE_TYPE_LENGTH + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    memcpy(aad + MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN, 
            receiver->get_dh_pubk_char(), DH_PUBK_LENGTH);
    memcpy(aad + MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH, 
            forwarding_message.c_str(), forwarding_message.length());
    // strcpy(aad, "10");
    // strcat(aad,(const char*)server_to_client_counter);
    // strcat(aad,(char*)iv);
    // strcat(aad,pubkey_char);
    // strcat(aad,forwarding_message.c_str());
    //
    int gcm_plaintext_len = source_username.length() + dest_username.length() + 1;
    unsigned char* gcm_plaintext = (unsigned char*)malloc(gcm_plaintext_len);
    strcpy((char*)gcm_plaintext, source_username.c_str());
    strcat((char*)gcm_plaintext, dest_username.c_str());
    //GCM encryption
    unsigned char* gcm_ciphertext{nullptr};
    unsigned char* tag{nullptr};
    int gcm_ciphertext_len = 0;
    if(-1 == (gcm_ciphertext_len = Security::gcm_encrypt((unsigned char *)aad, aad_len , gcm_plaintext, gcm_plaintext_len, 
                                                        key, iv, &gcm_ciphertext, &tag))){
        // free(server_to_client_counter);
        delete receiver;
        free(aad);
        free(iv);
        free(gcm_plaintext);
        free(gcm_ciphertext);
        free(tag);
        return 0;
    }
    ///TODO:Send the data to the network!
    ////
    // free(server_to_client_counter);
    delete receiver;
    free(aad);
    free(iv);
    free(gcm_plaintext);
    free(gcm_ciphertext);
    free(tag);
    return gcm_ciphertext_len;
}
//received by a client
int Message::parse_message_10(char* message, User* my_user){

    string msg (message);
    string tag = msg.substr(msg.length()-Security::GCM_TAG_LEN, msg.length());
    //calculate the inner encryption length
    string aad = msg.substr(0, msg.length() - tag.length() - 2*USERNAME_LENGTH);
    string server_client_ciphertext = msg.substr(aad.length(), msg.length()-tag.length());
    string gcm_iv = msg.substr(MESSAGE_TYPE_LENGTH+COUNTER_LENGTH,MESSAGE_TYPE_LENGTH+COUNTER_LENGTH+Security::GCM_IV_LEN);
    string peer_pubk = msg.substr(MESSAGE_TYPE_LENGTH+COUNTER_LENGTH+Security::GCM_IV_LEN, MESSAGE_TYPE_LENGTH+COUNTER_LENGTH+Security::GCM_IV_LEN+DH_PUBK_LENGTH);
    my_user->set_peer_dh_pubk_char((unsigned char*)peer_pubk.c_str());
    string clients_ciphertext = aad.substr(MESSAGE_TYPE_LENGTH+COUNTER_LENGTH+Security::GCM_IV_LEN+DH_PUBK_LENGTH, aad.length());
    unsigned char*decrypted_server_client{nullptr};
    int decrypted_server_client_len = 0;
    if(-1 == (decrypted_server_client_len = Security::gcm_decrypt((unsigned char*)aad.c_str(), aad.length(), 
                        (unsigned char*)server_client_ciphertext.c_str(), server_client_ciphertext.length(),
                        my_user->get_client_server_key(), 
                        (unsigned char*)gcm_iv.c_str(), &decrypted_server_client,
                        (unsigned char*)tag.c_str()))) return -1;

    string str_ ((char*)decrypted_server_client);
    free(decrypted_server_client);
    //message[0] is the message type
    unsigned short received_counter = 0;
    received_counter = message[1] << 8;  
    received_counter |= message[2];
    //check for replay
    if (!my_user->replay_check(true, received_counter)){ return 0; }
    //decrypt the text between two clients  
    unsigned char*decrypted_clients{nullptr};
    int decrypted_clients_len = 0;

    if(-1 == (decrypted_clients_len = Security::decryption_AES((unsigned char*)clients_ciphertext.c_str(), clients_ciphertext.length(),
                                                                my_user->get_clients_key(), NULL, &decrypted_clients))){ return -1;}
    return decrypted_clients_len;
                                        
}
int main(){
    
    return 1;
}
