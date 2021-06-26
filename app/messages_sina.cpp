//this script should be merged and then removed

#include "message_sina.h"
#include "Security.h"
#include <openssl/ossl_typ.h>
#include <string.h>
#include <iostream>
#include <cstdlib>
#include <stdio.h>

using namespace std;

//convert unsigned short to unsigned char
void short_to_char(unsigned short input, unsigned char **array){
    *array = (unsigned char*)malloc(sizeof(input));
    if(!*array){ cerr<< "Error: malloc for converting short to char returned NULL (too big short?)\n"; return;}
    (*array)[0] = (input >> 8);
    (*array)[1] = (input & 0xFF);
    (*array)[2] = '\0';
}
//confirmation message that the session key is received and generated sucessfully 
unsigned int Message::create_message_9(unsigned short client_to_server_counter, 
                                        EVP_PKEY* my_dh_pubk, char* my_dh_pubk_char,
                                        EVP_PKEY* peers_dh_pubk, char* peers_dh_pubk_char,
                                        char* source_username, char* dest_username,
                                        string my_username,
                                        unsigned char* clinets_key, unsigned char* server_client_key){
    //convert unsigned short to unsigned char                                 
    unsigned char* output{nullptr};
    short_to_char(client_to_server_counter, &output);
    //
    int text_to_sign_len =  strlen(my_dh_pubk_char) + strlen(peers_dh_pubk_char) + 1;
    unsigned char * text_to_sign = (unsigned char*)malloc(text_to_sign_len);
    if(!text_to_sign){ cerr<< "Error: malloc for DH pubks signature returned NULL (too big signature?)\n"; return 0;}
    //concatenating the two dh pubks {g^b'||g^a'}
    strcpy((char*)text_to_sign, peers_dh_pubk_char);
    strcat((char*)text_to_sign,my_dh_pubk_char);
    //sign the concatenation {g^b'||g^a'}
    unsigned char* signature{nullptr};
    int signature_len = Security::signature("./users/"+my_username+"/rsa_pubkey.pem", text_to_sign, text_to_sign_len, &signature);
    //Encrypt the digital signature
    unsigned char* cipher_signature{nullptr};
    int cipher_signature_len = Security::encryption_AES(signature, signature_len, clinets_key, NULL, &cipher_signature);
    //initialization vector
    unsigned char* iv{nullptr};
    if(Security::generate_iv(&iv, Security::GCM_IV_LEN)){return 0;}
    //creating aad: message type, client_to_server_counter, iv, encrypted signature
    int aad_len = 1 + sizeof(client_to_server_counter) + Security::GCM_IV_LEN + cipher_signature_len + 1;
    char * aad = (char*)malloc(aad_len);
    strcpy(aad, "9");
    strcat(aad,(const char*)output);
    strcat(aad,(char*)iv);
    strcat(aad,(char*)cipher_signature);
    //
    int gcm_plaintext_len = strlen(source_username) +  strlen(dest_username) + 1;
    unsigned char * gcm_plaintext = (unsigned char*)malloc(gcm_plaintext_len);
    strcpy((char*)gcm_plaintext, source_username);
    strcat((char*)gcm_plaintext, dest_username);
    //GCM encryption
    unsigned char* gcm_ciphertext{nullptr};
    unsigned char* tag{nullptr};
    int gcm_ciphertext_len = Security::gcm_encrypt((unsigned char *)aad, aad_len , gcm_plaintext, gcm_plaintext_len, 
                                                server_client_key, iv, &gcm_ciphertext, &tag);

    ///TODO:Send the data to the network!
    ////

    free(aad);
    free(iv);
    free(signature);
    free(output);
    free(gcm_plaintext);
    free(gcm_ciphertext);
    free(tag);
    return 0;
    
}
