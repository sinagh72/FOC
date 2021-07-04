#include "message_alycia.h"
#include "Security.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <string.h>
#include <iostream>
#include <cstdlib>
#include <stdio.h>

using namespace std;

// message 3

unsigned int Message::create_message_3(char ** msg_buf, User * my_user) {

    // generate iv
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){;
        return 0;
    }

    // aad creation
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN;
    char * aad = (char*)malloc(aad_len);
    if(!aad) {
        cerr << "Error: malloc for message returned NULL\n"; 
        return 0;
    }    
    aad[0] = 3;
    uint16_t * counter_pointer = (uint16_t *) (aad + 1);
    memcpy(aad + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);

    // encrypt identifier (username) with gcm 
    int id_pt_len = USERNAME_LENGTH;
    unsigned char * id_pt = (unsigned char*)calloc(id_pt_len, 1);
    memcpy(id_pt, (my_user->get_username()).c_str(), my_user->get_username().length());
    unsigned char* id_ct{nullptr};
    unsigned char* tag{nullptr};
    int id_ct_len = Security::gcm_encrypt((unsigned char *)aad, aad_len, id_pt, id_pt_len, my_user->get_server_client_key(), iv, &id_ct, &tag);
    if(id_ct_len == -1) {
        free(id_pt);    
        free(id_ct);
        free(tag);
        free(iv);
        free(aad);
        return 0;
    }
    
    int msg_buf_len = aad_len + id_ct_len + Security::GCM_TAG_LEN;
    *msg_buf = (char*)malloc(msg_buf_len);
    memcpy(*msg_buf, aad, aad_len);
    memcpy(*msg_buf + aad_len, id_ct, id_ct_len);
    memcpy(*msg_buf + aad_len + id_ct_len, tag, Security::GCM_TAG_LEN);

    my_user->increment_sent_counter();
    free(aad);
    free(iv);
    free(id_pt);
    free(id_ct);
    free(tag);

    return msg_buf_len;
}


int Message::handle_message_3(char * msg_buf, size_t msg_len, User * my_user){
    int k;
    string msg = "";
    for (k = 0; k < msg_len; k++) {
        msg = msg + msg_buf[k];
    }

    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN;

    string tag = msg.substr(msg.length() - Security::GCM_TAG_LEN, Security::GCM_TAG_LEN);
    string id_ct = msg.substr(aad_len, msg.length() - Security::GCM_TAG_LEN - aad_len);
    string aad = msg.substr(0, aad_len);
    string gcm_iv = msg.substr(aad_len - Security::GCM_IV_LEN, Security::GCM_IV_LEN);

    unsigned char * id_pt{nullptr};
    int id_pt_len = Security::gcm_decrypt((unsigned char*)aad.c_str(), aad_len, (unsigned char*)id_ct.c_str(), id_ct.length(), my_user->get_server_client_key(),(unsigned char*) gcm_iv.c_str(), &id_pt, (unsigned char*)tag.c_str());
    if(id_pt_len == -1) {
        return -1;
    }

    string id_pt_str ((char*)id_pt);
    free(id_pt);
    uint16_t received_counter = (uint16_t) *(msg_buf + 1);
    if(!my_user->replay_check(false, received_counter)){
        return -1;
    }

    if (id_pt_str.compare(my_user->get_username()) != 0) {
        return -1;
    }

    return 1;
}

// message 4

unsigned int Message::create_message_4(char** msg_buf, vector<User> * act_usr, User * dest_user) {

    // generate iv
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){;
        return 0;
    }

    // msg creation
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN;
    char * aad = (char*)malloc(aad_len);
    if(!aad) {
        cerr << "Error: malloc for message returned NULL\n"; 
        return 0;
    }    
    aad[0] = 3;
    uint16_t * counter_pointer = (uint16_t *) (aad + 1);
    memcpy(aad + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);


    // encrypt list of active users with gcm 
    int act_usr_pt_len = act_usr->size() * USERNAME_LENGTH;
    unsigned char * act_usr_pt = (unsigned char*)calloc(act_usr_pt_len, 1);
    int k;
    int count_len_usrnm = 0;
    int len_usrnm;
    for (vector<User>::iterator usr = act_usr->begin(); usr != act_usr->end() ; k++) {
        len_usrnm = (usr->get_username()).length();
        memcpy(act_usr_pt + count_len_usrnm, (usr->get_username()).c_str(), len_usrnm);
        count_len_usrnm += len_usrnm;
    }
    
    unsigned char* act_usr_ct{nullptr};
    unsigned char* tag{nullptr};
    int act_usr_ct_len = 0;
    if(-1 == (act_usr_ct_len = Security::gcm_encrypt((unsigned char *)aad, aad_len , act_usr_pt, act_usr_pt_len, dest_user->get_server_client_key(), iv, &act_usr_ct, &tag))){
        free(act_usr_pt);    
        free(act_usr_ct);
        free(tag);
        free(iv);
        free(aad);
        return 0;
    }

    // encrypt identifier (username) with gcm 
    int id_pt_len = USERNAME_LENGTH;
    unsigned char * id_pt = (unsigned char*)calloc(id_pt_len, 1);
    memcpy(id_pt, (dest_user->get_username()).c_str(), dest_user->get_username().length());
    unsigned char* id_ct{nullptr};
    int id_ct_len = 0;
    if(-1 == (id_ct_len = Security::gcm_encrypt((unsigned char *)aad, aad_len , id_pt, id_pt_len, dest_user->get_server_client_key(), iv, &id_ct, &tag))){
        free(id_pt);    
        free(id_ct);
        free(act_usr_pt);    
        free(act_usr_ct);
        free(tag);
        free(iv);
        free(aad);
        return 0;
    }
    
    int msg_buf_len = aad_len + act_usr_ct_len + id_ct_len + Security::GCM_TAG_LEN;
    *msg_buf = (char*)malloc(msg_buf_len);
    memcpy(*msg_buf, aad, aad_len);
    memcpy(*msg_buf + aad_len, act_usr_ct, act_usr_ct_len);
    memcpy(*msg_buf + aad_len + act_usr_ct_len, id_ct, id_ct_len);
    memcpy(*msg_buf + aad_len + act_usr_ct_len + id_ct_len, tag, Security::GCM_TAG_LEN);


    dest_user->increment_received_counter();
    free(aad);
    free(iv);
    free(act_usr_pt);
    free(act_usr_ct);
    free(tag);
    free(id_pt);    
    free(id_ct);

    return msg_buf_len;
}


int Message::handle_message_4(char * msg_buf, size_t msg_len, User * dest_user){
    int k;
    string msg = "";
    for (k = 0; k < msg_len; k++) {
        msg = msg + msg_buf[k];
    }

    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN;

    string tag = msg.substr(msg.length() - Security::GCM_TAG_LEN, Security::GCM_TAG_LEN);
    string ct = msg.substr(aad_len, msg.length() - Security::GCM_TAG_LEN - aad_len);
    string aad = msg.substr(0, aad_len);
    string gcm_iv = msg.substr(aad_len - Security::GCM_IV_LEN, Security::GCM_IV_LEN);

    unsigned char * pt{nullptr};
    int pt_len = Security::gcm_decrypt((unsigned char*)aad.c_str(), aad_len, (unsigned char*)ct.c_str(), ct.length(), dest_user->get_server_client_key(),(unsigned char*) gcm_iv.c_str(), &pt, (unsigned char*)tag.c_str());
    if(pt_len == -1) {
        return -1;
    }

    string pt_str ((char*)pt);
    free(pt);
    uint16_t received_counter = (uint16_t) *(msg_buf + 1);
    if(!dest_user->replay_check(false, received_counter)){
        return -1;
    }

    string id_pt = pt_str.substr(pt_str.length() - USERNAME_LENGTH, USERNAME_LENGTH);
    string list_act_usr_pt = pt_str.substr(0, pt_str.length() - USERNAME_LENGTH);

    if (id_pt.compare(dest_user->get_username()) != 0) {
        return -1;
    }

    return 1;
}