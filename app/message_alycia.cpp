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

unsigned int Message::send_message_3(char** msg_buf, User* my_user) {

    // generate iv
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){;
        return 0;
    }

    // msg creation
    int msg_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH;
    char * msg = (char*)malloc(msg_len);
    if(!msg) {
        cerr << "Error: malloc for message returned NULL\n"; 
        return 0;
    }    
    msg[0] = 3;
    uint16_t * counter_pointer = (uint16_t *) (msg + 1);
    *counter_pointer = my_user->get_client_coutner() + 1;

    // encrypt identifier (username) with gcm 
    int id_pt_len = USERNAME_LENGTH;
    unsigned char * id_pt = (unsigned char*)calloc(id_pt_len, 1);
    memcpy(id_pt, (my_user->get_username()).c_str(), my_user->get_username().length());
    unsigned char* id_ct{nullptr};
    unsigned char* tag{nullptr};
    int id_ct_len = 0;
    if(-1 == (id_ct_len = Security::gcm_encrypt((unsigned char *)msg, msg_len , id_pt, id_pt_len, my_user->get_server_client_key(), iv, &id_ct, &tag))){
        free(id_pt);    
        free(id_ct);
        free(tag);
        free(iv);
        free(msg);
        return 0;
    }

    
    int msg_buf_len = msg_len + id_ct_len + Security::GCM_TAG_LEN;
    *msg_buf = (char*)malloc(msg_buf_len);
    memcpy(*msg_buf, msg, msg_len);
    memcpy(*msg_buf + msg_len, id_ct, id_ct_len);
    memcpy(*msg_buf + msg_len + id_ct_len, tag, Security::GCM_TAG_LEN);


    my_user->increment_client_counter();
    free(msg);
    free(iv);
    free(id_pt);
    free(id_ct);
    free(tag);

    return msg_buf_len;
}


//int Message::parse_message_3(char * message, size_t message_len, User* sender, vector<User>users) ;


// message 4

unsigned int Message::send_message_4(char** msg_buf, vector<User> * act_usr, User * dest_user) {

    // generate iv
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){;
        return 0;
    }

    // msg creation
    int msg_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH;
    char * msg = (char*)malloc(msg_len);
    if(!msg) {
        cerr << "Error: malloc for message returned NULL\n"; 
        return 0;
    }    
    msg[0] = 3;
    uint16_t * counter_pointer = (uint16_t *) (msg + 1);
    *counter_pointer = dest_user->get_client_coutner() + 1;


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
    if(-1 == (act_usr_ct_len = Security::gcm_encrypt((unsigned char *)msg, msg_len , act_usr_pt, act_usr_pt_len, dest_user->get_server_client_key(), iv, &act_usr_ct, &tag))){
        free(act_usr_pt);    
        free(act_usr_ct);
        free(tag);
        free(iv);
        free(msg);
        return 0;
    }

    // encrypt identifier (username) with gcm 
    int id_pt_len = USERNAME_LENGTH;
    unsigned char * id_pt = (unsigned char*)calloc(id_pt_len, 1);
    memcpy(id_pt, (dest_user->get_username()).c_str(), dest_user->get_username().length());
    unsigned char* id_ct{nullptr};
    int id_ct_len = 0;
    if(-1 == (id_ct_len = Security::gcm_encrypt((unsigned char *)msg, msg_len , id_pt, id_pt_len, dest_user->get_server_client_key(), iv, &id_ct, &tag))){
        free(id_pt);    
        free(id_ct);
        free(act_usr_pt);    
        free(act_usr_ct);
        free(tag);
        free(iv);
        free(msg);
        return 0;
    }
    
    int msg_buf_len = msg_len + act_usr_ct_len + id_ct_len + Security::GCM_TAG_LEN;
    *msg_buf = (char*)malloc(msg_buf_len);
    memcpy(*msg_buf, msg, msg_len);
    memcpy(*msg_buf + msg_len, act_usr_ct, act_usr_ct_len);
    memcpy(*msg_buf + msg_len + act_usr_ct_len, id_ct, id_ct_len);
    memcpy(*msg_buf + msg_len + act_usr_ct_len + id_ct_len, tag, Security::GCM_TAG_LEN);


    dest_user->increment_server_counter();
    free(msg);
    free(iv);
    free(act_usr_pt);
    free(act_usr_ct);
    free(tag);
    free(id_pt);    
    free(id_ct);

    return msg_buf_len;
}


//int Message::parse_message_4(char * message, size_t message_len, User* sender, vector<User>users) ;