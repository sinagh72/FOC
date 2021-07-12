#include "Message.h"

//sent by the client A
int Message::send_message_0(char **buffer, User* my_user) {

    //generating new dh pubk -> g^a
    EVP_PKEY * g_a{nullptr};
    if(Security::generate_dh_pubk(&g_a) == -1){return 0;}
    my_user->set_client_server_pubk(g_a);
    //serialize the g^a
    unsigned char*a_char{nullptr};
    int a_char_size = Security::EVP_PKEY_to_chars(g_a, &a_char);
    if(a_char_size == -1){ 
        my_user->set_client_server_pubk(nullptr);
        EVP_PKEY_free(g_a);
        return -1;
    }
    my_user->set_client_server_pubk_char(a_char);

    unsigned int message_len = MESSAGE_TYPE_LENGTH + USERNAME_LENGTH + a_char_size;
    *buffer=(char*) malloc(message_len);
    memset(*buffer, 0, 1);
    memcpy(*buffer + MESSAGE_TYPE_LENGTH, my_user->get_username().c_str(), USERNAME_LENGTH);
    memcpy(*buffer + MESSAGE_TYPE_LENGTH + USERNAME_LENGTH, a_char, a_char_size);
    //
    ///TODO: check for the timeout
    ///https://stackoverflow.com/questions/9847441/setting-socket-timeout
    if (message_len != send(my_user->get_socket() , *buffer , message_len , 0)){
        my_user->set_client_server_pubk(nullptr);
        free(a_char);
        EVP_PKEY_free(g_a);
        return -1;
    }

    ///
    free(a_char);
    return message_len;
}

int Message::handle_message_0(char *buffer, int client_socket, char *ip, uint16_t port, vector <User*>*online_users) {

    string ip_str(ip);
    //extract the username
    string username(buffer+MESSAGE_TYPE_LENGTH);

    //extract the DH serialized pubkey
    string dh_pubkey_peer(buffer + MESSAGE_TYPE_LENGTH + USERNAME_LENGTH);

    string file_addr = "./users/"+username+"/rsa_pubkey.pem";
    //find the user RSA pubkey to be sure that he is registered
    FILE* pubkey_file = fopen(file_addr.c_str(), "r");
    if(!pubkey_file) {
        printf("User %s not registered", username.c_str());
        return -1;
    }
    EVP_PKEY* evpPkey;
    evpPkey= PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
    if(!evpPkey) {
        printf("Error: pubkey of user %s not loaded correctly", username.c_str());
        fclose(pubkey_file);
        return -1;
    }
    fclose(pubkey_file);
    EVP_PKEY_free(evpPkey);
    User *client = new User(username,"sina",ip, port, client_socket);
    client->set_status(CONNECTING);
    online_users->insert(online_users->begin(), client);
    cout << client->get_username() << "is connected with ip: " << ip << ", port: " << port << endl;
    //load server certificate from file and serialize it
    X509* cert;
    if(!Security::load_server_certificate(&cert)) {
        delete client;
        return -1;
    }

    unsigned char* certificate_serialized= nullptr;
    int cert_size = 0;
    if((cert_size = Security::X509_serialization(cert, &certificate_serialized)) ==-1) {
        X509_free(cert);
        return -1;
    };


    //server DH pubkey serialization
    long dh_pubkey_server_size;
    unsigned char* dh_pubkey_server_serialized = nullptr;
    EVP_PKEY *dh_pubkey_server = nullptr;
    //generate our own DH pubkey
    Security::generate_dh_pubk(&dh_pubkey_server);
    EVP_PKEY *peer_pubk {nullptr};
    Security::chars_to_EVP_PKEY(&peer_pubk,  (unsigned char*)dh_pubkey_peer.c_str());
    client->set_server_pubk(dh_pubkey_server);
    client->set_client_server_pubk(peer_pubk);


    dh_pubkey_server_size = Security::EVP_PKEY_to_chars(dh_pubkey_server,&dh_pubkey_server_serialized);
    //concatenate and sign DH pubkey
    char* dh_param_to_sign = nullptr;
    Security::serialize_concat_dh_pubkey(client->get_client_server_pubk(), client->get_server_pubk(), &dh_param_to_sign);

    unsigned char* signature = nullptr;
    int signature_len = Security::signature("./server_privK/ChatApp_key.pem", NULL, (unsigned char*)dh_param_to_sign,
                                            2*DH_PUBK_LENGTH, &signature);
    free(dh_param_to_sign);


    

    client->set_client_server_pubk(peer_pubk);

    unsigned char* shared_key= nullptr;
    int shared_key_len = Security::generate_dh_key(dh_pubkey_server, peer_pubk, &shared_key);
    if(shared_key_len==-1) {
        cerr<<"Error generating shared key"<<endl;
        return -1;
    }

    client->set_server_client_key(shared_key, shared_key_len);
    

    //generate IV
    unsigned char* iv= nullptr;
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)) {
        cerr<<"Error generating IV for message type 1";
        return -1;
    }


    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + cert_size + dh_pubkey_server_size+Security::GCM_IV_LEN;
    unsigned char* aad = (unsigned char*)malloc(aad_len);
    if(!aad) {
        cerr<<"Error during space allocation for AAD";
        free(iv);
        return -1;
    }

    memset(aad, 1, 1);
    //uint16_t* counter_pointer = aad[0];
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = client->get_server_counter();
    client->increment_server_counter();

    memcpy(aad+COUNTER_LENGTH+ MESSAGE_TYPE_LENGTH, iv, Security::GCM_IV_LEN);
    memcpy(aad+COUNTER_LENGTH+ MESSAGE_TYPE_LENGTH + Security::GCM_IV_LEN, certificate_serialized, cert_size);
    memcpy(aad+COUNTER_LENGTH+ MESSAGE_TYPE_LENGTH + Security::GCM_IV_LEN+cert_size, dh_pubkey_server_serialized, dh_pubkey_server_size);

    unsigned char* ciphertext= nullptr;
    unsigned char* tag = nullptr;
    int ciphertext_len = Security::gcm_encrypt(aad, aad_len, signature, signature_len, shared_key,
                          iv, &ciphertext, &tag);

    int msg_buffer_len =  aad_len+ciphertext_len+Security::GCM_TAG_LEN;
    char* msg_buffer = nullptr;
    msg_buffer = (char*)malloc(msg_buffer_len);
    if(!msg_buffer) {
        cerr<<"Error allocating buffer for sending message type 1";
        free(iv);
        free(aad);
        return -1;
    }
    memcpy(msg_buffer, aad, aad_len);
    memcpy(msg_buffer+aad_len, ciphertext, ciphertext_len);
    memcpy(msg_buffer+aad_len+ciphertext_len, tag, Security::GCM_TAG_LEN);

    //send the message to the client
    send(client->get_socket(), msg_buffer, msg_buffer_len, 0);
    free(msg_buffer);
    free(aad);
    free(ciphertext);
    free(certificate_serialized);
    free(dh_pubkey_server_serialized);
    free(tag);
    free(iv);
    return msg_buffer_len;
}

int Message::handle_message_1(char *buffer, int buffer_len, User *client) {
    //parsing the incoming message
    uint16_t counter_server = (uint16_t) *(buffer+MESSAGE_TYPE_LENGTH);
    if(counter_server != client->get_server_counter()) {
        cerr<<"Server counter verification failed"<<endl;
        return -1;
    }
    client->increment_server_counter();

    unsigned char* iv = (unsigned char*) malloc(Security::GCM_IV_LEN);
    memcpy(iv, buffer+MESSAGE_TYPE_LENGTH + COUNTER_LENGTH, Security::GCM_IV_LEN);

    string server_certificate_serialized(buffer+MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN);
    
    char* server_dh_pubkey_serialized = (char*) malloc(DH_PUBK_LENGTH);
    memcpy(server_dh_pubkey_serialized, buffer+MESSAGE_TYPE_LENGTH + COUNTER_LENGTH+Security::GCM_IV_LEN+server_certificate_serialized.length()+1, DH_PUBK_LENGTH);

    unsigned char* tag = (unsigned char*)buffer+buffer_len-Security::GCM_TAG_LEN;
    

    int ciphertext_len = buffer_len-MESSAGE_TYPE_LENGTH-COUNTER_LENGTH-Security::GCM_IV_LEN-Security::GCM_TAG_LEN-
                         server_certificate_serialized.length()-1-DH_PUBK_LENGTH;
    unsigned char* ciphertext = (unsigned char*)buffer+buffer_len-Security::GCM_TAG_LEN-ciphertext_len;

    //deserialize DH server pubkey
    EVP_PKEY *server_dh_pubkey= nullptr;
    if(Security::chars_to_EVP_PKEY(&server_dh_pubkey, (unsigned char*)server_dh_pubkey_serialized) <0) {
        cerr<<"Error deserializing DH server pubkey"<<endl;
        free(iv);
        EVP_PKEY_free(server_dh_pubkey);
        return -1;
    }
    client->set_server_pubk(server_dh_pubkey);

    
    // compute symmetric key with DH pubkey
    unsigned char* skey = nullptr;
    int skey_len = Security::generate_dh_key(client->get_client_server_pubk(), server_dh_pubkey, &skey);
    if(skey_len==-1) {
        cerr<<"Error deserializing DH server pubkey"<<endl;
        free(iv);
        free(skey);
        EVP_PKEY_free(server_dh_pubkey);
        return -1;
    }
    client->set_server_client_key(skey, skey_len);

    //verify tag and decrypt signature
    unsigned char* signature = nullptr;
    int aad_len= MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + server_certificate_serialized.length() + 1 + DH_PUBK_LENGTH;

    int signature_len = Security::gcm_decrypt((unsigned char*)buffer, aad_len, ciphertext,ciphertext_len, skey, iv, &signature, tag);

   
    // server certificate validation
    X509* cert = nullptr;
    Security::X509_deserialization((unsigned char*)server_certificate_serialized.c_str(), &cert);
    if(!Security::certificate_verification(cert)) {
        cerr<<"Error in server certificate validation"<<endl;
        free(iv);
        free(skey);
        EVP_PKEY_free(server_dh_pubkey);
        free(signature);
        return -1;
    }
    

    //verify signature
    char* serialized_pair = nullptr;
    
    int serialized_pair_len = Security::serialize_concat_dh_pubkey(client->get_client_server_pubk(), client->get_server_pubk(), &serialized_pair);
    if(serialized_pair_len==-1) {
        cerr<<"Error in server signature verification"<<endl;
        free(iv);
        free(skey);
        EVP_PKEY_free(server_dh_pubkey);
        X509_free(cert);
        free(signature);
        free(serialized_pair);
        return -1;
    }

    if(!Security::verify_signature(X509_get0_pubkey(cert), signature, signature_len, (unsigned char*)serialized_pair, serialized_pair_len)) {
        cerr<<"Error in server signature verification"<<endl;
        free(iv);
        free(skey);
        EVP_PKEY_free(server_dh_pubkey);
        X509_free(cert);
        free(signature);
        free(serialized_pair);
        return -1;
    }
    free(iv);
    free(serialized_pair);
    free(signature);
    X509_free(cert);

    //signature is good, lets make the answer message
    int aad_resp_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN;
    unsigned char* aad_resp = (unsigned char*) malloc(aad_resp_len);
    if(!aad_resp) {
        cerr<<"Message2 aad malloc failed"<<endl;
        free(skey);
        EVP_PKEY_free(server_dh_pubkey);
        return -1;
    }

    memset(aad_resp, 2, 1);

    uint16_t* counter_resp = (uint16_t*) (aad_resp + MESSAGE_TYPE_LENGTH);
    *counter_resp = client->get_client_counter();
    client->increment_client_counter();

    unsigned char* iv_answ= nullptr;
    Security::generate_iv(&iv_answ, Security::GCM_IV_LEN);
    memcpy(aad_resp+MESSAGE_TYPE_LENGTH+COUNTER_LENGTH, iv_answ, Security::GCM_IV_LEN);

    //generate the concatenation and sign it
    char* concat = nullptr;
    int concat_len = Security::serialize_concat_dh_pubkey(client->get_server_pubk(), client->get_client_server_pubk(), &concat);
    if(concat_len==-1) {
        cerr<<"Message2 DH Key concat failed"<<endl;
        free(skey);
        free(iv_answ);
        free(aad_resp);
        EVP_PKEY_free(server_dh_pubkey);
        return -1;
    }
    
    unsigned char* signature_answ = nullptr;
    int signature_answ_len = Security::signature("./users/"+client->get_username()+"/rsa_privkey.pem", 
                                                (unsigned char*)client->get_password().c_str(), 
                                                (unsigned char*)concat, concat_len, &signature_answ);
    if(signature_answ_len==-1) {
        cerr<<"Message2 concat failed"<<endl;
        free(skey);
        free(iv_answ);
        free(aad_resp);
        free(concat);
        free(signature_answ);
        EVP_PKEY_free(server_dh_pubkey);
        return -1;
    }


    //GCM encryption
    unsigned char* ciphertext_answ = nullptr;
    unsigned char* tag_answ = nullptr;
    int ciphertext_answ_len = Security::gcm_encrypt(aad_resp, aad_resp_len, signature_answ, signature_answ_len, skey, iv_answ, &ciphertext_answ, &tag_answ);
    if(ciphertext_answ_len==-1) {
        cerr<<"Message2 encryption failed"<<endl;
        free(skey);
        free(iv_answ);
        free(aad_resp);
        free(concat);
        free(signature_answ);
        EVP_PKEY_free(server_dh_pubkey);
        return -1;
    }

    free(iv_answ);

    int msg_len = Security::GCM_TAG_LEN +  aad_resp_len + ciphertext_answ_len;
    char* msg_to_send = (char*) malloc(msg_len);
    if(!msg_to_send) {
        cerr<<"Message2 allocation failed"<<endl;
        free(skey);
        free(iv_answ);
        free(aad_resp);
        free(concat);
        free(signature_answ);
        free(ciphertext_answ);
        free(tag_answ);
        EVP_PKEY_free(server_dh_pubkey);
        return -1;
    }

    memcpy(msg_to_send, aad_resp, aad_resp_len);
    free(aad_resp);
    memcpy(msg_to_send+ aad_resp_len, ciphertext_answ, ciphertext_answ_len);
    free(ciphertext_answ);
    memcpy(msg_to_send + aad_resp_len + ciphertext_answ_len, tag_answ, Security::GCM_TAG_LEN);
    free(tag_answ);

    //send the message
    if(send(client->get_socket(), msg_to_send, msg_len, 0) != msg_len){
        cerr <<"Error: sending message 2 over the socket failed" << endl;
        free(msg_to_send);
        free(concat);
        free(signature_answ);
        return -1;
    }


    free(msg_to_send);
    free(concat);
    free(signature_answ);
    return 1;

}

int Message::handle_message_2(char *buffer, int buffer_len, User *client) {
    //verify message counter
    uint16_t counter = (uint16_t)*(buffer + MESSAGE_TYPE_LENGTH);
    if(counter != client->get_client_counter()) {
        return -1;
    }
    client->increment_client_counter();

    //set pointer in the incoming buffer
    char* aad = buffer;
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN;
    char* ciphertext = buffer + aad_len;
    int ciphertext_len = buffer_len - Security::GCM_TAG_LEN - aad_len;
    char* tag = buffer + buffer_len - Security::GCM_TAG_LEN;
    char* iv = buffer + MESSAGE_TYPE_LENGTH + COUNTER_LENGTH;

    //verify the tag
    unsigned char* signature = nullptr;
    int signature_len = Security::gcm_decrypt((unsigned char*)aad, aad_len, (unsigned char*)ciphertext, 
    ciphertext_len, client->get_server_client_key(), (unsigned char*)iv, &signature, (unsigned char*)tag);
    if(signature_len==-1) {
        return -1;
    }

    char* concatenated = nullptr;
    int concatenated_len = Security::serialize_concat_dh_pubkey(client->get_server_pubk(), client->get_client_server_pubk(), &concatenated);
    if (concatenated_len==-1) {
        return -1;
    }

    //verify the signature and set status of the user ONLINE
    string file_addr = "./users/"+client->get_username()+"/rsa_pubkey.pem";
    FILE* pubkey_file = fopen(file_addr.c_str(), "r");
    if(!pubkey_file) {
        printf("User %s not registered", client->get_username().c_str());
        return -1;
    }
    EVP_PKEY* evpPkey;
    evpPkey= PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
    if(!evpPkey) {
        printf("Error: pubkey of user %s not loaded correctly", client->get_username().c_str());
        fclose(pubkey_file);
        return -1;
    }
    fclose(pubkey_file);

    if(!Security::verify_signature(evpPkey, signature, signature_len, (unsigned char*)concatenated, concatenated_len)) {
        return -1;
    }

    client->set_status(ONLINE);
    return 1;

}

//sent by the client A
int Message::send_message_3(User * my_user) {
    // generate iv
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){;
        return -1;
    }

    // aad creation
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN;
    char * aad = (char*)malloc(aad_len);
    if(!aad) {
        cerr << "Error: malloc for message returned NULL\n"; 
        return -1;
    }    
    aad[0] = 3;
    uint16_t * counter_pointer = (uint16_t *) (aad + 1);
    *counter_pointer = my_user->get_client_counter();
    my_user->increment_client_counter();
    memcpy(aad + MESSAGE_TYPE_LENGTH + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    // encrypt identifier (username) with gcm 
    int id_pt_len = USERNAME_LENGTH;
    unsigned char * id_pt = (unsigned char*)calloc(id_pt_len, 1);
    memcpy(id_pt, (my_user->get_username()).c_str(), my_user->get_username().length());
    unsigned char* id_ct{nullptr};
    unsigned char* tag{nullptr};

    int id_ct_len = Security::gcm_encrypt((unsigned char *)aad, aad_len, id_pt, id_pt_len, 
    my_user->get_server_client_key(), iv, &id_ct, &tag);
    if(id_ct_len == -1) {
        free(id_pt);    
        free(id_ct);
        free(tag);
        free(iv);
        free(aad);
        return -1;
    }
    
    int msg_buf_len = aad_len + id_ct_len + Security::GCM_TAG_LEN;
    char * msg_buf = (char*)malloc(msg_buf_len);
    memcpy(msg_buf, aad, aad_len);
    memcpy(msg_buf + aad_len, id_ct, id_ct_len);
    memcpy(msg_buf + aad_len + id_ct_len, tag, Security::GCM_TAG_LEN);

    if (msg_buf_len != send(my_user->get_socket(), msg_buf, msg_buf_len , 0)){
        cerr <<"Error: sending message 3 over the socket failed" << endl;
        free(id_pt);    
        free(id_ct);
        free(tag);
        free(iv);
        free(aad);
        free(msg_buf);
        return -1;
    }
 
    free(aad);
    free(iv);
    free(id_pt);
    free(id_ct);
    free(tag);
    free(msg_buf);

    return msg_buf_len;
}

//recevied by the server 
int Message::handle_message_3(char * message, size_t message_len, User * sender, vector<User*>online_users){
    int k;
    string msg = "";
    for (k = 0; k < message_len; k++) {
        msg = msg + message[k];
    }

    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN;

    string tag = msg.substr(msg.length() - Security::GCM_TAG_LEN, Security::GCM_TAG_LEN);
    string id_ct = msg.substr(aad_len, msg.length() - Security::GCM_TAG_LEN - aad_len);
    string aad = msg.substr(0, aad_len);
    string gcm_iv = msg.substr(aad_len - Security::GCM_IV_LEN, Security::GCM_IV_LEN);

    unsigned char * id_pt{nullptr};
    int id_pt_len = Security::gcm_decrypt((unsigned char*)aad.c_str(), aad_len,
     (unsigned char*)id_ct.c_str(), id_ct.length(), 
     sender->get_server_client_key(),(unsigned char*) gcm_iv.c_str(), &id_pt, (unsigned char*)tag.c_str());
    if(id_pt_len == -1) {
        cout << "Erro in handling message 3" << endl;
        return -1;
    }

    string id_pt_str ((char*)id_pt);
    free(id_pt);
    uint16_t server_counter = (uint16_t) *(message + MESSAGE_TYPE_LENGTH);
    if(!sender->replay_check(false, server_counter)){
        return -1;
    }

    if(Message::send_message_4(sender, online_users) == -1){
        cerr <<"Error in sending message 4" << endl;
        return -1;
    }
    cout << "reply message 4 to " << sender->get_username() << endl;
    return 1;
}

//sent by the server to client A
int Message::send_message_4(User* receiver, vector<User*>online_users) {

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
    *counter_pointer = receiver->get_server_counter();
    memcpy(aad + MESSAGE_TYPE_LENGTH + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    receiver->increment_server_counter();

    // encrypt list of active users with gcm 
    int act_usr_pt_len = online_users.size() * USERNAME_LENGTH +  (online_users.size() - 1) * DELIMITER.length();
    unsigned char * act_usr_pt = (unsigned char*)calloc(act_usr_pt_len, 1);
    int count_len_usrnm = 0;
    int len_usrnm;
    for (auto& usr : online_users) {
        len_usrnm = usr->get_username().length();
        memcpy(act_usr_pt + count_len_usrnm, (usr->get_username()).c_str(), len_usrnm);
        count_len_usrnm += len_usrnm;
        //put delimiter between usernames
        memcpy(act_usr_pt + count_len_usrnm, DELIMITER.c_str(), DELIMITER.length());
        count_len_usrnm += DELIMITER.length();
    }
    unsigned char* act_usr_ct{nullptr};
    unsigned char* tag{nullptr};
    int act_usr_ct_len = 0;
    if(-1 == (act_usr_ct_len = Security::gcm_encrypt((unsigned char *)aad, aad_len , act_usr_pt, act_usr_pt_len, 
                receiver->get_server_client_key(), iv, &act_usr_ct, &tag))){
        free(act_usr_pt);    
        free(iv);
        free(aad);
        return 0;
    } 
    int msg_buf_len = aad_len + act_usr_ct_len + Security::GCM_TAG_LEN;
    char * msg_buf = (char*)malloc(msg_buf_len);
    memcpy(msg_buf, aad, aad_len);
    memcpy(msg_buf + aad_len, act_usr_ct, act_usr_ct_len);
    memcpy(msg_buf + aad_len + act_usr_ct_len, tag, Security::GCM_TAG_LEN);

    if (msg_buf_len != send(receiver->get_socket(), msg_buf, msg_buf_len , 0)){
        cerr <<"Error: sending message 4 over the socket failed" << endl;
        free(aad);
        free(iv);
        free(act_usr_pt);
        free(act_usr_ct);
        free(tag);
        free(msg_buf);
        return -1;
        
    }

    free(aad);
    free(iv);
    free(act_usr_pt);
    free(act_usr_ct);
    free(tag);
    free(msg_buf);
    return msg_buf_len;
}

//recevied by the client A 
int Message::handle_message_4(User * my_user, vector<string>*usernames){

    char*message = (char*)malloc(MAX_MESSAGE_LENGTH);
    int val_read = read(my_user->get_socket(), message, MAX_MESSAGE_LENGTH);

    int k;
    string msg = "";
    for (k = 0; k < val_read; k++) {
        msg = msg + message[k];
    }

    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN;

    string tag = msg.substr(msg.length() - Security::GCM_TAG_LEN, Security::GCM_TAG_LEN);
    string ct = msg.substr(aad_len, msg.length() - Security::GCM_TAG_LEN - aad_len);
    string aad = msg.substr(0, aad_len);
    string gcm_iv = msg.substr(aad_len - Security::GCM_IV_LEN, Security::GCM_IV_LEN);

    unsigned char * pt{nullptr};
    int pt_len = Security::gcm_decrypt((unsigned char*)aad.c_str(), aad_len, (unsigned char*)ct.c_str(), ct.length(), 
    my_user->get_server_client_key(),(unsigned char*) gcm_iv.c_str(), &pt, (unsigned char*)tag.c_str());
    if(pt_len == -1) {
        return -1;
    }

    string pt_str ((char*)pt);
    free(pt);
    uint16_t server_counter = (uint16_t) *(message + MESSAGE_TYPE_LENGTH);
    if(!my_user->replay_check(true, server_counter)){
        return -1;
    }
    size_t pos = 0;
    string token;
    while ((pos = pt_str.find(DELIMITER)) != string::npos) {
        token = pt_str.substr(0, pos);
        if(token.compare(my_user->get_username()) != 0)
            usernames->push_back(token);
        pt_str.erase(0, pos + DELIMITER.length());
    }
    return usernames->size();
}

//sent by the client A
int Message::send_message_5(User* my_user, string receiver_username){
    //generating new dh pubk -> g^a'
    EVP_PKEY * newA{nullptr};
    if(Security::generate_dh_pubk(&newA) == -1){return -1;}
    my_user->set_clients_pubk(newA);
    //initialization vector
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){
        my_user->set_clients_pubk(nullptr);
        EVP_PKEY_free(newA);
        return -1;
    }
    //creating aad: message type, client_to_server_counter, iv, generated dh public key
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH;
    char * aad = (char*)malloc(aad_len);
    if(!aad){
        my_user->set_clients_pubk(nullptr);
        EVP_PKEY_free(newA);
        free(iv);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return -1;
    }
    
    aad[0] = 5;
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = my_user->get_client_counter();
    //add iv to aad
    memcpy(aad + MESSAGE_TYPE_LENGTH + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    unsigned char*newA_char{nullptr};
    if(Security::EVP_PKEY_to_chars(newA, &newA_char) == -1){ 
        my_user->set_clients_pubk(nullptr);
        EVP_PKEY_free(newA);
        free(iv);
        return -1;
    }
    my_user->set_clients_pubk_char(newA_char);
    //add generated dh public key to aad
    memcpy(aad + MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN, newA_char, DH_PUBK_LENGTH);
    //generate the gcm plaintext: sender username||receiver username
    int gcm_plaintext_len = 2*USERNAME_LENGTH;
    unsigned char* gcm_plaintext = (unsigned char*)calloc(gcm_plaintext_len, 1);
     if(!gcm_plaintext){
        EVP_PKEY_free(newA);
        my_user->set_clients_pubk(nullptr);
        free(iv);
        free(aad);
        cerr<< "Error: malloc for gcm plaintext returned NULL (too big usernames?)\n"; return -1;
    }
    memcpy(gcm_plaintext, (my_user->get_username()+receiver_username).c_str(), 
                            my_user->get_username().length()+receiver_username.length());

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
        free(iv);
        free(aad);
        return -1;
    }
    //
    int message_buf_len = aad_len + gcm_ciphertext_len + Security::GCM_TAG_LEN;
    char * message_buf = (char*)malloc(message_buf_len);
    memcpy(message_buf, aad, aad_len);
    memcpy(message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);

    if(send(my_user->get_socket(), message_buf, message_buf_len, 0) != message_buf_len){
        cerr <<"Error: sending message 5 over the socket failed" << endl;
        free(aad);
        free(iv);
        free(gcm_plaintext);
        free(gcm_ciphertext);
        free(tag);
        free(message_buf);
        return -1;
    }

    my_user->increment_client_counter();

    free(aad);
    free(iv);
    free(gcm_plaintext);
    free(gcm_ciphertext);
    free(tag);
    free(message_buf);
    return message_buf_len;
}
//recevied by the server 
int Message::handle_message_5(char * message, size_t message_len, User* sender, vector<User*>online_users){
    int i;
    string msg = "";
    for (i = 0; i < message_len; i++) {
        msg = msg + message[i];
    }
    string tag = msg.substr(msg.length() - Security::GCM_TAG_LEN, Security::GCM_TAG_LEN);
    string ciphertext = msg.substr(msg.length() - Security::GCM_TAG_LEN - 2 * USERNAME_LENGTH, 2 * USERNAME_LENGTH);
    string aad = msg.substr(0, msg.length() - ciphertext.length() - tag.length());
    string gcm_iv = msg.substr(COUNTER_LENGTH + MESSAGE_TYPE_LENGTH, Security::GCM_IV_LEN);
    unsigned char *decryptedtext{nullptr};
    int decryptedtext_len = 0;

    if(-1==(decryptedtext_len = Security::gcm_decrypt((unsigned char*)aad.c_str(), aad.length(), 
                                (unsigned char*)ciphertext.c_str(), ciphertext.length(),
                                sender->get_server_client_key(),(unsigned char*) gcm_iv.c_str(), &decryptedtext, 
                                (unsigned char*)tag.c_str()))){


        return -1;
    }
    string decryptedtext_str ((char*)decryptedtext);
    free(decryptedtext);
    uint16_t server_counter = (uint16_t) *(message + MESSAGE_TYPE_LENGTH);
    if(!sender->replay_check(false, server_counter)){
        return -1;
    }
    string dh_key = aad.substr(MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN, DH_PUBK_LENGTH); 
    sender->set_clients_pubk_char((unsigned char *)dh_key.c_str());
    string receiver_username = decryptedtext_str.substr(sender->get_username().length(),
                                decryptedtext_str.length() - sender->get_username().length());
    sender->set_peer_username(receiver_username);

    cout << "handling message 5 from " << sender->get_username()<<endl;

    User * receiver = find_user(sender->get_peer_username(), &online_users);
    if(receiver == nullptr){
       return -1;
    }
    if(Message::send_message_6(sender, receiver) == -1){
        cerr <<"Error in sending message 6" << endl;
        return -1;
    }
    cout << "forwarding message 6 from " << sender->get_username() <<" to " << receiver->get_username()<<endl;
    return 1;
}
//sent by the server to client B
int Message::send_message_6(User* sender, User* receiver){
    //
    //initialization vector
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){return -1;}
    //creating aad: message type, client_to_server_counter, iv, generated dh public key
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH;
    char * aad = (char*)malloc(aad_len);
    if(!aad){
        free(iv);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return -1;
    }
    //insert message type into aad
    aad[0] = 6;
    //insert counter into aad
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = receiver->get_server_counter();
    //insert the iv into aad
    memcpy(aad +  MESSAGE_TYPE_LENGTH +  COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //insert the generated dh public key into the aad
    memcpy(aad +  MESSAGE_TYPE_LENGTH +  COUNTER_LENGTH + Security::GCM_IV_LEN, sender->get_clients_pubk_char(), DH_PUBK_LENGTH);
    //generate the gcm plaintext: sender username||receiver username
    int gcm_plaintext_len = 2*USERNAME_LENGTH;
    unsigned char* gcm_plaintext = (unsigned char*)calloc(gcm_plaintext_len, 1);
    if(!gcm_plaintext){
        free(iv);
        free(aad);
        cerr<< "Error: malloc for gcm plaintext returned NULL (too big usernames?)\n"; return -1;
    }
    memcpy(gcm_plaintext, (sender->get_username()+receiver->get_username()).c_str(), 
                            sender->get_username().length()+receiver->get_username().length());

    
    //GCM encryption
    unsigned char* gcm_ciphertext{nullptr};
    unsigned char* tag{nullptr};
    int gcm_ciphertext_len = 0;
    ///TODO:
    if(-1 == (gcm_ciphertext_len = Security::gcm_encrypt((unsigned char *)aad, aad_len , gcm_plaintext, gcm_plaintext_len, 
                                                        receiver->get_server_client_key(), 
                                                        iv, &gcm_ciphertext, &tag))){ 

        free(gcm_plaintext);    
        free(iv);
        free(aad);
        return -1;
    }
    int message_buf_len = aad_len + gcm_ciphertext_len + Security::GCM_TAG_LEN;
    char * message_buf = (char*)malloc(message_buf_len);
    memcpy(message_buf, aad, aad_len);
    memcpy(message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);

    if(send(receiver->get_socket(), message_buf, message_buf_len, 0) != message_buf_len){
        cerr <<"Error: sending message 6 over the socket failed" << endl;
        free(gcm_plaintext);    
        free(gcm_ciphertext);
        free(tag);
        free(iv);
        free(aad);
        free(message_buf);
        return -1;
    }
    receiver->increment_server_counter();
    free(aad);
    free(iv);
    free(gcm_plaintext);
    free(gcm_ciphertext);
    free(tag);
    free(message_buf);
    return message_buf_len;
}
//received by the client B
int Message::handle_message_6(User*my_user){
    
    char*message = (char*)malloc(MESSAGE_6_LENGTH);
    int val_read = read(my_user->get_socket(), message, MESSAGE_6_LENGTH);

    if(val_read != MESSAGE_6_LENGTH){
        cerr << "Error in reading message 6 data" << endl;
        return -1;
    }
    string msg = "";
    for (int i = 0; i < val_read; i++) {
        msg = msg + message[i];
    }
    string tag = msg.substr(msg.length() - Security::GCM_TAG_LEN, Security::GCM_TAG_LEN);
    string ciphertext = msg.substr(msg.length() - Security::GCM_TAG_LEN - 2 * USERNAME_LENGTH, 2 * USERNAME_LENGTH);
    string aad = msg.substr(0, msg.length() - ciphertext.length() - tag.length());
    string gcm_iv = msg.substr(COUNTER_LENGTH + MESSAGE_TYPE_LENGTH, Security::GCM_IV_LEN);


    // unsigned char* tag_c = message + message_len - Security::GCM_TAG_LEN;
    // unsigned char* ciphertext_c = message + message_len - Security::GCM_TAG_LEN - 2 * USERNAME_LENGTH;
    // unsigned char* aad_c = message;
    // unsigned char* gcm_iv_c = message + COUNTER_LENGTH + MESSAGE_TYPE_LENGTH;


    unsigned char *decryptedtext{nullptr};
    int decryptedtext_len = 0;

    if(-1==(decryptedtext_len = Security::gcm_decrypt((unsigned char*)aad.c_str(), aad.length(), 
                                (unsigned char*)ciphertext.c_str(), ciphertext.length(),
                                my_user->get_server_client_key(),(unsigned char*) gcm_iv.c_str(), &decryptedtext, 
                                (unsigned char*)tag.c_str()))){
        return -1;
    }
    string decryptedtext_str ((char*)decryptedtext);
    free(decryptedtext);
    uint16_t server_counter = (uint16_t) *(message + MESSAGE_TYPE_LENGTH);
    if(!my_user->replay_check(true, server_counter)){
        return -1;
    }
    string sender_username = decryptedtext_str.substr(0,
                                decryptedtext_str.length() - my_user->get_username().length());
    my_user->set_peer_username(sender_username);
    //
    //accept or reject the request to talk
    string input;
    do{
        cout << sender_username << " has requested to talk to you.\nPlease Select an Option:\n"
        <<"1. Accept"<<endl
        <<"0. Reject"<<endl;
        cin >> input;
    }while(!check_user_input(input, 2));

    if(input.compare("0") == 0){
        if (send_message_11(my_user) == -1){
            return -1;
        }
        return 0;
    }
    ///if user accepts
    char * dh = message + MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN;
    string dh_key = aad.substr(MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN, DH_PUBK_LENGTH); 
    my_user->set_peer_pubk_char((unsigned char *)dh_key.c_str());

    if(-1 == Message::send_message_7(my_user)){
        cout <<"Error in sending message 7" <<endl;
        return -1;
    }
    return 1;

}
//sent by the client B
int Message::send_message_7(User* my_user){
    //generating new dh pubk g^b'
    EVP_PKEY * newB{nullptr};

    if(Security::generate_dh_pubk(&newB) == -1){return -1;}
    my_user->set_clients_pubk(newB);

    BIO *bio{nullptr};
    unsigned char *newB_char{nullptr};
    if(Security::EVP_PKEY_to_chars(newB ,&newB_char) == -1){
        EVP_PKEY_free(newB);
        my_user->set_clients_pubk(nullptr);
        return -1;
    }
    my_user->set_clients_pubk_char(newB_char);
    //convert peers pubk char into EVP_PKEY
    BIO *mbio{nullptr};
    EVP_PKEY * peer_pubk{nullptr};
    if(Security::chars_to_EVP_PKEY(&peer_pubk , my_user->get_peer_pubk_char()) == -1){
        EVP_PKEY_free(newB);
        my_user->set_clients_pubk(nullptr);
        my_user->set_clients_pubk_char(nullptr);
        return -1;
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
        EVP_PKEY_free(peer_pubk);
        return -1;
    }
    //put g^a' into the buffer
    memcpy(text_to_sign, my_user->get_peer_pubk_char(), DH_PUBK_LENGTH);
    //put g^b' into the buffer
    memcpy(text_to_sign+DH_PUBK_LENGTH, my_user->get_clients_pubk_char(), DH_PUBK_LENGTH);
    //sign the concatenation

    unsigned char *signature{nullptr};
    int signature_len = 0;
    if((signature_len = Security::signature("./users/"+my_user->get_username()+"/rsa_privkey.pem", 
                                            (unsigned char*) my_user->get_password().c_str(), text_to_sign, 
                                            2*DH_PUBK_LENGTH, &signature)) == -1){
        
        EVP_PKEY_free(newB);
        free(text_to_sign);
        my_user->set_clients_pubk(nullptr);
        my_user->set_clients_pubk_char(nullptr);
        my_user->set_peer_pubk(nullptr);
        EVP_PKEY_free(peer_pubk);
        return -1;
    }
    //generating session key between two client
    unsigned char * clients_key{nullptr};
    unsigned int clients_key_len = 0;
    if((clients_key_len = Security::generate_dh_key(my_user->get_clients_pubk(), my_user->get_peer_pubk(), &clients_key)) == -1){
        EVP_PKEY_free(newB);
        free(text_to_sign);
        my_user->set_clients_pubk(nullptr);
        my_user->set_clients_pubk_char(nullptr);
        my_user->set_peer_pubk(nullptr);
        free(signature);
        EVP_PKEY_free(peer_pubk);
        return -1;
    }
    my_user->set_clients_key(clients_key, clients_key_len);

    //encrypt the signature with the session key
    unsigned char* ciphertext{nullptr};
    int ciphertext_len = 0;
    if((ciphertext_len = Security::encryption_AES(signature, signature_len, my_user->get_clients_key(), NULL, &ciphertext)) == -1){
        EVP_PKEY_free(newB);
        free(text_to_sign);
        my_user->set_clients_pubk(nullptr);
        my_user->set_clients_pubk_char(nullptr);
        my_user->set_peer_pubk(nullptr);
        my_user->set_clients_key(nullptr, 0);
        free(signature);
        free(clients_key);
        EVP_PKEY_free(peer_pubk);
        return -1;
    }
     //initialization vector
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){
        EVP_PKEY_free(newB);
        free(text_to_sign);
        my_user->set_clients_pubk(nullptr);
        my_user->set_clients_pubk_char(nullptr);
        my_user->set_peer_pubk(nullptr);
        my_user->set_clients_key(nullptr, 0);
        free(signature);
        free(ciphertext);
        free(clients_key);
        EVP_PKEY_free(peer_pubk);
        return -1;
    }

    //creating aad: message type, client_to_server_counter, iv, generated dh public key,encrypted signature
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH + ciphertext_len;
    char * aad = (char*)malloc(aad_len);
    if(!aad){
        EVP_PKEY_free(newB);
        free(text_to_sign);
        my_user->set_clients_pubk(nullptr);
        my_user->set_clients_pubk_char(nullptr);
        my_user->set_peer_pubk(nullptr);
        my_user->set_clients_key(nullptr, 0);
        free(signature);
        free(iv);
        free(ciphertext);
        free(clients_key);
        EVP_PKEY_free(peer_pubk);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return -1;
    }
    //put message type into aad
    aad[0] = 7;
    //put counter into the aad
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = my_user->get_client_counter();
    //put the iv into the aad
    memcpy(aad + MESSAGE_TYPE_LENGTH +  COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //put the generated dh public key into the aad
    memcpy(aad + MESSAGE_TYPE_LENGTH +  COUNTER_LENGTH + Security::GCM_IV_LEN, my_user->get_clients_pubk_char(), DH_PUBK_LENGTH);
    //put the encryption of signature into the aad
    memcpy(aad + MESSAGE_TYPE_LENGTH +  COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH, ciphertext, ciphertext_len);
    //generate the gcm plaintext: sender username||receiver username
    int gcm_plaintext_len = 2*USERNAME_LENGTH;
    unsigned char* gcm_plaintext = (unsigned char*)calloc(gcm_plaintext_len, 1);
    if(!gcm_plaintext){
        EVP_PKEY_free(newB);
        free(text_to_sign);
        my_user->set_clients_pubk(nullptr);
        my_user->set_clients_pubk_char(nullptr);
        my_user->set_peer_pubk(nullptr);
        my_user->set_clients_key(nullptr, 0);
        free(signature);
        free(iv);
        free(ciphertext);
        free(clients_key);
        EVP_PKEY_free(peer_pubk);
        free(aad);
        cerr<< "Error: malloc for gcm plaintext returned NULL (too big usernames?)\n"; return -1;
    }
    memcpy(gcm_plaintext, (my_user->get_username()+my_user->get_peer_username()).c_str(), 
                            my_user->get_username().length()+my_user->get_peer_username().length());
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
        my_user->set_clients_key(nullptr, 0);
        free(signature);
        free(iv);
        free(ciphertext);
        free(aad);
        free(clients_key);
        EVP_PKEY_free(peer_pubk);
        return -1;
    }
    int message_buf_len = aad_len + gcm_ciphertext_len + Security::GCM_TAG_LEN;
    char * message_buf = (char*)malloc(message_buf_len);
    memcpy(message_buf, aad, aad_len);
    memcpy(message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);
    //Send the data to the network!
    if(send(my_user->get_socket(), message_buf, message_buf_len, 0) != message_buf_len){
        cerr <<"Error: sending message 7 over the socket failed" << endl;
        my_user->set_clients_pubk(nullptr);
        my_user->set_clients_pubk_char(nullptr);
        my_user->set_peer_pubk(nullptr);
        my_user->set_clients_key(nullptr, 0);
        EVP_PKEY_free(newB);
        EVP_PKEY_free(peer_pubk);
        free(text_to_sign);
        free(signature);
        free(iv);
        free(ciphertext);
        free(aad);
        free(gcm_ciphertext);
        free(clients_key);
        free(message_buf);
        return -1;
    }
    ////
    EVP_PKEY_free(newB);
    EVP_PKEY_free(peer_pubk);
    free(text_to_sign);
    my_user->increment_client_counter();
    free(signature);
    free(iv);
    free(ciphertext);
    free(aad);
    free(gcm_ciphertext);
    free(clients_key);
    free(message_buf);
    return message_buf_len;
}
//recevied by the server 
int Message::handle_message_7(char * message, size_t message_len, User* sender, vector<User*>users){
    int i;
    string msg = "";
    for (i = 0; i < message_len; i++) {
        msg = msg + message[i];
    }
    string tag = msg.substr(msg.length() - Security::GCM_TAG_LEN, Security::GCM_TAG_LEN);
    string gcm_ciphertext = msg.substr(msg.length() - Security::GCM_TAG_LEN - 2 * USERNAME_LENGTH, 2 * USERNAME_LENGTH);
    string aad = msg.substr(0, msg.length() - gcm_ciphertext.length() - tag.length());
    string gcm_iv = msg.substr(COUNTER_LENGTH + MESSAGE_TYPE_LENGTH, Security::GCM_IV_LEN);
    string clients_ciphertext_str = aad.substr(MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH, 
                                            aad.length() - MESSAGE_TYPE_LENGTH - COUNTER_LENGTH - Security::GCM_IV_LEN - DH_PUBK_LENGTH);

    unsigned char *gcm_decryptedtext{nullptr};
    
    if(-1==(Security::gcm_decrypt((unsigned char*)aad.c_str(), aad.length(), 
                                (unsigned char*)gcm_ciphertext.c_str(), gcm_ciphertext.length(),
                                sender->get_server_client_key(),(unsigned char*) gcm_iv.c_str(), &gcm_decryptedtext, 
                                (unsigned char*)tag.c_str()))){                       
        return -1;
    }
    
    string gcm_decryptedtext_str ((char*)gcm_decryptedtext);
    free(gcm_decryptedtext);
    uint16_t server_counter = (uint16_t) *(message + MESSAGE_TYPE_LENGTH);
    if(!sender->replay_check(false, server_counter)){
        return -1;
    }
    sender->set_peer_username(gcm_decryptedtext_str.substr(sender->get_username().length(), 
                                                            gcm_decryptedtext_str.length() - sender->get_username().length()));
    
    string dh_key = aad.substr(MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN, DH_PUBK_LENGTH);
    sender->set_clients_pubk_char((unsigned char *)dh_key.c_str());
    cout << "handling message 7 from " << sender->get_username()<<endl;
    User * receiver = find_user(sender->get_peer_username(), &users);
    if(receiver == nullptr){
        return -1;
    }
    if(Message::send_message_8(sender, receiver,(unsigned char*) clients_ciphertext_str.c_str(),
                                    clients_ciphertext_str.length()) == -1){
        cerr <<"Error in sending message 8" << endl;
        return -1;
    }
    cout << "forwarding message 8 from " << sender->get_username() <<" to " << receiver->get_username()<<endl;
    return clients_ciphertext_str.length();

}
//sent by the server to client A
int Message::send_message_8(User* sender, User* receiver, unsigned char * clients_ciphertext, int clients_ciphertext_len){
    //initialization vector
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){return -1;}
    //load and send the rsa_public key of the sender
    // load rsa public key:
    string filename = "./users/"+sender->get_username() + "/rsa_pubkey.pem";
    FILE* pubk_file = fopen(filename.c_str(), "r");
    if(!pubk_file){ cerr << "Error: cannot open file '" << filename << "' (missing?)\n"; exit(1); }
    EVP_PKEY* pubk = PEM_read_PUBKEY(pubk_file, NULL, NULL, NULL);
    fclose(pubk_file);
    if(!pubk){ cerr << "Error: PEM_read_PUBKEY returned NULL\n"; exit(1); }

    //serialize the rsa public key
    unsigned char *pk_buf{nullptr};
    int rsa_buf_size = 0;
    if(-1==(rsa_buf_size = Security::EVP_PKEY_to_chars(pubk, &pk_buf))){
        free(iv);
        EVP_PKEY_free(pubk);
        return -1;
    }
    //creating aad: message type, client_to_server_counter, iv, generated dh public key, rsa publick key, encrypted signature
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH + 
                    (rsa_buf_size - 1) + clients_ciphertext_len;
    char * aad = (char*)malloc(aad_len);
    if(!aad){
        free(pk_buf);
        free(iv);
        EVP_PKEY_free(pubk);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return -1;
    }
    //put the message type into aad
    aad[0] = 8;
    //put the counter into aad
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = receiver->get_server_counter();
    //put the iv into the aad
    memcpy(aad + MESSAGE_TYPE_LENGTH +  COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //put the generated dh public key into the aad
    memcpy(aad + MESSAGE_TYPE_LENGTH +  COUNTER_LENGTH + Security::GCM_IV_LEN, sender->get_clients_pubk_char(), DH_PUBK_LENGTH);
    //put the rsa public key into the aad 
    memcpy(aad + MESSAGE_TYPE_LENGTH +  COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH, pk_buf, (rsa_buf_size - 1));
    //put the encrypted signature into the aad
    memcpy(aad + MESSAGE_TYPE_LENGTH +  COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH + (rsa_buf_size - 1), clients_ciphertext,
                                                                                        clients_ciphertext_len);

    //generate the gcm plaintext: sender username||receiver username
    int gcm_plaintext_len = 2*USERNAME_LENGTH;
    unsigned char* gcm_plaintext = (unsigned char*)calloc(gcm_plaintext_len, 1);
    if(!gcm_plaintext){
        free(pk_buf);
        free(iv);
        free(aad);
        EVP_PKEY_free(pubk);
        cerr<< "Error: malloc for gcm plaintext returned NULL (too big usernames?)\n"; return -1;
    }
    memcpy(gcm_plaintext, (sender->get_username()+receiver->get_username()).c_str(), 
                            sender->get_username().length()+receiver->get_username().length());
    //GCM encryption
    unsigned char* gcm_ciphertext{nullptr};
    unsigned char* tag{nullptr};
    int gcm_ciphertext_len = 0;
    if(-1 == (gcm_ciphertext_len = Security::gcm_encrypt((unsigned char *)aad, aad_len , gcm_plaintext, gcm_plaintext_len, 
                                                        receiver->get_server_client_key(), 
                                                        iv, &gcm_ciphertext, &tag))){
        EVP_PKEY_free(pubk);
        free(gcm_plaintext);    
        free(iv);
        free(aad);
        free(pk_buf);
        return gcm_ciphertext_len;
    }

    int message_buf_len = aad_len + gcm_ciphertext_len + Security::GCM_TAG_LEN;
    char * message_buf = (char*)malloc(message_buf_len);
    memcpy(message_buf, aad, aad_len);
    memcpy(message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);
    //Send the data to the network!
    if(send(receiver->get_socket(), message_buf, message_buf_len, 0) != message_buf_len){
        cerr <<"Error: sending message 8 over the socket failed" << endl;
        free(aad);
        free(iv);
        free(gcm_plaintext);
        free(gcm_ciphertext);
        free(tag);
        free(pk_buf);
        EVP_PKEY_free(pubk);
        free(message_buf);
        return -1;
    }
    ////
    receiver->increment_server_counter();
    free(aad);
    free(iv);
    free(gcm_plaintext);
    free(gcm_ciphertext);
    free(tag);
    free(pk_buf);
    EVP_PKEY_free(pubk);
    sender->set_clients_pubk_char(nullptr);//remove it
    receiver->set_peer_username(sender->get_username());
    return message_buf_len;
}
//received by the client A
int Message::handle_message_8(char* message, size_t message_len, User * my_user){
    int i;
    string msg = "";
    for (i = 0; i < message_len; i++) {
        msg = msg + message[i];
    }
    string tag = msg.substr(msg.length() - Security::GCM_TAG_LEN, Security::GCM_TAG_LEN);
    string gcm_ciphertext = msg.substr(msg.length() - Security::GCM_TAG_LEN - 2 * USERNAME_LENGTH, 2 * USERNAME_LENGTH);
    string aad = msg.substr(0, msg.length() - gcm_ciphertext.length() - tag.length());
    string gcm_iv = msg.substr(COUNTER_LENGTH + MESSAGE_TYPE_LENGTH, Security::GCM_IV_LEN);
    string clients_ciphertext_str = aad.substr(MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH + RSA_PUBK_LENGTH, 
                                            aad.length() - RSA_PUBK_LENGTH - MESSAGE_TYPE_LENGTH - COUNTER_LENGTH - Security::GCM_IV_LEN - DH_PUBK_LENGTH);
    unsigned char *gcm_decryptedtext{nullptr};

    if(-1==(Security::gcm_decrypt((unsigned char*)aad.c_str(), aad.length(), 
                                (unsigned char*)gcm_ciphertext.c_str(), gcm_ciphertext.length(),
                                my_user->get_server_client_key(),(unsigned char*) gcm_iv.c_str(), &gcm_decryptedtext, 
                                (unsigned char*)tag.c_str()))){
        return -1;
    }
    string gcm_decryptedtext_str ((char*)gcm_decryptedtext);
    free(gcm_decryptedtext);
    uint16_t server_counter = (uint16_t) *(message + MESSAGE_TYPE_LENGTH);
    if(!my_user->replay_check(true, server_counter)){
        return -1;
    }
    string dh_key = aad.substr(MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN, DH_PUBK_LENGTH);
    //deserialize the peer dh public key
    EVP_PKEY *peers_pubk{nullptr};
    if(Security::chars_to_EVP_PKEY(&peers_pubk,(unsigned char *) dh_key.c_str()) == -1){
        return -1;
    }
    unsigned char * clients_key{nullptr};
    int clients_key_len = 0;
    if(-1 == (clients_key_len = Security::generate_dh_key(my_user->get_clients_pubk(), peers_pubk, &clients_key))){
        EVP_PKEY_free(peers_pubk);
        return -1;
    }
    //decrypt the clients cipher text
    int clients_decryptext_len = 0;
    unsigned char * clients_decryptext{nullptr};
    if(-1 == (clients_decryptext_len = Security::decryption_AES((unsigned char *)clients_ciphertext_str.c_str(), 
                                                                clients_ciphertext_str.length(), 
                                                                clients_key, NULL, &clients_decryptext))){
        
        EVP_PKEY_free(peers_pubk);
        return -1;
    }
    string rsa_pubk_str = aad.substr(MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH, RSA_PUBK_LENGTH);
    //desrialize the rsa public key
    EVP_PKEY *pkey{nullptr};
    if(-1 == Security::chars_to_EVP_PKEY(&pkey, (unsigned char *)rsa_pubk_str.c_str())){
        free(clients_decryptext);
        EVP_PKEY_free(peers_pubk);
        return -1;
    }
    //generating the clear text for verification of the signature
    //concatenation g^a'||g^b'
    unsigned char* text_to_sign = (unsigned char*)malloc(2*DH_PUBK_LENGTH);
    if(!text_to_sign){
        cerr <<"malloc for concatenation returned NULL (text_to_sign is too big?)"<<endl;
        free(clients_decryptext);
        EVP_PKEY_free(peers_pubk);
        EVP_PKEY_free(pkey);
        return -1;
    }
    //put g^a' into the buffer
    memcpy(text_to_sign, my_user->get_clients_pubk_char(), DH_PUBK_LENGTH);
    //put g^b' into the buffer
    memcpy(text_to_sign + DH_PUBK_LENGTH,(unsigned char *)dh_key.c_str(), DH_PUBK_LENGTH);

    //verify the signature
    if(-1 == Security::verify_signature(pkey, clients_decryptext, clients_decryptext_len, text_to_sign,2*DH_PUBK_LENGTH)){
        free(clients_decryptext);
        EVP_PKEY_free(peers_pubk);
        free(text_to_sign);
        EVP_PKEY_free(pkey);
        return -1;
    }
    my_user->set_clients_key(clients_key, clients_key_len);
    my_user->set_peer_pubk_char((unsigned char *)dh_key.c_str());
    my_user->set_peer_username(gcm_decryptedtext_str.substr(0,gcm_decryptedtext_str.length()-my_user->get_username().length()));

    free(clients_decryptext);
    EVP_PKEY_free(peers_pubk);
    free(text_to_sign);
    EVP_PKEY_free(pkey);
    return 1;
}
//sent by a client A
int Message::send_message_9(User* my_user){
    //generating the clear text for verification of the signature
    //concatenation g^b'||g^a'
    unsigned char* text_to_sign = (unsigned char*)malloc(2*DH_PUBK_LENGTH);
    if(!text_to_sign){
        cerr <<"malloc for concatenation returned NULL (text_to_sign is too big?)"<<endl;
        return -1;
    }
    //put g^b' into the buffer
    memcpy(text_to_sign, my_user->get_peer_pubk_char(), DH_PUBK_LENGTH);
    //put g^a' into the buffer
    memcpy(text_to_sign + DH_PUBK_LENGTH, my_user->get_clients_pubk_char(), DH_PUBK_LENGTH);
    
    //sign the concatenation {g^b'||g^a'}
    unsigned char* signature{nullptr};
    int signature_len = 0;
    if((signature_len = Security::signature("./users/"+my_user->get_username()+"/rsa_privkey.pem", 
                                            (unsigned char*) my_user->get_password().c_str(), text_to_sign, 
                                            2*DH_PUBK_LENGTH, &signature)) == -1){
        return -1;
    }
    //Encrypt the digital signature
    unsigned char* cipher_signature{nullptr};
    int cipher_signature_len = 0;
    if(-1 == (cipher_signature_len = Security::encryption_AES(signature, signature_len, my_user->get_clients_key(), 
                                                                NULL, &cipher_signature))){
        free(text_to_sign);
        free(signature);
        return -1;

    }

    //initialization vector
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){
        // free(client_to_server_counter);
        free(text_to_sign);
        free(signature);
        free(cipher_signature);
        return -1;
    }
    //creating aad: message type, client_to_server_counter, iv, encrypted signature
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + cipher_signature_len;
    char * aad = (char*)malloc(aad_len);
    if(!aad){ 
        free(text_to_sign);
        free(signature);
        free(cipher_signature);
        free(iv);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return -1;
    }
    //put message type into aad
    aad[0] = 9;
    //put counter into aad
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = my_user->get_client_counter();
    //put iv into the aad
    memcpy(aad + MESSAGE_TYPE_LENGTH +  COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //put encrypted cipher text into the aad
    memcpy(aad + MESSAGE_TYPE_LENGTH +  COUNTER_LENGTH + Security::GCM_IV_LEN, cipher_signature, cipher_signature_len);
    //
    //generate the gcm plaintext: sender username||receiver username
    int gcm_plaintext_len = 2*USERNAME_LENGTH;
    unsigned char* gcm_plaintext = (unsigned char*)calloc(gcm_plaintext_len, 1);
    if(!gcm_plaintext){
        free(text_to_sign);
        free(signature);
        free(cipher_signature);
        free(iv);
        free(aad);
        cerr<< "Error: malloc for gcm plaintext returned NULL (too big usernames?)\n"; return -1;
    }
    memcpy(gcm_plaintext, (my_user->get_username()+my_user->get_peer_username()).c_str(), 
                            my_user->get_username().length()+my_user->get_peer_username().length());
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
        free(iv);
        free(aad);
        return -1;
    }

    int message_buf_len = aad_len + gcm_ciphertext_len + Security::GCM_TAG_LEN;
    char *message_buf = (char*)malloc(message_buf_len);
    memcpy(message_buf, aad, aad_len);
    memcpy(message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);
    //Send the data to the network!
    if(send(my_user->get_socket(), message_buf, message_buf_len, 0) != message_buf_len){
            cerr <<"Error: sending message 9 over the socket failed" << endl;
            free(text_to_sign);
            free(signature);
            free(cipher_signature); 
            free(gcm_plaintext);    
            free(gcm_ciphertext);
            free(tag);
            free(iv);
            free(aad);
            free(message_buf);
            return -1;
        }

    ////
    my_user->increment_client_counter();
    //remove the public keys
    my_user->set_peer_pubk(nullptr);
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
    free(message_buf);

    return message_buf_len;
}
//received by the server
int Message::handle_message_9(char * message, size_t message_len, User* sender, vector<User*>users){
    int i;
    string msg = "";
    for (i = 0; i < message_len; i++) {
        msg = msg + message[i];
    }
    string tag = msg.substr(msg.length() - Security::GCM_TAG_LEN, Security::GCM_TAG_LEN);
    string gcm_ciphertext = msg.substr(msg.length() - Security::GCM_TAG_LEN - 2 * USERNAME_LENGTH, 2 * USERNAME_LENGTH);
    string aad = msg.substr(0, msg.length() - gcm_ciphertext.length() - tag.length());
    string gcm_iv = msg.substr(COUNTER_LENGTH + MESSAGE_TYPE_LENGTH, Security::GCM_IV_LEN);
    string clients_ciphertext_str = aad.substr(MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN, 
                                            aad.length() - MESSAGE_TYPE_LENGTH - COUNTER_LENGTH - Security::GCM_IV_LEN);

    unsigned char *gcm_decryptedtext{nullptr};
    if(-1==(Security::gcm_decrypt((unsigned char*)aad.c_str(), aad.length(), 
                                (unsigned char*)gcm_ciphertext.c_str(), gcm_ciphertext.length(),
                                sender->get_server_client_key(),(unsigned char*) gcm_iv.c_str(), &gcm_decryptedtext, 
                                (unsigned char*)tag.c_str()))){
  
        return -1;
    }
    string gcm_decryptedtext_str ((char*)gcm_decryptedtext);
    free(gcm_decryptedtext);
    uint16_t server_counter = (uint16_t) *(message + MESSAGE_TYPE_LENGTH);
    if(!sender->replay_check(false, server_counter)){
        return -1;
    }
    sender->set_peer_username(gcm_decryptedtext_str.substr(sender->get_username().length(), 
                                                            gcm_decryptedtext_str.length() - sender->get_username().length()));

    cout << "handling message 9 from " << sender->get_username()<<endl;
    User *receiver = find_user(sender->get_peer_username(), &users);
    if(receiver == nullptr){
        return -1;
    }
    if(Message::send_message_10(sender, receiver,(unsigned char*) clients_ciphertext_str.c_str(),
                                    clients_ciphertext_str.length()) == -1){
        cerr <<"Error in sending message 10" << endl;
        return -1;
    }
    cout << "forwarding message 10 from " << sender->get_username() <<" to " << receiver->get_username()<<endl;
    return clients_ciphertext_str.length();


}
//sent by the server to client B
int Message::send_message_10(User* sender, User* receiver, unsigned char * clients_ciphertext, int clients_ciphertext_len){
     //
    //initialization vector
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){return -1;}
    //load and send the rsa_public key of the sender
    // load rsa public key:
    string filename = "./users/"+sender->get_username() + "/rsa_pubkey.pem";
    FILE* pubk_file = fopen(filename.c_str(), "r");
    if(!pubk_file){ cerr << "Error: cannot open file '" << filename << "' (missing?)\n"; exit(1); }
    EVP_PKEY* pubk = PEM_read_PUBKEY(pubk_file, NULL, NULL, NULL);
    fclose(pubk_file);
    if(!pubk){ cerr << "Error: PEM_read_PUBKEY returned NULL\n"; exit(1); }

    //serialize the rsa public key
    unsigned char *pk_buf{nullptr};
    int rsa_buf_size = 0;
    if(-1==(rsa_buf_size = Security::EVP_PKEY_to_chars(pubk, &pk_buf))){
        free(iv);
        EVP_PKEY_free(pubk);
        return -1;
    }

    //creating aad: message type, client_to_server_counter, iv, rsa publick key, encrypted signature
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + (rsa_buf_size - 1) + clients_ciphertext_len;
    char * aad = (char*)malloc(aad_len);
    if(!aad){
        free(pk_buf);
        free(iv);
        EVP_PKEY_free(pubk);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return -1;
    }
    //put the message type into aad
    aad[0] = 10;
    //put the counter into aad
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = receiver->get_server_counter();
    //put the iv into the aad
    memcpy(aad + MESSAGE_TYPE_LENGTH +  COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //put the rsa public key into the aad 
    memcpy(aad + MESSAGE_TYPE_LENGTH +  COUNTER_LENGTH + Security::GCM_IV_LEN, pk_buf, (rsa_buf_size - 1));
    //put the encrypted signature into the aad
    memcpy(aad + MESSAGE_TYPE_LENGTH +  COUNTER_LENGTH + Security::GCM_IV_LEN + (rsa_buf_size - 1), clients_ciphertext, clients_ciphertext_len);

    //generate the gcm plaintext: sender username||receiver username
    int gcm_plaintext_len = 2*USERNAME_LENGTH;
    unsigned char* gcm_plaintext = (unsigned char*)calloc(gcm_plaintext_len, 1);
    if(!gcm_plaintext){
        free(pk_buf);
        free(iv);
        free(aad);
        EVP_PKEY_free(pubk);
        cerr<< "Error: malloc for gcm plaintext returned NULL (too big usernames?)\n"; return -1;
    }
    memcpy(gcm_plaintext, (sender->get_username()+receiver->get_username()).c_str(), 
                            sender->get_username().length()+receiver->get_username().length());
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
        free(pk_buf);
        return gcm_ciphertext_len;
    }

    int message_buf_len = aad_len + gcm_ciphertext_len + Security::GCM_TAG_LEN;
    char * message_buf = (char*)malloc(message_buf_len);
    memcpy(message_buf, aad, aad_len);
    memcpy(message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);
    //Send the data to the network!
    if(send(receiver->get_socket(), message_buf, message_buf_len, 0) != message_buf_len){   
        cerr <<"Error: sending message 10 over the socket failed" << endl;
        free(aad);
        free(iv);
        free(gcm_plaintext);
        free(gcm_ciphertext);
        free(tag);
        free(pk_buf);
        EVP_PKEY_free(pubk);
        free(message_buf);
        return -1;
    }
    ////
    receiver->increment_server_counter();
    free(aad);
    free(iv);
    free(gcm_plaintext);
    free(gcm_ciphertext);
    free(tag);
    free(pk_buf);
    free(message_buf);
    EVP_PKEY_free(pubk);
    sender->set_clients_pubk_char(nullptr);//remove it
    receiver->set_peer_username(sender->get_username());
    return message_buf_len;
}
//received by a client B
int Message::handle_message_10(User* my_user){

    char*message = (char*)malloc(MESSAGE_10_LENGTH);  
    int val_read = read(my_user->get_socket(), message, MESSAGE_10_LENGTH);
    if(val_read != MESSAGE_10_LENGTH){
        cerr << "Error in reading message 10 data" << endl;
        return -1;
    }
    int i;
    string msg = "";
    for (i = 0; i < val_read; i++) {
        msg = msg + message[i];
    }
    string tag = msg.substr(msg.length() - Security::GCM_TAG_LEN, Security::GCM_TAG_LEN);
    string gcm_ciphertext = msg.substr(msg.length() - Security::GCM_TAG_LEN - 2 * USERNAME_LENGTH, 2 * USERNAME_LENGTH);
    string aad = msg.substr(0, msg.length() - gcm_ciphertext.length() - tag.length());
    string gcm_iv = msg.substr(COUNTER_LENGTH + MESSAGE_TYPE_LENGTH, Security::GCM_IV_LEN);
    string clients_ciphertext_str = aad.substr(MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + RSA_PUBK_LENGTH, 
                                            aad.length() - RSA_PUBK_LENGTH - MESSAGE_TYPE_LENGTH - COUNTER_LENGTH - Security::GCM_IV_LEN);
    unsigned char *gcm_decryptedtext{nullptr};

    if(-1==(Security::gcm_decrypt((unsigned char*)aad.c_str(), aad.length(), 
                                (unsigned char*)gcm_ciphertext.c_str(), gcm_ciphertext.length(),
                                my_user->get_server_client_key(),(unsigned char*) gcm_iv.c_str(), &gcm_decryptedtext, 
                                (unsigned char*)tag.c_str()))){
        return -1;
    }
    string gcm_decryptedtext_str ((char*)gcm_decryptedtext);
    free(gcm_decryptedtext);
    uint16_t server_counter = (uint16_t) *(message + MESSAGE_TYPE_LENGTH);
    if(!my_user->replay_check(true, server_counter)){
        return -1;
    }
    //decrypt the clients cipher text
    int clients_decryptext_len = 0;
    unsigned char * clients_decryptext{nullptr};
    if(-1 == (clients_decryptext_len = Security::decryption_AES((unsigned char *)clients_ciphertext_str.c_str(), 
                                                                clients_ciphertext_str.length(), 
                                                                my_user->get_clients_key(), NULL, &clients_decryptext))){
        
        return -1;
    }
    string rsa_pubk_str = aad.substr(MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN, RSA_PUBK_LENGTH);
    //desrialize the rsa public key
    EVP_PKEY *pkey{nullptr};
    if(-1 == Security::chars_to_EVP_PKEY(&pkey, (unsigned char *)rsa_pubk_str.c_str())){
        free(clients_decryptext);
        return -1;
    }

    //generating the clear text for verification of the signature
    //concatenation g^a'||g^b'
    unsigned char* text_to_sign = (unsigned char*)malloc(2*DH_PUBK_LENGTH);
    if(!text_to_sign){
        cerr <<"malloc for concatenation returned NULL (text_to_sign is too big?)"<<endl;
        free(clients_decryptext);
        EVP_PKEY_free(pkey);
        return -1;
    }

    //put g^a' into the buffer
    memcpy(text_to_sign, my_user->get_clients_pubk_char(), DH_PUBK_LENGTH);
    //put g^b' into the buffer
    memcpy(text_to_sign+DH_PUBK_LENGTH,my_user->get_peer_pubk_char(), DH_PUBK_LENGTH);

    //verify the signature
    if(-1 == Security::verify_signature(pkey, clients_decryptext, clients_decryptext_len, text_to_sign,2*DH_PUBK_LENGTH)){
        free(clients_decryptext);
        free(text_to_sign);
        EVP_PKEY_free(pkey);
        return -1;
    }
    my_user->set_peer_username(gcm_decryptedtext_str.substr(0,gcm_decryptedtext_str.length()-my_user->get_username().length()));

    free(clients_decryptext);
    free(text_to_sign);
    EVP_PKEY_free(pkey);
    //removing the public keys
    my_user->set_peer_pubk(nullptr);
    my_user->set_peer_pubk_char(nullptr);
    my_user->set_clients_pubk(nullptr);
    my_user->set_clients_pubk_char(nullptr);
    return 1;
                                        
}

//sent by client B to the server 
int Message::send_message_11(User* my_user){
    //wrap around check
    if(my_user->get_client_counter() > UINT16_MAX - 2){
        cout <<"This session is not secure anymore! Try to loggin again" <<endl;
        return send_message_17(my_user);
    }
    //initialization vector
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){
        return -1;
    }
    //creating aad: message type, client_to_server_counter, iv
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN;
    char * aad = (char*)malloc(aad_len);
    if(!aad){
        free(iv);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return -1;
    }
    
    aad[0] = 11;
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = my_user->get_client_counter();
    //add iv to aad
    memcpy(aad + MESSAGE_TYPE_LENGTH +  COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //generate the gcm plaintext: sender username||receiver username
    int gcm_plaintext_len = 2*USERNAME_LENGTH;
    unsigned char* gcm_plaintext = (unsigned char*)calloc(gcm_plaintext_len, 1);
     if(!gcm_plaintext){
        free(iv);
        free(aad);
        cerr<< "Error: malloc for gcm plaintext returned NULL (too big usernames?)\n"; return -1;
    }
    memcpy(gcm_plaintext, (my_user->get_username()+my_user->get_peer_username()).c_str(), 
                            my_user->get_username().length()+my_user->get_peer_username().length());
    //GCM encryption
    unsigned char* gcm_ciphertext{nullptr};
    unsigned char* tag{nullptr};
    int gcm_ciphertext_len = 0;
    
    if(-1 == (gcm_ciphertext_len = Security::gcm_encrypt((unsigned char *)aad, aad_len , gcm_plaintext, gcm_plaintext_len, 
                                                        my_user->get_server_client_key(), iv, &gcm_ciphertext, &tag))){
        free(gcm_plaintext);    
        free(iv);
        free(aad);
        return -1;
    }
    //
    int message_buf_len = aad_len + gcm_ciphertext_len + Security::GCM_TAG_LEN;
    char * message_buf = (char*)malloc(message_buf_len);
    memcpy(message_buf, aad, aad_len);
    memcpy(message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);

    ///Send the data to the network!
    if(send(my_user->get_socket(), message_buf, message_buf_len, 0) != message_buf_len){
        cerr <<"Error: sending message 11 over the socket failed" << endl;
        free(aad);
        free(message_buf);
        free(iv);
        free(gcm_plaintext);
        free(gcm_ciphertext);
        free(tag);
        return -1;
    }
    ////
    my_user->increment_client_counter();
    free(aad);
    free(message_buf);
    free(iv);
    free(gcm_plaintext);
    free(gcm_ciphertext);
    free(tag);
    my_user->set_peer_username("");

    return message_buf_len;
}
//recevied by the server 
int Message::handle_message_11(char * message, size_t message_len, User* sender, vector<User*>users){
    int i;
    string msg = "";
    for (i = 0; i < message_len; i++) {
        msg = msg + message[i];
    }
    string tag = msg.substr(msg.length() - Security::GCM_TAG_LEN, Security::GCM_TAG_LEN);
    string ciphertext = msg.substr(msg.length() - Security::GCM_TAG_LEN - 2 * USERNAME_LENGTH, 2 * USERNAME_LENGTH);
    string aad = msg.substr(0, msg.length() - ciphertext.length() - tag.length());
    string gcm_iv = msg.substr(COUNTER_LENGTH + MESSAGE_TYPE_LENGTH, Security::GCM_IV_LEN);
    unsigned char *decryptedtext{nullptr};
    int decryptedtext_len = 0;
    
    if(-1==(decryptedtext_len = Security::gcm_decrypt((unsigned char*)aad.c_str(), aad.length(), 
                                (unsigned char*)ciphertext.c_str(), ciphertext.length(),
                                sender->get_server_client_key(),(unsigned char*) gcm_iv.c_str(), &decryptedtext, 
                                (unsigned char*)tag.c_str()))){
        return -1;
    }
    string decryptedtext_str ((char*)decryptedtext);
    free(decryptedtext);
    uint16_t server_counter = (uint16_t) *(message + MESSAGE_TYPE_LENGTH);
    if(!sender->replay_check(false, server_counter)){
        return -1;
    }
    string receiver_username = decryptedtext_str.substr(sender->get_username().length(),
                                decryptedtext_str.length() - sender->get_username().length());
    sender->set_peer_username(receiver_username);
    cout << "handling message 11 from " << sender->get_username()<<endl;
    User *receiver = find_user(sender->get_peer_username(), &users);
    if(receiver == nullptr){
        return -1;
    }
    if(Message::send_message_12(sender, receiver) == -1){
        cerr <<"Error in sending message 12" << endl;
        return -1;
    }
    cout << "forwarding message 11 from " << sender->get_username() <<" to " << receiver->get_username()<<endl;
    return 1;
}

//sent by the server to client A
unsigned int Message::send_message_12(User* sender, User* receiver){
    //initialization vector
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){return 0;}
    //creating aad: message type, client_to_server_counter, iv
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN;
    char * aad = (char*)malloc(aad_len);
    if(!aad){
        free(iv);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return 0;
    }
    //insert message type into aad
    aad[0] = 12;
    //insert counter into aad
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = receiver->get_server_counter();
    //insert the iv into aad
    memcpy(aad + MESSAGE_TYPE_LENGTH +  COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //generate the gcm plaintext: sender username||receiver username
    int gcm_plaintext_len = 2*USERNAME_LENGTH;
    unsigned char* gcm_plaintext = (unsigned char*)calloc(gcm_plaintext_len, 1);
    if(!gcm_plaintext){
        free(iv);
        free(aad);
        cerr<< "Error: malloc for gcm plaintext returned NULL (too big usernames?)\n"; return 0;
    }
    memcpy(gcm_plaintext, (sender->get_username()+receiver->get_username()).c_str(), 
                            sender->get_username().length()+receiver->get_username().length());

    
    //GCM encryption
    unsigned char* gcm_ciphertext{nullptr};
    unsigned char* tag{nullptr};
    int gcm_ciphertext_len = 0;
    
    if(-1 == (gcm_ciphertext_len = Security::gcm_encrypt((unsigned char *)aad, aad_len , gcm_plaintext, gcm_plaintext_len, 
                                                        receiver->get_server_client_key(), 
                                                        iv, &gcm_ciphertext, &tag))){
        
        free(gcm_plaintext);    
        free(iv);
        free(aad);
        return gcm_ciphertext_len;
    }
    int message_buf_len = aad_len + gcm_ciphertext_len + Security::GCM_TAG_LEN;
    char * message_buf = (char*)malloc(message_buf_len);
    memcpy(message_buf, aad, aad_len);
    memcpy(message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);
    ///Send the data to the network!
    if(send(receiver->get_socket(), message_buf, message_buf_len, 0) != message_buf_len){   
        cerr <<"Error: sending message 12 over the socket failed" << endl;
        free(aad);
        free(iv);
        free(gcm_plaintext);
        free(gcm_ciphertext);
        free(tag);
        free(message_buf);
        return -1;
    }
    ////
    receiver->increment_server_counter();
    free(aad);
    free(iv);
    free(gcm_plaintext);
    free(gcm_ciphertext);
    free(message_buf);
    free(tag);
    sender->set_peer_username("");//remove it
    return message_buf_len;
}
//received by the client B
int Message::handle_message_12(char* message, size_t message_len, User*my_user){
   int i;
    string msg = "";
    for (i = 0; i < message_len; i++) {
        msg = msg + message[i];
    }
    string tag = msg.substr(msg.length() - Security::GCM_TAG_LEN, Security::GCM_TAG_LEN);
    string ciphertext = msg.substr(msg.length() - Security::GCM_TAG_LEN - 2 * USERNAME_LENGTH, 2 * USERNAME_LENGTH);
    string aad = msg.substr(0, msg.length() - ciphertext.length() - tag.length());
    string gcm_iv = msg.substr(COUNTER_LENGTH + MESSAGE_TYPE_LENGTH, Security::GCM_IV_LEN);
    unsigned char *decryptedtext{nullptr};
    int decryptedtext_len = 0;
    if(-1==(decryptedtext_len = Security::gcm_decrypt((unsigned char*)aad.c_str(), aad.length(), 
                                (unsigned char*)ciphertext.c_str(), ciphertext.length(),
                                my_user->get_server_client_key(),(unsigned char*) gcm_iv.c_str(), &decryptedtext, 
                                (unsigned char*)tag.c_str()))){


        return -1;
    }
    string decryptedtext_str ((char*)decryptedtext);
    free(decryptedtext);
    uint16_t server_counter = (uint16_t) *(message + MESSAGE_TYPE_LENGTH);
    if(!my_user->replay_check(true, server_counter)){
        return -1;
    }
    string sender_username = decryptedtext_str.substr(0,
                                decryptedtext_str.length() - my_user->get_username().length());
    my_user->set_peer_username("");
    my_user->set_clients_pubk_char(nullptr);
    my_user->set_clients_pubk(nullptr);
    cout<< sender_username <<" Decliend Your Request to Chat!" <<endl;
    return 1;

}

//sent by client A to the server 
int Message::send_message_13(unsigned char* message, size_t message_len, User* my_user){
    //wrap around check
    if(my_user->get_client_counter() > UINT16_MAX - 2){
        cout <<"This session is not secure anymore! Try to loggin again" <<endl;
        char * msg {nullptr};
        return send_message_17(my_user);
    }
    //encrypt the message with the session key
    unsigned char* ciphertext{nullptr};
    int ciphertext_len = 0;
    if((ciphertext_len = Security::encryption_AES(message, message_len, my_user->get_clients_key(), NULL, &ciphertext)) == -1){
        return 0;
    }
     //initialization vector
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){
        free(ciphertext);
        return 0;
    }
    //creating aad: message type, client_to_server_counter, iv, generated dh public key,encrypted signature
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + ciphertext_len;
    char * aad = (char*)malloc(aad_len);
    if(!aad){
        free(iv);
        free(ciphertext);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return 0;
    }
    //put message type into aad
    aad[0] = 13;
    //put counter into the aad
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = my_user->get_client_counter();
    //put the iv into the aad
    memcpy(aad + MESSAGE_TYPE_LENGTH +  COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //put the encrypted message into the aad
    memcpy(aad + MESSAGE_TYPE_LENGTH +  COUNTER_LENGTH + Security::GCM_IV_LEN, ciphertext, ciphertext_len);
    //generate the gcm plaintext: sender username||receiver username
    int gcm_plaintext_len = 2*USERNAME_LENGTH;
    unsigned char* gcm_plaintext = (unsigned char*)calloc(gcm_plaintext_len, 1);
    if(!gcm_plaintext){
        free(iv);
        free(ciphertext);
        free(aad);
        cerr<< "Error: malloc for gcm plaintext returned NULL (too big usernames?)\n"; return 0;
    }
    memcpy(gcm_plaintext, (my_user->get_username()+my_user->get_peer_username()).c_str(), 
                            my_user->get_username().length()+my_user->get_peer_username().length());
    //GCM encryption
    unsigned char* gcm_ciphertext{nullptr};
    unsigned char* tag{nullptr};
    int gcm_ciphertext_len = 0;
    
    if(-1 == (gcm_ciphertext_len = Security::gcm_encrypt((unsigned char *)aad, aad_len , gcm_plaintext, gcm_plaintext_len, 
                                                        my_user->get_server_client_key(), iv, &gcm_ciphertext, &tag))){

        free(iv);
        free(ciphertext);
        free(aad);
        free(gcm_plaintext);
        return 0;
    }
    int message_buf_len = aad_len + gcm_ciphertext_len + Security::GCM_TAG_LEN;
    char * message_buf = (char*)malloc(message_buf_len);
    memcpy(message_buf, aad, aad_len);
    memcpy(message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);
    cout << my_user->get_username()<<" sends message 13"<<endl;
    ///TODO:Send the data to the network!

    ////
    my_user->increment_client_counter();
    free(iv);
    free(ciphertext);
    free(aad);
    free(gcm_ciphertext);
    return message_buf_len;
}
//recevied by the server 
int Message::handle_message_13(unsigned char ** clients_ciphertext, char * message, size_t message_len, User* sender){
    int i;
    string msg = "";
    for (i = 0; i < message_len; i++) {
        msg = msg + message[i];
    }
    string tag = msg.substr(msg.length() - Security::GCM_TAG_LEN, Security::GCM_TAG_LEN);
    string gcm_ciphertext = msg.substr(msg.length() - Security::GCM_TAG_LEN - 2 * USERNAME_LENGTH, 2 * USERNAME_LENGTH);
    string aad = msg.substr(0, msg.length() - gcm_ciphertext.length() - tag.length());
    string gcm_iv = msg.substr(COUNTER_LENGTH + MESSAGE_TYPE_LENGTH, Security::GCM_IV_LEN);
    string clients_ciphertext_str = aad.substr(MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN, 
                                            aad.length() - MESSAGE_TYPE_LENGTH - COUNTER_LENGTH - Security::GCM_IV_LEN);
    ///TODO:remove it (just for testing)
    *clients_ciphertext=(unsigned char *)malloc(clients_ciphertext_str.length());
    memcpy(*clients_ciphertext, clients_ciphertext_str.c_str(), clients_ciphertext_str.length());

    unsigned char *gcm_decryptedtext{nullptr};

    if(-1==(Security::gcm_decrypt((unsigned char*)aad.c_str(), aad.length(), 
                                (unsigned char*)gcm_ciphertext.c_str(), gcm_ciphertext.length(),
                                sender->get_server_client_key(),(unsigned char*) gcm_iv.c_str(), &gcm_decryptedtext, 
                                (unsigned char*)tag.c_str()))){
        return -1;
    }
    string gcm_decryptedtext_str ((char*)gcm_decryptedtext);
    free(gcm_decryptedtext);
    uint16_t server_counter = (uint16_t) *(message + MESSAGE_TYPE_LENGTH);
    if(!sender->replay_check(false, server_counter)){
        return -1;
    }
    sender->set_peer_username(gcm_decryptedtext_str.substr(sender->get_username().length(), 
                                                            gcm_decryptedtext_str.length() - sender->get_username().length()));
    return clients_ciphertext_str.length();
}
//sent by the server to the client B
unsigned int Message::send_message_14(User* sender, User* receiver, unsigned char * clients_ciphertext, int clients_ciphertext_len){
    //initialization vector
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){return 0;}
    //load and send the rsa_public key of the sender
    //creating aad: message type, client_to_server_counter, iv, encrypted clients message
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + clients_ciphertext_len;
    char * aad = (char*)malloc(aad_len);
    if(!aad){
        free(iv);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return 0;
    }
    //put the message type into aad
    aad[0] = 14;
    //put the counter into aad
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = receiver->get_server_counter();
    //put the iv into the aad
    memcpy(aad + MESSAGE_TYPE_LENGTH +  COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //put the encrypted encrypted clients message into the aad
    memcpy(aad + MESSAGE_TYPE_LENGTH +  COUNTER_LENGTH + Security::GCM_IV_LEN, clients_ciphertext, clients_ciphertext_len);
    //generate the gcm plaintext: sender username||receiver username
    int gcm_plaintext_len = 2*USERNAME_LENGTH;
    unsigned char* gcm_plaintext = (unsigned char*)calloc(gcm_plaintext_len, 1);
    if(!gcm_plaintext){
        free(iv);
        free(aad);
        cerr<< "Error: malloc for gcm plaintext returned NULL (too big usernames?)\n"; return 0;
    }
    memcpy(gcm_plaintext, (sender->get_username()+receiver->get_username()).c_str(), 
                            sender->get_username().length()+receiver->get_username().length());
    //GCM encryption
    unsigned char* gcm_ciphertext{nullptr};
    unsigned char* tag{nullptr};
    int gcm_ciphertext_len = 0;
    if(-1 == (gcm_ciphertext_len = Security::gcm_encrypt((unsigned char *)aad, aad_len , gcm_plaintext, gcm_plaintext_len, 
                                                        receiver->get_server_client_key(), 
                                                        iv, &gcm_ciphertext, &tag))){
        free(gcm_plaintext);    
        free(iv);
        free(aad);
        return gcm_ciphertext_len;
    }

    int message_buf_len = aad_len + gcm_ciphertext_len + Security::GCM_TAG_LEN;
    char * message_buf = (char*)malloc(message_buf_len);
    memcpy(message_buf, aad, aad_len);
    memcpy(message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);
    cout << "Server sends message 14 to " << receiver->get_username() <<endl;
    ///TODO:Send the data to the network!

    ////
    receiver->increment_server_counter();
    free(aad);
    free(iv);
    free(gcm_plaintext);
    free(gcm_ciphertext);
    free(tag);
    receiver->set_peer_username(sender->get_username());
    return message_buf_len;
}
//received by the client A
int Message::handle_message_14(char* message, size_t message_len, User * my_user){
    int i;
    string msg = "";
    for (i = 0; i < message_len; i++) {
        msg = msg + message[i];
    }
    string tag = msg.substr(msg.length() - Security::GCM_TAG_LEN, Security::GCM_TAG_LEN);
    string gcm_ciphertext = msg.substr(msg.length() - Security::GCM_TAG_LEN - 2 * USERNAME_LENGTH, 2 * USERNAME_LENGTH);
    string aad = msg.substr(0, msg.length() - gcm_ciphertext.length() - tag.length());
    string gcm_iv = msg.substr(COUNTER_LENGTH + MESSAGE_TYPE_LENGTH, Security::GCM_IV_LEN);
    string clients_ciphertext_str = aad.substr(MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN, 
                                            aad.length() -  MESSAGE_TYPE_LENGTH - COUNTER_LENGTH - Security::GCM_IV_LEN);
    unsigned char *gcm_decryptedtext{nullptr};
    if(-1==(Security::gcm_decrypt((unsigned char*)aad.c_str(), aad.length(), 
                                (unsigned char*)gcm_ciphertext.c_str(), gcm_ciphertext.length(),
                                my_user->get_server_client_key(),(unsigned char*) gcm_iv.c_str(), &gcm_decryptedtext, 
                                (unsigned char*)tag.c_str()))){
        return -1;
    }
    string gcm_decryptedtext_str ((char*)gcm_decryptedtext);
    free(gcm_decryptedtext);
    uint16_t server_counter = (uint16_t) *(message + MESSAGE_TYPE_LENGTH);
    if(!my_user->replay_check(true, server_counter)){
        return -1;
    }
    //decrypt the clients cipher text
    int clients_decryptext_len = 0;
    unsigned char * clients_decryptext{nullptr};
    if(-1 == (clients_decryptext_len = Security::decryption_AES((unsigned char *)clients_ciphertext_str.c_str(), 
                                                                clients_ciphertext_str.length(), 
                                                                my_user->get_clients_key(), NULL, &clients_decryptext))){
        
        return -1;
    }
    string clients_decryptext_str((char*)clients_decryptext);
    cout << my_user->get_peer_username() <<": " << trim(clients_decryptext_str) <<endl;
    return clients_decryptext_len;
}

//sent by client A to the server 
unsigned int Message::send_message_17(User* my_user){
    //initialization vector
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){
        return 0;
    }
    //creating aad: message type, client_to_server_counter, iv
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN;
    char * aad = (char*)malloc(aad_len);
    if(!aad){
        free(iv);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return 0;
    }
    
    aad[0] = 17;
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = my_user->get_client_counter();
    //add iv to aad
    memcpy(aad + MESSAGE_TYPE_LENGTH +  COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //generate the gcm plaintext: sender username||receiver username
    int gcm_plaintext_len = USERNAME_LENGTH;
    unsigned char* gcm_plaintext = (unsigned char*)calloc(gcm_plaintext_len, 1);
     if(!gcm_plaintext){
        free(iv);
        free(aad);
        cerr<< "Error: malloc for gcm plaintext returned NULL (too big usernames?)\n"; return 0;
    }
    memcpy(gcm_plaintext, (my_user->get_username()).c_str(), my_user->get_peer_username().length());
    //GCM encryption
    unsigned char* gcm_ciphertext{nullptr};
    unsigned char* tag{nullptr};
    int gcm_ciphertext_len = 0;

    if(-1 == (gcm_ciphertext_len = Security::gcm_encrypt((unsigned char *)aad, aad_len , gcm_plaintext, gcm_plaintext_len, 
                                                        my_user->get_server_client_key(), iv, &gcm_ciphertext, &tag))){
        free(gcm_plaintext);    
        free(iv);
        free(aad);
        return 0;
    }
    //
    int message_buf_len = aad_len + gcm_ciphertext_len + Security::GCM_TAG_LEN;
    char * message_buf = (char*)malloc(message_buf_len);
    memcpy(message_buf, aad, aad_len);
    memcpy(message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);

    ///Send the data to the network!
    if(send(my_user->get_socket(), message_buf, message_buf_len, 0) != message_buf_len){
        cerr <<"Error: sending message 11 over the socket failed" << endl;
        free(aad);
        free(message_buf);
        free(iv);
        free(gcm_plaintext);
        free(gcm_ciphertext);
        free(tag);
        return -1;
    }
    ////
    my_user->increment_client_counter();
    free(aad);
    free(iv);
    free(gcm_plaintext);
    free(gcm_ciphertext);
    free(tag);
    free(message_buf);
    delete my_user;//due to log out 
    return message_buf_len;
}
//recevied by the server 
int Message::handle_message_17(char * message, size_t message_len, User* sender){
    int i;
    string msg = "";
    for (i = 0; i < message_len; i++) {
        msg = msg + message[i];
    }
    string tag = msg.substr(msg.length() - Security::GCM_TAG_LEN, Security::GCM_TAG_LEN);
    string ciphertext = msg.substr(msg.length() - Security::GCM_TAG_LEN - USERNAME_LENGTH, USERNAME_LENGTH);
    string aad = msg.substr(0, msg.length() - ciphertext.length() - tag.length());
    string gcm_iv = msg.substr(MESSAGE_TYPE_LENGTH + COUNTER_LENGTH, Security::GCM_IV_LEN);
    unsigned char *decryptedtext{nullptr};
    int decryptedtext_len = 0;

    if(-1==(decryptedtext_len = Security::gcm_decrypt((unsigned char*)aad.c_str(), aad.length(), 
                                (unsigned char*)ciphertext.c_str(), ciphertext.length(),
                                sender->get_server_client_key(),(unsigned char*) gcm_iv.c_str(), &decryptedtext, 
                                (unsigned char*)tag.c_str()))){
        return -1;
    }
    string decryptedtext_str ((char*)decryptedtext);
    free(decryptedtext);
    uint16_t server_counter = (uint16_t) *(message + MESSAGE_TYPE_LENGTH);
    if(!sender->replay_check(false, server_counter)){
        return -1;
    }
    if(!sender->get_peer_username().empty()){
        ///TODO:inform the peer that this client has logged out by message 16
    }
    sender->clear();
    cout << sender->get_username() << " has logged out!"<<endl;
    return -17;
}