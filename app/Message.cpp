#include "Message.h"

//sent by the client A
int Message::send_message_0(char **buffer, User* my_user) {

    //generating new dh pubk -> g^a
    EVP_PKEY * g_a{nullptr};
    if(Security::generate_dh_pubk(&g_a) == -1){return 0;}
    my_user->set_client_server_pubk(g_a);
    //serialize the g^a
    unsigned char*a_char{nullptr};
    if(Security::EVP_PKEY_to_chars(g_a, &a_char) == -1){ 
        my_user->set_client_server_pubk(nullptr);
        EVP_PKEY_free(g_a);
        return -1;
    }
    my_user->set_client_server_pubk_char(a_char);

    unsigned int message_len = MESSAGE_TYPE_LENGTH + USERNAME_LENGTH + DH_PUBK_LENGTH;
    *buffer=(char*) malloc(message_len);
    memset(*buffer, 0, 1);
    memcpy(*buffer, my_user->get_username().c_str(), USERNAME_LENGTH);
    memcpy(*buffer, a_char, DH_PUBK_LENGTH);
    //
    ///TODO: check for the timeout
    ///https://stackoverflow.com/questions/9847441/setting-socket-timeout
    if (message_len != send(my_user->get_socket() , *buffer , message_len , 0)){
        return -1;
    }

    ///
    free(a_char);
    EVP_PKEY_free(g_a);
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








//sent by the client A
unsigned int Message::send_message_5(char**message_buf, User* my_user, string receiver_username){
    //generating new dh pubk -> g^a'
    EVP_PKEY * newA{nullptr};
    if(Security::generate_dh_pubk(&newA) == -1){return 0;}
    my_user->set_clients_pubk(newA);
    //initialization vector
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){
        my_user->set_clients_pubk(nullptr);
        EVP_PKEY_free(newA);
        return 0;
    }
    //creating aad: message type, client_to_received_counter, iv, generated dh public key
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH;
    char * aad = (char*)malloc(aad_len);
    if(!aad){
        my_user->set_clients_pubk(nullptr);
        EVP_PKEY_free(newA);
        free(iv);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return 0;
    }
    
    aad[0] = 5;
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = my_user->get_sent_counter() + 1;
    //add iv to aad
    memcpy(aad + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    unsigned char*newA_char{nullptr};
    if(Security::EVP_PKEY_to_chars(newA, &newA_char) == -1){ 
        my_user->set_clients_pubk(nullptr);
        EVP_PKEY_free(newA);
        free(iv);
        return 0;
    }
    my_user->set_clients_pubk_char(newA_char);
    //add generated dh public key to aad
    memcpy(aad + COUNTER_LENGTH + Security::GCM_IV_LEN, newA_char, DH_PUBK_LENGTH);
    //generate the gcm plaintext: sender username||receiver username
    int gcm_plaintext_len = 2*USERNAME_LENGTH;
    unsigned char* gcm_plaintext = (unsigned char*)calloc(gcm_plaintext_len, 1);
     if(!gcm_plaintext){
        EVP_PKEY_free(newA);
        my_user->set_clients_pubk(nullptr);
        free(iv);
        free(aad);
        cerr<< "Error: malloc for gcm plaintext returned NULL (too big usernames?)\n"; return 0;
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
        free(gcm_ciphertext);
        free(tag);
        free(iv);
        free(aad);
        return 0;
    }
    //
    int message_buf_len = aad_len + gcm_ciphertext_len + Security::GCM_TAG_LEN;
    *message_buf = (char*)malloc(message_buf_len);
    memcpy(*message_buf, aad, aad_len);
    memcpy(*message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(*message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);

    ///TODO:Send the data to the network!

    ////
    my_user->increment_sent_counter();
    free(aad);
    free(iv);
    free(gcm_plaintext);
    free(gcm_ciphertext);
    free(tag);
    cout << my_user->get_username()<<" sent message 5 to " << receiver_username <<endl;
    return message_buf_len;
}
//recevied by the server 
int Message::handle_message_5(char * message, size_t message_len, User* sender){
    int i;
    string msg = "";
    for (i = 0; i < message_len; i++) {
        msg = msg + message[i];
    }
    string tag = msg.substr(msg.length() - Security::GCM_TAG_LEN, Security::GCM_TAG_LEN);
    string ciphertext = msg.substr(msg.length() - Security::GCM_TAG_LEN - 2 * USERNAME_LENGTH, 2 * USERNAME_LENGTH);
    string aad = msg.substr(0, msg.length() - ciphertext.length() - tag.length());
    string gcm_iv = msg.substr(COUNTER_LENGTH, Security::GCM_IV_LEN);
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
    uint16_t received_counter = (uint16_t) *(message+1);
    if(!sender->replay_check(false, received_counter)){
        return -1;
    }
    string dh_key = aad.substr(COUNTER_LENGTH+Security::GCM_IV_LEN,DH_PUBK_LENGTH); 
    sender->set_clients_pubk_char((unsigned char *)dh_key.c_str());
    string receiver_username = decryptedtext_str.substr(sender->get_username().length(),
                                decryptedtext_str.length() - sender->get_username().length());
    sender->set_peer_username(receiver_username);
    return 1;
}
//sent by the server to client B
unsigned int Message::send_message_6(char**message_buf, User* sender, User* receiver){
    //
    //initialization vector
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){return 0;}
    //creating aad: message type, client_to_received_counter, iv, generated dh public key
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH;
    char * aad = (char*)malloc(aad_len);
    if(!aad){
        free(iv);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return 0;
    }
    //insert message type into aad
    aad[0] = 6;
    //insert counter into aad
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = receiver->get_received_counter() + 1;
    //insert the iv into aad
    memcpy(aad + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //insert the generated dh public key into the aad
    memcpy(aad + COUNTER_LENGTH + Security::GCM_IV_LEN, sender->get_clients_pubk_char(), DH_PUBK_LENGTH);
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
        free(gcm_ciphertext);
        free(tag);
        free(iv);
        free(aad);
        return gcm_ciphertext_len;
    }
    int message_buf_len = aad_len + gcm_ciphertext_len + Security::GCM_TAG_LEN;
    *message_buf = (char*)malloc(message_buf_len);
    memcpy(*message_buf, aad, aad_len);
    memcpy(*message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(*message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);
    cout << "Server sends message 6 to " << receiver->get_username() <<endl;
    ///TODO:Send the data to the network!

    ////
    receiver->increment_received_counter();
    free(aad);
    free(iv);
    free(gcm_plaintext);
    free(gcm_ciphertext);
    free(tag);
    sender->set_clients_pubk_char(nullptr);//remove it
    return message_buf_len;
}
//received by the client B
int Message::handle_message_6(char* message, size_t message_len, User*my_user){
   int i;
    string msg = "";
    for (i = 0; i < message_len; i++) {
        msg = msg + message[i];
    }
    string tag = msg.substr(msg.length() - Security::GCM_TAG_LEN, Security::GCM_TAG_LEN);
    string ciphertext = msg.substr(msg.length() - Security::GCM_TAG_LEN - 2 * USERNAME_LENGTH, 2 * USERNAME_LENGTH);
    string aad = msg.substr(0, msg.length() - ciphertext.length() - tag.length());
    string gcm_iv = msg.substr(COUNTER_LENGTH, Security::GCM_IV_LEN);
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
    uint16_t received_counter = (uint16_t) *(message+1);
    if(!my_user->replay_check(true, received_counter)){
        return -1;
    }
    string sender_username = decryptedtext_str.substr(0,
                                decryptedtext_str.length() - my_user->get_username().length());
    my_user->set_peer_username(sender_username);
    ///
    ///
    ///TODO: specify to user the to accept or reject this request
    ///
    //if we want to accept
    string dh_key = aad.substr(COUNTER_LENGTH+Security::GCM_IV_LEN,DH_PUBK_LENGTH); 
    my_user->set_peer_pubk_char((unsigned char *)dh_key.c_str());
    return 1;

}
//sent by the client B
unsigned int Message::send_message_7(char**message_buf, User* my_user){
    //generating new dh pubk g^b'
    EVP_PKEY * newB{nullptr};

    if(Security::generate_dh_pubk(&newB) == -1){return 0;}
    my_user->set_clients_pubk(newB);

    BIO *bio{nullptr};
    unsigned char *newB_char{nullptr};
    if(Security::EVP_PKEY_to_chars(newB ,&newB_char) == -1){
        EVP_PKEY_free(newB);
        my_user->set_clients_pubk(nullptr);
        return 0;
    }
    my_user->set_clients_pubk_char(newB_char);
    //convert peers pubk char into EVP_PKEY
    BIO *mbio{nullptr};
    EVP_PKEY * peer_pubk{nullptr};
    if(Security::chars_to_EVP_PKEY(&peer_pubk , my_user->get_peer_pubk_char()) == -1){
        EVP_PKEY_free(newB);
        my_user->set_clients_pubk(nullptr);
        my_user->set_clients_pubk_char(nullptr);
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
        EVP_PKEY_free(peer_pubk);
        return 0;
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
        return 0;
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
        return 0;
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
        return 0;
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
        return 0;
    }

    //creating aad: message type, client_to_received_counter, iv, generated dh public key,encrypted signature
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
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return 0;
    }
    //put message type into aad
    aad[0] = 7;
    //put counter into the aad
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = my_user->get_sent_counter() + 1;
    //put the iv into the aad
    memcpy(aad + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //put the generated dh public key into the aad
    memcpy(aad + COUNTER_LENGTH + Security::GCM_IV_LEN, my_user->get_clients_pubk_char(), DH_PUBK_LENGTH);
    //put the encryption of signature into the aad
    memcpy(aad + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH, ciphertext, ciphertext_len);
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
        return 0;
    }
    int message_buf_len = aad_len + gcm_ciphertext_len + Security::GCM_TAG_LEN;
    *message_buf = (char*)malloc(message_buf_len);
    memcpy(*message_buf, aad, aad_len);
    memcpy(*message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(*message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);
    cout << my_user->get_username()<<" sends message 7"<<endl;
    ///TODO:Send the data to the network!

    ////
    EVP_PKEY_free(newB);
    EVP_PKEY_free(peer_pubk);
    free(text_to_sign);
    my_user->increment_sent_counter();
    free(signature);
    free(iv);
    free(ciphertext);
    free(aad);
    free(gcm_ciphertext);
    free(clients_key);
    return message_buf_len;
}
//recevied by the server 
int Message::handle_message_7(unsigned char ** clients_ciphertext, char * message, size_t message_len, User* sender){
    int i;
    string msg = "";
    for (i = 0; i < message_len; i++) {
        msg = msg + message[i];
    }
    string tag = msg.substr(msg.length() - Security::GCM_TAG_LEN, Security::GCM_TAG_LEN);
    string gcm_ciphertext = msg.substr(msg.length() - Security::GCM_TAG_LEN - 2 * USERNAME_LENGTH, 2 * USERNAME_LENGTH);
    string aad = msg.substr(0, msg.length() - gcm_ciphertext.length() - tag.length());
    string gcm_iv = msg.substr(COUNTER_LENGTH, Security::GCM_IV_LEN);
    string clients_ciphertext_str = aad.substr(COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH, 
                                            aad.length() - MESSAGE_TYPE_LENGTH - COUNTER_LENGTH - Security::GCM_IV_LEN - DH_PUBK_LENGTH);
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
    uint16_t received_counter = (uint16_t) *(message+1);
    if(!sender->replay_check(false, received_counter)){
        return -1;
    }
    sender->set_peer_username(gcm_decryptedtext_str.substr(sender->get_username().length(), 
                                                            gcm_decryptedtext_str.length() - sender->get_username().length()));
    string dh_key = aad.substr(COUNTER_LENGTH + Security::GCM_IV_LEN, DH_PUBK_LENGTH);
    sender->set_clients_pubk_char((unsigned char *)dh_key.c_str());
    return clients_ciphertext_str.length();
}
//sent by the server to client A
unsigned int Message::send_message_8(char**message_buf, User* sender, User* receiver, unsigned char * clients_ciphertext, int clients_ciphertext_len){
    //initialization vector
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){return 0;}
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
        return 0;
    }
    //creating aad: message type, client_to_received_counter, iv, generated dh public key, rsa publick key, encrypted signature
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH + 
                    (rsa_buf_size - 1) + clients_ciphertext_len;
    char * aad = (char*)malloc(aad_len);
    if(!aad){
        free(pk_buf);
        free(iv);
        EVP_PKEY_free(pubk);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return 0;
    }
    //put the message type into aad
    aad[0] = 8;
    //put the counter into aad
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = receiver->get_received_counter() + 1;
    //put the iv into the aad
    memcpy(aad + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //put the generated dh public key into the aad
    memcpy(aad + COUNTER_LENGTH + Security::GCM_IV_LEN, sender->get_clients_pubk_char(), DH_PUBK_LENGTH);
    //put the rsa public key into the aad 
    memcpy(aad + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH, pk_buf, (rsa_buf_size - 1));
    //put the encrypted signature into the aad
    memcpy(aad + COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH + (rsa_buf_size - 1), clients_ciphertext,
                                                                                        clients_ciphertext_len);

    //generate the gcm plaintext: sender username||receiver username
    int gcm_plaintext_len = 2*USERNAME_LENGTH;
    unsigned char* gcm_plaintext = (unsigned char*)calloc(gcm_plaintext_len, 1);
    if(!gcm_plaintext){
        free(pk_buf);
        free(iv);
        free(aad);
        EVP_PKEY_free(pubk);
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
    *message_buf = (char*)malloc(message_buf_len);
    memcpy(*message_buf, aad, aad_len);
    memcpy(*message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(*message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);
    cout << "Server sends message 8 to " << receiver->get_username() <<endl;
    ///TODO:Send the data to the network!

    ////
    receiver->increment_received_counter();
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
    string gcm_iv = msg.substr(COUNTER_LENGTH, Security::GCM_IV_LEN);
    string clients_ciphertext_str = aad.substr(COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH + RSA_PUBK_LENGTH, 
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
    uint16_t received_counter = (uint16_t) *(message+1);
    if(!my_user->replay_check(true, received_counter)){
        return -1;
    }
    string dh_key = aad.substr(COUNTER_LENGTH + Security::GCM_IV_LEN, DH_PUBK_LENGTH);
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
    string rsa_pubk_str = aad.substr(COUNTER_LENGTH + Security::GCM_IV_LEN + DH_PUBK_LENGTH, RSA_PUBK_LENGTH);
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
unsigned int Message::send_message_9(char**message_buf, User* my_user){
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
    if((signature_len = Security::signature("./users/"+my_user->get_username()+"/rsa_privkey.pem", 
                                            (unsigned char*) my_user->get_password().c_str(), text_to_sign, 
                                            2*DH_PUBK_LENGTH, &signature)) == -1){
        return 0;
    }
    //Encrypt the digital signature
    unsigned char* cipher_signature{nullptr};
    int cipher_signature_len = 0;
    if(-1 == (cipher_signature_len = Security::encryption_AES(signature, signature_len, my_user->get_clients_key(), 
                                                                NULL, &cipher_signature))){
        free(text_to_sign);
        free(signature);
        return 0;

    }

    //initialization vector
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){
        // free(client_to_received_counter);
        free(text_to_sign);
        free(signature);
        free(cipher_signature);
        return 0;
    }
    //creating aad: message type, client_to_received_counter, iv, encrypted signature
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + cipher_signature_len;
    char * aad = (char*)malloc(aad_len);
    if(!aad){ 
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
    *counter_pointer = my_user->get_sent_counter() + 1;
    //put iv into the aad
    memcpy(aad + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //put encrypted cipher text into the aad
    memcpy(aad + COUNTER_LENGTH + Security::GCM_IV_LEN, cipher_signature, cipher_signature_len);
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

    int message_buf_len = aad_len + gcm_ciphertext_len + Security::GCM_TAG_LEN;
    *message_buf = (char*)malloc(message_buf_len);
    memcpy(*message_buf, aad, aad_len);
    memcpy(*message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(*message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);
    cout << my_user->get_username() <<" sends message 9 to " << my_user->get_peer_username() <<endl;
    ///TODO:Send the data to the network!

    ////
    my_user->increment_sent_counter();
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
    return message_buf_len;
}
//received by the server
int Message::handle_message_9(unsigned char ** clients_ciphertext, char * message, size_t message_len, User* sender){
    int i;
    string msg = "";
    for (i = 0; i < message_len; i++) {
        msg = msg + message[i];
    }
    string tag = msg.substr(msg.length() - Security::GCM_TAG_LEN, Security::GCM_TAG_LEN);
    string gcm_ciphertext = msg.substr(msg.length() - Security::GCM_TAG_LEN - 2 * USERNAME_LENGTH, 2 * USERNAME_LENGTH);
    string aad = msg.substr(0, msg.length() - gcm_ciphertext.length() - tag.length());
    string gcm_iv = msg.substr(COUNTER_LENGTH, Security::GCM_IV_LEN);
    string clients_ciphertext_str = aad.substr(COUNTER_LENGTH + Security::GCM_IV_LEN, 
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
    uint16_t received_counter = (uint16_t) *(message+1);
    if(!sender->replay_check(false, received_counter)){
        return -1;
    }
    sender->set_peer_username(gcm_decryptedtext_str.substr(sender->get_username().length(), 
                                                            gcm_decryptedtext_str.length() - sender->get_username().length()));
    return clients_ciphertext_str.length();

}
//sent by the server to client B
unsigned int Message::send_message_10(char**message_buf, User* sender, User* receiver, unsigned char * clients_ciphertext, int clients_ciphertext_len){
     //
    //initialization vector
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){return 0;}
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
        return 0;
    }

    //creating aad: message type, client_to_received_counter, iv, rsa publick key, encrypted signature
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN + (rsa_buf_size - 1) + clients_ciphertext_len;
    char * aad = (char*)malloc(aad_len);
    if(!aad){
        free(pk_buf);
        free(iv);
        EVP_PKEY_free(pubk);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return 0;
    }
    //put the message type into aad
    aad[0] = 10;
    //put the counter into aad
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = receiver->get_received_counter() + 1;
    //put the iv into the aad
    memcpy(aad + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //put the rsa public key into the aad 
    memcpy(aad + COUNTER_LENGTH + Security::GCM_IV_LEN, pk_buf, (rsa_buf_size - 1));
    //put the encrypted signature into the aad
    memcpy(aad + COUNTER_LENGTH + Security::GCM_IV_LEN + (rsa_buf_size - 1), clients_ciphertext, clients_ciphertext_len);

    //generate the gcm plaintext: sender username||receiver username
    int gcm_plaintext_len = 2*USERNAME_LENGTH;
    unsigned char* gcm_plaintext = (unsigned char*)calloc(gcm_plaintext_len, 1);
    if(!gcm_plaintext){
        free(pk_buf);
        free(iv);
        free(aad);
        EVP_PKEY_free(pubk);
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

        EVP_PKEY_free(pubk);
        free(gcm_plaintext);    
        free(gcm_ciphertext);
        free(tag);
        free(iv);
        free(aad);
        free(pk_buf);
        return gcm_ciphertext_len;
    }
    cout << receiver->get_server_client_key()  <<endl;


    int message_buf_len = aad_len + gcm_ciphertext_len + Security::GCM_TAG_LEN;
    *message_buf = (char*)malloc(message_buf_len);
    memcpy(*message_buf, aad, aad_len);
    memcpy(*message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(*message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);
    cout << "Server sends message 10 to " << receiver->get_username() <<endl;
    ///TODO:Send the data to the network!

    ////
    receiver->increment_received_counter();
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
//received by a client B
int Message::handle_message_10(char * message, size_t message_len, User* my_user){
    int i;
    string msg = "";
    for (i = 0; i < message_len; i++) {
        msg = msg + message[i];
    }
    string tag = msg.substr(msg.length() - Security::GCM_TAG_LEN, Security::GCM_TAG_LEN);
    string gcm_ciphertext = msg.substr(msg.length() - Security::GCM_TAG_LEN - 2 * USERNAME_LENGTH, 2 * USERNAME_LENGTH);
    string aad = msg.substr(0, msg.length() - gcm_ciphertext.length() - tag.length());
    string gcm_iv = msg.substr(COUNTER_LENGTH, Security::GCM_IV_LEN);
    string clients_ciphertext_str = aad.substr(COUNTER_LENGTH + Security::GCM_IV_LEN + RSA_PUBK_LENGTH, 
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
    uint16_t received_counter = (uint16_t) *(message+1);
    if(!my_user->replay_check(true, received_counter)){
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
    string rsa_pubk_str = aad.substr(COUNTER_LENGTH + Security::GCM_IV_LEN, RSA_PUBK_LENGTH);
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
        return 0;
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
    cout <<"Handshake protocol is completed successfully!" <<endl;
    return 1;
                                        
}

//sent by client B to the server 
int Message::send_message_11(char**message_buf, User* my_user){
    //wrap around check
    if(my_user->get_sent_counter() > UINT16_MAX - 2){
        cout <<"This session is not secure anymore! Try to loggin again" <<endl;
        char * msg {nullptr};
        return send_message_17(&msg, my_user);
    }
    //initialization vector
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){
        return -1;
    }
    //creating aad: message type, client_to_received_counter, iv
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN;
    char * aad = (char*)malloc(aad_len);
    if(!aad){
        free(iv);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return -1;
    }
    
    aad[0] = 11;
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = my_user->get_sent_counter() + 1;
    //add iv to aad
    memcpy(aad + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
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
        free(gcm_ciphertext);
        free(tag);
        free(iv);
        free(aad);
        return -1;
    }
    //
    int message_buf_len = aad_len + gcm_ciphertext_len + Security::GCM_TAG_LEN;
    *message_buf = (char*)malloc(message_buf_len);
    memcpy(*message_buf, aad, aad_len);
    memcpy(*message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(*message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);

    ///TODO:Send the data to the network!

    ////
    my_user->increment_sent_counter();
    free(aad);
    free(iv);
    free(gcm_plaintext);
    free(gcm_ciphertext);
    free(tag);
    cout << my_user->get_username()<<" sent message 11 to " << my_user->get_peer_username() <<endl;
    my_user->set_peer_username("");

    return message_buf_len;
}
//recevied by the server 
int Message::handle_message_11(char * message, size_t message_len, User* sender){
    int i;
    string msg = "";
    for (i = 0; i < message_len; i++) {
        msg = msg + message[i];
    }
    string tag = msg.substr(msg.length() - Security::GCM_TAG_LEN, Security::GCM_TAG_LEN);
    string ciphertext = msg.substr(msg.length() - Security::GCM_TAG_LEN - 2 * USERNAME_LENGTH, 2 * USERNAME_LENGTH);
    string aad = msg.substr(0, msg.length() - ciphertext.length() - tag.length());
    string gcm_iv = msg.substr(COUNTER_LENGTH, Security::GCM_IV_LEN);
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
    uint16_t received_counter = (uint16_t) *(message+1);
    if(!sender->replay_check(false, received_counter)){
        return -1;
    }
    string receiver_username = decryptedtext_str.substr(sender->get_username().length(),
                                decryptedtext_str.length() - sender->get_username().length());
    sender->set_peer_username(receiver_username);
    return 1;
}

//sent by the server to client A
unsigned int Message::send_message_12(char**message_buf, User* sender, User* receiver){
    //initialization vector
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){return 0;}
    //creating aad: message type, client_to_received_counter, iv
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
    *counter_pointer = receiver->get_received_counter() + 1;
    //insert the iv into aad
    memcpy(aad + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
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
        free(gcm_ciphertext);
        free(tag);
        free(iv);
        free(aad);
        return gcm_ciphertext_len;
    }
    int message_buf_len = aad_len + gcm_ciphertext_len + Security::GCM_TAG_LEN;
    *message_buf = (char*)malloc(message_buf_len);
    memcpy(*message_buf, aad, aad_len);
    memcpy(*message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(*message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);
    cout << "Server sends message 12 to " << receiver->get_username() <<endl;
    ///TODO:Send the data to the network!

    ////
    receiver->increment_received_counter();
    free(aad);
    free(iv);
    free(gcm_plaintext);
    free(gcm_ciphertext);
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
    string gcm_iv = msg.substr(COUNTER_LENGTH, Security::GCM_IV_LEN);
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
    uint16_t received_counter = (uint16_t) *(message+1);
    if(!my_user->replay_check(true, received_counter)){
        return -1;
    }
    string sender_username = decryptedtext_str.substr(0,
                                decryptedtext_str.length() - my_user->get_username().length());
    my_user->set_peer_username("");
    my_user->set_clients_pubk_char(nullptr);
    my_user->set_clients_pubk(nullptr);
    cout<< sender_username <<" Decliend Your Request to Chat!" <<endl;
    ///
    ///
    return 1;

}

//sent by client A to the server 
int Message::send_message_13(char**message_buf, unsigned char* message, size_t message_len, User* my_user){
    //wrap around check
    if(my_user->get_sent_counter() > UINT16_MAX - 2){
        cout <<"This session is not secure anymore! Try to loggin again" <<endl;
        char * msg {nullptr};
        return send_message_17(&msg, my_user);
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
    //creating aad: message type, client_to_received_counter, iv, generated dh public key,encrypted signature
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
    *counter_pointer = my_user->get_sent_counter() + 1;
    //put the iv into the aad
    memcpy(aad + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //put the encrypted message into the aad
    memcpy(aad + COUNTER_LENGTH + Security::GCM_IV_LEN, ciphertext, ciphertext_len);
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
    *message_buf = (char*)malloc(message_buf_len);
    memcpy(*message_buf, aad, aad_len);
    memcpy(*message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(*message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);
    cout << my_user->get_username()<<" sends message 13"<<endl;
    ///TODO:Send the data to the network!

    ////
    my_user->increment_sent_counter();
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
    string gcm_iv = msg.substr(COUNTER_LENGTH, Security::GCM_IV_LEN);
    string clients_ciphertext_str = aad.substr(COUNTER_LENGTH + Security::GCM_IV_LEN, 
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
    uint16_t received_counter = (uint16_t) *(message+1);
    if(!sender->replay_check(false, received_counter)){
        return -1;
    }
    sender->set_peer_username(gcm_decryptedtext_str.substr(sender->get_username().length(), 
                                                            gcm_decryptedtext_str.length() - sender->get_username().length()));
    return clients_ciphertext_str.length();
}
//sent by the server to the client B
unsigned int Message::send_message_14(char**message_buf, User* sender, User* receiver, unsigned char * clients_ciphertext, int clients_ciphertext_len){
    //initialization vector
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){return 0;}
    //load and send the rsa_public key of the sender
    //creating aad: message type, client_to_received_counter, iv, encrypted clients message
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
    *counter_pointer = receiver->get_received_counter() + 1;
    //put the iv into the aad
    memcpy(aad + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //put the encrypted encrypted clients message into the aad
    memcpy(aad + COUNTER_LENGTH + Security::GCM_IV_LEN, clients_ciphertext, clients_ciphertext_len);
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
        free(gcm_ciphertext);
        free(tag);
        free(iv);
        free(aad);
        return gcm_ciphertext_len;
    }

    int message_buf_len = aad_len + gcm_ciphertext_len + Security::GCM_TAG_LEN;
    *message_buf = (char*)malloc(message_buf_len);
    memcpy(*message_buf, aad, aad_len);
    memcpy(*message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(*message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);
    cout << "Server sends message 14 to " << receiver->get_username() <<endl;
    ///TODO:Send the data to the network!

    ////
    receiver->increment_received_counter();
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
    string gcm_iv = msg.substr(COUNTER_LENGTH, Security::GCM_IV_LEN);
    string clients_ciphertext_str = aad.substr(COUNTER_LENGTH + Security::GCM_IV_LEN, 
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
    uint16_t received_counter = (uint16_t) *(message+1);
    if(!my_user->replay_check(true, received_counter)){
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
unsigned int Message::send_message_17(char**message_buf, User* my_user){
    //initialization vector
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){
        return 0;
    }
    //creating aad: message type, client_to_received_counter, iv
    int aad_len = MESSAGE_TYPE_LENGTH + COUNTER_LENGTH + Security::GCM_IV_LEN;
    char * aad = (char*)malloc(aad_len);
    if(!aad){
        free(iv);
        cerr<< "Error: malloc for AAD returned NULL (too big AAD?)\n"; return 0;
    }
    
    aad[0] = 17;
    uint16_t * counter_pointer = (uint16_t *) (aad+1);
    *counter_pointer = my_user->get_sent_counter() + 1;
    //add iv to aad
    memcpy(aad + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
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
        free(gcm_ciphertext);
        free(tag);
        free(iv);
        free(aad);
        return 0;
    }
    //
    int message_buf_len = aad_len + gcm_ciphertext_len + Security::GCM_TAG_LEN;
    *message_buf = (char*)malloc(message_buf_len);
    memcpy(*message_buf, aad, aad_len);
    memcpy(*message_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(*message_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);

    ///TODO:Send the data to the network!

    ////
    my_user->increment_sent_counter();
    free(aad);
    free(iv);
    free(gcm_plaintext);
    free(gcm_ciphertext);
    free(tag);
    cout << my_user->get_username()<<" sent message 17 to server"<<endl;
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
    string gcm_iv = msg.substr(COUNTER_LENGTH, Security::GCM_IV_LEN);
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
    uint16_t received_counter = (uint16_t) *(message+1);
    if(!sender->replay_check(false, received_counter)){
        return -1;
    }
    if(!sender->get_peer_username().empty()){
        ///TODO:inform the peer that this client has logged out by message 16
    }
    sender->clear();
    cout << sender->get_username() << " has logged out!"<<endl;
    return -17;
}
