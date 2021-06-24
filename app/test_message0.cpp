#include "Security.h"
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/dh.h>
#include <string.h>
#include "Message.h"
#include <openssl/rand.h>

using namespace std;

int main(){
    //g^a
    EVP_PKEY * my_pubk{nullptr};
    //g^b
    EVP_PKEY * peers_pubk{nullptr};
    //session key g^{ab}
    unsigned char* skey{nullptr};
    // generate g^a
    Security::generate_dh_pubk(&my_pubk);
    char* my_pubk_char = Security::EVP_PKEY_to_chars(my_pubk);
    // generate g^b
    Security::generate_dh_pubk(&peers_pubk);
    char* peers_pubk_char = Security::EVP_PKEY_to_chars(peers_pubk);
    //generate g^{ab}
    Security::generate_dh_key(my_pubk, peers_pubk, &skey);
    //concat -> g^a,b^b
    BIO_dump_fp (stdout, (const char *)my_pubk_char, strlen((const char*)my_pubk_char));
    BIO_dump_fp (stdout, (const char *)peers_pubk_char, strlen((const char*)peers_pubk_char));

    int plaintext_len = strlen((const char*)my_pubk_char) + strlen((const char*)peers_pubk_char)+2;
    char * plaintext = (char*)malloc(plaintext_len);
    strcpy(plaintext,my_pubk_char);
    strcat(plaintext,",");
    strcat(plaintext,peers_pubk_char);
    BIO_dump_fp (stdout, (const char *)plaintext, strlen((const char*)plaintext));
    int text_to_sign_len = strlen(my_pubk_char);
    unsigned char* signature{nullptr};
    //digitally signed the {g^a,b^b} by private key
    Security::signature("users/sina/rsa_privkey.pem", (unsigned char *)plaintext, text_to_sign_len, &signature);

    unsigned char* tag{nullptr};
    unsigned char* ciphertext{nullptr};
    unsigned char* iv{nullptr};
    unsigned char* decryptedtext{nullptr};
    
    iv = (unsigned char *)malloc(Security::GCM_IV_LEN);
    if (!iv){ cerr << "Error: malloc returned NULL (iv is too big?)\n"; return -1; }
    //seed OpenSSL PRNG
    RAND_poll();
    RAND_bytes((unsigned char*)iv, Security::GCM_IV_LEN);
    //aad: g^a||iv
    int aad_len = strlen((const char*)my_pubk_char)+Security::GCM_IV_LEN+1;
    char * aad = (char*)malloc(aad_len);
    strcpy(aad,my_pubk_char);
    strcat(plaintext,(const char*)iv);
    cout << "PT: "<< endl;
    BIO_dump_fp (stdout, plaintext, plaintext_len);
    //GCM encryption
    int ciphertext_len = Security::gcm_encrypt((unsigned char *)aad, aad_len , (unsigned char *)plaintext, plaintext_len, 
        skey, iv, &ciphertext, &tag);

    cout << "CT: "<<endl;
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    cout << "TAG: "<< endl;
    BIO_dump_fp (stdout, (const char *)tag, Security::GCM_TAG_LEN);
    //GCM decryption
    int decryptedtext_len = Security::gcm_decrypt((unsigned char *)aad, aad_len, ciphertext, ciphertext_len,
        skey, iv, &decryptedtext, tag);

    cout << "DT: "<< endl;
    BIO_dump_fp (stdout, (const char *)decryptedtext, ciphertext_len);

    free(tag);
    free(ciphertext);
    free(iv);
    free(skey);
    free(signature);
    free(decryptedtext);
    free(plaintext);
    free(aad);
    EVP_PKEY_free(peers_pubk);
    EVP_PKEY_free(my_pubk);
    

    // printf("prima di create message");
    // char* message{nullptr};
    // printf("%d\n", Message::create_message_0("pippo", &message));
    // printf("%s", message+33);

    return 0;


}