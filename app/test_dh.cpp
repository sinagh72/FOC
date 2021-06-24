#include "security.h"
#include <cstdlib>
#include <iostream>
#include "security.h"
#include <openssl/dh.h>
#include <string.h>

using namespace std;

int main(){
    EVP_PKEY * my_pubk{nullptr};
    EVP_PKEY * peers_pubk{nullptr};
    unsigned char* skey{nullptr};
    Security::generate_dh_pubk(&my_pubk);
    Security::generate_dh_pubk(&peers_pubk);
    Security::generate_dh_key(my_pubk, peers_pubk, &skey);
    unsigned char * plaintext = (unsigned char*) "this is the message to encrypt";
    unsigned char* tag{nullptr};
    unsigned char* ciphertext{nullptr};
    unsigned char* iv{nullptr};
    cout << "key size: "<< strlen((char *)skey) <<endl;
    //
    unsigned char iv_gcm[]= "123456780912";
    int ciphertext_len = Security::gcm_encrypt(iv_gcm, Security::GCM_IV_LEN , plaintext, strlen((char *)plaintext), 
        skey, &iv, &ciphertext, &tag);

    free(tag);
    free(ciphertext);
    free(iv);
    free(skey);
    EVP_PKEY_free(peers_pubk);
    EVP_PKEY_free(my_pubk);

    return 0;
}