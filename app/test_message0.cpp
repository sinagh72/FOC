#include "Security.h"
#include <cstdlib>
#include <iostream>
#include <openssl/dh.h>
#include <string.h>
#include "Message.h"
#include <openssl/rand.h>

using namespace std;

int main(){
    EVP_PKEY * my_pubk{nullptr};
    EVP_PKEY * peers_pubk{nullptr};
    unsigned char* skey{nullptr};
    Security::generate_dh_pubk(&my_pubk);
    Security::generate_dh_pubk(&peers_pubk);
    Security::generate_dh_key(my_pubk, peers_pubk, &skey);
    unsigned char* plaintext = (unsigned char*) "very short message";
    unsigned char* tag{nullptr};
    unsigned char* ciphertext{nullptr};
    unsigned char* iv{nullptr};
    unsigned char* decryptedtext{nullptr};
    iv = (unsigned char *)malloc(Security::GCM_IV_LEN);
    if (!iv){ cerr << "Error: malloc returned NULL (iv is too big?)\n"; return -1; }
    //seed OpenSSL PRNG
    RAND_poll();
    RAND_bytes((unsigned char*)iv, Security::GCM_IV_LEN);
    //here aad is equal to iv!
    int ciphertext_len = Security::gcm_encrypt(iv, Security::GCM_IV_LEN , plaintext, strlen((const char*)plaintext), 
        skey, iv, &ciphertext, &tag);

    cout << "CT: "<<endl;
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    cout << "TAG: "<< endl;
    BIO_dump_fp (stdout, (const char *)tag, Security::GCM_TAG_LEN);

    int decryptedtext_len = Security::gcm_decrypt(iv, Security::GCM_IV_LEN, ciphertext, ciphertext_len,
        skey, iv, &decryptedtext, tag);

    cout << "PT: "<< endl;
    BIO_dump_fp (stdout, (const char *)decryptedtext, ciphertext_len);

    free(tag);
    free(ciphertext);
    free(iv);
    free(skey);
    free(decryptedtext);
    EVP_PKEY_free(peers_pubk);
    EVP_PKEY_free(my_pubk);

    printf("prima di create message");
    char* message{nullptr};
    printf("%d\n", Message::create_message_0("pippo", &message));
    printf("%s", message+33);

    return 0;


}