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
    // generate g^a
    Security::generate_dh_pubk(&my_pubk);
    char* my_pubk_char = Security::EVP_PKEY_to_chars(my_pubk);
    cout<<"My DH public " <<strlen((const char*)my_pubk_char) << " key: "<<endl;
    BIO_dump_fp (stdout, (const char *)my_pubk_char, strlen((const char*)my_pubk_char));
    
    //g^b
    EVP_PKEY * peers_pubk{nullptr};
    // generate g^b
    Security::generate_dh_pubk(&peers_pubk);
    char* peers_pubk_char = Security::EVP_PKEY_to_chars(peers_pubk);
    cout<<"Other party DH public " <<strlen((const char*)peers_pubk_char) << " key: "<<endl;
    BIO_dump_fp (stdout, (const char *)peers_pubk_char, strlen((const char*)peers_pubk_char));

    //generate g^{ab}
    unsigned char* skey{nullptr}; //session key g^{ab}
    Security::generate_dh_key(my_pubk, peers_pubk, &skey);

    //concat -> g^a,b^b
    int plaintext_len = strlen((const char*)my_pubk_char) + strlen((const char*)peers_pubk_char)+2;
    char * plaintext = (char*)malloc(plaintext_len);
    strcpy(plaintext,my_pubk_char);
    strcat(plaintext,",");
    strcat(plaintext,peers_pubk_char);
    cout<<"Concatenation: " <<endl;
    BIO_dump_fp (stdout, (const char *)plaintext, plaintext_len);
    cout<<endl;

    //digital signature
    unsigned char* signature{nullptr};
    //digitally signed the {g^a,b^b} by private key
    Security::signature("users/sina/rsa_privkey.pem", (unsigned char *)plaintext, plaintext_len, &signature);
    int signature_len = strlen((const char*)signature);
    cout << "PT: "<< endl;
    
    BIO_dump_fp (stdout, (const char *)signature, signature_len);

    unsigned char* tag{nullptr};
    unsigned char* ciphertext{nullptr};
    unsigned char* iv{nullptr};
    unsigned char* decryptedtext{nullptr};
    
    //initialization vector
    iv = (unsigned char *)malloc(Security::GCM_IV_LEN);
    if (!iv){ cerr << "Error: malloc returned NULL (iv is too big?)\n"; return -1; }
    //seed OpenSSL PRNG
    RAND_poll();
    RAND_bytes((unsigned char*)iv, Security::GCM_IV_LEN);

    //aad
    //aad: g^a||iv
    int aad_len = strlen((const char*)my_pubk_char)+Security::GCM_IV_LEN+1;
    char * aad = (char*)malloc(aad_len);
    strcpy(aad,my_pubk_char);
    strcat(aad,(const char*)iv);
    
    
    //GCM encryption
    int ciphertext_len = Security::gcm_encrypt((unsigned char *)aad, aad_len , signature, signature_len, 
        skey, iv, &ciphertext, &tag);

    cout << "CT: "<<endl;
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    cout << "TAG: "<< endl;
    BIO_dump_fp (stdout, (const char *)tag, Security::GCM_TAG_LEN);
    //GCM decryption
    int decryptedtext_len = Security::gcm_decrypt((unsigned char *)aad, aad_len, ciphertext, ciphertext_len,
        skey, iv, &decryptedtext, tag);

    cout << "DT: "<< endl;
    BIO_dump_fp (stdout, (const char *)decryptedtext, decryptedtext_len);
    cout << endl;
    Security::verify_signature("users/sina/rsa_pubkey.pem", signature, signature_len, 
                            (unsigned char *)plaintext, plaintext_len);
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