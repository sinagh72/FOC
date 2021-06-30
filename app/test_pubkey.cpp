#include "Security.h"
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string.h>
//#include "Message.h"
#include <openssl/rand.h>

using namespace std;

int main(){
    int size = 0;
    //g^a
    EVP_PKEY * g_a{nullptr};
    Security::generate_dh_pubk(&g_a);
    unsigned char*g_a_char{nullptr};
    size = Security::EVP_PKEY_to_chars(g_a, &g_a_char);
    cout << "size of g^a " << size <<endl;
    //g^b
    EVP_PKEY * g_b{nullptr};
    Security::generate_dh_pubk(&g_b);
    unsigned char*g_b_char{nullptr};
    size = Security::EVP_PKEY_to_chars(g_b, &g_b_char);
    cout << "size of g^b " << size <<endl;
    //digest key
    unsigned char *digest{nullptr};
    size = Security::generate_dh_key(g_a, g_b, &digest);
    cout << "size of digest " << size <<endl;
    ///deserialize the dh pubks
    EVP_PKEY * g_a_d{nullptr};
    Security::chars_to_EVP_PKEY(&g_a_d, g_a_char);
    EVP_PKEY * g_b_d{nullptr};
    Security::chars_to_EVP_PKEY(&g_b_d, g_b_char);
    //
    cout << "The compare: " << EVP_PKEY_cmp(g_a_d, g_a) <<endl;
    //1 means they are not equal
    //digest key
    unsigned char *digest_d{nullptr};
    size = Security::generate_dh_key(g_a_d, g_b_d, &digest_d);
    cout << "size of digest des " << size <<endl;


    // BIO_dump_fp (stdout, pkey_buf, 1190);

    // char* pubkey_buf = (char*)malloc(pubkey_size);
    // BIO *mbio = BIO_new(BIO_s_mem());   
    // int c = BIO_write(mbio,pubkey_buf,pubkey_size);
    // cout << c <<endl;
    // EVP_PKEY *desrialize = PEM_read_bio_PUBKEY(mbio, NULL,NULL,NULL);
    // BIO_free(mbio);
    // char* pubkey_buf2 = NULL;
    // Security::EVP_PKEY_to_chars(desrialize, &pubkey_buf2);
    // cout << "SIZE EVPkey:"<<EVP_PKEY_size(desrialize)<<endl;
    // cout << "SIZE strlen:"<<strlen(my_pubk_char2)<<endl;


    // // generate g^a
    // Security::generate_dh_pubk(&my_pubk);
    // char* pubkey_buf = NULL;
    // Security::EVP_PKEY_to_chars(my_pubk, &pubkey_buf);
    // // cout<<"My DH public " <<strlen((const char*)my_pubk_char) << " key: "<<endl;
    // BIO_dump_fp (stdout, pubkey_buf, 6);
    // cout << "SIZE EVPkey:"<<EVP_PKEY_size(my_pubk)<<endl;
    // cout << "SIZE strlen:"<<strlen(pubkey_buf)<<endl;

    // BIO *mbio = BIO_new(BIO_s_mem());
    // BIO_write(mbio,pubkey_buf,1190);
    // EVP_PKEY *desrialize = PEM_read_bio_PUBKEY(mbio, NULL,NULL,NULL);
    // BIO_free(mbio);
    // char* pubkey_buf2 = NULL;
    // Security::EVP_PKEY_to_chars(desrialize, &pubkey_buf2);
    // cout << "SIZE EVPkey:"<<EVP_PKEY_size(desrialize)<<endl;
    //cout << "SIZE strlen:"<<strlen(my_pubk_char2)<<endl;
    
}