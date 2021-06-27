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
    //g^a
    EVP_PKEY * pubk{nullptr};
    Security::generate_dh_pubk(&pubk);
    cout << "SIZE EVPkey:"<<EVP_PKEY_size(pubk)<<endl;
    unsigned char*pkey_buf{nullptr};
    // Security::EVP_PKEY_to_chars(pubk, &pkey_buf);
    BIO *bio = NULL;
    Security::EVP_PKEY_to_chars(bio, pubk, &pkey_buf);
    // BIO *bio = BIO_new(BIO_s_mem());
    // PEM_write_bio_PUBKEY(bio, pubk);
    // char*pkey_buf = NULL;
    // long pubkey_size =  BIO_get_mem_data(bio, &pkey_buf);
    // cout << "SIZE long:" <<pubkey_size<<endl;
    // BIO_dump_fp (stdout, pkey_buf, 1190);
    cout << "buffer size outside the function:"<<strlen((char*)pkey_buf)<<endl;
    BIO_free(bio);

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