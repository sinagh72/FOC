#include <cstring>
#include <iostream>
#include <openssl/bio.h>
#include <string>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>
#include <openssl/pem.h>
#include <string.h>
#include <stdio.h>
#include <openssl/conf.h>
#include "Security.h"
#include "dimensions.h"
using namespace std;
int main(){
    EVP_PKEY * pubkeyA{nullptr};
    Security::generate_dh_pubk(&pubkeyA);
    BIO *bio{nullptr};
    unsigned char*pk_bufA{nullptr};
    Security::EVP_PKEY_to_chars(bio, pubkeyA, &pk_bufA);
    BIO_dump_fp (stdout, (const char *)pk_bufA, DH_PUBK_LENGTH);
    cout<<"===================================\n";
    EVP_PKEY * pubkB{nullptr};
    Security::generate_dh_pubk(&pubkB);
    BIO_dump_fp (stdout, (const char *)pk_bufA, DH_PUBK_LENGTH);
    cout<<"===================================\n";
    EVP_PKEY * pubkc{nullptr};
    Security::generate_dh_pubk(&pubkc);
    BIO_dump_fp (stdout, (const char *)pk_bufA, DH_PUBK_LENGTH);
    EVP_PKEY * pubkd{nullptr};
    BIO *mio{nullptr};
    Security::chars_to_EVP_PKEY(mio, &pubkd, pk_bufA);
    BIO_dump_fp (stdout, (const char *)pk_bufA, DH_PUBK_LENGTH);

    


}