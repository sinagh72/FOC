#include "Security.h"
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <string.h>
//#include "Message.h"
#include <openssl/rand.h>
#include <fstream>  

using namespace std;

int main(){
    int size = 0;
    //g^a
    EVP_PKEY * g_a{nullptr};
    Security::generate_dh_pubk(&g_a);
    unsigned char*g_a_char{nullptr};
    size = Security::EVP_PKEY_to_chars(g_a, &g_a_char);
    cout << "size of g^a " << size <<endl;
    // //g^b
    EVP_PKEY * g_b{nullptr};
    Security::generate_dh_pubk(&g_b);
    unsigned char*g_b_char{nullptr};
    size = Security::EVP_PKEY_to_chars(g_b, &g_b_char);
    cout << "size of g^b " << size <<endl;

    FILE *p1w = fopen("g_b.pem", "w");
    if(!p1w){ cerr << "Error: cannot open file '"<< "test.pem" << "' (missing?)\n"; exit(1); }
    PEM_write_PUBKEY(p1w, g_b);
    fclose(p1w);

    FILE * pubk_file = fopen("g_b.pem", "r");
    if(!pubk_file){ cerr << "Error: cannot open file '" << "g_b.pem"<< "' (missing?)\n"; exit(1); }
    EVP_PKEY * g_b_ = PEM_read_PUBKEY(pubk_file, NULL, NULL, NULL);
    fclose(pubk_file);
    if(!pubk_file){ cerr << "Error: PEM_read_PUBKEY returned NULL\n"; exit(1); }


    unsigned char *digest{nullptr};
    size = Security::generate_dh_key(g_a, g_b, &digest);
    cout << "size of digest " << size <<endl;
    BIO_dump_fp (stdout, (char*)digest, size);

    unsigned char *digest2{nullptr};
    size = Security::generate_dh_key(g_a, g_b_, &digest2);
    cout << "size of digest " << size <<endl;
    BIO_dump_fp (stdout, (char*)digest2, size);


}