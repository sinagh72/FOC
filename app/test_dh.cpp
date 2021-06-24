#include "Security.h"
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/dh.h>
#include <string.h>
#include "Message.h"
#include <openssl/rand.h>
#include <unistd.h>

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
    return 0;

}