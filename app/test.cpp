#include <cstring>
#include <iostream>
#include <string>
#include <string.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>
#include <openssl/pem.h>
#include <string.h>
#include <stdio.h>
#include <mcheck.h>
#include <openssl/conf.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include "Security.h"
using namespace std;
int main(){
    unsigned char* txt = (unsigned char*)"asdfasdffasdfasdf";
    unsigned char* signature{nullptr};
    int signature_len = Security::signature("./users/sina/rsa_privkey.pem", txt, strlen((char*)txt), &signature);
    cout << signature_len;

}