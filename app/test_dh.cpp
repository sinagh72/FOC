#include "security.h"
#include <cstdlib>
#include <iostream>
#include "security.h"

using namespace std;

int main(){
    EVP_PKEY * my_pubk{nullptr};
    EVP_PKEY * peers_pubk{nullptr};
    unsigned char* skey{nullptr};
    Security::generate_dh_pubk(&my_pubk);
    Security::generate_dh_pubk(&peers_pubk);
    Security::generate_dh_key(my_pubk, peers_pubk, &skey);
    //
    
}