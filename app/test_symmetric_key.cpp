#include <cstdlib>
#include <iostream>
#include <string.h>
#include "Security.h"

using namespace std;

int main(){
    unsigned char * key  = (unsigned char *) "1234567890123456";
    unsigned char plaintext[] = "This is very short message";
    unsigned char* ciphertext{nullptr};
    unsigned char* iv{nullptr};
    unsigned char* decryptedtext{nullptr};
    int ciphertext_len = Security::encryption_AES(plaintext,  strlen((char *)plaintext), key, &iv, &ciphertext);
    
    int decrypted_len = Security::decryption_AES(ciphertext, ciphertext_len, key, iv, &decryptedtext);
    //decryptedtext[decrypted_len] = '\0';
    std::cout << "Decrypted:\n" <<endl;
    std::cout << decryptedtext <<endl;
    delete iv;
    free(ciphertext);
    free(decryptedtext);
    return 0;
}