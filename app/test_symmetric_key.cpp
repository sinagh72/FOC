#include <cstdlib>
#include <iostream>
#include <string.h>
#include "security.h"

using namespace std;
int main(){
    unsigned char * key  = (unsigned char *) "1234567890123456";
    unsigned char plaintext[] = "This is very short message";
    unsigned char* ciphertext = (unsigned char *)malloc(sizeof(plaintext)+16);
    unsigned char* iv = (unsigned char *)malloc(Security::AES_IV_LEN);
    int ciphertext_len = Security::encryption_AES(plaintext,  strlen((char *)plaintext), key, iv, ciphertext);

    unsigned char*decryptedtext = (unsigned char*)malloc(ciphertext_len);
    Security::decryption_AES(ciphertext,ciphertext_len, key, iv, decryptedtext);
    cout << "Decrypted:\n";
    cout << decryptedtext <<endl;
    free(decryptedtext);
    free(ciphertext);
    free(iv);
}