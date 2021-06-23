#include <cstdlib>
#include <iostream>
#include <string.h>
#include "security.h"

using namespace std;
int main(){
    unsigned char * key  = (unsigned char *) "1234567890123456";
    unsigned char plaintext[] = "This is very short message";
    unsigned char* ciphertext{nullptr};
    unsigned char* iv{nullptr};
    unsigned char* decryptedtext{nullptr};
    int ciphertext_len = Security::encryption_AES(plaintext,  strlen((char *)plaintext), key, &iv, &ciphertext);
 
    // int decrypted_len = Security::decryption_AES(ciphertext, ciphertext_len, key, iv, &decryptedtext);
    // decryptedtext[decrypted_len] = '\0';
    // cout << "Decrypted:\n";
    // cout << decryptedtext <<endl;
    free(ciphertext);
    // free(decryptedtext);
    free(iv);
    //delete iv;
    //free(ciphertext);
    //cout << "IV:\n";
    //BIO_dump_fp (stdout, (const char *)iv, Security::AES_IV_LEN);
    //free(iv,);
}