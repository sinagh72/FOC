#include "Security.h"
#include <string.h>

int main(){
    unsigned char * text_to_sign = (unsigned char *)"This is a test to check if signature works fine";
    unsigned char * signature {nullptr};
    int text_to_sign_len = strlen((const char*)text_to_sign) ;
    int signature_len = Security::signature("users/sina/rsa_privkey.pem", text_to_sign, text_to_sign_len, &signature);
    Security::verify_signature("users/sina/rsa_pubkey.pem", signature, signature_len, text_to_sign, text_to_sign_len);
    return 0;
}