#include "security.h"
#include <string.h>

int main(){
    unsigned char * text_to_sign = (unsigned char *)"This is a test to check if signature works fine";
    unsigned char * signature {nullptr};
    int text_to_sign_len = strlen((const char*)text_to_sign) + 1;
    int signature_len = Security::signature("server_privK/ChatApp_key.pem", text_to_sign, text_to_sign_len, &signature);
    Security::verify_signature(signature, signature_len, text_to_sign, text_to_sign_len);
    return 0;
}