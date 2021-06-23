#ifndef _CHATTINGAPP_HPP_
#define _CHATTINGAPP_HPP_
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <string>

using namespace std;

// const EVP_CIPHER* const AES_CIPHER = EVP_aes_256_cbc();
// const int AES_IV_LEN = EVP_CIPHER_iv_length(AES_CIPHER);
// const int AES_BLOCK_SIZE = EVP_CIPHER_block_size(AES_CIPHER);
// const EVP_MD * const SHA_256 = EVP_sha256();

class Security{

public:
    static const EVP_CIPHER * const AES_CIPHER;
    static const int AES_IV_LEN;
    static const int AES_BLOCK_SIZE;
    static const EVP_MD* const SHA_256;
    //======================================================================================
    /**
     * encrypt the message using symmetric key and AES CBC mode
     * @param plaintext the plaintext to encrypt
     * @param plaintext_len the length of the plaintext
     * @param key the symmetric key
     * @param iv the initialization vector. It will be assigned inside this function
     * @param ciphertext the ciphertext
     * @return intger to specify that the encryption is succeeded (length of ciphertext) or not -1
     */
    static int encryption_AES(unsigned char *plaintext, int plaintext_len, unsigned char *key, 
    unsigned char **iv, unsigned char **ciphertext);
     //======================================================================================
    /**
     * encrypt the message using symmetric key and AES CBC mode
     * @param ciphertext the ciphertext to decrypt
     * @param ciphertext_len the length of the ciphertext
     * @param key the symmetric key
     * @param iv the initialization vector
     * @param decryptedtext the decryptedtext
     * @return intger to specify that the encryption is succeeded (length of plaintext) or not -1 
     */
    static int decryption_AES(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, 
    unsigned char *iv, unsigned char **decryptedtext);
    //======================================================================================
     /**
     * digitally signed the input text
     * @param prvkey_filename private key file name for digital signature
     * @param input_signtext the input we want to signed with the private key
     * @param output_signtext the digitally signed input. We passed nullptr. It will be initiallized inside the function
     * @return the digital signature of the corresponding input 
     */
    int signature(string prvkey_filename, unsigned char * input_sign, unsigned char * output_sign);
    //======================================================================================
    static unsigned char* verify_signature();

};

#endif