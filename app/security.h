#ifndef APP_SECURITY_H
#define APP_SECURITY_H
#include <openssl/conf.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <string>

using namespace std;

// const EVP_CIPHER* const AES_CIPHER = EVP_aes_256_cbc();
// const int AES_IV_LEN = EVP_CIPHER_iv_length(AES_CIPHER);
// const int AES_BLOCK_SIZE = EVP_CIPHER_block_size(AES_CIPHER);
// const EVP_MD * const SHA_256 = EVP_sha256();

class Security{

public:
    static const EVP_CIPHER* const AES_CIPHER;
    static const int AES_IV_LEN;
    static const int AES_BLOCK_SIZE;
    static const EVP_MD* const SHA_256;
    static const EVP_CIPHER* const GCM_CIPHER;
    static const int GCM_IV_LEN;
    static const int GCM_BLOCK_SIZE;
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
    * @return intger to specify that the decryption is succeeded (length of plaintext) or not -1 
    */
    static int decryption_AES(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, 
    unsigned char *iv, unsigned char **decryptedtext);
    //======================================================================================
    /**
    * digitally signed the input text
    * @param prvk_filename address of the private key file name for digital signature
    * @param text_to_sign the input text we want to signed with the private key
    * @param text_to_sign_len the lenght of the input text
    * @param signature the digitally signed signature. 
    * @return intger to specify that the signing is succeeded (length of plaintext) or not -1 
    */
    static int signature(string prvk_filename, unsigned char * text_to_sign, int text_to_sign_len,
     unsigned char ** signature);
    //======================================================================================
    /**
    * verify signature according to the public key
    * @param pubk_filename the public key of the peer to verify the signature
    * @param signature address of the private key file name for digital signature
    * @param signature_len the input text we want to signed with the private key
    * @param clear_text the lenght of the input text
    * @param clear_text_len the digitally signed signature. 
    * @return intger to specify that the verification is succeeded (length of plaintext) or not -1 
    */
    static int verify_signature(string pubk_filename, unsigned char * signature, int signature_len, unsigned char * clear_text, int clear_text_len);
    //======================================================================================
    /**
    * verify the input certificate and verify it according to the store
    * @param cert_file_name the address of the certificate to verify
    * @return intger to specify that the verification is succeeded (length of plaintext) or not -1 
    */
    static int verify_certificate(string cert_file_name);
    //======================================================================================
    static int gcm_encrypt(unsigned char * aad, int aad_len, unsigned char * plaintext, int plaintext_len, 
    unsigned char * key, unsigned char **iv, unsigned char ** ciphertext, unsigned char ** tag);

    //======================================================================================
    static int gcm_decrypt(unsigned char * aad, int aad_len, unsigned char * ciphertext, int ciphertext_len, 
    unsigned char * key, unsigned char *iv, int iv_len, unsigned char ** decryptedtext, unsigned char * tag);
    //======================================================================================
    /**
    * generates a DH public key and assign it to the variable pubk
    * @return intger to specify that the generating is succeeded (length of plaintext) or not -1 
    */
    static int generate_dh_pubk(EVP_PKEY** pubk);
    //======================================================================================
    //
    /**
    * generates the p and g for DH
    * @return the DH param for generating DH key  
    */
    static DH* get_dh2048(void);
    //======================================================================================
    /**
    * generates a DH session key with two public keys
    * @param my_pubk the public key of they client that calls the function
    * @param peers_pubk the public key of the peers
    * @param skey the established session key
    * @return intger to specify that the generating is succeeded (length of plaintext) or not -1 
    */
    static int generate_dh_key(EVP_PKEY * my_pubk, EVP_PKEY * peers_pubk,  unsigned char **skey);
};

#endif