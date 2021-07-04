#ifndef APP_SECURITY_H
#define APP_SECURITY_H

#include <openssl/conf.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <string>
#include <cstdlib>
#include <cstring>
#include <openssl/bio.h>
#include <openssl/ossl_typ.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>
#include <openssl/pem.h>
#include <stdio.h>
#include "dimensions.h"
 #include <openssl/rsa.h>

using namespace std;

class Security{

public:
    static const EVP_CIPHER * const AES_CIPHER;
    static const int AES_IV_LEN;
    static const int AES_BLOCK_SIZE;
    static const EVP_MD * const SHA_256;
    static const EVP_CIPHER * const GCM_CIPHER;
    static const int GCM_IV_LEN;
    static const int GCM_TAG_LEN;
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
    unsigned char *iv, unsigned char **ciphertext);
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
    * @param password the password of the private key file
    * @param text_to_sign the input text we want to signed with the private key
    * @param text_to_sign_len the lenght of the input text
    * @param signature the digitally signed signature. 
    * @return intger to specify that the signing is succeeded (length of plaintext) or not -1 
    */
    static int signature(string prvk_filename, unsigned char * password, unsigned char * text_to_sign, int text_to_sign_len,
     unsigned char ** signature);
    //======================================================================================
    /**
    * verify signature according to the public key
    * @param pubk the public key of the peer to verify the signature
    * @param signature address of the private key file name for digital signature
    * @param signature_len the input text we want to signed with the private key
    * @param clear_text the lenght of the input text
    * @param clear_text_len the digitally signed signature. 
    * @return intger to specify that the verification is succeeded (length of plaintext) or not -1 
    */
    static int verify_signature(EVP_PKEY* pubk, unsigned char * signature, int signature_len, unsigned char * clear_text, int clear_text_len);
    //======================================================================================
    /**
    * verify the input certificate and verify it according to the store
    * @param cert_file_name the address of the certificate to verify
    * @return intger to specify that the verification is succeeded (length of plaintext) or not -1 
    */
    static int verify_certificate(string cert_file_name);
    //======================================================================================
    /**
    * use the GCM to authenticate and encrypt the plaintext and returns the tag and ciphertext 
    * @param aad aad for the GCM
    * @param aad_len the length of the aad for the GCM
    * @param plaintext plaintext we want to encrypt
    * @param plaintext_len length of the plaintext we want to encrypt
    * @param key key for authentication and encryption
    * @param iv initialization vector 
    * @param ciphertext the ciphertext of the encryption
    * @param tag the generated tag after encryption and authentication
    * @return intger to specify the length of the ciphertext
    */
    static int gcm_encrypt(unsigned char * aad, int aad_len, unsigned char * plaintext, int plaintext_len, 
    unsigned char * key, unsigned char *iv, unsigned char ** ciphertext, unsigned char ** tag);

    //======================================================================================
    /**
    * use the GCM to verify authentication by the tag, decrypt the ciphertext and returns plaintext
    * @param aad aad for the GCM
    * @param aad_len the length of the aad for the GCM
    * @param ciphertext ciphertext we want to encrypt
    * @param ciphertext_len length of the ciphertext we want to decrypt
    * @param key key for verify authentication and decryption
    * @param iv initialization vector 
    * @param decryptedtext the decrypted text
    * @param tag the tag for verify authentication
    * @return intger to specify the length of the decryptedtext 
    */
    static int gcm_decrypt(unsigned char * aad, int aad_len, unsigned char * ciphertext, int ciphertext_len, 
    unsigned char * key, unsigned char *iv, unsigned char ** decryptedtext, unsigned char * tag);
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
    * generates a DH session key with two public keys. The input keys are not deallocated in this function
    * So their memory should be deallocated! 
    * @param my_dhkey the public key of they client that calls the function (g^a)
    * @param peers_dhk the public key of the peers (g^b)
    * @param digest the digest of the established session key
    * @return intger to specify that the generating is succeeded (length of the key) or not -1
    */
    static unsigned int generate_dh_key(EVP_PKEY * my_dhkey, EVP_PKEY * peers_dhk, unsigned char ** key);
    //======================================================================================
    /**
    * convert the EVP_PKEY into char*
    * @param pkey the public key to convert into char*
    * @param bio BIO serialization, null pointer to BIO should pass to this function
    * @param pk_buf the output buffer 
    * @return intger to specify that serialization is succeeded (length of output buffer) or not -1  
    */
    static int EVP_PKEY_to_chars(EVP_PKEY *pkey, unsigned char** pk_buf);
    //======================================================================================
        //======================================================================================
    /**
    * convert char* into EVP_PKEY 
    * @param pk_buf the public key in character
    * @param pkey the output pubk 
    * @return intger to specify that serialization is succeeded (length of output buffer) or not -1  
    */
    static int chars_to_EVP_PKEY(EVP_PKEY **pkey, unsigned char* pk_buf);
    //======================================================================================
    /** 
    * generates initialization vector 
    * @param iv the iv we want to initialize
    * @param iv_len the lenght of the iv
    */
    static bool generate_iv(unsigned char**iv, int iv_len);
    //======================================================================================

};

#endif