#include "security.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>
#include <openssl/pem.h>
#include <string.h>
#include<stdio.h>

using namespace std;


const EVP_CIPHER* const Security::AES_CIPHER = EVP_aes_256_cbc();
const int Security::AES_IV_LEN = EVP_CIPHER_iv_length(Security::AES_CIPHER);
const int Security::AES_BLOCK_SIZE = EVP_CIPHER_block_size(Security::AES_CIPHER);
const EVP_MD * const Security::SHA_256 = EVP_sha256();

int Security::encryption_AES(unsigned char *plaintext, int plaintext_len, 
    unsigned char *key, unsigned char **iv, unsigned char **ciphertext){
    
    *ciphertext = (unsigned char *)malloc(sizeof(plaintext)+16);
    if (!*ciphertext){ cerr << "Error: malloc returned NULL (ciphertext is too big?)\n"; return -1; }
    *iv = (unsigned char *)malloc(Security::AES_IV_LEN);
    if (!*iv){ cerr << "Error: malloc returned NULL (iv is too big?)\n"; return -1; }

    EVP_CIPHER_CTX *ctx;
    int ret;
    //seed OpenSSL PRNG
    RAND_poll();
    //
    ret = RAND_bytes((unsigned char*)&*iv[0], AES_IV_LEN);

    cout << "IV:\n";
    BIO_dump_fp (stdout, (const char *)*iv, AES_IV_LEN);
    //create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx){ cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; return -1; }
    ret = EVP_EncryptInit(ctx, AES_CIPHER, key, *iv);
    if (ret != 1){ cerr << "Error: EVP_EncryptInit Failed\n"; EVP_CIPHER_CTX_free(ctx); return -1; }

    int update_len = 0;// bytes encrypted at each chunk
    int total_len = 0;// total encrypted bytes
 
    //Encrypt Update
    ret = EVP_EncryptUpdate(ctx, *ciphertext, &update_len, plaintext, plaintext_len);
    if (ret != 1){ cerr << "Error: EVP_EncryptUpdate Failed\n"; EVP_CIPHER_CTX_free(ctx); return -1; }

    total_len += update_len;

    //Encrypt Final. Finalize the encryption and adds the padding
    ret = EVP_EncryptFinal(ctx, *ciphertext+total_len, &update_len);
    if (ret != 1){ cerr << "Error: EVP_EncryptFinal Failed\n"; EVP_CIPHER_CTX_free(ctx); return -1; }

    total_len += update_len;
    int ciphertext_len = total_len;

    
    cout << "Encrypted:\n";
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
    //delete the context and the plain_text from memory
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;

}

int Security::decryption_AES(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, 
    unsigned char *iv, unsigned char **decryptedtext){
        
    *decryptedtext = (unsigned char*)malloc(ciphertext_len);
    if (!*decryptedtext){ cerr << "Error: malloc returned NULL (decryptedtext is too big?)\n"; return -1; }

    EVP_CIPHER_CTX *ctx;
    int ret;
    //create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx){ cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; EVP_CIPHER_CTX_free(ctx); return -1; }
    ret = EVP_DecryptInit(ctx, AES_CIPHER, key, iv);
    if (ret != 1){ cerr << "Error: EVP_DecryptInit Failed\n"; EVP_CIPHER_CTX_free(ctx); return -1; }

    int update_len = 0;// bytes encrypted at each chunk
    int total_len = 0;// total encrypted bytes

    //Encrypt Update
    ret = EVP_DecryptUpdate(ctx, *decryptedtext, &update_len, ciphertext, ciphertext_len);
    if (ret != 1){ cerr << "Error: EVP_DecryptUpdate Failed\n"; EVP_CIPHER_CTX_free(ctx); return -1; }

    total_len += update_len;

    //Encrypt Final. Finalize the encryption and adds the padding
    ret = EVP_DecryptFinal(ctx, *decryptedtext+total_len, &update_len);
    if (ret != 1){ cerr << "Error: EVP_DecryptFinal Failed\n"; EVP_CIPHER_CTX_free(ctx); return -1; }

    total_len += update_len;
    int plaintext_len = total_len;

    //delete the context and the plain_text from memory
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int Security::signature(string prvkey_filename, unsigned char * input_sign, unsigned char * output_sign){
    // load private key:    
    FILE* prvkey_file = fopen(prvkey_filename.c_str(), "r");
    if(!prvkey_file){ cerr << "Error: cannot open file '" << prvkey_filename << "' (missing?)\n"; return -1; }
    EVP_PKEY* prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
    fclose(prvkey_file);
    if(!prvkey){ cerr << "Error: PEM_read_PrivateKey returned NULL\n"; return -1; }
    // allocate buffer for signature:
    output_sign = (unsigned char*)malloc(EVP_PKEY_size(prvkey));
    if(!output_sign) { cerr << "Error: malloc returned NULL (signature too big?)\n"; return -1; }

    // create the signature context
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; return -1; }

    int ret; // used for return values
    ret = EVP_SignInit(md_ctx, SHA_256);
    if(ret == 0){ cerr << "Error: EVP_SignInit returned " << ret << "\n"; return -1; }
    ret = EVP_SignUpdate(md_ctx, input_sign, strlen((const char*)input_sign));
    if(ret == 0){ cerr << "Error: EVP_SignUpdate returned " << ret << "\n"; return -1; }
    unsigned int output_sign_len;
    ret = EVP_SignFinal(md_ctx, output_sign, &output_sign_len, prvkey);
    if(ret == 0){ cerr << "Error: EVP_SignFinal returned " << ret << "\n"; return -1; }

    // delete the digest and the private key from memory:
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(prvkey);

    /*
    // write the signature into a '.sgn' file:
    string sgnt_file_name = output_filename + ".sgn";
    FILE* sgnt_file = fopen(sgnt_file_name.c_str(), "wb");
    if(!sgnt_file) { cerr << "Error: cannot open file '" << sgnt_file_name << "' (no permissions?)\n"; return -1; }
    ret = fwrite(sign_buf, 1, sgnt_size, sgnt_file);
    if(ret < sgnt_size) { cerr << "Error while writing the file '" << sgnt_file_name << "'\n"; return -1; }
    fclose(sgnt_file);
    */
    // deallocate buffers:
    //free(sign_buf);
    return output_sign_len;
}

