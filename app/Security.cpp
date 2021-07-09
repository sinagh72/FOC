#include "Security.h"

const EVP_CIPHER* const Security::AES_CIPHER = EVP_aes_256_cbc();
const int Security::AES_IV_LEN = EVP_CIPHER_iv_length(Security::AES_CIPHER);
const int Security::AES_BLOCK_SIZE = EVP_CIPHER_block_size(Security::AES_CIPHER);
const EVP_MD * const Security::SHA_256 = EVP_sha256();
const EVP_CIPHER* const Security::GCM_CIPHER =  EVP_aes_256_gcm();
const int Security::GCM_IV_LEN = EVP_CIPHER_iv_length(Security::GCM_CIPHER);
const int Security::GCM_TAG_LEN = 16;

int Security::encryption_AES(unsigned char *plaintext, int plaintext_len, 
    unsigned char *key, unsigned char *iv, unsigned char **ciphertext){

    *ciphertext = (unsigned char *)malloc(plaintext_len + AES_BLOCK_SIZE);
    if (!*ciphertext){ cerr << "Error: malloc returned NULL (ciphertext is too big?)\n"; return -1; }

    EVP_CIPHER_CTX *ctx;

    // cout << "IV:\n";
    // BIO_dump_fp (stdout, (const char *)*iv, AES_IV_LEN);
    //create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())){ free(*ciphertext); cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; return -1; }

    if (1 != EVP_EncryptInit(ctx, AES_CIPHER, key, iv)){ free(*ciphertext);cerr << "Error: EVP_EncryptInit Failed\n"; EVP_CIPHER_CTX_free(ctx); return -1; }

    int update_len = 0;// bytes encrypted at each chunk
    int total_len = 0;// total encrypted bytes
 
    //Encrypt Update
    if (1 != EVP_EncryptUpdate(ctx, *ciphertext, &update_len, plaintext, plaintext_len)){ 
        free(*ciphertext);
        cerr << "Error: EVP_EncryptUpdate Failed\n"; EVP_CIPHER_CTX_free(ctx); return -1; 
    }

    total_len += update_len;

    //Encrypt Final. Finalize the encryption and adds the padding
    if (1 != EVP_EncryptFinal(ctx, *ciphertext+total_len, &update_len)){ 
        free(*ciphertext);
        cerr << "Error: EVP_EncryptFinal Failed\n"; EVP_CIPHER_CTX_free(ctx); return -1; 
    }

    total_len += update_len;
    int ciphertext_len = total_len;

    
    // cout << "Encrypted:\n";
    // BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
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
    if (!(ctx = EVP_CIPHER_CTX_new())){ 
        cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; free(*decryptedtext); EVP_CIPHER_CTX_free(ctx); return -1; 
    }

    if (1 != EVP_DecryptInit(ctx, AES_CIPHER, key, iv)){ 
        cerr << "Error: EVP_DecryptInit Failed\n"; free(*decryptedtext); EVP_CIPHER_CTX_free(ctx); return -1; 
    }

    int update_len = 0;// bytes encrypted at each chunk
    int total_len = 0;// total encrypted bytes

    //Encrypt Update
    if (1 != EVP_DecryptUpdate(ctx, *decryptedtext, &update_len, ciphertext, ciphertext_len)){ 
        cerr << "Error: EVP_DecryptUpdate Failed\n"; free(*decryptedtext); EVP_CIPHER_CTX_free(ctx); return -1; 
    }

    total_len += update_len;

    //Encrypt Final. Finalize the encryption and adds the padding
    if (1 != EVP_DecryptFinal(ctx, *decryptedtext+total_len, &update_len)){ 
        cerr << "Error: EVP_DecryptFinal Failed\n"; free(*decryptedtext); EVP_CIPHER_CTX_free(ctx); return -1; 
    }

    total_len += update_len;
    int plaintext_len = total_len;
    //delete the context and the plain_text from memory
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int Security::signature(string prvk_filename, unsigned char * password, 
                        unsigned char * text_to_sign, int text_to_sign_len, 
                        unsigned char ** signature){
    // load private key:    
    FILE* prvk_file = fopen(prvk_filename.c_str(), "r");
    if(!prvk_file){ cerr << "Error: cannot open file '" << prvk_filename << "' (missing?)\n"; return -1; }
    EVP_PKEY* prvk = PEM_read_PrivateKey(prvk_file, NULL, NULL, password);
    fclose(prvk_file);
    if(!prvk){ cerr << "Error: PEM_read_PrivateKey returned NULL\n"; return -1; }
    // allocate buffer for signature:
    *signature = (unsigned char*)malloc(EVP_PKEY_size(prvk));
    if(!signature) { EVP_PKEY_free(prvk);cerr << "Error: malloc returned NULL (signature too big?)\n"; return -1; }

    // create the signature context
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(!md_ctx){ free(*signature);EVP_PKEY_free(prvk);cerr << "Error: EVP_MD_CTX_new returned NULL\n"; return -1; }

    int ret; // used for return values
    ret = EVP_SignInit(md_ctx, SHA_256);
    if(ret == 0){ free(*signature); EVP_PKEY_free(prvk);EVP_MD_CTX_free(md_ctx);
        cerr << "Error: EVP_SignInit returned " << ret << "\n"; return -1; 
    }
    ret = EVP_SignUpdate(md_ctx, text_to_sign, text_to_sign_len);
    if(ret == 0){ 
        free(*signature); EVP_PKEY_free(prvk);EVP_MD_CTX_free(md_ctx);
        cerr << "Error: EVP_SignUpdate returned " << ret << "\n"; return -1; 
    }
    unsigned int signature_len;
    ret = EVP_SignFinal(md_ctx, *signature, &signature_len, prvk);
    if(ret == 0){ 
        free(*signature); EVP_PKEY_free(prvk);EVP_MD_CTX_free(md_ctx);
        cerr << "Error: EVP_SignFinal returned " << ret << "\n"; return -1; 
    }
    // delete the digest and the private key from memory:
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(prvk);
    return signature_len;
}

int Security::verify_signature(EVP_PKEY* pubk, unsigned char * signature, int signature_len, unsigned char * clear_text, int clear_text_len){
    int ret;
    // create the signature context:
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(!md_ctx){ EVP_MD_CTX_free(md_ctx);cerr << "Error: EVP_MD_CTX_new returned NULL\n"; return -1; }

    // verify the plaintext
    ret = EVP_VerifyInit(md_ctx, SHA_256);
    if(ret == 0){ 
        EVP_PKEY_free(pubk);EVP_MD_CTX_free(md_ctx);
        cerr << "Error: EVP_VerifyInit returned " << ret << "\n"; return -1; }
    ret = EVP_VerifyUpdate(md_ctx, clear_text, clear_text_len);  
    if(ret == 0){ 
        EVP_PKEY_free(pubk);EVP_MD_CTX_free(md_ctx);
        cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n"; return -1;
    }
    ret = EVP_VerifyFinal(md_ctx, signature, signature_len, pubk);
    if(ret == -1){ 
        EVP_PKEY_free(pubk);EVP_MD_CTX_free(md_ctx);
        cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
        return -1;
    }else if(ret == 0){
        EVP_PKEY_free(pubk);EVP_MD_CTX_free(md_ctx);
        cerr << "Error: Invalid signature!\n";
        return -1;
    }

    // deallocate data:
    EVP_MD_CTX_free(md_ctx);
    return 1;
}

int Security::verify_certificate(string cert_file_name){
    int ret; // used for return values
    // load the CA's certificate:
    string cacert_file_name="certificates/Foc_cert.pem";
    FILE* cacert_file = fopen(cacert_file_name.c_str(), "r");
    if(!cacert_file){ cerr << "Error: cannot open file '" << cacert_file_name << "' (missing?)\n"; return -1; }
    X509* cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
    fclose(cacert_file);
    if(!cacert){ cerr << "Error: PEM_read_X509 returned NULL\n"; return -1; }

    // load the CRL:
    string crl_file_name="certificates/Foc_crl.pem";
    FILE* crl_file = fopen(crl_file_name.c_str(), "r");
    if(!crl_file){ X509_free(cacert);cerr << "Error: cannot open file '" << crl_file_name << "' (missing?)\n"; return -1; }
    X509_CRL* crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
    fclose(crl_file);
    if(!crl){ X509_free(cacert); cerr << "Error: PEM_read_X509_CRL returned NULL\n"; return -1; }

    // build a store with the CA's certificate and the CRL:
    X509_STORE* store = X509_STORE_new();
    if(!store) { X509_free(cacert);X509_CRL_free(crl);cerr << "Error: X509_STORE_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; return -1; }
    ret = X509_STORE_add_cert(store, cacert);
    if(ret != 1) { X509_free(cacert);X509_CRL_free(crl);cerr << "Error: X509_STORE_add_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; return -1; }
    ret = X509_STORE_add_crl(store, crl);
    if(ret != 1) { X509_free(cacert);X509_CRL_free(crl);cerr << "Error: X509_STORE_add_crl returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; return -1; }
    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if(ret != 1) { X509_free(cacert);X509_CRL_free(crl); 
        cerr << "Error: X509_STORE_set_flags returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; return -1; 
    }

    // load the peer's certificate:
    FILE* cert_file = fopen(cert_file_name.c_str(), "r");
    if(!cert_file){ X509_free(cacert);X509_CRL_free(crl); X509_STORE_free(store);cerr << "Error: cannot open file '" << cert_file_name << "' (missing?)\n"; return -1; }
    X509* cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    if(!cert){ 
        X509_free(cacert);X509_CRL_free(crl); X509_STORE_free(store);
        cerr << "Error: PEM_read_X509 returned NULL\n"; return -1; }

    // verify the certificate:
    X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();
    if(!certvfy_ctx) { X509_free(cacert);X509_CRL_free(crl); X509_STORE_free(store);X509_free(cert);cerr << "Error: X509_STORE_CTX_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; return -1; }
    ret = X509_STORE_CTX_init(certvfy_ctx, store, cert, NULL);
    if(ret != 1) { X509_free(cacert);X509_CRL_free(crl); X509_STORE_free(store);X509_free(cert);cerr << "Error: X509_STORE_CTX_init returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; return -1; }
    ret = X509_verify_cert(certvfy_ctx);
    if(ret != 1) { X509_free(cacert);X509_CRL_free(crl); X509_STORE_free(store);X509_free(cert);cerr << "Error: X509_verify_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; return -1; }

    // print the successful verification to screen:
    char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    cout << "Certificate of \"" << tmp << "\" (released by \"" << tmp2 << "\") verified successfully\n";
    free(tmp);
    free(tmp2);
    X509_free(cert);
    X509_STORE_free(store);
    X509_free(cacert); // already deallocated by X509_STORE_free()
    X509_CRL_free(crl); // already deallocated by X509_STORE_free()
    X509_STORE_CTX_free(certvfy_ctx);

    return 1;
}

int Security::gcm_encrypt(unsigned char * aad, int aad_len, unsigned char * plaintext, int plaintext_len, 
    unsigned char * key, unsigned char *iv, unsigned char ** ciphertext, unsigned char ** tag){

    EVP_CIPHER_CTX *ctx;
    int len=0;
    int ciphertext_len=0;

    *ciphertext = (unsigned char *)malloc(plaintext_len + AES_BLOCK_SIZE);
    if (!*ciphertext){ cerr << "Error: malloc returned NULL (ciphertext is too big?)\n"; return -1; }
    
    *tag = (unsigned char *)malloc(GCM_TAG_LEN);
    if (!*ciphertext){ free(*ciphertext);cerr << "Error: malloc returned NULL (tag is too big?)\n"; return -1; }

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())){ free(*ciphertext);free(tag);cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; return -1; }
    // Initialise the encryption operation.
    if(1 != EVP_EncryptInit(ctx, GCM_CIPHER, key, iv)) { free(*ciphertext);free(tag);EVP_CIPHER_CTX_free(ctx);cerr << "Error: EVP_EncryptInit Failed\n"; return -1; }

    //Provide any AAD data. This can be called zero or more times as required
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) { free(*ciphertext);free(tag);EVP_CIPHER_CTX_free(ctx);cerr << "Error: EVP_EncryptUpdate AAD Failed\n"; return -1; }

    if(1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len)) { 
        free(*ciphertext);free(tag);EVP_CIPHER_CTX_free(ctx);
        cerr << "Error: EVP_EncryptUpdate Failed\n"; return -1;
    }
    ciphertext_len = len;
	//Finalize Encryption
    if(1 != EVP_EncryptFinal(ctx, *ciphertext + len, &len)){ free(*ciphertext);free(tag);EVP_CIPHER_CTX_free(ctx);cerr << "Error: EVP_EncryptFinal Failed\n"; return -1; }
    ciphertext_len += len;
    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, GCM_TAG_LEN, *tag)) {
        free(*ciphertext);free(tag);EVP_CIPHER_CTX_free(ctx);
        cerr << "Error: EVP_CIPHER_CTX_ctrl Failed\n"; return -1;
    }
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}
int Security::gcm_decrypt(unsigned char * aad, int aad_len, unsigned char * ciphertext, int ciphertext_len, 
    unsigned char * key, unsigned char *iv, unsigned char ** decryptedtext, unsigned char * tag){

    EVP_CIPHER_CTX *ctx;
    int ret;
    int len = 0;
    int decryptedtext_len = 0;

    *decryptedtext = (unsigned char*)malloc(ciphertext_len);
    if (!*decryptedtext){ cerr << "Error: malloc returned NULL (decryptedtext is too big?)\n"; return -1; }

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())){ free(*decryptedtext); cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; return -1; }
    // Initialise the encryption operation.
    if(1 != EVP_DecryptInit(ctx, GCM_CIPHER, key, iv)) { free(*decryptedtext);EVP_CIPHER_CTX_cleanup(ctx);cerr << "Error: EVP_DecryptInit Failed\n"; return -1; }

    //Provide any AAD data. This can be called zero or more times as required
    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) { free(*decryptedtext);EVP_CIPHER_CTX_cleanup(ctx);cerr << "Error: EVP_DecryptUpdate AAD Failed\n"; return -1; }

    if(1 != EVP_DecryptUpdate(ctx, *decryptedtext, &len, ciphertext, ciphertext_len)) { free(*decryptedtext);EVP_CIPHER_CTX_cleanup(ctx);cerr << "Error: EVP_DecryptUpdate Failed\n"; return -1; }
    decryptedtext_len = len;
	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, GCM_TAG_LEN, tag)){ 
        free(*decryptedtext);EVP_CIPHER_CTX_cleanup(ctx);
        cerr << "Error: EVP_CIPHER_CTX_ctrl Failed\n"; return -1; }
    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the decryptedtext is not trustworthy.
     */
    ret = EVP_DecryptFinal(ctx, *decryptedtext + len, &len);
    // cout <<"===================decryptedtext==================================="<<endl;
    BIO_dump_fp(stdout, (char*)*decryptedtext, decryptedtext_len);
    cout <<"====================inside dec=================================="<<endl;
    cout <<"==================cipher txt===================================="<<endl;
    BIO_dump_fp(stdout, (char*)ciphertext, ciphertext_len);
    cout <<"=====================tag================================="<<endl;
    BIO_dump_fp(stdout, (char*)tag, Security::GCM_TAG_LEN);
    cout <<"=======================iv==============================="<<endl;
    BIO_dump_fp(stdout, (char*)iv, Security::GCM_IV_LEN);
    cout <<"=====================key================================="<<endl;
    BIO_dump_fp(stdout, (char*)key, 16);
    cout <<"===================aad==================================="<<endl;
    BIO_dump_fp(stdout, (char*)aad, aad_len);
    cout <<"===================key==================================="<<endl;
    BIO_dump_fp(stdout, (char*)key, strlen((char*)key));

    /* Clean up */
    EVP_CIPHER_CTX_cleanup(ctx);
    if(ret > 0) {
        /* Success */
        decryptedtext_len += len;
        return decryptedtext_len;
    } else {
        /* Verify failed */
        cerr << "Error: Decryption verification Failed\n";
        return -1;
    }
}

DH * Security::get_dh2048(void)
{
    static unsigned char dhp_2048[] = {
        0xA3, 0x1F, 0xC7, 0x25, 0x28, 0x22, 0x6E, 0xA5, 0xD1, 0x1A,
        0xBE, 0x59, 0x31, 0xAA, 0x43, 0x54, 0x08, 0xCB, 0x8F, 0x1C,
        0xBB, 0x69, 0x41, 0x6C, 0x59, 0x20, 0x0D, 0x18, 0xC8, 0x0A,
        0xB4, 0x7B, 0x0F, 0x2A, 0x2E, 0x6F, 0xB0, 0x87, 0x7A, 0x18,
        0x89, 0x0B, 0x06, 0x47, 0x91, 0xBB, 0xD4, 0xED, 0x15, 0x61,
        0x44, 0x9B, 0x0E, 0x29, 0xCD, 0x58, 0x96, 0x8A, 0x01, 0x05,
        0xC7, 0x18, 0x17, 0x9D, 0xEB, 0xDF, 0xCB, 0x97, 0x5A, 0xB0,
        0x47, 0x92, 0x69, 0x99, 0x33, 0x7A, 0x83, 0xB0, 0xB4, 0xA1,
        0x97, 0x45, 0xCF, 0x80, 0x34, 0x9A, 0xC8, 0x59, 0x44, 0x97,
        0x39, 0x95, 0xE2, 0x5C, 0x11, 0xF6, 0x4B, 0x54, 0x94, 0xCF,
        0xED, 0x9A, 0xA6, 0xCD, 0xAF, 0xD6, 0xB4, 0x77, 0xB3, 0xB6,
        0x11, 0x7F, 0x44, 0x27, 0xFE, 0xE2, 0x00, 0xBA, 0x1B, 0xF5,
        0x55, 0x49, 0xBC, 0xF2, 0x93, 0xD0, 0x13, 0xE2, 0x24, 0x80,
        0x60, 0x13, 0x0D, 0xBD, 0xDB, 0xAD, 0x2D, 0x3E, 0xF2, 0xDC,
        0x40, 0xD5, 0xE8, 0x4D, 0xEB, 0x19, 0xB3, 0x9B, 0x37, 0x0F,
        0xF1, 0xA6, 0x24, 0x41, 0x1A, 0xA9, 0x87, 0xFC, 0xDD, 0xE2,
        0xA2, 0xB8, 0x55, 0x05, 0xFA, 0x28, 0xC3, 0x30, 0x55, 0x31,
        0x11, 0xC5, 0x57, 0xCB, 0xC5, 0x21, 0x42, 0x2D, 0x99, 0xC1,
        0x0E, 0x10, 0x3A, 0x34, 0xA0, 0xFD, 0xAE, 0x8F, 0xCF, 0xBA,
        0x07, 0xC5, 0x13, 0xC8, 0xEE, 0x25, 0x0A, 0x90, 0x2F, 0xE6,
        0x22, 0xBE, 0xF7, 0x87, 0xF2, 0xED, 0x1E, 0xCF, 0x27, 0x09,
        0xE3, 0x6E, 0xC4, 0x98, 0x10, 0xAC, 0xC6, 0x18, 0x61, 0x30,
        0x84, 0xC4, 0x59, 0xD8, 0x49, 0x1D, 0xD1, 0xA8, 0xE7, 0xEE,
        0xCB, 0x85, 0xA9, 0x91, 0x83, 0x87, 0x0B, 0x7D, 0x85, 0x90,
        0x54, 0x69, 0x77, 0x66, 0x7E, 0x3C, 0x17, 0x54, 0x68, 0xA5,
        0x50, 0x9B, 0xC9, 0x1D, 0x39, 0xCB
    };
    static unsigned char dhg_2048[] = {
        0x02
    };
    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (dh == NULL)
        return NULL;
    p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
    g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);
    if (p == NULL || g == NULL
            || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }
    return dh;
}

int Security::generate_dh_pubk(EVP_PKEY ** pubk){
    EVP_PKEY *params;
    if(NULL == (params = EVP_PKEY_new())) { cerr << "Error: EVP_PKEY_new returned NULL\n"; return -1; }
    //DH* temp = Security::get_dh2048();
    if(1 != EVP_PKEY_set1_DH(params, DH_get_2048_224())){ cerr << "Error: EVP_PKEY_set1_DH Failed\n"; return -1; }
    //DH_free(temp);
    /* Create context for the key generation */
    EVP_PKEY_CTX *DHctx;
    if(!(DHctx = EVP_PKEY_CTX_new(params, NULL))){ cerr << "Error: EVP_PKEY_CTX_new returned in generate dh pubkNULL\n"; return -1; }
    /* Generate a new key */
    if(1 != EVP_PKEY_keygen_init(DHctx)){ cerr << "Error: EVP_PKEY_keygen_init Failed\n"; return -1; }
    if(1 != EVP_PKEY_keygen(DHctx, pubk)){ cerr << "Error: EVP_PKEY_keygen Failed\n"; return -1; }

    EVP_PKEY_CTX_free(DHctx);
    EVP_PKEY_free(params);
    return 1;
}
unsigned int Security::generate_dh_key(EVP_PKEY * my_dhkey, EVP_PKEY * peer_pubkey, unsigned char ** digest){
    /*creating a context, the buffer for the shared key and an int for its length*/
    EVP_PKEY_CTX *derive_ctx{nullptr};
    size_t skeylen;
    unsigned char * skey{nullptr};
    derive_ctx = EVP_PKEY_CTX_new(my_dhkey, NULL);
    if (!derive_ctx) { cerr << "Error: EVP_PKEY_CTX_new returned NULL in generate dh shared key\n"; return 0; }
    if (EVP_PKEY_derive_init(derive_ctx) <= 0) { cerr << "Error: EVP_PKEY_derive_init Failed\n"; return 0; }
    /*Setting the peer with its pubkey*/
    if (EVP_PKEY_derive_set_peer(derive_ctx, peer_pubkey) <= 0) { 
        EVP_PKEY_CTX_free(derive_ctx);
        cerr << "Error: EVP_PKEY_derive_set_peer Failed\n"; 
        return 0; 
    }

    /* Determine buffer length, by performing a derivation but writing the result nowhere */
    if (EVP_PKEY_derive(derive_ctx, NULL, &skeylen) <= 0){
        EVP_PKEY_CTX_free(derive_ctx);
        cerr << "Error: EVP_PKEY_derive Failed\n"; 
        return 0; 
    }

    /*allocate buffer for the shared secret*/
    skey = (unsigned char*)(malloc(int(skeylen)));
    if (!skey) { EVP_PKEY_CTX_free(derive_ctx);cerr << "Error: malloc returns NULL (skey is too big?)\n"; return 0; }
    /*Perform again the derivation and store it in skey buffer*/
    int res = EVP_PKEY_derive(derive_ctx, skey, &skeylen);

    if (res <= 0 ) {
        cout <<"RESULT: " <<res <<endl;
        EVP_PKEY_CTX_free(derive_ctx);
        free(skey);
        cerr << "Error: EVP_PKEY_derive Failed\n"; 
        return 0; 
    }
    //FREE EVERYTHING INVOLVED WITH THE EXCHANGE (not the shared secret tho)
    EVP_PKEY_CTX_free(derive_ctx);
    //Hashing the shared seret to obtain a key
    //create digest pointer and length variable
    unsigned int digest_len;
    //Create and init context
    EVP_MD_CTX * Hctx;
    Hctx = EVP_MD_CTX_new();
    if(!Hctx){ free(skey);cerr << "Error: EVP_MD_CTX_new returned NULL\n"; return 0; }
    //allocate memory for digest
    *digest = (unsigned char*)malloc(EVP_MD_size(SHA_256));
    if(!*digest){ free(skey); EVP_MD_CTX_free(Hctx); cerr << "Error: EVP_MD_CTX_new returned NULL\n"; return 0; }
    //init, update, and finalize
    if(1 != EVP_DigestInit(Hctx, SHA_256)){ free(skey); EVP_MD_CTX_free(Hctx); cerr << "Error: EVP_DigestInit returned NULL\n"; return 0; }
    if(1 != EVP_DigestUpdate(Hctx, skey, skeylen)){ free(skey); EVP_MD_CTX_free(Hctx); cerr << "Error: EVP_DigestUpdate returned NULL\n"; return 0; }
    if(1 != EVP_DigestFinal(Hctx, *digest, &digest_len)){ free(skey); EVP_MD_CTX_free(Hctx); cerr << "Error: EVP_DigestFinal returned NULL\n"; return 0; }

    EVP_MD_CTX_free(Hctx);
    return digest_len;
}

int Security::EVP_PKEY_to_chars(EVP_PKEY *pkey, unsigned char ** pk_buf){
    BIO * bio{nullptr};
    if (NULL == pkey){
        cerr << "Error: pkey is NULL\n";
        return -1;
    }
    if((bio = BIO_new(BIO_s_mem())) == NULL){
        cerr << "Error: MBIO is NULL\n";
        return -1;
    }
    if (0 == PEM_write_bio_PUBKEY(bio, pkey)){
      cerr << "Error: PEM_write_bio_PUBKEY Failed\n";
      BIO_free(bio);
      return -1;
    }
    unsigned char* buf{nullptr};
    long pkey_size = BIO_get_mem_data(bio, &buf);
    *pk_buf = (unsigned char*)malloc(pkey_size);
    if(!*pk_buf){
        cerr << "Error: malloc returned NULL (pk_buf is too big?)"<<endl;
        BIO_free(bio);
        return -1;
    }
    memcpy(*pk_buf, buf, pkey_size);
    BIO_free(bio);
    return pkey_size;   
}
int Security::chars_to_EVP_PKEY(EVP_PKEY ** pkey, unsigned char * pk_buf){
    BIO * bio{nullptr};
    if (NULL == pk_buf){
        cerr << "Error: pubk_char is NULL\n";
        return -1;
    }
    if((bio = BIO_new(BIO_s_mem())) == NULL){
        cerr << "Error: MBIO is NULL\n";
        return -1;
    }
    if (0 == BIO_write(bio, pk_buf, strlen((char*)pk_buf))){
        BIO_free(bio);
        cerr << "Error: BIO_write Failed\n";
        return -1;
    }
    *pkey= PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return DH_PUBK_LENGTH;
}
bool Security::generate_iv(unsigned char**iv, int iv_len){
    *iv = (unsigned char *)malloc(iv_len);
    if (!*iv){ cerr << "Error: malloc for iv returned NULL (iv is too big?)\n"; return false; }
    //seed OpenSSL PRNG
    RAND_poll();
    RAND_bytes((unsigned char*)iv[0], iv_len);
    return true;
}

bool Security::load_server_certificate(X509 **cert) {
    FILE* cert_file = fopen("./certificates/ChatApp_cert.pem", "r");
    if(!cert_file)  {
        printf("Error opening server certificate file");
        return false;
    }

    *cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    if(!*cert) {
        printf("Error loading server certificate");
        fclose(cert_file);
        return false;
    }
    fclose(cert_file);
    return true;
}

int Security::X509_serialization(X509 *cert, unsigned char **buffer) {
    BIO* bio = nullptr;
    if((bio = BIO_new(BIO_s_mem())) == NULL){
        cerr << "Error: MBIO is NULL\n";
        return -1;
    }
    if(PEM_write_bio_X509(bio, cert)!=1) {
        printf("Error serializing the certificate");
        BIO_free(bio);
        return -1;
    }

    char* certificate_serialized= nullptr;
    int cert_size= (int)BIO_get_mem_data(bio, &certificate_serialized);
    *buffer =(unsigned char*) malloc(cert_size+1);
    memcpy(*buffer, certificate_serialized, cert_size);
    memset(*buffer+cert_size, 0, 1);

    BIO_free(bio);
    return cert_size+1;
}

bool Security::X509_deserialization(unsigned char *buffer, X509 **cert) {
    BIO * bio{nullptr};
    if (cert == NULL){
        cerr << "Error: X509 cert is NULL\n";
        return false;
    }
    if((bio = BIO_new(BIO_s_mem())) == NULL){
        cerr << "Error: MBIO is NULL\n";
        return false;
    }
    if (0 == BIO_write(bio, buffer, strlen((char*)buffer))){
        BIO_free(bio);
        cerr << "Error: BIO_write Failed\n";
        return false;
    }
    *cert= PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return true;
}

bool Security::certificate_verification(X509 *cert) {
    int ret; // used for return values
    // load the CA's certificate:
    string cacert_file_name="certificates/Foc_cert.pem";
    FILE* cacert_file = fopen(cacert_file_name.c_str(), "r");
    if(!cacert_file){ cerr << "Error: cannot open file '" << cacert_file_name << "' (missing?)\n"; return false; }
    X509* cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
    fclose(cacert_file);
    if(!cacert){ cerr << "Error: PEM_read_X509 returned NULL\n"; return false; }

    // load the CRL:
    string crl_file_name="certificates/Foc_crl.pem";
    FILE* crl_file = fopen(crl_file_name.c_str(), "r");
    if(!crl_file){ X509_free(cacert);cerr << "Error: cannot open file '" << crl_file_name << "' (missing?)\n"; return false; }
    X509_CRL* crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
    fclose(crl_file);
    if(!crl){ X509_free(cacert); cerr << "Error: PEM_read_X509_CRL returned NULL\n"; return false; }

    // build a store with the CA's certificate and the CRL:
    X509_STORE* store = X509_STORE_new();
    if(!store) { X509_free(cacert);X509_CRL_free(crl);cerr << "Error: X509_STORE_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; return false; }
    ret = X509_STORE_add_cert(store, cacert);
    if(ret != 1) { X509_free(cacert);X509_CRL_free(crl);cerr << "Error: X509_STORE_add_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; return false; }
    ret = X509_STORE_add_crl(store, crl);
    if(ret != 1) { X509_free(cacert);X509_CRL_free(crl);cerr << "Error: X509_STORE_add_crl returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; return false; }
    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if(ret != 1) { X509_free(cacert);X509_CRL_free(crl);
        cerr << "Error: X509_STORE_set_flags returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; return false;
    }

    // verify the certificate:
    X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();
    if(!certvfy_ctx) { X509_free(cacert);X509_CRL_free(crl); X509_STORE_free(store);X509_free(cert);cerr << "Error: X509_STORE_CTX_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; return false; }
    ret = X509_STORE_CTX_init(certvfy_ctx, store, cert, NULL);
    if(ret != 1) { X509_free(cacert);X509_CRL_free(crl); X509_STORE_free(store);X509_free(cert);cerr << "Error: X509_STORE_CTX_init returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; return false; }
    ret = X509_verify_cert(certvfy_ctx);
    if(ret != 1) { X509_free(cacert);X509_CRL_free(crl); X509_STORE_free(store);X509_free(cert);cerr << "Error: X509_verify_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; return false; }

    // print the successful verification to screen:
    char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);

    if(strcmp(tmp, "/C=IT/CN=ChatApp")!=0 || strcmp(tmp2, "/C=IT/O=FoC/OU=Certification Authority/CN=Foc")!=0) {
        cerr<<"Server certificate not valid"<<endl;
        free(tmp);
        free(tmp2);
        X509_free(cert);
        X509_STORE_free(store);
        X509_free(cacert);
        X509_CRL_free(crl);
        X509_STORE_CTX_free(certvfy_ctx);
        return false;
    }
    free(tmp);
    free(tmp2);
    X509_STORE_free(store);
    X509_free(cacert); // already deallocated by X509_STORE_free()
    X509_CRL_free(crl); // already deallocated by X509_STORE_free()
    X509_STORE_CTX_free(certvfy_ctx);

    return true;
}


int Security::serialize_concat_dh_pubkey(EVP_PKEY* a, EVP_PKEY *b, char** concatenated) {
    *concatenated = nullptr;
    unsigned char* a_char{nullptr};
    unsigned char* b_char{nullptr};
    int a_len = Security::EVP_PKEY_to_chars(a, &a_char);
    int b_len = Security::EVP_PKEY_to_chars(b, &b_char);
    if(a_len==-1 || b_len==-1) {
        return -1;
    }
    //debug
    cout<<"A_LEN: "<<a_len<<"   B_LEN: "<<b_len<<endl;
    cout<<"A_LEN: "<<strlen((char *)a_char)<<"   B_LEN: "<<strlen((char *)b_char)<<endl;

    *concatenated = (char*) malloc(a_len+b_len);
    if(!(*concatenated)) {
        free(a_char);
        free(b_char);
        return -1;
    }
    *concatenated[0] = '\0';
    strcat(*concatenated, (char *)a_char);
    strcat(*concatenated, (char *)b_char);

    return a_len+b_len;
}