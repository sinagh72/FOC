#include "Security.h"
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string.h>
//#include "Message.h"
#include <openssl/rand.h>
#include <fstream>  

using namespace std;
int handleErrors(){
	printf("An error occourred.\n");
	exit(1);
}
	
int main(){
    printf("Start: loading g^a\n");
    EVP_PKEY *params;
    if(NULL == (params = EVP_PKEY_new())) handleErrors();
    // DH* temp = get_dh2048();
    if(1 != EVP_PKEY_set1_DH(params, DH_get_2048_224())) handleErrors();
    // DH_free(temp);
    printf("\n");
    printf("Generating ephemeral DH KeyPair\n");
    /* Create context for the key generation */
    EVP_PKEY_CTX *DHctx;
    if(!(DHctx = EVP_PKEY_CTX_new(params, NULL))) handleErrors();
    /* Generate a new key */
    EVP_PKEY *g_a = NULL;
    if(1 != EVP_PKEY_keygen_init(DHctx)) handleErrors();
    if(1 != EVP_PKEY_keygen(DHctx, &g_a)) handleErrors();


    /*write my public key into a file, so the other client can read it*/
    FILE* p1w = fopen("g_a", "w");
    if(!p1w){ cerr << "Error: cannot open file '"<< "g_a" << "' (missing?)\n"; exit(1); }
    PEM_write_PUBKEY(p1w, g_a);
    fclose(p1w);


    printf("Start: loading g^b\n");
    EVP_PKEY *params2;
    if(NULL == (params2 = EVP_PKEY_new())) handleErrors();
    // DH* temp = get_dh2048();
    if(1 != EVP_PKEY_set1_DH(params2, DH_get_2048_224())) handleErrors();
    // DH_free(temp);
    printf("\n");
    printf("Generating ephemeral DH KeyPair\n");
    /* Create context for the key generation */
    EVP_PKEY_CTX *DHctx2;
    if(!(DHctx2 = EVP_PKEY_CTX_new(params2, NULL))) handleErrors();
    /* Generate a new key */
    EVP_PKEY *g_b = NULL;
    if(1 != EVP_PKEY_keygen_init(DHctx2)) handleErrors();
    if(1 != EVP_PKEY_keygen(DHctx2, &g_b)) handleErrors();

    
    /*write my public key into a file, so the other client can read it*/
    FILE* p1w2 = fopen("g_b", "w");
    if(!p1w2){ cerr << "Error: cannot open file '"<< "g_b" << "' (missing?)\n"; exit(1); }
    PEM_write_PUBKEY(p1w2, g_b);
    fclose(p1w2);


    /*Load peer public key from a file*/
    FILE* p2r = fopen("g_a", "r");
    if(!p2r){ cerr << "Error: cannot open file '"<< "g_a" <<"' (missing?)\n"; exit(1); }
    EVP_PKEY* my_dhkey = PEM_read_PUBKEY(p2r, NULL, NULL, NULL);
    fclose(p2r);
    if(!my_dhkey){ cerr << "Error: PEM_read_PUBKEY returned NULL\n"; exit(1); }


    /*Load peer public key from a file*/
    // FILE* p2r2 = fopen("g_b", "r");
    // if(!p2r2){ cerr << "Error: cannot open file '"<< "g_b" <<"' (missing?)\n"; exit(1); }
    // EVP_PKEY* peer_pubkey = PEM_read_PUBKEY(p2r2, NULL, NULL, NULL);
    // fclose(p2r2);
    // if(!peer_pubkey){ cerr << "Error: PEM_read_PUBKEY returned NULL\n"; exit(1); }

    printf("Deriving a shared secret\n");
    /*creating a context, the buffer for the shared key and an int for its length*/
    EVP_PKEY_CTX *derive_ctx;
    unsigned char *skey;
    size_t skeylen;
    derive_ctx = EVP_PKEY_CTX_new(my_dhkey,NULL);
    if (!derive_ctx) handleErrors();
    if (EVP_PKEY_derive_init(derive_ctx) <= 0) handleErrors();
    /*Setting the peer with its pubkey*/
    if (EVP_PKEY_derive_set_peer(derive_ctx, g_b) <= 0) handleErrors();
    /* Determine buffer length, by performing a derivation but writing the result nowhere */
    EVP_PKEY_derive(derive_ctx, NULL, &skeylen);
    /*allocate buffer for the shared secret*/
    skey = (unsigned char*)(malloc(int(skeylen)));
    if (!skey) handleErrors();
    /*Perform again the derivation and store it in skey buffer*/
    if (EVP_PKEY_derive(derive_ctx, skey, &skeylen) <= 0) handleErrors();
    printf("Here it is the shared secret: \n");
    BIO_dump_fp (stdout, (const char *)skey, skeylen);
    /*WARNING! YOU SHOULD NOT USE THE DERIVED SECRET AS A SESSION KEY!
    * IS COMMON PRACTICE TO HASH THE DERIVED SHARED SECRET TO OBTAIN A SESSION KEY.
    * IN NEXT LABORATORY LESSON WE ADDRESS HASHING!
    */
    //FREE EVERYTHING INVOLVED WITH THE EXCHANGE (not the shared secret tho)
    EVP_PKEY_CTX_free(derive_ctx);
    // EVP_PKEY_free(peer_pubkey);
    EVP_PKEY_free(my_dhkey);

    EVP_PKEY_CTX_free(DHctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(DHctx2);
    EVP_PKEY_free(params2);
    EVP_PKEY_free(g_a);
    EVP_PKEY_free(g_b);




}