#include "user.h"
#include <cstddef>
#include <vector>


const string WHITESPACE = " \n\r\t\f\v";
const string DELIMITER = "||";

static string ltrim(const string &s)
{
    size_t start = s.find_first_not_of(WHITESPACE);
    return (start == string::npos) ? "" : s.substr(start);
}
static string rtrim(const string &s)
{
    size_t end = s.find_last_not_of(WHITESPACE);
    return (end == string::npos) ? "" : s.substr(0, end + 1);
}
 
static string trim(const string &s) {
    return rtrim(ltrim(s));
}

static void client_menu_0(){
    cout << "Main Menu:\n" << "Please Select an Option:\n" << "1. Check Online Users\n" << "2. Listening\n" 
    <<"0. Log out" <<endl;
}

static bool check_user_input(const string& input, int option_size){
    char * ok_chars = (char*)malloc(option_size);
    for(int i = 0; i < option_size; i++){
        memset(ok_chars + i, '0' + i, 1);
    }
    if(input.find_first_not_of(ok_chars) != string::npos){
        cout << "Invalid Input. Try again!\n" <<endl;
        free(ok_chars);
        return false;
    }
    free(ok_chars);
    return true;
}
static size_t print_list_online_users(vector<string> usernames){
    if(usernames.size() == 0){
        cout << "There is No Available User" << endl;
        return 0;
    }
    cout << "Online Users:\n";
    cout << "Select The User You Want to Chat:\n";
        
    size_t c = 1;
    for(string usr: usernames){
        cout << c <<". " << usr;
        c++;
    }
    cout << "0. Go Back" <<endl;

    return usernames.size() - 1;
}


static User* find_user(string username, vector<User*>*users){
    for (User* usr : *users) // access by reference to avoid copying
    {  
        if (usr->get_username().compare(username)==0)
        {   
            return usr;
        }
    }
    cerr<< "User '" << username << "' Not Found Error" <<endl;
    return NULL;
}

static int inner_gcm_encrypt(uint16_t counter, unsigned char * plaintext, int plaintext_len, 
                                      unsigned char * key,
                                      unsigned char ** inner_gcm_buf){
    //inner gcm
    //initialization vector for inner gcm
    unsigned char* iv{nullptr};
    if(!Security::generate_iv(&iv, Security::GCM_IV_LEN)){
        return -1;
    }
    int aad_len = COUNTER_LENGTH + Security::GCM_IV_LEN;
    char * aad = (char*)malloc(aad_len);
    //put counter into the aad
    uint16_t * counter_pointer = (uint16_t *) (aad);
    *counter_pointer = counter;

    //put the iv into the aad
    memcpy(aad + COUNTER_LENGTH , iv, Security::GCM_IV_LEN);
    //inner GCM encryption
    unsigned char* gcm_ciphertext{nullptr};
    unsigned char* tag{nullptr};
    int gcm_ciphertext_len = 0;

    if(-1 == (gcm_ciphertext_len = Security::gcm_encrypt((unsigned char*)aad, aad_len , 
                                                        plaintext, plaintext_len, 
                                                        key, iv, &gcm_ciphertext, &tag))){
        free(iv);
        free(aad);
        free(tag);
        free(gcm_ciphertext);
        return -1;
    }
    
    int inner_gcm_buf_len = aad_len + gcm_ciphertext_len + Security::GCM_TAG_LEN;
    *inner_gcm_buf = (unsigned char*)malloc(inner_gcm_buf_len);
    memcpy(*inner_gcm_buf, aad, aad_len);
    memcpy(*inner_gcm_buf + aad_len, gcm_ciphertext, gcm_ciphertext_len);
    memcpy(*inner_gcm_buf + aad_len + gcm_ciphertext_len, tag, Security::GCM_TAG_LEN);

    free(iv);
    free(aad);
    free(tag);
    free(gcm_ciphertext);

    return inner_gcm_buf_len;                             
}