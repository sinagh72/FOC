#include <openssl/bio.h>
#include <openssl/ossl_typ.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include <vector>
#include "NetworkMessage.h"
#include "CLI.h"

#define PORT 8888
#define MSEC 10000 
const string IP = "127.0.0.1";

int main(int argc, char const *argv[])
{
 
    string username;
    string password;
    bool valid = false;
    cout << "====================**Welcome to ChatApp**====================\n";
    do{
        //system("clear");
        cout << "Please Enter Your Username:\n";
        cin >> username;
        if(!cin){
            cerr << "Invalid Input\n";
            valid = false;
        }
        else {
            string privk_file = "users/" + username + "/rsa_privkey.pem";
            struct stat buffer;   
            if (!(stat(privk_file.c_str(), &buffer) == 0)){
                cout << "Username '" << username << "' is invalid\n";
                valid = false;
            }
            else{
                cout << "Please Enter Your Password:\n";
                cin >> password;
                if(!cin){
                    cerr << "Invalid Input"<<endl;
                    valid = false;
                }else{
                    //check if the password is the same to the PEM file    
                    FILE* prvk_file = fopen(privk_file.c_str(), "r");
                    if(!prvk_file){ 
                        cerr << "Invalid Password"<<endl; 
                        valid = false; 
                    }
                    EVP_PKEY* prvk = PEM_read_PrivateKey(prvk_file, NULL, NULL, (unsigned char*)password.c_str());
                    fclose(prvk_file);
                    if(!prvk){ 
                        cerr << "Invalid Password"<<endl; 
                        valid = false; 
                    }
                    else 
                        valid = true;
                }
            }
        }
    }while(!valid);
    User* my_user = nullptr;
    if(!connect_to_server(username, password, IP.c_str(), PORT, &my_user)){
        exit(EXIT_FAILURE);
    };
    
    string input;
    string input_username;
    vector<string> usernames;
    do{
        main_menu(my_user, usernames);
        select_main_menu(my_user, usernames);

    }while(1);

    close(my_user->get_socket());

    return 0;
}


