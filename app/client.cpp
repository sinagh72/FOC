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

#define PORT 8888
#define MSEC 10000 
#define IP "127.0.0.1"


bool send_secure(){
    do{
        cout << "You: ";
        string input;
        cin >> input;
        if(!cin){

        }else{

        }
    }while(1);
}


int main(int argc, char const *argv[])
{
 
    string username;
    string password;
    bool valid = false;
    
    do{
        system("clear");
        cout << "====================**Welcome to ChatApp**====================\n";
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
    }
    while(!valid);

    User* my_user = nullptr;
    if(!connect_to_server(username, password, IP, PORT, &my_user)){
        exit(EXIT_FAILURE);
    };

    string input;
    string input_username;
    vector<string> usernames;
    while(1) {
        //Main Menu:
        //Please select the user you want to chat with or wait for a request to talk:
        //1. Check Online Users
        //2. listening
        //0. Log out
        
        main_menu(my_user, usernames);
        select_main_menu(my_user);


    }

    close(my_user->get_socket());

    return 0;
}


void select_main_menu(User* my_user) {
    fd_set rfds;
    int retval;

    /* Watch stdin (fd 0) to see when it has input. */
    /* add socket with the server to check incoming request */
    FD_ZERO(&rfds);
    FD_SET(0, &rfds);
    FD_SET(my_user->get_socket(), &rfds);

    retval = select(2, &rfds, NULL, NULL, NULL);

    if (retval == -1)
        perror("Error in select()");
    else if (retval)
        if(FD_ISSET(0, &rfds)) {
            // ready input coming from keyboard
            //we give priority to the user will
            string input;

            cin >> input;
            if (!check_user_input(input, 3))
                return;

            if (input.compare("e") == 0){
                if(0 == NetworkMessage::send_message_17(my_user)){
                    ///TODO: handle error in sending message 17
                    //we should quit anyway
                }
                 
            }

            if(input.compare("r") == 0){
                if(NetworkMessage::send_message_3(my_user) == -1){
                    ///TODO:maybe server is off!
                    continue;
                }
                vector<string> usernames;
                int onlines = NetworkMessage::handle_message_4(my_user, &usernames);
                if(onlines == -1){
                    ///TODO:error
                    continue;
                }else if (onlines == 0){
                    cout << "There is No Available User" << endl;
                    continue;
                }
                bool valid_handshake = false;
                bool established = false;

                do{
                    my_user->set_status(ONLINE);
                    cout << "Online Users:\n";
                    cout << "Select The User You Want to Chat:\n";
                    size_t c = 1;
                    for(string usr: usernames){
                        cout << c <<". " << usr << endl;
                        c++;
                    }
                    cout << "0. Exit" <<endl;
                    cin >> input_username;
                    if (!check_user_input(input_username, usernames.size()+1))
                    valid_handshake = false;
                    else if(input_username.compare("0") == 0)
                        valid_handshake = true;
                    else
                    valid_handshake = establish_handshake_clients(my_user, usernames.at(stoi(input_username) - 1));
                }while (!valid_handshake);

                //how established can be true?
                if (established) 
                    send_secure();
                
            }else if(input.compare("2") == 0){
                int out = NetworkMessage::handle_message_6(my_user);
                if(-1 == out){
                    continue;
                }else if(out > 0){
                    if(-1 == NetworkMessage::handle_message_10(my_user)){
                        cout << "Error in Establishing Secure Connection (10)" <<endl;
                        continue;
                    }
                    cout <<"Secure Connection between You and " << my_user->get_peer_username() <<" is Established!" <<endl;
                }
            }

            return;
        }

        if(FD_ISSET(my_user->get_socket(), &rfds)) {
            // message coming from server (at this stage should be a request to talk)
        }

    exit(EXIT_SUCCESS);
}