#include <openssl/bio.h>
#include <openssl/ossl_typ.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include <thread>
#include <mutex>
#include <vector>
#include "Message.h"



#define PORT 8888
#define MSEC 10000 
#define IP "127.0.0.1"

bool establishe_handshake_clients(User * my_user, string receiver_username){
    int val_read = 0;
    my_user->set_status(RTT);
    if (Message::send_message_5(my_user, receiver_username) == -1){
        cout << "Error in Establishing Secure Connection (5)" <<endl;
        return false;
    }
    char buffer[MAX_MESSAGE_LENGTH] = {0};
    val_read = read(my_user->get_socket() , buffer, MAX_MESSAGE_LENGTH);
    if(buffer[0] == 8){
        if(-1 == Message::handle_message_8(buffer, val_read, my_user)){
            cout << "Error in Establishing Secure Connection (8)" <<endl;
            return false;
        }
        if(-1 == Message::send_message_9(my_user)){
            cout << "Error in Establishing Secure Connection (9)" <<endl;
            return false;
        }
        cout <<"Secure Connection between You and " << receiver_username <<" is Established!" <<endl;
    }else if(buffer[0] == 12){
        if(-1 == Message::handle_message_12(buffer, val_read, my_user)){
            cout << "Error in Establishing Secure Connection (12)" <<endl;
            return false;
        }
    }
    return true;
}

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

void listening_loop();
int sock = 0;

mutex user_mutex;
User * my_user;

int main(int argc, char const *argv[])
{
    //log in
    string username("sina");
    if (argv[1][0] == 's'){
        username.assign("sina");
    }else{
        username.assign("lore");
    }
    string password("sina");
    // string username;
    // string password;
    // bool valid = false;
    // cout << "====================**Welcome to ChatApp**====================\n";
    // do{
    //     cout << "Please Enter Your Username:\n";
    //     cin >> username;
    //     if(!cin){
    //         cerr << "Invalid Input\n";
    //         valid = false;
    //     }
    //     else {
    //         string privk_file = "users/" + username + "/rsa_privkey.pem";
    //         struct stat buffer;   
    //         if (!(stat(privk_file.c_str(), &buffer) == 0)){
    //             cout << "No private key is generate for " << username << "\n";
    //             valid = false;
    //         }
    //         else{
    //             cout << "Please Enter Your Password:\n";
    //             cin >> password;
    //             if(!cin){
    //                 cerr << "Invalid Input"<<endl;
    //                 valid = false;
    //             }else{
    //                 //check if the password is similar to the PEM file    
    //                 FILE* prvk_file = fopen(privk_file.c_str(), "r");
    //                 if(!prvk_file){ cerr << "Invalid Password"<<endl; valid = false; }
    //                 EVP_PKEY* prvk = PEM_read_PrivateKey(prvk_file, NULL, NULL, (unsigned char*)password.c_str());
    //                 fclose(prvk_file);
    //                 if(!prvk){ cerr << "Invalid Password"<<endl; valid = false; }
    //                 valid = true;
    //             }
    //         }
    //     }
    // }
    // while(!valid);

    int valread;
    struct sockaddr_in serv_addr;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }
   
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
       
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, IP, &serv_addr.sin_addr)<=0) 
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
   
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }
    //creating the user
    User * my_user = new User(username, password, IP, PORT, sock);
    //send message 0
    char *buffer_0 {nullptr};
    int buffer_len = Message::send_message_0(&buffer_0, my_user);
    if(buffer_len == -1){
        cout << "Error in sending message type 0" <<endl;
        return -1;
    }
    ///TODO:check errors
    char *buffer = (char*)malloc(MAX_MESSAGE_LENGTH);
    //handle message type 1
    valread = read( sock , buffer, MAX_MESSAGE_LENGTH);

    if(Message::handle_message_1(buffer, valread, my_user) == -1){
        cout << "Error in handling message type 1" <<endl;
        return -1;
    }
    free(buffer);

    //now the key between server and the client is established
    cout <<"Secure Connection is Established" <<endl;

    string input;
    string input_username;
    bool ok1 = false;
    // buffer[0] = argv[1][0];
    // send(sock, buffer, 1, 0);

    do{
        //Main Menu:
        //Please Select One Option:
        //1. Check Online Users
        //2. listening
        //0. Log out
        client_menu_0();
        select_main_menu(my_user);
        cin >> input;
        if (!check_user_input(input, 3))
            continue;
        if(input.compare("1") == 0){
            if(Message::send_message_3(my_user) == -1){
                ///TODO:maybe server is off!
                continue;
            }
            vector<string> usernames;
            int onlines = Message::handle_message_4(my_user, &usernames);
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
                   valid_handshake = establishe_handshake_clients(my_user, usernames.at(stoi(input_username) - 1));
            }while (!valid_handshake);
            if (established) 
                send_secure();
            
        }else if(input.compare("2") == 0){
            int out = Message::handle_message_6(my_user);
            if(-1 == out){
                continue;
            }else if(out > 0){
                if(-1 == Message::handle_message_10(my_user)){
                    cout << "Error in Establishing Secure Connection (10)" <<endl;
                    continue;
                }
                cout <<"Secure Connection between You and " << my_user->get_peer_username() <<" is Established!" <<endl;
            }
        }else if (input.compare("0") == 0){
            if(0 == Message::send_message_17(my_user)){
                ///TODO: handle error in sending message 17
            }
            break;  
        }
    }while (1);
    //thread t2 (listening_loop);
    
    ///TODO:check if the client receive a request
    // Client does not want to make a request

    // char const *hello = "sina";
    // send(sock , hello , strlen(hello) , 0 );
    // printf("Hello message sent\n");
    // usleep(MSEC);
    // valread = read( sock , buffer, 1024);
    // printf("%s\n",buffer);
    // t1.join();
    //t2.join();
    close(sock);

    return 0;
}

void listening_loop(){
    while(1){

    }
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
            return;
        }

        if(FD_ISSET(my_user->get_socket(), &rfds)) {
            // message coming from server (at this stage should be a request to talk)
        }

    exit(EXIT_SUCCESS);
}