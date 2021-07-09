#include <cstdlib>
#include <openssl/bio.h>
#include <openssl/ossl_typ.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include "user.h"
#include <iostream>
#include <vector>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include "Message.h"

using namespace std;

#define PORT 8888
#define MSEC 10000 
#define IP "127.0.0.1"

bool establishe_handshake_clients(User * my_user, string receiver_username){
    int val_read = 0;
    char *message_buf_5 {nullptr};
    if (Message::send_message_5(&message_buf_5, my_user, receiver_username) == -1){
        cout << "Error: sending message 5 failed" <<endl;
        return false;
    }
    ///TODO:
    char buffer_8[MESSAGE_8_LENGTH] = {0};
    val_read = read(my_user->get_socket() , buffer_8, MESSAGE_8_LENGTH);
    if(val_read == -1){
        ///TODO:error in reading
        return false;
    }
    ///
    if(-1 == Message::handle_message_8(buffer_8, MESSAGE_8_LENGTH, my_user)){
         ///TODO:error in handling message 8
        return false;

    }
    char *message_buf_9 {nullptr};
    if(0 == Message::send_message_9(&message_buf_9, my_user)){
         ///TODO:error in sending message 9
        return false;

    }
    return true;
}

int main(int argc, char const *argv[])
{
    // log in
    string username("sina");
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

    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    char *buffer = (char*)malloc(10100);
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
    unsigned char* server_client_1 = (unsigned char*)"1234567890123456";
    my_user->set_server_client_key(server_client_1 ,16);
    //send message 0
    // char *buffer_0 {nullptr};
    // int buffer_len = Message::send_message_0(&buffer_0, my_user);
    // if(buffer_len == -1){
    //     cout << "Error in sending message type 0" <<endl;
    //     return -1;
    // }
    //handle message type 1
    //valread = read( sock , buffer, 10100);
    //Message::handle_message_1(buffer, valread, my_user);
    //free(buffer);
    //now the key between server and the client is established
    //cout <<"Secure Connection is Established" <<endl;
    string input;
    bool ok1 = false;
    buffer[0] = argv[1][0];
    send(sock, buffer, 1, 0);
    do{
        //Main Menu:
        //Please Select One Option:
        //1. Check Online Users
        //2. listening
        //0. Log out
        client_menu_0();
        cin >> input;
        if (!check_user_input(input, 3))
            continue;
        if(input.compare("1") == 0){
            ///TODO:send message 3 and handle message 4
            //Message::send_message_3(...);
            //Message::handle_message_4(...)
            bool valid_handshake = false;
            do{
                //print_list_online_users();//this function is empty, according to the data received we can print the list of online users
                // Example:
                // 1. Alycia
                // 2. Sina
                // 3. Lorenzo
                // 0. Go Back
                //cin >> input;
                ///TODO: according to the input number find the corresponding username
                //string username_for_request;

                //if (!check_user_input(input, 2))// instead of 2, should be the number of online users + 1
                   // continue;
                //else{
                //    valid_handshake = establishe_handshake_clients(my_user, username_for_request);
                //}
                establishe_handshake_clients(my_user, "lorenzo");
                valid_handshake = true;
            }while (!valid_handshake);
        }else if(input.compare("2") == 0){
            char*message_buf6 = (char*)malloc(MESSAGE_6_LENGTH);
            int val_read = read(my_user->get_socket(), message_buf6, MESSAGE_6_LENGTH);
            if(0 == Message::handle_message_6(message_buf6, val_read, my_user)){
                cout <<"Error in handling message 6" <<endl;
            }
            free(message_buf6);
            break;
        }else if (input.compare("0") == 0){
            ///TODO:send message 17 for logout
            char *message_buf_17;
            if(0 == Message::send_message_17(&message_buf_17, my_user)){
                ///TODO: handle error in sending message 17
            }
            break;  
        }
    }while (1);
    ///TODO:check if the client receive a request
    // Client does not want to make a request

    // char const *hello = "sina";
    // send(sock , hello , strlen(hello) , 0 );
    // printf("Hello message sent\n");
    // usleep(MSEC);
    // valread = read( sock , buffer, 1024);
    // printf("%s\n",buffer);
    close(sock);

    return 0;
}