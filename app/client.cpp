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

using namespace std;

#define PORT 8888
#define MSEC 10000 
int main(int argc, char const *argv[])
{

    string username;
    bool valid = false;
    do{
        cout<<"Please Enter Your Username:\n";
        cin >> username;
        if(!cin){
            cerr<<"Wrong Input.\n";
            valid = false;
        }else{
            string privk_file = "users/" + username + "/rsa_privkey.pem";
            string pubk_file = "users/" + username + "/rsa_pubkey.pem";
            struct stat buffer;   
            if (!(stat(privk_file.c_str(), &buffer) == 0)){
                cout << "No private key is generate for " << username<<"\n";
                valid = false;
            }
            else if(!(stat (pubk_file.c_str(), &buffer) == 0)){
                cout << "No public key is generate for "<< username<<"\n";
                valid = false;
            }
            else 
                valid = true;
        }
    }while(!valid);
    //User *this_user = new User(username, "localhost", PORT);
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    char const *hello = "sina";
    char buffer[1024] = {0};
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }
   
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
       
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) 
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
   
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }
    send(sock , hello , strlen(hello) , 0 );
    printf("Hello message sent\n");
    usleep(MSEC);
    valread = read( sock , buffer, 1024);
    printf("%s\n",buffer);
    close(sock);
    return 0;
}