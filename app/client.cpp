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

    // log in
    string username;
    bool valid = false;
    do{
        cout << "Please Enter Your Username:\n";
        cin >> username;
        if(!cin){
            cerr << "Wrong Input.\n";
            valid = false;
        }
        else {
            string privk_file = "users/" + username + "/rsa_privkey.pem";
            string pubk_file = "users/" + username + "/rsa_pubkey.pem";
            struct stat buffer;   
            if (!(stat(privk_file.c_str(), &buffer) == 0)){
                cout << "No private key is generate for " << username << "\n";
                valid = false;
            }
            else if(!(stat (pubk_file.c_str(), &buffer) == 0)){
                cout << "No public key is generate for "<< username<<"\n";
                valid = false;
            }
            else 
                valid = true;
        }
    }
    while(!valid);
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

    // users available to make a request
    /* send message 3 to server to ask for list of available user  */

    string answer;
    bool ok1 = false;
    while (!ok1) {
        cout << "Do you want to make a request ? Yes / No\n";
        cin >> answer;
        if(!cin){
            cerr << "Wrong Input. \n";
        }
        else {

            // Client wants to make a request
            if (!(answer.compare("Yes")) or !(answer.compare("yes"))){
                string username_for_request;
                bool ok2 = false;
                while (!ok2) {
                    cout << "Enter the username of the user you want to request. \n";
                    cin >> username_for_request;
                    if (!cin) {
                        cerr << "Wrong Input. \n";
                    }
                    else {
                        /* check username in list */               
                        /* if (usn valid)
                            send message 5 to server */
                            cout << "Waiting for an answer... /n";   
                            /* update received message from server with answer */
                                /* if (error) */
                                    cerr << "Error answer server.\n";
                                /* else {
                                    /* if (answer positive) */
                                        cout << "Request accepted. \n";
                                        ok1 = true;
                                    /* else answer negative */
                                        cout << "Request dennied. \n";
                                    ok2 = true;
                                /* } */
                            /* else ask again */
                            cout << "Invalid username, please enter a valid username. \n";
                    }
                }
            }
                
            // Client does not want to make a request
            else {
                if(!(answer.compare("No")) or !(answer.compare("no"))){
                    string check_mailbox;
                    bool ok3 = false;
                    while (!ok3) {
                        cout << "Do you want to check if you have received a request ? Yes / No \n";
                        cin >> check_mailbox;
                        if (!cin) {
                            cerr << "Wrong Input. \n";
                        }
                        else {
                            // Client wants to check mailbox
                            if (!(check_mailbox.compare("Yes")) or !(check_mailbox.compare("yes"))){
                                /* check if received any request */
                                /* if request */
                                string username_requester; /* get username of requester*/
                                string answer_request;
                                bool ok4 = false;
                                while (!ok4) {
                                    cout << "Do you want to talk with" + username_requester + "/n";
                                    cin >> answer_request;
                                    if (!cin) {
                                        cerr << "Wrong Input.\n";   
                                    }
                                    else {
                                        // Client wants to talk with the user who send the request
                                        if (!(answer_request.compare("Yes")) or !(answer_request.compare("yes"))){
                                            /* send answer to server and start connection*/
                                            ok3 = true;
                                            ok1 = true;
                                            ok4 = true;
                                        }
                                        else {
                                            if (!(answer_request.compare("No")) or !(answer_request.compare("no"))) {
                                                /* send answer to server */
                                                ok3 = true;
                                                ok4 = true;
                                            }
                                            // invalid answer for request answer
                                            else {
                                                cout << "Please enter Yes or No .\n"; 
                                            }
                                        }
                                    }
                                }
                            }
                            else {
                                // Client does not want to check mail box
                                if (!(check_mailbox.compare("No")) or !(check_mailbox.compare("no"))) {
                                    string logout_answer;
                                    bool ok5 = false;
                                    while (!ok5) {
                                        cout << "Do you want to log out ? \n";
                                        cin >> logout_answer;
                                        if (!cin) {
                                            cerr << "Wrong input. \n";
                                        }
                                        else {
                                            // Client wants to log out
                                            if (!(logout_answer.compare("Yes")) or !(logout_answer.compare("yes"))) {
                                                ok1 = true;
                                                ok3 = true;
                                                ok5 = true;
                                            }
                                            else {
                                                // Client does not want to log out
                                                if (!(logout_answer.compare("No")) or !(logout_answer.compare("no")))  {
                                                    ok5 = true;
                                                    ok3 = true;
                                                }
                                                // invalid answer for log out answer
                                                else {
                                                    cout << "Please answer yes or no. \n";
                                                }
                                            }
                                        }
                                    }
                                }
                                // invalid answer for check mailbox 
                                else {
                                    cout << "Please answer Yes or No. \n";
                                }
                            }
                        }
                    }
                }
                // invalid answer for make a request
                else {
                    cout << "Please enter Yes of No .\n";
                    ok1 = false; 
                }
            }
        }
    }






    send(sock , hello , strlen(hello) , 0 );
    printf("Hello message sent\n");
    usleep(MSEC);
    valread = read( sock , buffer, 1024);
    printf("%s\n",buffer);
    close(sock);
    return 0;
}