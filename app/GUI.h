#ifndef APP_GUI_H
#define APP_GUI_H

#include <cstddef>
#include <cstdlib>
#include <unistd.h>
#include <vector>
#include <arpa/inet.h>
#include <limits>
#include "NetworkMessage.h"
#include "user.h"
#include "utility.h"

bool get_available_users(User*  my_user, vector<string> &usernames) {
    usernames.clear();
    if(NetworkMessage::send_message_3(my_user) == -1){
        cout<< "Error in sending online user request (maybe server is offline)" <<endl;
        return false;
    }
    
    int onlines = NetworkMessage::handle_message_4(my_user, &usernames);
    if(onlines == -1){
        cout << "Error retriving online users" << endl;
        return false;
    }else if (onlines == 0){
        cout << "There is no available User" << endl;
        return false;
    }
    return true;
}

void main_menu(User* my_user, vector<string> &usernames){
    
    //system("clear");
    //cout<<"Welcome "+ my_user->get_username() <<endl<<endl;
    if(my_user->get_status() == CHATTING){
       
    }else if(my_user->get_status() == RTT){

    }else{
        cout << "You can: " <<endl;
        cout << "r : refresh the list of avaiable users" <<endl;
        cout << "x : exit the application" <<endl<<endl;
        if(get_available_users(my_user, usernames)) {
            cout<<"Or you can request to talk with one of the available users: "<<endl;
            int c=0;
            for(string usr: usernames) {
                cout << c <<": " << usr << endl;
                c++;
            }
        }
        cout<<"Type the character corresponding to the wanted action or the number of the user you want to chat with:" <<endl;
    }

  
}

bool establish_handshake_clients(User * my_user, string receiver_username){
    int val_read = 0;
    my_user->set_status(RTT);
    if (NetworkMessage::send_message_5(my_user, receiver_username) == -1){
        return false;
    }
    char buffer[MAX_MESSAGE_LENGTH] = {0};
    val_read = read(my_user->get_socket() , buffer, MAX_MESSAGE_LENGTH);
    if(val_read < 0){
        cout << "Connection Failed Error" <<endl;
        exit(EXIT_FAILURE);
    }
    if(buffer[0] == 8){
        if(-1 == NetworkMessage::handle_message_8(buffer, val_read, my_user)){
            return false;
        }
        if(-1 == NetworkMessage::send_message_9(my_user)){
            return false;
        }
        cout <<"\nSecure Connection between You and " << receiver_username <<" is Established!\nYou May Now Start Chatting:\n" <<endl;
        my_user->set_status(CHATTING);
    }else if(buffer[0] == 12){
        if(-1 == NetworkMessage::handle_message_12(buffer, val_read, my_user)){
            return false;
        }
    }
    return true;
}

bool connect_to_server(string username, string password, const char* IP, const int PORT, User** my_user) {
    int sock;
    int valread;
    struct sockaddr_in serv_addr;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return false;
    }
   
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
       
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, IP, &serv_addr.sin_addr)<=0) 
    {
        printf("\nInvalid address/ Address not supported \n");
        return false;
    }
   
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return false;
    }
    //creating the user
    *my_user = new User(username, password, IP, PORT, sock);
    //send message 0
    int buffer_len = NetworkMessage::send_message_0(*my_user);
    if(buffer_len == -1){
        return false;
    }
    char *buffer = (char*)malloc(MAX_MESSAGE_LENGTH);
    //handle message type 1
    valread = read( sock , buffer, MAX_MESSAGE_LENGTH);

    if(NetworkMessage::handle_message_1(buffer, valread, *my_user) == -1){
        return false;
    }
    free(buffer);

    //now the key between server and the client is established
    cout <<"\nSecure Connection is Established\n" <<endl;
    return true;
}


void select_main_menu(User* my_user, vector<string> &usernames) {
    fd_set rfds;
    int retval;

    /* Watch stdin (fd 0) to see when it has input. */
    /* add socket with the server to check incoming request */
    FD_ZERO(&rfds);
    FD_SET(0, &rfds);
    FD_SET(my_user->get_socket(), &rfds);
    
    int max_sock = max(my_user->get_socket(), 0) +1 ;
    
    retval = select(max_sock, &rfds, NULL, NULL, NULL);

    if (retval == -1)
        perror("Error in select()");
    else if (retval)
        if(FD_ISSET(my_user->get_socket(), &rfds)) {
            // message coming from server (at this stage should be a request to talk)
            char*message = (char*)malloc(MAX_MESSAGE_LENGTH);
            int val_read = read(my_user->get_socket(), message, MAX_MESSAGE_LENGTH);

            if(val_read < 1){
                cout << "Connection Failed" <<endl;
                exit(EXIT_FAILURE);

            }
            int accept;
            switch (message[0]) {
                case 6:
                    if(my_user->get_status() == CHATTING) break;//make sure user is not in chatting state
                    accept = NetworkMessage::handle_message_6(message, val_read, my_user);
                    if(accept < 1){
                        break;
                    }
                    //after message 6, the client program blocks until receiving message 10
                    //read is inside message 10
                    if(-1 == NetworkMessage::handle_message_10(my_user)){ 
                        break;
                    }
                    cout <<"\nSecure Connection between You and " << my_user->get_peer_username() <<
                    " is Established!\nYou May now Sart Chatting:\n" <<endl;
                    break;
                case 12:
                    if(my_user->get_status() == CHATTING) break;
                    if(-1 == NetworkMessage::handle_message_12(message, val_read, my_user)){
                        break;
                    }
                    break;
                case 14:
                    if(my_user->get_status() != CHATTING) break; // make sure user is in chatting state
                    if(-1 == NetworkMessage::handle_message_14(message, val_read, my_user)){
                        break;
                    }
                    break;
                case 16:
                    if(-1 == NetworkMessage::handle_message_16(message, val_read, my_user)){
                        break;
                    }
                    break;
                
            }
            free(message);
            return;
        }
        if(FD_ISSET(0, &rfds)) {
            // ready input coming from keyboard
            //we give priority to the user will
            string input;
            if (my_user->get_status() == CHATTING){
                getline(cin, input);
                if(input.empty()) return;
                size_t len = (input.length() > MAX_CHARS) ? MAX_CHARS : input.length();
                do{
                    if(NetworkMessage::send_message_13((unsigned char *)input.substr(0, len).c_str(), len ,my_user) == -1){
                        break;
                    }
                    input.erase(0, len);
                    len = (input.length() > MAX_CHARS) ? MAX_CHARS : input.length();
                    usleep(DELAY);
                }while(!input.empty()); // check 10k characters
                return;   
            }
            cin >> input;
            if (input.compare("x") == 0){
                if(-1 == NetworkMessage::send_message_17(my_user)){
                    cout<< "Quit message not send correctly"<<endl;
                }
                cout<< "User disconnected from server"<<endl;
                exit(EXIT_SUCCESS);
            }

            if(input.compare("r") == 0){
                return;
            }
            
            if(!check_user_input(input, usernames.size())) {
                cout<< "Invalid input, try again"<<endl;
                //sleep(1);
                return;
            }
            establish_handshake_clients(my_user, usernames.at(stoi(input)));
        }

}

#endif