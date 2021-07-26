#include "CLI.h"
#include <cstdlib>
#include <openssl/bio.h>


bool get_available_users(User*  my_user, vector<string> &usernames) {
    usernames.clear();
    if(NetworkMessage::send_message_3(my_user) == -1){
        cout<< "Error in sending online user request" <<endl;
        return false;
    }
    char*message = (char*)malloc(MAX_MESSAGE_LENGTH);
    int val_read = read(my_user->get_socket(), message, MAX_MESSAGE_LENGTH);
    if(val_read < 1){
        free(message);
        cerr<< "Socket Error (Handle 4)" <<endl;
        return false;
    }
    if(message[0] == 16){
        NetworkMessage::handle_message_16(message, val_read, my_user);
        free(message);
        return false;
    }
    if(message[0] == 'e'){
        NetworkMessage::handle_error_message(message, val_read, my_user);
        free(message);
        return false;
    }
    if(message[0] != 4){
        cout << "Error (Handle 4)" << endl;
        cout << message << endl;
        free(message);
        return false;
    }

    int onlines = NetworkMessage::handle_message_4(message, val_read, my_user, &usernames);
    if(onlines == -1){
        return false;
    }else if (onlines == 0){
        cout << "There is no available User" << endl;
        return false;
    }
    return true;
}

void main_menu(User* my_user, vector<string> &usernames){
    if(my_user->get_status() == CHATTING){
       
    }else if(my_user->get_status() == RTT){

    }else{
        cout<<endl;
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
        // cout<<endl<<"Type the character corresponding to the wanted action or the number of the user you want to chat with:" <<endl<<"> "<<flush;
    }

  
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
        cerr << "Server is Down. Try Again Later" <<endl;
        return false;
    }
    //creating the user
    *my_user = new User(username, password, IP, PORT, sock);
    //send message 0
    int buffer_len = NetworkMessage::send_message_0(*my_user);
    if(buffer_len == -1){
        return false;
    }
    
    //handle message type 1
    fd_set rfds;
    struct timeval tv;
    int retval;

    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);

    /* Wait up to five seconds. */
    tv.tv_sec = 10;
    tv.tv_usec = 0;

    retval = select(sock+1, &rfds, NULL, NULL, &tv);
    if(retval==-1 or retval==0) {
        cout<<endl<<"Server is not answering (maybe you are logged from another device?)"<<endl;
        exit(EXIT_FAILURE);
    }

    char *buffer = (char*)malloc(MAX_MESSAGE_LENGTH);
    valread = read( sock , buffer, MAX_MESSAGE_LENGTH);

    if(NetworkMessage::handle_message_1(buffer, valread, *my_user) == -1){
        return false;
    }
    free(buffer);

    //now the key between server and the client is established
    cout <<"\nSecure connection is established\n" <<endl;
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
                cout << "Server is Down. Try Again Later" <<endl;
                exit(EXIT_FAILURE);

            }
            int accept;
            switch (message[0]) {
                case 4:
                    if(my_user->get_status() != ONLINE) break;
                    NetworkMessage::handle_message_4(message, val_read, my_user, &usernames);
                    break;
                case 6:
                    //make sure user is not in chatting nor request to talk state
                    if(my_user->get_status() == CHATTING or my_user->get_status() == RTT) break;
                    accept = NetworkMessage::handle_message_6(message, val_read, my_user);
                    if(accept < 1){
                        my_user->set_status(ONLINE);
                        break;
                    }
                    //after message 6, the client program blocks until receiving message 10
                    //read is inside message 10
                    if(-1 == NetworkMessage::handle_message_10(my_user)){ 
                        break;
                    }
                    cout <<"\nSecure connection between you and " << my_user->get_peer_username() <<" is established!"<<endl;
                    cout<< "You can type /q to close the chat and return to main menu"<<endl;
                    cout<<"You may now start chatting:" <<endl<<endl;
                    break;
                case 8:
                    if(my_user->get_status() != RTT) break;
                    if(-1 == NetworkMessage::handle_message_8(message, val_read, my_user)){
                        my_user->set_status(ONLINE);
                        break;
                    }
                    cout <<"\nSecure connection between you and " << my_user->get_peer_username() <<" is established!"<<endl;
                    cout<< "You can type /q to close the chat and return to main menu"<<endl;
                    cout<<"You may now start chatting:" <<endl<<endl;
                    break;
                case 12:
                    if(my_user->get_status() == CHATTING) break;
                    if(-1 == NetworkMessage::handle_message_12(message, val_read, my_user)){}
                    break;
                case 14:
                    if(my_user->get_status() != CHATTING) break; // make sure user is in chatting state
                    if(-1 == NetworkMessage::handle_message_14(message, val_read, my_user)){}
                    break;
                case 16:
                    if(-1 == NetworkMessage::handle_message_16(message, val_read, my_user)){}
                    break;
                case 'e':
                    if(-1 == NetworkMessage::handle_error_message(message, val_read, my_user)){}
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
                if(input.compare("/q")==0) {
                    NetworkMessage::send_message_15(my_user);
                    return;
                }
                size_t len = (input.length() > MAX_CHARS) ? MAX_CHARS : input.length();
                do{
                    if(NetworkMessage::send_message_13((unsigned char *)input.substr(0, len).c_str(), len ,my_user) == -1){
                        break;
                    }
                    input.erase(0, len);
                    len = (input.length() > MAX_CHARS) ? MAX_CHARS : input.length();
                    usleep(CLIENT_DELAY);
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
                cout<< "Invalid input, Try again"<<endl;
                // sleep(1);
                return;
            }
            my_user->set_status(RTT);
            if (NetworkMessage::send_message_5(my_user, usernames.at(stoi(input))) == -1){
                return;
            }
            cout<<endl<<"Request to talk has been sent to "<< usernames.at(stoi(input))<< " sucessfully" <<endl;

            //establish_handshake_clients(my_user, );
        }

}