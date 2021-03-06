#include <cstdint>
#include <errno.h> 
#include <arpa/inet.h>    //close 
#include <netinet/in.h> 
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros
#include "NetworkMessage.h"
#include <algorithm>

#define TRUE   1 
#define FALSE  0 

using namespace std;


int main(int argc , char* argv[]) {
    //
    uint16_t port = 8888;
    int opt = TRUE;
    int master_socket;
    int addrlen;
    int new_socket;
    //socket with clients
    vector<User*> online_users;
    int ready_socket, i , valread;
    int max_sd;
    struct sockaddr_in address;

    //set of socket descriptors
    // list of connections and sockets
    fd_set readfds;

    
    if(argc>2) {
        cout<<"Invalid argument number: run using ./server listening_port"<<endl;
        return EXIT_FAILURE;
    }

    if(argc==2) {
        int int_port=0;
        string port_string(argv[1]);
        try {
            int_port = stoi(port_string);
            if(int_port<1024 or int_port>65535) throw out_of_range("Not valid port");
        } catch (invalid_argument const &exception) {
            cout<<"Error: server listening port number is not an integer"<<endl;
            return EXIT_FAILURE;
        } catch (out_of_range const &exception) {
            cout<<"Error: server listening port number must be in range 1024-65535"<<endl;
            return EXIT_FAILURE;
        }
        port = int_port;
    }   
         
    //create a master socket
    //AF_INET: IPV4
    //SOCK_STREAM: TCP
    //0: Internet Protocol(IP) 
    if((master_socket = socket(AF_INET , SOCK_STREAM , 0)) == 0)  
    {  
        perror("socket creation failed");
        exit(EXIT_FAILURE);  
    }  
     
    //set master socket to allow multiple connections , 
    //this is just a good habit, it will work without this 
    if(setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0)  
    {  
        perror("setsockopt");  
        exit(EXIT_FAILURE);  
    }  
     
    //type of socket created 
    address.sin_family = AF_INET;  
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( port );
         
    //bind the socket to all available interfaces on the selected port
    if (bind(master_socket, (struct sockaddr *)&address, sizeof(address))<0)  
    {  
        perror("bind failed");  
        exit(EXIT_FAILURE);  
    }

    printf("Listening on port %d \n", port);
         
    //try to specify maximum of 3 pending connections for the master socket 
    if (listen(master_socket, 50) < 0)
    {  
        perror("listen");  
        exit(EXIT_FAILURE);  
    }  
    //accept the incoming connection 
    addrlen = sizeof(address);  
    puts("Waiting for connections ...");  
    int counter = 0;
    while(TRUE)  
    {

        counter ++;
        //clear the socket set 
        FD_ZERO(&readfds);  
        //add master socket to set 
        FD_SET(master_socket, &readfds);

        max_sd = master_socket;  
             
        //add child sockets to set 
        for (vector<User*>::iterator it = online_users.begin(); it != online_users.end() ; it++)
        {  
            //socket descriptor
            int sd;
            sd = (*it)->get_socket();
            //if valid socket descriptor then add to read list 
            if(sd > 0){
                FD_SET( sd , &readfds);
            }
                 
            //highest file descriptor number, need it for the select function 
            if(sd > max_sd)  
                max_sd = sd;  
        }  
        //wait for an activity on one of the sockets , timeout is NULL , 
        //so wait indefinitely 
        ready_socket = select( max_sd + 1 , &readfds , NULL , NULL , NULL);
        if ((ready_socket < 0) && (errno!=EINTR))  
        {  
            printf("select error");  
        }  
             
        //If something happened on the master socket , 
        //then its an incoming connection 
        if (FD_ISSET(master_socket, &readfds))  
        {  
            if ((new_socket = accept(master_socket, 
                    (struct sockaddr *)&address, (socklen_t*)&addrlen))<0)  
            {  
                perror("accept"); 
                printf("accept error");   
                exit(EXIT_FAILURE);  
            }
            char* buffer=(char*) malloc(MAX_MESSAGE_LENGTH);
            valread = read(new_socket, buffer, MAX_MESSAGE_LENGTH);
            //check for message type 0
            if(buffer[0]==0){
                int output = NetworkMessage::handle_message_0(buffer, new_socket, inet_ntoa(address.sin_addr),
                                                     ntohs(address.sin_port), &online_users);
                if(output < 1){
                    cerr << "Error in establishing key with the new Client" <<endl;             
                }
            }
            free(buffer);
           
        } 
        bool removed = false;
        //else its some IO operation on some other socket
        for(auto it = online_users.begin(); it != online_users.end();){
            int sd = (*it)->get_socket(); 
            removed = false;
            if (FD_ISSET( sd , &readfds)){  
                //Check if it was for closing , and also read the 
                //incoming message 
                char *buffer = (char*)malloc(MAX_MESSAGE_LENGTH);
                valread = read( sd , buffer, MAX_MESSAGE_LENGTH);
                if (valread == 0){  
                    //Somebody disconnected , get his details and print 
                    getpeername(sd , (struct sockaddr*)&address , \
                        (socklen_t*)&addrlen);
                    cout << (*it)->get_username() << " disconnected, ip: " << inet_ntoa(address.sin_addr) 
                    << ", port: " << ntohs(address.sin_port) << endl;
                         
                    //Close the socket and mark as 0 in list for reuse 
                    close( sd ); 
                    FD_CLR(sd , &readfds);
                    //
                    if(!(*it)->get_peer_username().empty()){
                        User *receiver = find_user((*it)->get_peer_username(), &online_users, "Send 16");
                        if(receiver == nullptr){
                            break;
                        }
                        if(NetworkMessage::send_message_16((*it), receiver) != -1){
                            cout <<"sending message 16 to " << receiver->get_username() <<endl;
                        }

                    }
                    (*it)->clear();
                    it = online_users.erase(it);
                    removed = true;
                    break;  
                }  
                else { 
                    //set the string terminating NULL byte on the end 
                    //of the data read
                    switch (buffer[0]) {
                        case 2:
                            if(NetworkMessage::handle_message_2(buffer, valread, (*it)) == -1){
                            }
                            break;
                        case 3:
                            if(NetworkMessage::handle_message_3(buffer, valread, (*it), online_users) == -1){
                                string err_msg = "Server Cannot Handle Your Request";
                                NetworkMessage::send_error_message((unsigned char*)err_msg.c_str(), err_msg.length(), (*it));
                            }
                            break;
                        case 5:
                            if(NetworkMessage::handle_message_5(buffer, valread, (*it), online_users) == -1){
                                (*it)->set_status(ONLINE);
                                string err_msg = "Server Cannot Handle Your Request";
                                NetworkMessage::send_error_message((unsigned char*)err_msg.c_str(), err_msg.length(), (*it));
                            }
                            break;
                        case 7:
                            if(NetworkMessage::handle_message_7(buffer, valread, (*it), online_users) == -1){
                                (*it)->set_status(ONLINE);
                                string err_msg = "Server Cannot Handle Your Request";
                                NetworkMessage::send_error_message((unsigned char*)err_msg.c_str(), err_msg.length(), (*it));
                            }
                            break;
                        case 9:
                            if(NetworkMessage::handle_message_9(buffer, valread, (*it), online_users) == -1){
                                (*it)->set_status(ONLINE);
                                 string err_msg = "Server Cannot Handle Your Request";
                                NetworkMessage::send_error_message((unsigned char*)err_msg.c_str(), err_msg.length(), (*it));
                            }
                            break;
                        case 11:
                            if(NetworkMessage::handle_message_11(buffer, valread, (*it), online_users) == -1){
                                (*it)->set_status(ONLINE);
                                string err_msg = "Server Cannot Handle Your Request";
                                NetworkMessage::send_error_message((unsigned char*)err_msg.c_str(), err_msg.length(), (*it));
                            }
                            break;
                        case 13:
                            if(NetworkMessage::handle_message_13(buffer, valread, (*it), online_users) == -1){
                                string err_msg = "Server Cannot Handle Your Request";
                                NetworkMessage::send_error_message((unsigned char*)err_msg.c_str(), err_msg.length(), (*it));
                            }
                            break;
                        case 15:
                            if(NetworkMessage::handle_message_15(buffer, valread, (*it), online_users) == -1){
                                (*it)->set_status(ONLINE);
                                string err_msg = "Server Cannot Handle Your Request";
                                NetworkMessage::send_error_message((unsigned char*)err_msg.c_str(), err_msg.length(), (*it));
                            }
                            break;
                        case 17:
                            if(NetworkMessage::handle_message_17(buffer, valread, (*it), online_users) == -1){
                                (*it)->set_status(ONLINE);
                                break;
                            }
                            it = online_users.erase(it);
                            removed = true;
                            break;
                            
                        }
                }
                free(buffer);  
            }
            if(!removed) it++;
        }
    }
    close(master_socket);  
    FD_CLR(master_socket, &readfds); 
    return 0;  
}  