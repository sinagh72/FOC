#include <cstdint>
#include <errno.h> 
#include <unistd.h>   //close 
#include <arpa/inet.h>    //close 
#include <netinet/in.h> 
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros
#include "Message.h"

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

    User * sina = new User("sina", "sina", "127.0.0.1", port, -1);
    unsigned char key_gcm[]="1234567890123456";
    sina->set_server_client_key(key_gcm ,16);
    sina->set_peer_username("lorenzo");
    online_users.push_back(sina);

    // User * lorenzo = new User("lorenzo", "sina", "127.0.0.1", port, -1);
    // unsigned char* server_client_2 = (unsigned char*)"0987654321098765";
    // lorenzo->set_server_client_key(server_client_2 ,16);
    // online_users.push_back(lorenzo);
  
         
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
            char* buffer=(char*) malloc(10100);
            valread = read(new_socket, buffer, 10100);
            cout << "User connected: " << inet_ntoa(address.sin_addr) << " " <<ntohs(address.sin_port) << endl;
            //check for message type 0
            if(buffer[0]=='s'){
                string tmp = "sina";
                auto it = find_if(online_users.begin(), online_users.end(), 
                [&tmp](const User *obj) {return obj->get_username() == tmp;});
                (*it)->set_socket(new_socket);
            }else if (buffer[0] == 'l') {
                string tmp = "lorenzo";
                auto it = find_if(online_users.begin(), online_users.end(), 
                [&tmp](const User *obj) {return obj->get_username() == tmp;});
                (*it)->set_socket(new_socket);
            }
            if(buffer[0]==0){
                
                //Message::handle_message_0(buffer, new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port), online_users);
                //free(buffer);
            }
            free(buffer);
           
        }  
        //else its some IO operation on some other socket
        for(User* usr : online_users){

            int sd = usr->get_socket();  
            if (FD_ISSET( sd , &readfds)){  
                //Check if it was for closing , and also read the 
                //incoming message 
                char *buffer = (char*)malloc(10100);
                valread = read( sd , buffer, 10100);
                if (valread == 0){  
                    //Somebody disconnected , get his details and print 
                    getpeername(sd , (struct sockaddr*)&address , \
                        (socklen_t*)&addrlen);  
                    printf("Host disconnected , ip %s , port %d \n" , 
                          inet_ntoa(address.sin_addr) , ntohs(address.sin_port));  
                         
                    //Close the socket and mark as 0 in list for reuse 
                    close( sd ); 
                    FD_CLR(sd , &readfds); 
                    usr->clear();
                    break;  
                }  
                else {  
                    //set the string terminating NULL byte on the end 
                    //of the data read
                    switch (buffer[0]) {
                        case 2:
                            // Message::handle_message_2(buffer, valread, &user);
                            break;
                        case 4:
                            // Message::handle_message_4(buffer, valread, &user);
                            break;
                        case 5:
                            cout << "handling message 5 from " << usr->get_username()<<endl;
                            //BIO_dump_fp(stdout, buffer, valread);
                            if(Message::handle_message_5(buffer, valread, sina) == -1){
                                cerr <<"Error in handling message 5" << endl;
                                break;
                            }
                            // User* receiver = find_user(&online_users, (*it)->get_peer_username());
                            // char*message_buf6{nullptr};
                            // cout << "send message 6 to " << receiver->get_username()<<endl;
                            // Message::send_message_6(&message_buf6, it.base(), receiver);
                            break;
                        }
                }
                    // buffer[valread] = '\0';
                    // std::cout<< "Client " << inet_ntoa(address.sin_addr) <<"_" << ntohs(address.sin_port) << ": "
                    // << buffer << std::endl; 
                    // std::cout<< "valread is: " << valread << std::endl;
                    // if(send(sd , buffer , strlen(buffer) , 0 )!= strlen(buffer)){
                    //     perror("send");
                    //     exit(EXIT_FAILURE); 
                    // }
                free(buffer);  
            }  
        }  
    }
    close(master_socket);  
    FD_CLR(master_socket, &readfds); 
    return 0;  
}  