//Example code: A simple server side code, which echos back the received message.
//Handle multiple socket connections with select and fd_set on Linux 
#include <iostream>
#include <stdio.h> 
#include <string.h>   //strlen 
#include <stdlib.h> 
#include <errno.h> 
#include <unistd.h>   //close 
#include <arpa/inet.h>    //close 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros
#include <vector>
#include "user.h"
#include "dimensions.h"
     
#define TRUE   1 
#define FALSE  0 

using namespace std;
     
int main(int argc , char *argv[]) {
    const int port;
    int opt = TRUE;
    int master_socket;
    int addrlen;
    int new_socket;
    //socket with clients
    vector<User> online_users;
    int ready_socket, i , valread;
    int max_sd;
    struct sockaddr_in address;

    //set of socket descriptors
    // list of connections and sockets
    fd_set readfds;


    if(argc!=2) {
        string port_string(argv[1]);
        try {
            port= stoi(port_string);
            if(port<1024 or port>65535) throw out_of_range("Not valid port");
        } catch (invalid_argument const &exception) {
            cout<<"Error: server port number is not an integer"<<endl;
            return;
        } catch (out_of_range const &exception) {
            cout<<"Error: server port number outside range 1024-65535"<<endl;
            return;
        }
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

    printf("Listening on port %d \n", PORT);
         
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
        for ( vector<User>::iterator it= online_users.begin(); it != online_users.end() ; i++)
        {  
            //socket descriptor
            int sd;
            sd = it->get_client_socket();
                 
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
       
        if ((activity < 0) && (errno!=EINTR))  
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
            char* buffer=(char*) malloc(MESSAGE_TYPE_0_DIMENSION);
            read(new_socket, buffer, MESSAGE_TYPE_0_DIMENSION);

            //check for message type 0
            if(buffer[0]==0) handle_message_0(buffer, new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port), online_users)


            //send new connection greeting message 
            if(send(new_socket, message, strlen(message), 0) != strlen(message))  
            {  
                perror("send");
                printf("send error");    
            }  
                 
            puts("Welcome message sent successfully");  
                 
            //add new socket to array of sockets 
            for (i = 0; i < max_clients; i++)  
            {  
                //if position is empty 
                if( client_socket[i] == 0 )  
                {  
                    client_socket[i] = new_socket;  
                    printf("Adding to list of sockets as %d\n" , i);   
                    break;  
                }  
            }  
        }  
             
        //else its some IO operation on some other socket
        for (i = 0; i < max_clients; i++)  
        {  
            sd = client_socket[i];  
                 
            if (FD_ISSET( sd , &readfds))  
            {  
                //Check if it was for closing , and also read the 
                //incoming message 
                if ((valread = read( sd , buffer, 1024)) == 0)
                {  
                    //Somebody disconnected , get his details and print 
                    getpeername(sd , (struct sockaddr*)&address , \
                        (socklen_t*)&addrlen);  
                    printf("Host disconnected , ip %s , port %d \n" , 
                          inet_ntoa(address.sin_addr) , ntohs(address.sin_port));  
                         
                    //Close the socket and mark as 0 in list for reuse 
                    close( sd ); 
                    FD_CLR(sd , &readfds); 
                    client_socket[i] = 0;  
                }  
                     
                //Echo back the message that came in 
                else 
                {  
                    //set the string terminating NULL byte on the end 
                    //of the data read 
                    buffer[valread] = '\0';
                    std::cout<< "Client " << inet_ntoa(address.sin_addr) <<"_" << ntohs(address.sin_port) << ": "
                    << buffer << std::endl; 
                    std::cout<< "valread is: " << valread << std::endl;
                    if(send(sd , buffer , strlen(buffer) , 0 )!= strlen(buffer)){
                        perror("send");
                        exit(EXIT_FAILURE); 
                    }  
                }  
            }  
        }  
    }
    close(master_socket);  
    FD_CLR(master_socket, &readfds); 
    return 0;  
}  