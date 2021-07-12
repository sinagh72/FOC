#ifndef APP_MESSAGE_H
#define APP_MESSAGE_H

#include "user.h"
#include <sys/socket.h>
#include "utility.h"
#include <unistd.h> 


class Message {

public:
    /**
     * create a message of type 0
     * @param buffer is a pointer to pointer that will point to a buffer allocated inside the function
     * @param my_user the sender of the message!
     * @return the length of the message sent to toward the server. It will return -1 if some error happens
    */
    static int send_message_0(char **buffer, User* my_user);
    //===================================================================================================================  
    /**
     * handle function for message type 0
     * @param buffer is the message buffer
     * @param client_socket is the socket with the client
     * @param ip : ip address of the client
     * @param port :port of the client
     * @param online_users : vector of Users that are online
     */
    static int handle_message_0(char *buffer, int client_socket, char *ip, uint16_t port, vector <User*>*online_users);

    static int handle_message_1(char* buffer,  int buffer_len, User *client);

    static int handle_message_2(char* buffer, int buffer_len, User *client);

    // message 3
    static int send_message_3(User * my_user);
    static int handle_message_3(char * message, size_t message_len, User * my_user, vector<User*>online_users);

    // message 4
    static int send_message_4(User* sender, vector<User*>online_users);
    static int handle_message_4(User * my_user, vector<string>*usernames);
    
     /**
     * create a message type 5. This function will be called inside the client application
     * @param my_user the sender of the message!
     * @return integer to specify if the sending is successful or not. If it is successful it will return the
     * size of the message_buf, otherwise -1
    */
    static int send_message_5(User* my_user, string receiver_username);
    //===================================================================================================================  
    /**
     * handle message type 5. This function will be called inside the server application
     * @param message the buffer which is received from the socket.
     * @param message_len the size of the received message
     * @param sender the sender of the message! This user resides inside the server application (inside a vector of users)
     * @return integer to specify if parsing the message is successful or not. If it is successful it will return the
     * size of the 1, otherwise -1
    */
    static int handle_message_5(char * message, size_t message_len, User* sender, vector<User*>online_users);
    //===================================================================================================================  
    /**
     * create a message type 6. This function will be called inside the server application
     * @param sender the sender of the message! We assumed the server knows who is the sender
     * @param receiver the receiver of the message! We assumed the server knows who is the receiver
     * @return integer to specify if the sending is successful or not. If it is successful it will return the
     * size of the message_buf, otherwise -1
    */
    static int send_message_6(User* sender, User* receiver);
    //===================================================================================================================
    /**
     * handle message type 6. This function will be called inside the client application
     * @param message the buffer which is received from the socket.
     * @param message_len the size of the received message
     * @param my_user the receiver of the message!
     * @return integer to specify if parsing the message is successful or not. If it is successful it will return the
     * size of the 1, otherwise -1
    */
    static int handle_message_6(User* my_user);
    //=================================================================================================================== 
    /**
     * create a message type 7. This funciton will be called inside the client application
     * @param my_user the sender of the message!
     * @return integer to specify if the sending is successful or not. If it is successful it will return the
     * size of the message_buf, otherwise -1
    */
    static int send_message_7(User* my_user);
    //=================================================================================================================== 
    /**
     * handle message type 7. This function will be called inside the server application
     * @param message the buffer which is received from the socket.
     * @param message_len the size of the received message
     * @param sender the sender of the message! This user resides inside the server application (inside a vector of users)
     * @return integer to specify if parsing the message is successful or not. If it is successful it will return the
     * size of the 1, otherwise -1
    */
    static int handle_message_7(char * message, size_t message_len, User* sender, vector<User*>online_users);
    //=================================================================================================================== 
    /**
     * create a message type 8. This function will be called inside the server application
     * @param sender the sender of the message! We assumed the server knows who is the sender
     * @param receiver the receiver of the message! We assumed the server knows who is the receiver
     * @param clients_ciphertext the buffer which contains the cipher text between two clients
     * @param clients_ciphertext_len the length of the cipher text between two clients
     * @return integer to specify if the sending is successful or not. If it is successful it will return the
     * size of the message_buf, otherwise -1
    */
    static int send_message_8(User* sender, User* receiver, 
                                        unsigned char * clients_ciphertext, int clients_ciphertext_len);
    //=================================================================================================================== 
     /**
     * handle message type 8. This function will be called inside the client application
     * @param message the buffer which is received from the socket.
     * @param message_len the size of the received message
     * @param my_user the receiver of the message!
     * @return integer to specify if parsing the message is successful or not. If it is successful it will return the
     * size of the 1, otherwise -1
    */
    static int handle_message_8(char * message, size_t message_len, User* my_user);
    //===================================================================================================================
    /**
     * create a message type 9. This funciton will be called inside the client application
     * @param my_user the sender of the message!
     * @return unsgined integer to specify if the sending is successful or not. If it is successful it will return the
     * size of the message_buf, otherwise 0
    */
    static int send_message_9(User* my_user);
    //===================================================================================================================
    /**
     * handle message type 9. This function will be called inside the server application
     * @param clients_ciphertext the buffer which will be contain the cipher text between two clients, will be initialized inside
     * @param message the buffer which is received from the socket.
     * @param message_len the size of the received message
     * @param sender the sender of the message! This user resides inside the server application (inside a vector of users)
     * @return integer to specify if parsing the message is successful or not. If it is successful it will return the
     * size of the 1, otherwise -1
    */
    static int handle_message_9(char * message, size_t message_len, User* sender, vector<User*>online_users);
    //===================================================================================================================
    /**
     * create a message type 10. This function will be called inside the server application
     * @param message_buf buffer which contains the whole dataframe. It will be initialized and sent to the socket.
     * @param sender the sender of the message! We assumed the server knows who is the sender
     * @param receiver the receiver of the message! We assumed the server knows who is the receiver
     * @param clients_ciphertext the buffer which contains the cipher text between two clients
     * @param clients_ciphertext_len the length of the cipher text between two clients
     * @return unsgined integer to specify if the sending is successful or not. If it is successful it will return the
     * size of the message_buf, otherwise 0
    */
    static int send_message_10(User* sender, User* receiver, unsigned char * clients_ciphertext, int clients_ciphertext_len);
    //===================================================================================================================
    /**
     * handle message type 10. This function will be called inside the client application
     * @param message the buffer which is received from the socket.
     * @param message_len the size of the received message
     * @param my_user the receiver of the message!
     * @return integer to specify if parsing the message is successful or not. If it is successful it will return the
     * size of the 1, otherwise -1
    */
    static int handle_message_10(User* my_user);
    //===================================================================================================================
    /**
     * create a message type 11. This function will be called inside the client application
     * @param my_user the sender of the message!
     * @return integer to specify if the sending is successful or not. If it is successful it will return the
     * size of the message_buf, else if the session has reached the max counter, it will return -17, otherwise -1
     */
    static int send_message_11(User* my_user);
    //===================================================================================================================
    /**
     * handle message type 11. This function will be called inside the server application
     * @param message the buffer which is received from the socket.
     * @param message_len the size of the received message
     * @param sender the sender of the message! This user resides inside the server application (inside a vector of users)
     * @return integer to specify if parsing the message is successful or not. If it is successful it will return the
     * size of the 1, otherwise -1
    */
    static int handle_message_11(char * message, size_t message_len, User* sender, vector<User*>online_users);
    //===================================================================================================================
    /**
     * create a message type 12. This function will be called inside the server application
     * @param message_buf buffer which contains the whole dataframe. It will be initialized and sent to the socket.
     * @param sender the sender of the message! We assumed the server knows who is the sender
     * @param receiver the receiver of the message! We assumed the server knows who is the receiver
     * @return unsgined integer to specify if the sending is successful or not. If it is successful it will return the
     * size of the message_buf, otherwise 0
    */
    static unsigned int send_message_12(User* sender, User* receiver);
    //===================================================================================================================
    /**
     * handle message type 12. This function will be called inside the client application
     * @param message the buffer which is received from the socket.
     * @param message_len the size of the received message
     * @param my_user the receiver of the message!
     * @return integer to specify if parsing the message is successful or not. If it is successful it will return the
     * size of the 1, otherwise -1
    */
    static int handle_message_12(char* message, size_t message_len, User*my_user);
    //=================================================================================================================== 
    /**
     * create a message type 13. This function will be called inside the client application
     * @param message_buf buffer which contains the whole dataframe. It will be initialized and sent to the socket.
     * @param message the message that the client wants to send to the other client.
     * @param message_len the length of the message that the client wants to send to the other client.
     * @param my_user the sender of the message!
     * @return integer to specify if the sending is successful or not. If it is successful it will return the
     * size of the message_buf, else if the session has reached the max counter, it will return -17, otherwise -1
     */
    static int send_message_13(unsigned char* message, size_t message_len, User* my_user);
    //=================================================================================================================== 
    /**
     * handle message type 13. This function will be called inside the server application
     * @param clients_ciphertext the buffer which will be contain the cipher text between two clients, will be initialized inside
     * @param message the buffer which is received from the socket.
     * @param message_len the size of the received message
     * @param sender the sender of the message! This user resides inside the server application (inside a vector of users)
     * @return integer to specify if parsing the message is successful or not. If it is successful it will return the
     * size of the 1, otherwise -1
    */
    static int handle_message_13(unsigned char ** clients_ciphertext, char * message, size_t message_len, User* sender);
    //=================================================================================================================== 
    /**
     * create a message type 14. This function will be called inside the server application
     * @param message_buf buffer which contains the whole dataframe. It will be initialized and sent to the socket.
     * @param sender the sender of the message! We assumed the server knows who is the sender
     * @param receiver the receiver of the message! We assumed the server knows who is the receiver
     * @param clients_ciphertext the buffer which contains the cipher text between two clients
     * @param clients_ciphertext_len the length of the cipher text between two clients
     * @return unsgined integer to specify if the sending is successful or not. If it is successful it will return the
     * size of the message_buf, otherwise 0
    */
    static unsigned int send_message_14(User* sender, User* receiver, unsigned char * clients_ciphertext, int clients_ciphertext_len);
    //=================================================================================================================== 
    /**
     * handle message type 10. This function will be called inside the client application
     * @param message the buffer which is received from the socket.
     * @param message_len the size of the received message
     * @param my_user the receiver of the message!
     * @return integer to specify if parsing the message is successful or not. If it is successful it will return the
     * size of the 1, otherwise -1
    */
    static int handle_message_14(char * message, size_t message_len, User* my_user);
    //===================================================================================================================
    /**
     * create a message type 17. This function will be called inside the client application
     * @param message_buf buffer which contains the whole dataframe. It will be initialized and sent to the socket.
     * @param my_user the sender of the message!
     * @return unsgined integer to specify if the sending is successful or not. If it is successful it will return the
     * size of the message_buf, otherwise 0
    */
    static unsigned int send_message_17(User* my_user);
    //===================================================================================================================
    /**
     * handle message type 17. This function will be called inside the server application
     * @param message the buffer which is received from the socket.
     * @param message_len the size of the received message
     * @param sender the sender of the message! This user resides inside the server application (inside a vector of users)
     * @return integer to specify if parsing the message is successful or not. If it is successful it will return the
     * size of the 1, otherwise -1
    */
    static int handle_message_17(char * message, size_t message_len, User* sender);
};


#endif