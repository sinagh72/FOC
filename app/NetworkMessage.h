#ifndef APP_NETWORKMESSAGE_H
#define APP_NETWORKMESSAGE_H

#include "User.h"
#include <sys/socket.h>
#include "utility.h"
#include <unistd.h> 


class NetworkMessage {

public:
    /**
     * create a message of type 0
     * @param buffer is a pointer to pointer that will point to a buffer allocated inside the function
     * @param my_user the sender of the message!
     * @return the length of the message sent to toward the server. It will return -1 if some error happens
    */
    static int send_message_0(User* my_user);
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
    //===================================================================================================================  
    /**
     * handle message for message type 1
     * @param buffer buffer of incoming message 1
     * @param buffer_len lenght of the incoming message
     * @param client Pointer to User struct that represent the client
     * @return -1 on error, 1 on success
     */
    static int handle_message_1(char* buffer,  int buffer_len, User *client);
    //===================================================================================================================  
    /**
     * handle message for message type 2
     * @param buffer buffer of incoming message 2
     * @param buffer_len lenght of the incoming message
     * @param client Pointer to User struct that represent the client into the server
     * @return -1 on error, 1 on success
     */
    static int handle_message_2(char* buffer, int buffer_len, User *client);
    //===================================================================================================================  
     /**
     * create a message type 3. This function will be called inside the server application. 
     * @param my_user the sender of the message 3
     * @return  -1 on error, 1 on success
    */
    static int send_message_3(User * my_user);
    //===================================================================================================================  
     /**
     * handle message of message type 3
     * @param message the message received from the socket
     * @param message_len the size of the received message
     * @param my_user the sender of the message
     * @param username the vector containing the list of active users
     * @return -1 on error, 1 on success
     */
    static int handle_message_3(char * message, size_t message_len, User * my_user, vector<User*>online_users);
    //===================================================================================================================  
     /**
     * create a message type 4. This function will be called inside the server application. 
     * @param my_user the sender of the message 3
     * @param online_users the vector containing the list of active users
     * @return  -1 on error, 1 on success
    */
    static int send_message_4(User* sender, vector<User*>online_users);
    //===================================================================================================================  
     /**
     * handle message of message type 4
     * @param my_user the sender of the message 3
     * @param username the vector conatining the list of usernames of the active users
     * @return -1 on error, 1 on success
     */
    static int handle_message_4(User * my_user, vector<string>*usernames);
    //===================================================================================================================  
     /**
     * create a message type 5. This function will be called inside the client application. This function terminates the 
     * whole program if the counter between server and client reaches max.
     * @param my_user the sender of the message!
     * @param receiver_username the username of the other clients we want to communicate
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
     * @param online_users the vector of online users inside the server
     * @return integer to specify if parsing the message is successful or not. If it is successful it will return the
     * size of the 1, otherwise -1
    */
    static int handle_message_5(char * message, size_t message_len, User* sender, vector<User*>online_users);
    //===================================================================================================================  
    /**
     * create a message type 6. This function will be called inside the server application
     * @param sender the sender of the message!
     * @param receiver the receiver of the message!
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
    static int handle_message_6(char * message, size_t message_len, User* my_user);
    //=================================================================================================================== 
    /**
     * create a message type 7. This funciton will be called inside the client application. This function terminates the 
     * whole program if the counter between server and client reaches max.
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
     * @param online_users the vector of online users inside the server
     * @return integer to specify if parsing the message is successful or not. If it is successful it will return the
     * size of the 1, otherwise -1
    */
    static int handle_message_7(char * message, size_t message_len, User* sender, vector<User*>online_users);
    //=================================================================================================================== 
    /**
     * create a message type 8. This function will be called inside the server application
     * @param sender the sender of the message!
     * @param receiver the receiver of the message!
     * @param inner_gcm the buffer which contains the cipher text between two clients
     * @param inner_gcm_len the length of the cipher text between two clients
     * @return integer to specify if the sending is successful or not. If it is successful it will return the
     * size of the message_buf, otherwise -1
    */
    static int send_message_8(User* sender, User* receiver, unsigned char * inner_gcm, int inner_gcm_len);
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
     * size of the message_buf, otherwise -1
    */
    static int send_message_9(User* my_user);
    //===================================================================================================================
    /**
     * handle message type 9. This function will be called inside the server application
     * @param message the buffer which is received from the socket.
     * @param message_len the size of the received message
     * @param sender the sender of the message! This user resides inside the server application (inside a vector of users)
     * @param online_users the vector of online users inside the server
     * @return integer to specify if parsing the message is successful or not. If it is successful it will return the
     * size of the 1, otherwise -1
    */
    static int handle_message_9(char * message, size_t message_len, User* sender, vector<User*>online_users);
    //===================================================================================================================
    /**
     * create a message type 10. This function will be called inside the server application
     * @param sender the sender of the message!
     * @param receiver the receiver of the message!
     * @param inner_gcm the buffer which contains the cipher text between two clients
     * @param inner_gcm_len the length of the cipher text between two clients
     * @return unsgined integer to specify if the sending is successful or not. If it is successful it will return the
     * size of the message_buf, otherwise -1
    */
    static int send_message_10(User* sender, User* receiver, unsigned char * inner_gcm, int inner_gcm_len);
    //===================================================================================================================
    /**
     * handle message type 10. This function will be called inside the client application
     * @param my_user the receiver of the message!
     * @return integer to specify if parsing the message is successful or not. If it is successful it will return the
     * size of the 1, otherwise -1
    */
    static int handle_message_10(User* my_user);
    //===================================================================================================================
    /**
     * create a message type 11. This function will be called inside the client application. This function terminates the 
     * whole program if the counter between server and client reaches max.
     * @param my_user the sender of the message!
     * @return integer to specify if the sending is successful or not. If it is successful it will return the
     * size of the message_buf, otherwise -1
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
     * @param sender the sender of the message!
     * @param receiver the receiver of the message!
     * @return unsgined integer to specify if the sending is successful or not. If it is successful it will return the
     * size of the message_buf, otherwise 0
    */
    static int send_message_12(User* sender, User* receiver);
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
     * create a message type 13. This function will be called inside the client application. This function terminates the 
     * whole program if the counter between server and client reaches max.
     * @param message the message that the client wants to send to the other client.
     * @param message_len the length of the message that the client wants to send to the other client.
     * @param my_user the sender of the message!
     * @return integer to specify if the sending is successful or not. If it is successful it will return the
     * size of the message_buf. If an error happens -1, otherwise if the counter between two clients reaches max, it will return 0.
     */
    static int send_message_13(unsigned char* message, size_t message_len, User* my_user);
    //=================================================================================================================== 
    /**
     * handle message type 13. This function will be called inside the server application
     * @param message the buffer which is received from the socket.
     * @param message_len the size of the received message
     * @param sender the sender of the message! This user resides inside the server application (inside a vector of users)
     * @param online_users the vector of online users inside the server
     * @return integer to specify if parsing the message is successful or not. If it is successful it will return the
     * size of the 1, otherwise -1
    */
    static int handle_message_13(char * message, size_t message_len, User* sender, vector<User*>online_users);
    //=================================================================================================================== 
    /**
     * create a message type 14. This function will be called inside the server application
     * @param sender the sender of the message!
     * @param receiver the receiver of the message!
     * @param inner_gcm the buffer which contains the cipher text between two clients
     * @param inner_gcm_len the length of the cipher text between two clients
     * @return unsgined integer to specify if the sending is successful or not. If it is successful it will return the
     * size of the message_buf, otherwise -1
    */
    static int send_message_14(User* sender, User* receiver, unsigned char * inner_gcm, int inner_gcm_len);
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
     * create a message type 15. This function will be called inside the client application. This function terminates the 
     * whole program if the counter between server and client reaches max.
     * @param my_user the sender of the message!
     * @return unsgined integer to specify if the sending is successful or not. If it is successful it will return the
     * size of the message_buf, otherwise -1
    */
    static int send_message_15(User* my_user);
    //===================================================================================================================
    /**
     * create a message type 15. This function will be called inside the server application
     * @param message the buffer which is received from the socket.
     * @param message_len the size of the received message
     * @param sender the sender of the message!
     * @param online_users the vector of online users inside the server
     * @return unsgined integer to specify if the sending is successful or not. If it is successful it will return the
     * size of the message_buf, otherwise -1
    */
    static int handle_message_15(char * message, size_t message_len, User* sender, vector<User*>online_users);
    //===================================================================================================================
    /**
     * create a message type 15. This function will be called inside the server application
     * @param my_user the sender of the message!
     * @return unsgined integer to specify if the sending is successful or not. If it is successful it will return the
     * size of the message_buf, otherwise -1
    */
    static int send_message_16(User* sender, User* receiver);
    //===================================================================================================================
    /**
     * handle message type 16. This function will be called inside the client application
     * @param message the buffer which is received from the socket.
     * @param message_len the size of the received message
     * @param my_user the user of the receiver of the message!
     * @return integer to specify if parsing the message is successful or not. If it is successful it will return the
     * size of the 1, otherwise -1
    */
    static int handle_message_16(char * message, size_t message_len, User* my_user);
    //===================================================================================================================
    /**
     * create a message type 17. This function will be called inside the client application
     * @param my_user the sender of the message!
     * @return unsgined integer to specify if the sending is successful or not. If it is successful it will return the
     * size of the message_buf, otherwise -1
    */
    static int send_message_17(User* my_user);
    //===================================================================================================================
    /**
     * handle message type 17. This function will be called inside the server application
     * @param message the buffer which is received from the socket.
     * @param message_len the size of the received message
     * @param sender the sender of the message! This user resides inside the server application (inside a vector of users)
     * @param online_users the vector of online users inside the server
     * @return integer to specify if parsing the message is successful or not. If it is successful it will return the
     * size of the 1, otherwise -1
    */
    static int handle_message_17(char * message, size_t message_len, User* sender, vector<User*>online_users);
    //===================================================================================================================
    static int send_error_message(unsigned char * message, size_t message_len, User* receiver);
    //===================================================================================================================
    static int handle_error_message(char * message, size_t message_len, User* my_user);

};


#endif
