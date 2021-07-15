#include "user.h"
#include <cstddef>
#include <vector>
#include <arpa/inet.h>


const string WHITESPACE = " \n\r\t\f\v";
const string DELIMITER = "||";


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
        false
    }
    return true;
}

void main_menu(User* my_user, vector<string> &usernames){
    
    system("clear");
    cout<<"Welcome "+ my_user->get_username() <<endl;
    
    cout << "You can: " <<endl;
    cout << "r : refresh the list of avaiable users" <<endl;
    cout << "x : exit the application" <<endl<<endl;
    if(get_available_users(my_user, usernames)) {
        cout<<"Or you can request to talk with one of the available user: "<<endl;
        int c=0;
        for(string usr: usernames) {
            cout << c <<". " << usr << endl;
            c++;
        }
    }

    cout<<"Type the character corrisponding to the wanted action or the number of the user you want to chat with:"<<endl;
    cout<< "> ";
}

bool establish_handshake_clients(User * my_user, string receiver_username){
    int val_read = 0;
    my_user->set_status(RTT);
    if (NetworkMessage::send_message_5(my_user, receiver_username) == -1){
        cout << "Error in Establishing Secure Connection (5)" <<endl;
        return false;
    }
    char buffer[MAX_MESSAGE_LENGTH] = {0};
    val_read = read(my_user->get_socket() , buffer, MAX_MESSAGE_LENGTH);
    if(buffer[0] == 8){
        if(-1 == NetworkMessage::handle_message_8(buffer, val_read, my_user)){
            cout << "Error in Establishing Secure Connection (8)" <<endl;
            return false;
        }
        if(-1 == NetworkMessage::send_message_9(my_user)){
            cout << "Error in Establishing Secure Connection (9)" <<endl;
            return false;
        }
        cout <<"Secure Connection between You and " << receiver_username <<" is Established!" <<endl;
    }else if(buffer[0] == 12){
        if(-1 == NetworkMessage::handle_message_12(buffer, val_read, my_user)){
            cout << "Error in Establishing Secure Connection (12)" <<endl;
            return false;
        }
    }
    return true;
}

bool connect_to_server(string username, string password, char* IP, int PORT, User** my_user) {
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
    char *buffer_0 {nullptr};
    int buffer_len = NetworkMessage::send_message_0(&buffer_0, *my_user);
    if(buffer_len == -1){
        cout << endl << "Error in sending message type 0" <<endl;
        cout << "Connection failed";
        return false;
    }
    ///TODO:check errors
    char *buffer = (char*)malloc(MAX_MESSAGE_LENGTH);
    //handle message type 1
    valread = read( sock , buffer, MAX_MESSAGE_LENGTH);

    if(NetworkMessage::handle_message_1(buffer, valread, *my_user) == -1){
        cout << endl <<"Error in handling message type 1" <<endl;
        cout <<"Connection failed" <<endl;
        return false;
    }
    free(buffer);

    //now the key between server and the client is established
    cout <<"Secure Connection is Established" <<endl;
}



static string ltrim(const string &s)
{
    size_t start = s.find_first_not_of(WHITESPACE);
    return (start == string::npos) ? "" : s.substr(start);
}
static string rtrim(const string &s)
{
    size_t end = s.find_last_not_of(WHITESPACE);
    return (end == string::npos) ? "" : s.substr(0, end + 1);
}
 
static string trim(const string &s) {
    return rtrim(ltrim(s));
}


bool check_user_input(const string& input, int option_size){
    char * ok_chars = (char*)malloc(option_size);
    for(int i = 0; i < option_size; i++){
        memset(ok_chars + i, '0' + i, 1);
    }
    if(input.find_first_not_of(ok_chars) != string::npos){
        cout << "Invalid Input. Try again!\n" <<endl;
        free(ok_chars);
        return false;
    }
    free(ok_chars);
    return true;
}

static User* find_user(string username, vector<User*>*users){
    for (User* usr : *users) // access by reference to avoid copying
    {  
        if (usr->get_username().compare(username)==0)
        {   
            return usr;
        }
    }
    cerr<< "User '" << username << "' Not Found Error" <<endl;
    return NULL;
}
