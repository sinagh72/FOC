#include "message_sina.h"
#include "user.h"
#include <cstring>
#include <openssl/bio.h>
#include <vector>

User* find_user(string user, vector<User>users){
    for (auto &usr : users) // access by reference to avoid copying
    {  
        if (usr.get_username().compare(user)==0)
        {   
            return new User(usr);
        }
    }
    cerr<< "Error: Receiver not found (find_dhpubk)!" <<endl;
    return NULL;
}

int main(){
    unsigned char* server_client_1 = (unsigned char*)"1234567890123456";
    unsigned char* server_client_2 = (unsigned char*)"0987654321098765";
    //server
    vector<User>users;
    User * sina_s = new User();
    sina_s->set_username("sina");
    sina_s->set_server_client_key(server_client_1);
    users.push_back(*sina_s);

    User * lore_s = new User();
    lore_s->set_username("lore");
    lore_s->set_server_client_key(server_client_2);
    users.push_back(*lore_s);
    //
    //clients A
    User * sina = new User();
    sina->set_username("sina");
    sina->set_server_client_key(server_client_1);
    sina->set_password("sina");
    //client B
    User * lore = new User();
    lore->set_username("lore");
    lore->set_server_client_key(server_client_2);
    lore->set_password("sina");
    //client A sends message 5 to server
    char*message{nullptr};
    int msg_len = Message::send_message_5(&message, sina, "lore");
    cout << "Message 5 len: "<<msg_len << endl;
    //server receives the message 5 and sends message 6
    //we assumed that the server can realize who is the sender and who is the receiver
    Message::handle_message_5(message, msg_len, sina_s);
    char*message2{nullptr};
    //we assumed that the server can realize who is the sender and who is the receiver
    msg_len = Message::send_message_6(&message2, sina_s, lore_s);
    cout << "Message 6 len: "<<msg_len << endl;
    //client B receives message 6 and sends message 7
    Message::handle_message_6(message2, msg_len, lore);
    char*message3{nullptr};
    msg_len = Message::send_message_7(&message3, lore);
    cout << "Message 7 len: "<<msg_len << endl;
    //server receives the message 7 and sends message 8
    unsigned char* clients_ciphertext{nullptr};
    //we assumed that the server can realize who is the sender and who is the receiver
    msg_len = Message::handle_message_7(&clients_ciphertext, message3, msg_len, lore_s);
    char*message4{nullptr};
    //we assumed that the server can realize who is the sender and who is the receiver
    msg_len = Message::send_message_8(&message4, lore_s , sina_s, clients_ciphertext, msg_len);
    cout << "Message 8 len: "<<msg_len << endl;
    //client A receives message 8 and sends message 9 to server  
    Message::handle_message_8(message4, msg_len, sina);
    char*message5{nullptr};
    msg_len = Message::send_message_9(&message5, sina);
    cout << "Message 9 len: "<<msg_len << endl;
    //server receives the message 9 and sends message 10
    unsigned char* clients_ciphertext2{nullptr};
    //we assumed that the server can realize who is the sender and who is the receiver
    msg_len = Message::handle_message_9(&clients_ciphertext2, message5, msg_len, sina_s);
    char*message6{nullptr};
    //we assumed that the server can realize who is the sender and who is the receiver
    msg_len = Message::send_message_10(&message6, sina_s , lore_s, clients_ciphertext2, msg_len);
    cout << "Message 10 len: "<<msg_len << endl;
    //client B receives message 10
    Message::handle_message_10(message6, msg_len, lore);
    cout <<"=======================================================================================\n";
    //cilent A sends a message
    char*message13{nullptr};
    unsigned char * clients_plaintext = (unsigned char*) "sina";
    msg_len = Message::send_message_13(&message13, clients_plaintext, strlen((char*)clients_plaintext), sina);
    cout << "Message 13 len: "<<msg_len << endl;
    //server receives the message 13 and sends message 14
    unsigned char*clients_ciphertext13{nullptr};
    msg_len = Message::handle_message_13(&clients_ciphertext13, message13, msg_len, sina_s);
    char*message14{nullptr};
    msg_len = Message::send_message_14(&message14, sina_s, lore_s, clients_ciphertext13, msg_len);
    cout << "Message 14 len: "<<msg_len << endl;
    //client B receives message 14
    Message::handle_message_14(message14, msg_len, lore);
    cout <<"=======================================================================================\n";
    //cilent B declined request to talk
    char*message11{nullptr};
    msg_len = Message::send_message_11(&message11, lore);
    cout << "Message 11 len: "<<msg_len << endl;
    //server receives the message 11 and sends message 12
    Message::handle_message_11(message11, msg_len, lore_s);
    char*message12{nullptr};
    Message::send_message_12(&message12, lore_s, sina_s);
    cout << "Message 12 len: "<<msg_len << endl;
    //client A receives message 12
    Message::handle_message_12(message12, msg_len, sina);
    cout <<"=======================================================================================\n";
    // // //print counters
    cout<<"clients: "<<endl;
    cout <<"sina-> sent counter:"<< sina->get_sent_counter()<<", received counter:"<< sina->get_received_counter()<<endl;
    cout <<"lore-> sent counter:"<< lore->get_sent_counter()<<", received counter:"<< lore->get_received_counter()<<endl;

    cout<<"server: "<<endl;
    cout <<"sina_s-> sent counter:"<< sina_s->get_sent_counter()<<", received counter:"<< sina_s->get_received_counter()<<endl;
    cout <<"lore_s-> sent counter:"<< lore_s->get_sent_counter()<<", received counter:"<< lore_s->get_received_counter()<<endl;
    cout <<"=======================================================================================\n";
    //cilent A sends log out message
    char*message17{nullptr};
    msg_len = Message::send_message_17(&message17, sina);
    //server receive the log out message
    Message::handle_message_17(message17, msg_len, sina_s);
    cout <<"=======================================================================================\n";

    free(message);
    free(message2);
    free(message3);
    free(message4);
    free(message5);
    free(message6);
    free(message11);
    free(message12);
    free(message14);
    free(message13);
    free(message17);
    free(clients_ciphertext);
    free(clients_ciphertext2);






    //BIO_dump_fp (stdout, message, msg_len);

}