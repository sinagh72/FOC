#include "message_sina.h"
#include "user.h"
#include <cstring>
#include <vector>

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
    //client B
    User * lore = new User();
    lore->set_username("lore");
    lore->set_server_client_key(server_client_2);
    //client A sends message 5 to server
    char*message{nullptr};
    int msg_len = Message::send_message_5(&message, sina, "lore");
    cout << "Message 5 len: "<<msg_len << endl;
    //server receives the message 5 and sends message 6
    Message::handle_message_5(message, msg_len, sina_s, users);
    char*message2{nullptr};
    msg_len = Message::send_message_6(&message2, sina_s , users);
    cout << "Message 6 len: "<<msg_len << endl;
    //client B receives message 6 and sends message 7
    Message::handle_message_6(message2, msg_len, lore);
    char*message3{nullptr};
    msg_len = Message::send_message_7(&message3, lore);
    cout << "Message 7 len: "<<msg_len << endl;
    //server receives the message 7 and sends message 8
    unsigned char* clients_ciphertext{nullptr};
    msg_len = Message::handle_message_7(&clients_ciphertext, message3, msg_len, lore_s, users);
    char*message4{nullptr};
    msg_len = Message::send_message_8(&message4, lore_s , clients_ciphertext, msg_len, users);
    cout << "Message 8 len: "<<msg_len << endl;
    //client A receives message 8 and sends message 9 to server  
    Message::handle_message_8(message4, msg_len, sina);



    // //print counters
    // cout<<"clients: "<<endl;
    // cout <<"sina-> client counter:"<< sina->get_client_coutner()<<", server counter:"<< sina->get_server_counter()<<endl;
    // cout <<"lore-> client counter:"<< lore->get_client_coutner()<<", server counter:"<< lore->get_server_counter()<<endl;

    // cout<<"server: "<<endl;
    // cout <<"sina_s-> client counter:"<< sina_s->get_client_coutner()<<", server counter:"<< sina_s->get_server_counter()<<endl;
    // cout <<"lore_s-> client counter:"<< lore_s->get_client_coutner()<<", server counter:"<< lore_s->get_server_counter()<<endl;

    free(message);
    free(message2);
    free(message3);
    free(message4);
    free(clients_ciphertext);





    //BIO_dump_fp (stdout, message, msg_len);

}