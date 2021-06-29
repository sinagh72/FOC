#include "message_sina.h"
#include "user.h"
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
    //clients
    User * sina = new User();
    sina->set_username("sina");
    sina->set_server_client_key(server_client_1);
    //
    User * lore = new User();
    lore->set_username("lore");
    lore->set_server_client_key(server_client_2);
    //client A sends message to server
    char*message{nullptr};
    int msg_len = Message::send_message_5(&message, sina, "lore");
    cout << "Message 5 len: "<<msg_len << endl;
    //server receives the message and sends message 6
    Message::parse_message_5(message, msg_len, sina_s, users);
    free(message);
    char*message2{nullptr};
    msg_len = Message::send_message_6(&message2, sina_s , users);
    cout << "Message 6 len: "<<msg_len << endl;
    //client B receives message 6 and sends message 7
    Message::parse_message_6(message2, msg_len, lore);
    free(message2);
    char*message3{nullptr};

    msg_len = Message::send_message_7(&message3, lore);
    cout << "Message 7 len: "<<msg_len << endl;




    //BIO_dump_fp (stdout, message, msg_len);

}