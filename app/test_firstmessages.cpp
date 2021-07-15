#include "Message.h"
#include "Security.h"
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
    //server
    vector<User*>users;
    //
    //clients A
    User * sina = new User();
    sina->set_username("sina");
    sina->set_password("sina");
    //client B
    User * lore = new User();
    lore->set_username("lore");
    lore->set_password("sina");
    //
    int size = 0;
    char * buffer0{nullptr};
    NetworkMessage::send_message_0(&buffer0, sina);

    cout << sina->get_client_server_pubk() <<endl;
    char* buffer1{nullptr};
    size = NetworkMessage::handle_message_0(buffer0, &buffer1, 0, (char*)"ip", 0, users);

    NetworkMessage::handle_message_1(buffer1, size, sina);



    free(buffer0);
    free(buffer1);





    //BIO_dump_fp (stdout, message, msg_len);

}