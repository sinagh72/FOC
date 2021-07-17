#include "utility.h"


void cin_flush() {
    cin.ignore(numeric_limits<streamsize>::max());
    cin.clear();
}

bool check_user_input(const string& input, int nOption){
    bool ret = false;
    for(unsigned int counter = 0; counter<nOption; counter++) {
        if(input.compare(to_string(counter))==0) {
            ret = true;
        }
        if(ret) break;
    }

    return ret;
}


User* find_user(string username, vector<User*>*users){
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