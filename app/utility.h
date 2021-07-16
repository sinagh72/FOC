#ifndef APP_UTILITY_H
#define APP_UTILITY_H


#include "user.h"
#include <cstddef>
#include <vector>
#include <arpa/inet.h>
#include <limits>
#include <unistd.h>


const string WHITESPACE = " \n\r\t\f\v";
const string DELIMITER = "||";

static void cin_flush() {
    cin.ignore(numeric_limits<streamsize>::max());
    cin.clear();
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


static bool check_user_input(const string& input, int nOption){
    bool ret = false;
    for(unsigned int counter = 0; counter<nOption; counter++) {
        if(input.compare(to_string(counter))==0) {
            ret = true;
        }
        if(ret) break;
    }

    return ret;
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

#endif