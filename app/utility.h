#include <algorithm>
#include <cstddef>
#include <string>
#include <iostream>
#include "user.h"
#include <vector>

using namespace std;


const string WHITESPACE = " \n\r\t\f\v";
const string DELIMITER = "||";

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

static void client_menu_0(){
    cout << "Main Menu:\n" << "Please Select an Option:\n" << "1. Check Online Users\n" << "2. Listening\n" 
    <<"0. Log out" <<endl;
}

static bool check_user_input(const string& input, int option_size){
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
static size_t print_list_online_users(string users, string my_username){
    size_t c = 0;
    if(users.compare(my_username) == 0){
        cout << "There is No Available User" << endl;
        return 0;
    }
    cout << "Online Users:\n";
    cout << "Select The User You Want to Chat:\n";
    size_t pos = 0;
    string token;
    while ((pos = users.find(DELIMITER)) != string::npos) {
        token = users.substr(0, pos);
        cout << c + 1 << ". " << token << endl;
        users.erase(0, pos + DELIMITER.length());
        c++;
    }
    cout << "0. Go Back" <<endl;
    return c;
}


static User* find_user(string username, vector<User*>*users){
    for (User* usr : *users) // access by reference to avoid copying
    {  
        if (usr->get_username().compare(username)==0)
        {   
            return usr;
        }
    }
    cerr<< "Error: User '" << username << "' not found!" <<endl;
    return NULL;
}