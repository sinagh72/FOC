#include "user.h"
#include <cstddef>
#include <vector>


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

/*
static size_t print_list_online_users(vector<string> usernames){
    if(usernames.size() == 0){
        cout << "There is No Available User" << endl;
        return 0;
    }
    cout << "Online Users:\n";
    cout << "Select The User You Want to Chat:\n";
        
    size_t c = 1;
    for(string usr: usernames){
        cout << c <<". " << usr;
        c++;
    }
    cout << "0. Go Back" <<endl;

    return usernames.size() - 1;
}
*/

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
