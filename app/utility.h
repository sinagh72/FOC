#include <algorithm>
#include <string>
#include <iostream>
#include "user.h"
#include <vector>

using namespace std;


const string WHITESPACE = " \n\r\t\f\v";

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
    cout << "Main Menu:\n" << "Please Select One Option:\n" << "1. Check Online Users\n" << "2. Listening\n" 
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
static void print_list_online_users(){
    cout << "Online Users:\n" << "Select The User You Want to Chat:\n"<<"0. Go Back" <<endl;
}


static User* find_user(vector<User>*users, string receiver){
    for (int i = 0; i < users->size(); i++) {
        if(users->at(i).get_username().compare(receiver) == 0){
            return &users->at(i);
        }
    }
    return nullptr;
}