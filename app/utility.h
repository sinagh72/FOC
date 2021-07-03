#include <algorithm>
#include <string>
#include <iostream>
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
    cout << "Main Menu:\n" << "Please Select One Option:\n" << "1. Check Online Users\n" <<"0. Log out" <<endl;
}

static bool check_user_input(const string& input, int option_size){
    char * ok_chars = (char*)malloc(option_size);
    for(int i = 0; i < option_size; i++){
        ok_chars[i] = i;
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
    cout << "Online Users:\n" << "Select The User You Want to Chat:\n" << " add list of users..." <<"0. Go Back" <<endl;
}