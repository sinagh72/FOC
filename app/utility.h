#ifndef APP_UTILITY_H
#define APP_UTILITY_H


#include "User.h"
#include <vector>
#include <limits>
#include <unistd.h>


const string WHITESPACE = " \n\r\t\f\v";
const string DELIMITER = "||";


void cin_flush();

bool check_user_input(const string& input, int nOption);

User* find_user(string username, vector<User*>*users, string message_type);

#endif