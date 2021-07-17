#ifndef APP_CLI_H
#define APP_CLI_H

#include <cstddef>
#include <cstdlib>
#include <unistd.h>
#include <vector>
#include <arpa/inet.h>
#include <limits>
#include "NetworkMessage.h"
#include "User.h"
#include "utility.h"

bool get_available_users(User*  my_user, vector<string> &usernames);

void main_menu(User* my_user, vector<string> &usernames);

bool establish_handshake_clients(User * my_user, string receiver_username);

bool connect_to_server(string username, string password, const char* IP, const int PORT, User** my_user);

void select_main_menu(User* my_user, vector<string> &usernames);
#endif