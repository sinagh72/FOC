#include <cstring>
#include <iostream>
#include <string>
#include <string.h>

using namespace std;
int main(){
    unsigned char* txt = (unsigned char*)"sina";
    unsigned char* t = (unsigned char*)malloc(4);
    t[0] = 5;
    uint16_t * counter_pointer = (uint16_t *) (t+1);
    *counter_pointer = 10 + 1;
    memcpy(t+1+2, txt, 4);
    //txt[119] = '\0';
    cout << t << endl;
    free(t);

}