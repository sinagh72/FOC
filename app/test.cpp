
#include "Message.h"
#include <vector>
int main(){
    vector<int> ints;
    for(int i = 0; i <= 10; i++){
        ints.push_back(i);
    }
    for(auto i = ints.begin(); i != ints.end(); i++){
        cout << *i << endl;
    }

    for(auto i = ints.begin(); i != ints.end(); ){
       if(*i%2==0){
            cout <<"removing " << *i << endl;
            i = ints.erase(i);
       }
       else{
           i++;
       }
    }
    cout <<"wow" << endl;
    for(auto i = ints.begin(); i != ints.end(); i++){
        cout << *i << endl;
    }
    
}