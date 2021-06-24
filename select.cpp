#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <iostream>

using namespace std;

int main(void)
       {
           fd_set rfds;
           struct timeval tv;
           int retval;
           char string[20];

           /* Watch stdin (fd 0) to see when it has input. */

           FD_ZERO(&rfds);
           FD_SET(0, &rfds);

           /* Wait up to five seconds. */

           tv.tv_sec = 5;
           tv.tv_usec = 0;

           retval = select(1, &rfds, NULL, NULL, NULL/*&tv*/);
           /* Don't rely on the value of tv now!  That's because select decrement time in tv*/

           if (retval == -1)
               perror("select()");
           else if (retval) {
               printf("Data is available now.\n");
               cin>>string;
               /* FD_ISSET(0, &rfds) will be true. */
               }
           else
               printf("No data within five seconds.\n");

	cout<<"end:    "<<string<<endl;
           exit(EXIT_SUCCESS);
       }
