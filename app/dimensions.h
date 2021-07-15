#ifndef APP_DIMENSIONS_H
#define APP_DIMENSIONS_H

#endif //APP_DIMENSIONS_H

const unsigned int USERNAME_LENGTH = 32;
const unsigned int COUNTER_LENGTH = 2;
const unsigned int MESSAGE_TYPE_LENGTH = 1;
// due to the fact that we are using DH_get_2048_224()
const unsigned int DH_PUBK_LENGTH = 1190; 
const unsigned int SIGNATURE_LENGTH = 384; 
const unsigned int RSA_PUBK_LENGTH = 625; 
// const unsigned int MESSAGE_5_LENGTH = 1285;
// const unsigned int MESSAGE_6_LENGTH = 1285;
// const unsigned int MESSAGE_7_LENGTH = 1685;
// const unsigned int MESSAGE_8_LENGTH = 2309;
// const unsigned int MESSAGE_9_LENGTH = 509;
// const unsigned int MESSAGE_10_LENGTH = 1119;
const unsigned int MAX_CHARS = 10000;
//message type + 2 counters + 2 usernames + 2tags + 2ivs + 10k chars
const unsigned int MAX_MESSAGE_LENGTH = MESSAGE_TYPE_LENGTH + 2*COUNTER_LENGTH + 2*16 + 2*12 + 2*USERNAME_LENGTH + MAX_CHARS;

