#makefile

all: client server

client: client.cpp User.cpp User.h utility.cpp utility.h Security.cpp Security.h NetworkMessage.cpp NetworkMessage.h CLI.cpp CLI.h dimensions.h
	g++ client.cpp User.cpp utility.cpp Security.cpp NetworkMessage.cpp CLI.cpp -o client -lcrypto

server: server.cpp User.cpp User.h  NetworkMessage.cpp NetworkMessage.h utility.h utility.cpp dimensions.h Security.h Security.cpp
	g++ server.cpp User.cpp NetworkMessage.cpp utility.cpp Security.cpp -o server -lcrypto

clean:
	rm client server
