all: myids testattack

myids: myids.cc
	g++ -Wall myids.cc -o myids -lpcap

testattack: testattack.cc
	g++ -Wall testattack.cc -o testattack -lpcap
