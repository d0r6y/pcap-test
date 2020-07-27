all: pcap-test

pcap-test: header_parse.o main.o
	g++ -g -o pcap-test header_parse.o main.o -lpcap 

header_parse.o: header_parse.h header_parse.cpp
	g++ -g -c -o header_parse.o header_parse.cpp

main.o: main.cpp header_parse.h
	g++ -g -c -o main.o main.cpp

clean:
	rm -f pcap-test *.o

