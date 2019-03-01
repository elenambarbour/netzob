CFLAGS = -g -fno-stack-protector -W -Wall -ansi -pedantic -Wno-pointer-sign

default: server.o client.o amo_api.o amo_net.o amo_parser.o common.o
	gcc $(CFLAGS)  -o server server.o amo_api.o amo_net.o amo_parser.o common.o
	gcc $(CFLAGS)  -o client client.o amo_net.o common.o amo_parser.o amo_api.o

server.o: server.c
	gcc $(CFLAGS)  -o server.o -c server.c

client.o: client.c
	gcc $(CFLAGS)  -o client.o -c client.c

api.o: amo_api.c
	gcc $(CFLAGS)  -o amo_api.o -c amo_api.c

common.o: common.c
	gcc $(CFLAGS)  -o common.o -c common.c

net.o: amo_net.c
	gcc $(CFLAGS)  -o amo_net.o -c amo_net.c

parser.o: amo_parser.c amo_api.h
	gcc $(CFLAGS)  -o amo_parser.o -c amo_parser.c amo_api.c

clean:
	rm -f server client *.o *~
