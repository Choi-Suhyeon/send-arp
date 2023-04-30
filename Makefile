all: send-arp

send-arp: main.o
	gcc -o send-arp main.o

main.o: main.c
	gcc -O2 -c -o main.o main.c

clean:
	rm -f *.o
	rm -f send-arp
