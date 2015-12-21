CC = gcc

FLAGS = -g -O2 -D_REENTRANT -Wall

CFLAGS = ${FLAGS} -I/home/courses/cse533/Stevens/unpv13e/lib

LIBUNP_NAME = /home/courses/cse533/Stevens/unpv13e/libunp.a
 
LIBS = ${LIBUNP_NAME} -lpthread

CLEANFILES =	tour tour.o arp arp.o

		
all:	tour arp
	
tour: tour.o
	${CC} ${FLAGS} -o tour tour.o ${LIBS}
tour.o: tour.c
	${CC} ${CFLAGS} -c tour.c
	
arp: arp.o
	${CC} ${FLAGS} -o arp arp.o ${LIBS}
arp.o: arp.c
	${CC} ${CFLAGS} -c arp.c

clean:
	rm -f $(CLEANFILES)
