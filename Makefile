-include site.mak

all: pgcollect pgreport

pgcollect: pgcollect.c
	gcc -std=gnu99 -Wall -g -D_GNU_SOURCE -o pgcollect pgcollect.c ${FLAGS}

pgreport: pgreport.cpp
	g++ -Wall -g -o pgreport pgreport.cpp ${FLAGS} -ldw
