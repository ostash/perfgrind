-include site.mak

SOURCES = AddressResolver.cpp Profile.cpp
HEADERS = AddressResolver.h Profile.h

all: pgcollect pginfo pgconvert

pgcollect: pgcollect.c
	gcc -std=gnu99 -Wall -g -D_GNU_SOURCE -o pgcollect pgcollect.c ${FLAGS}

pginfo: pginfo.cpp $(SOURCES) $(HEADERS)
	g++ -Wall -g -o pginfo pginfo.cpp $(SOURCES) -ldw -lelf ${FLAGS}

pgconvert: pgconvert.cpp $(SOURCES) $(HEADERS)
	g++ -Wall -g -o pgconvert pgconvert.cpp $(SOURCES) -ldw -lelf ${FLAGS}
