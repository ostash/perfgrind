-include site.mak

all: pgcollect pgreport pginfo

pgcollect: pgcollect.c
	gcc -std=gnu99 -Wall -g -D_GNU_SOURCE -o pgcollect pgcollect.c ${FLAGS}

pgreport: pgreport.cpp
	g++ -Wall -g -o pgreport pgreport.cpp ${FLAGS} -ldw

libpg.so: Profile.h Profile.cpp
	g++ -Wall -g -fPIC --shared -o libpg.so Profile.cpp ${FLAGS}

pginfo: pginfo.cpp libpg.so
	g++ -Wall -g -o pginfo pginfo.cpp -L. -lpg -Wl,--rpath=. ${FLAGS}
