main: contact.o  
	gcc -o contact contact.o -L. -lpbc -lgmp -lstdc++
contact.o: contact.cpp sm3.cpp
	gcc -c contact.cpp -L. -lpbc -lgmp -lstdc++
clear: 
	rm -f *.o contact
