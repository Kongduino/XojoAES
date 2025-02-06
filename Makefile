all:
	gcc -Wall -O3 -g -c *.c
	gcc -dynamiclib *.o -o aes.dylib
	nm -gU aes.dylib

clean:
	rm *.o *.dylib

test:
	python3 test.py 
