client_hello: client_hello.c
				gcc client_hello.c -o clienthello | gcc -D OUTPUT_CH client_hello.c -o ch 

