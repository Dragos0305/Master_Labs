all:
	gcc -L/usr/local/lib dhe.c -o dhe -lcrypto -lssl
	gcc -L/usr/local/lib dhe_server.c -o dhe_server -lcrypto -lssl

start_client:
	./dhe

start_server:
	./dhe_server

clean:
	rm dhe dhe_server


