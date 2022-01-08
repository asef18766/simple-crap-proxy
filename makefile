all:
	gcc vpn_client.c utils.c -o vpn_client.exe -lssl -lcrypto
	g++ vpn_client_state.cpp client_manager.cpp utils.c vpn_server.cpp -o vpn_server.exe -lssl -lcrypto -g
	cd simple-tcp && make
create_crt:
	openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.pem
clean:
	rm -f vpn_client.exe vpn_server.exe
	cd simple-tcp && make clean
