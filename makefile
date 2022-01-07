all:
	gcc vpn_client.c utils.c -o vpn_client.exe
	gcc vpn_server.c utils.c -o vpn_server.exe
	cd simple-tcp && make
clean:
	rm -f vpn_client.exe vpn_server.exe
	cd simple-tcp && make clean