all:
	gcc vpn_client.c utils.c -o vpn_client.exe
	gcc vpn_server.c utils.c -o vpn_server.exe -lssl -lcrypto
	cd simple-tcp && make
clean:
	rm -f vpn_client.exe vpn_server.exe
	cd simple-tcp && make clean
run_server:
	sudo ./vpn_server 48763