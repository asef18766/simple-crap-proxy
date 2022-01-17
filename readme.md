# Simple Crap Proxy
a simple & crap vpn implemented via tun/tap, currently worked on linux
## archetecture
this vpn simply simulate a hub which broadcast all the packets to elsewhere except source machine.
## how to use
1. install ```gcc```, ```g++```
2. install other build requirements(for ubuntu)
    ```
    apt install libssl-dev libpcap-dev
    ```
### for server side
1. create certificate
    ```
    make create_crt
    ```
2. create server binary
    ```
    make
    ```
3. run server and listen to a port
    ```
    ./vpn_server 48763
    ```
### for client side
1. create client binary
    ```
    make
    ```
2. run client and connected to remote vpn server to accquire address
    ```
    sudo ./vpn_client <server ip> 48763
    ```