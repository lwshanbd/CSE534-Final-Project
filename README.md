# CSE534 Final Project -- Shadowsock Pro

Authors: 

Yilun Wu (Yilun.Wu@stonybrook.edu) 

Baodi Shan (Baodi.Shan@stonybrook.edu)

# Install

Prerequisite:

Golang 1.17.3 for both Linux, Microsoft Windows or Mac OS(with Intel CPU)

For client:

```
cd cmd/shadowsocks-local
go install
```

For server:
```
cd cmd/shadowsocks-server
go install
```

# Usage

> Please update your system time before using 

Both the server and client program will look for `config.json` in the current directory. You can use `-c` option to specify another configuration file.


```
server          your server ip or hostname
server_port     server port
local_port      local socks5 proxy port
method          encryption method, null by default (table), the following methods are supported:
                    aes-128-cfb, aes-192-cfb, aes-256-cfb, bf-cfb, cast5-cfb, des-cfb, rc4-md5, rc4-md5-6, chacha20, salsa20, rc4, table
password        a password used to encrypt transfer
timeout         server option, in seconds
```

Run `shadowsocks-server` on your server. To run it in the background, run `shadowsocks-server > log &`.

On client, run `shadowsocks-local`. Change proxy settings of your browser to

```
SOCKS5 127.0.0.1:local_port
```

If you are using Chromium-Based browser, you could use [Proxy SwitchyOmega](https://chrome.google.com/webstore/detail/proxy-switchyomega/padekgcemlokbadohgkifijomclgjgif?hl=en) to set the proxy.

## About encryption method

In **Shadowsock Pro**, we use [ChaCha20-Poly1305](https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305) as our encryption method.


## About Timestamp Filter



## Command line options

Command line options can override settings from configuration files. Use `-h` option to see all available options.

```
shadowsocks-local -s server_address -p server_port -k password
    -m newChacha20Poly1305 -c config.json
    -b local_address -l local_port
shadowsocks-server -p server_port -k password
    -m newChacha20Poly1305 -c config.json
    -t timeout
```

## Reference

Original [Go-Shadowsocks](https://github.com/shadowsocks/shadowsocks-go)s


