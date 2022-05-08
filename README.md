# pwrecovery

Openssl library is used when calculating hashes with CPU. On Linux install the necessary library with:
```
sudo apt-get install libssl-dev
```

And then compile the program with lcrypto-flag:
```
g++ main.cpp -o pwrecovery -lcrypto
```

