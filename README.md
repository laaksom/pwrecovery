# pwrecovery

Openssl library is used when calculating hashes with CPU. On Linux install the necessary library with:
```
sudo apt-get install libssl-dev
```

Run ```make``` in directory bcryptLib to generate bcrypt.a files

And then compile the program with lcrypto-flag:
```
g++ main.cpp ./bcryptLib/bcrypt.a -o pwrecovery -lcrypto
```

