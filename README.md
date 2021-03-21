# WSU-Crypt
# Matthew Fritz
# matthew.fritz@wsu.edu

TO COMPILE:
    make

TO CLEAN:
    make clean

TO ENCRYPT (Assumnig key.txt is key file, plaintext.txt is the file you want to encrypt, 
                and ciphertext.hex is the file you want to write the ciphertext to):
    ./crypt -e key.txt plaintext.txt ciphertext.hex

TO DECRYPT:
    ./crypt -d key.txt ciphertext.hex recovered_plaintext.txt
