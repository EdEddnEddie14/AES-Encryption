# AES-Encryption
Implementation of AES encryption algorithm for CS361 assignment 5 in Spring 2017
UTEID: [hidden]
FIRSTNAME: Eduardo
LASTNAME: Molina
CSACCOUNT: [hidden]
EMAIL: molinaeddie50@yahoo.com

[Program 5]
[Description]
There is only one file: AES.java. There are functions for each operation in the AES algorithm: subBytes, shiftRows, mixColumns, and addRoundkey. There are also inverse functions for each of these, except for subBytes, which takes a boolean argument to indicate whether the function should be run in encryption or decryption mode. The main method interprets the arguments sent from the command line and loops through each round, calling all the operational functions as appropriate. To compile the program, use “java *.java”. To run it in encryption mode, use “java e key plaintext”, where key is the name of a file containing the key and plaintext is the name of a file containing the data to be encrypted. To run it using decryption mode, use “java d key plaintext”. 

[Finish]
I finished all parts of the algorithm, which seems to be working correctly. There is, however, a bug that prevents multiple lines of input being processed. Regardless of how many lines I put in the input files, only one line ended up in the output files.

[Test Case 1]

[Command line]
java AES e key.txt plaintext.txt

[Input Filenames]
key.text
plaintext.txt

[Output Filenames]
plaintext.enc
plaintext.enc.dec




[Test Case 2]

[Command line]
java AES e key2.txt plaintext2.txt

[Input Filenames]
key.text
plaintext2.txt

[Output Filenames]
plaintext2.enc
plaintext2.enc.dec




[Test Case 3]

[Command line]
java AES e key3.txt plaintext3.txt

[Input Filenames]
key.text
plaintext3.txt

[Output Filenames]
plaintext3.enc
plaintext3.enc.dec



[Test Case 4]

[Command line]
java AES e key4.txt plaintext4.txt

[Input Filenames]
key.text
plaintext4.txt

[Output Filenames]
plaintext4.enc
plaintext4.enc.dec


