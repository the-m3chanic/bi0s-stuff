# isitnot 

I was given [this](https://drive.google.com/file/d/18aLucoktLEgflx69DvKljl5QRGKdBcWI/view?usp=sharing) file
Find the flag, pretty simple right?
One catch tho, I was only allowed to use [GDB](https://ctf101.org/reverse-engineering/what-is-gdb/) to solve this challenge. 

After running through the program a couple of times, I quickly realised the `strcmp` function being used was not actually the library function (I'll get to this part in a bit)
Stepping into the function lets us take a closer look at what it might be doing. Reading the disassembly, we can observe the following:
![screenshot](./screenshot)

This is repeated 15 times. Essentially, its a byte by byte `rol` operation on our input. 
<br><br>
Next, a similar operation is performed:
![Screenshot](./screenshot_ror)

So basically, our input is being rotated to the left (byte by byte) once. Pretty simple. 

Now here came the confusing part.
These were the args passed to the `strcmp` function:
![Screenshot](./screenshot_args)
So naturally, I assumed our input must be getting jumbled and turning into the 2nd argument and that was in fact the flag. Ah, not so much.

Initially, our argument was stored in `r8`, then moved byte by byte into `rdi` after being rotated to the left by 3. 
Then, keeping it in `rdi`, our input is rotated to the right by 2.

However, what I failed to notice at first glance was that the further encryption was performed on the *2nd* argument (the one already in the program), and not my input. That was stored in `rsi`.
<br><br>
Now, we can see another function call inside the `strcmp` function:
![screenshot](./screenshot_sec)
<br>
<br>


Important detail to be observed here:
![alt](./screenshot_imp)
`al` contains *our input*, it stores it byte by byte.<br> 
`cl` contains the *2nd arg* passed to the `strcmp` function.

This is an important distinction because operations are only being performed on `cl` in this function, whereas `al` is only present as a check to see if the input string has ended or not (observe the `test` being performed before moving further into `l3`, this is most likely to check for the null byte at the end of string). 
This was something I failed to catch in my first time analysing this function, cost me some time. 
<br>

Now, coming to the encryption bit:
![alt](./screenshot_second)

Each byte of the 2nd arg is being `XOR`ed with `0xc` and then has 6 added to it.
*This* is the string that's being compared to our rotated input.
<br>
So, if we can get our hands on the input string that's passed onto the `strncmp` function, and perform the `XOR`ing and adding, then rotate that to the right by 1, we should get our flag, hopefully?
<br>

How do we get that input argument though?
<br>
Well, if we hop back to where `strncmp` is called, we can see the 2 args being passed into it. 
![alt](./screenshot_final)

We can see the 2nd string is stored at offset `0x7fffffffe039`, so with a little GDB magic, we can print the 15 bytes stored there. 
![alt](./screenshot_offset)

Now, all we have to do is put these in an array, perform the required operations and we should get the flag. 

So I wrote a script to do that
```py
flag = [0xb0, 0xa4, 0x68, 0xc2, 0xce, 0x84,	0xa2, 0xd2, 0x9a, 0x84, 0xde, 0x6a, 0x98, 0x52,	0x6e]
for i in range(len(flag)):
	flag[i] ^= 0xc
	flag[i] += 6
	flag[i] = (flag[i] >> 1 | flag[i] << 7) & 0xff

print(''.join(chr(i) for i in flag))
```
Output:
> aW5jdGZrNGl6M24

Let's input this to the program and check
![alt](./screenshot_flag)

*nicE*
<br><br><hr>
**Important point to note though**
<br>
It's very smart how the author had their own `strcmp` function instead of the standard library one. Nobody would usually think of stepping into it. 
<br>
My guess on how they did it is probably just not including the `string.h` header file and defining their own in the program. <br>
Regardless, still very cool, will definitely be implementing something like this in one of my own challenges very soon ;)
<br><hr><br>


### Author
***th3mech4nic***





