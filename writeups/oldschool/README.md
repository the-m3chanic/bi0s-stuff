
<b>tl;dr</b>
<br>
<ul>
<li> Keygen-based crackme, with custom UI window </li>
<li> Anti-debug check using custom ptrace syscall </li>
<li> Identity matrix check to verify user-password relation</li>
<li> Compile time string obfuscation</li>
</ul>
<br>

<p style="font-size:22.4px">Challenge description</p>

```
This challenge takes you back to the (good) old days of crackmes.de.
Your goal for this challenge is to write a "keygen", a program that generates valid passwords for arbitrary given usernames.
You are also given 'flag_maker.py' which contains a list of usernames that you have to find their corresponding passwords.
Once you find all passwords, run the script and you will get the flag.
```

We're given 2 files along with the challenge. 
1. The binary, `oldschool` 
2. `flag_maker.py` <br><br>
```py
#!/usr/bin/env python3
# GCTF'23 - Old School - Flag Maker
import hashlib

# Find the passwords for the following 50 usernames, substitute them inside the pairs,
# and then run the script to get the flag.
pairs = [
  ('gdwAnDgwbRVnrJvEqzvs', '{password}'),
  ('ZQdsfjHNgCpHYnOVcGvr', '{password}'),
  ('PmJgHBtIpaWNEMKiDQYW', '{password}'),
  ('OAmhVkxiUjUQWcmCCrVj', '{password}'),
  ('ALdgOAnaBbMwhbXExKrN', '{password}'),
  ('tqBXanGeFuaRSMDmwrAo', '{password}'),
  ('etTQMfSiRlMbNSuEOFZo', '{password}'),
  ('wceLFjLkBstBfQTtwnmv', '{password}'),
  ('rBiaRSHGLToSvIAQhZIs', '{password}'),
  ('ackTeRoASCkkkRUIBjmX', '{password}'),
  ('UBFLQMizCtLCnnOjaLMa', '{password}'),
  ('UwiBcAZEAJHKmZSrLqTB', '{password}'),
  ('oYlcWeZwpEEejIGuCHSU', '{password}'),
  ('txWHHXTtBXbckmRPxgCx', '{password}'),
  ('mhPdqEbAligcqQCsHLGl', '{password}'),
  ('UsIdCFPOqrXwsSMoqfIv', '{password}'),
  ('OdSAfswQJnMyjOlqpmqJ', '{password}'),
  ('eNKVZRlVwQCxWzDvUrUW', '{password}'),
  ('dUVNMmEPDxRIdVRXzbKa', '{password}'),
  ('iMBkfiyJxewhnvxDWXWB', '{password}'),
  ('xlQgeOrNItMzSrkldUAV', '{password}'),
  ('UPEfpiDmCeOzpXeqnFSC', '{password}'),
  ('ispoleetmoreyeah1338', '{password}'),
  ('dNcnRoRDFvfJbAtLraBd', '{password}'),
  ('FKBEgCvSeebMGixUVdeI', '{password}'),
  ('DfBrZwIrsHviSIbenmKy', '{password}'),
  ('OvQEEDVvxzZGSgNOhaEW', '{password}'),
  ('iNduNnptWlmAVsszvTIZ', '{password}'),
  ('GvTcyPNIUuojKfdqCbIQ', '{password}'),
  ('noAJKHffdaRrCDOpvMyj', '{password}'),
  ('rAViEUMTbUByuosLYfMv', '{password}'),
  ('YiECebDqMOwStHZyqyhF', '{password}'),
  ('phHkOgbzfuvTWVbvRlyt', '{password}'),
  ('arRzLiMFyEqSAHeemkXJ', '{password}'),
  ('jvsYsTpHxvXCxdVyCHtM', '{password}'),
  ('yOOsAYNxQndNLuPlMoDI', '{password}'),
  ('qHRTGnlinezNZNUCFUld', '{password}'),
  ('HBBRIZfprBYDWLZOIaAd', '{password}'),
  ('kXWLSuNpCGxenDxYyalv', '{password}'),
  ('EkrdIpWkDeVGOSPJNDVr', '{password}'),
  ('pDXIOdNXHhehzlpbJYGs', '{password}'),
  ('WMkwVDmkxpoGvuLvgESM', '{password}'),
  ('aUwdXCDDUWlPQwadOliF', '{password}'),
  ('WmlngotWTsikaXRDakbp', '{password}'),
  ('thrZhzSRBzJFPrxKmetr', '{password}'),
  ('TcurEDzLjepMrNwspPqd', '{password}'),
  ('SScTJRokTraQbzQpwDTR', '{password}'),
  ('PObUeTjQTwEflLQtPOJM', '{password}'),
  ('LUDPGXGvuVFAYlMTTowZ', '{password}'),
  ('UlTVDrBlCmXmFBmwLLKX', '{password}'),
]

print('CTF{' + hashlib.sha1(b'|'.join(f'{u}:{p}'.encode('utf-8') for u, p in pairs)).hexdigest() + '}')
```

<br>

So, it's a keygen program.
Now we move on to reversing it. 


<p style="font-size:22.4px">Triaging</p>

Upon running the binary, we seem to be hit with an error complaining about our terminal size. <br>
![](https://hackmd.io/_uploads/r1tw-Ew_3.png)


Hmm, alright. 

<br>

<p style="font-size:22.4px">Static Analysis</p>

Popping the binary in IDA, we can see that a lot of the functions from the `curses.h` library are being used. Noted.<br>
Upon further analysis, we can see this check being made:

![](https://hackmd.io/_uploads/rJ2wFHhu2.png)
<br>
There is a call being made to a function, and it jumps to `endwin` based on the outcome of that function. Jumping into that function, we can see the following checks being made:




![](https://hackmd.io/_uploads/r1RrcB3Oh.png)

(Variables and function names were renamed to make things easier).

What this tells us is, the screen size needs to be bigger than the specified amount. Unfortunately, our screen does not fit that size, so we can go ahead and patch the check. 
<br>



Upon running the (now patched) binary, we are presented with a retro-styled terminal screen asking for input:<br>
![](https://hackmd.io/_uploads/BJ6oWEw_h.png)




<br>
<p style="font-size:22.4px">Debugging</p>

While debugging, the binary steps through a lot of function calls, most of which are part of the `curses.h` library to set up/destroy the new window.<br><br>

One interesting point to note about this binary is:
It implements <i>Compile Time String Obfuscation</i>. In the sense that each error message is encrypted and stored in a memory location, and only decrypted during runtime. This is done to obfuscate what different sections of the binary might be doing since error messages are a useful indicator of the same. <br>
These are the repeating loops that we see throughout the entire binary. <br>
![](https://hackmd.io/_uploads/r19TWVv_n.png)<br>
The author seems to have added 2 function calls (instead of the usual 1) for each decryption pattern so that any decompiler wouldn't be able to optimise it and print the message as it is. Pretty neat. 
<br>



 

All user interaction with the binary takes place in the following while-loop: <br>
![](https://hackmd.io/_uploads/r12H2s6t3.png)
<br>
The multiple checks right after character input is received is essentially to mimic the button logic that the custom window is displaying. 

<br>


Each of the fields in the form (of the terminal) corresponds to each element of the form, i.e. field 1 --> username, field 3 --> password, and so on. <br>


Going a bit further down, we are met with this function call

![](https://hackmd.io/_uploads/S1gU2S3_2.png)


Which seems to be taking both our username and password. Must be the check function. 
<br>
<p style="font-size:22.4px">Check for password format</p>

![](https://hackmd.io/_uploads/H1x_G4Puh.png)


This tells us that the password should be of length 29, with the 5th, 11th, 17th and 23rd indices as the '`-`' symbol.<br>
Basically, the password must be of the format `ABCDA-EFGHP-JKLMN-EPQRS-TUVWX`and contain only
 `23456789ABCDEFGHJKLMNPQRSTUVWXYZ`   as its characters. <br>
And it only seems to be accepting characters from a particular character set. Here, `possible_chars` contains the array of acceptable inputs. 


<br>
<p style="font-size:22.4px">Our username</p>

![](https://hackmd.io/_uploads/HktqRrh_n.png)


This code block is doing multiple things:<br>
<ol type="a">
<li> Converts each character of our password into a <i>dword</i> and stores them in <i>big endian</i> format. </li> 
    <li> Sets another variable to collect the <i>8th, 1st, and 9th</i> bits out of each such dword and stores it in a variable (which we later found out through the author's write-up, were to be used as key triplets for a <b>Feistel key network</b>, but we didn't worry about it because it remained constant with constant usernames). </li>
<li> Does more such bit manipulations on our username, which eventually
would form a (2D) array of integers between 0 & 24. 
</ol>

<br>


<b>What the user array is responsible for:</b>
To be multiplied with the encrypted `pass_array` to form an Identity matrix after undergoing inversion.   


<br>
<p style="font-size:22.4px">Our password</p>

![](https://hackmd.io/_uploads/H15hhs6t3.png)


<br>

What is interesting to note is, the password forms a 2D matrix. If you recall, the format of the password was 5 blocks of 5 characters. That forms a perfect 5x5 matrix. 
And `user_dword` (the variable storing all the bits <i>except</i> the specified bits in our username check), is conveniently 25 bits long. 


After being used as indices for an array and undergoing an XOR, our password is being shuffled. The array being used for the XOR keys is set earlier in the program. 

Next, we correlate the username and the password. <br>
![](https://hackmd.io/_uploads/HJ5LXEPd3.png)


Here, imagine a <b>5x5 (square) matrix</b> .<br>
What these loops are doing is, essentially performing a <i>matrix multiplication</i> of the username and password matrices. The condition is that the resultant matrix must be an <i>Identity matrix</i> (matrix with diagonal elements as 1 and rest as 0).
<br>

Plug these constraints into `z3` and it solves it for us and gives us the password. 
However, this password is still encrypted (shuffled and xored). <br>
So after decrypting it, we can use the array as indices to extract bytes from the `possible_chars` array. 

So, by writing a script to fulfil each of these checks, we should be able to get by the check successfully. However, upon running the program...<br>
![](https://hackmd.io/_uploads/SkiDmEDO2.png)

Hmm.


<br>

<p style="font-size:22.4px">The Anti-Debug check</p>

After debugging the program further, we took a closer look at the point where our `xor_array` was being set. <br>
![](https://hackmd.io/_uploads/SyKu74w_3.png)


Where is the `unkdword` coming from?
Tracing the variable backward, we can observe that it is being assigned the value of the `eax` register after this syscall. 

![](https://hackmd.io/_uploads/rk-8pjTF3.png)


Now the interesting thing is, after these operations:
1. `eax` is being set to 26 (8892/342)
2. `esi` & `edx` are set to 0 (or NULL), and `edx` is set to 1

These arguments are the exact ones to be passed to perform a `PTRACE` syscall, and the output is conveniently stored in the `eax` register, which is then moved to our controlling variable. 


So, there is a ptrace flag being set!<br>
Meaning, the binary checks if the binary is being debugged and sets the flag accordingly (0 if no debugger is present).
(The author implemented a custom call to `ptrace` in such a manner that the decompiler wouldn't be able to identify it. Indirectly setting the syscall number based on division result of 2 registers and passing it as an argument function was pretty neat).

Quickly patching the binary to manually assign 0 to the flag (XORing `eax` just before it is assigned to the variable), we get a completely different XOR array. <br>
Doing so also prevents this from being a hindrance later in the program, because there are multiple checks, and subsequently multiple values being manipulated based on the PTRACE flag. 
<i>That</i> was the Anti-Debug check. Pretty neat.

Modifying our script to include the different XOR array, we can successfully generate a key for any provided username. <br>
To extract each `user_r0` array (the array being generated based on each username), we built an emulation script for the password-checking function. 
<br>
<p style="font-size:22.4px">Emulator script</p>

```c 
#include <stdio.h>
#include <string.h>  
  
int main(int argc, char *argv[])
  {
    if(argc != 2)
    {
      printf("Usage: %s <username>\n", argv[0]);
      return 1;
    }
    int v9, v7, v34, v8, v24, v23, i, v10, v32, v31, v11, v25;
    int v38=0;
    int v37=0x7a69;
    int v35 =0;
    int v36 =0;
    char *username = argv[1];

    int user_r0[80] = {0};
    int dword1[] = {10,3,22,12,4,16,13,20,22,22,13,19,13,14,12,7,23,19,20,14,1,7,11,24,11,25,13,9,8,1,7,12,20,19,21,16,23,6,7,18,10,17,11,2,4,10,3,12,26,5,8,15,6,4,0,10,15,14,1,9,7,11,1,1,25,23,9,1,24,23,15,19,22,16,15,4,12,23,24,19,5,8,19,13,1,18,21,4,7,19,8,25,17,6,14,23};

  for ( int k = 0; k < strlen(username); k += 4 )
  {
    v9 = strlen(username);
    v34 = 0;
    for ( int m = 0; m <= 3; ++m )
    {
      v7 = k + m;
      if ( v7 == strlen(username) )
        break;
      v34 = (v34 << 7) | username[k + m] & 0x7F;
    }
    for ( i = 0; i <= 2; ++i )
    {
      v23 = dword1[3 * (v37 % 32) + i];
      v38 = (2 * v38) | ((v34 & (1 << v23)) >> v23);
    }
    for ( i = 0; i <= 2; ++i )
    {
      v24 = dword1[3 * (v37 % 32) + i];
      v34 = (v34 >> (v24 + 1) << v24) | v34 & ((1 << v24) - 1);
    }
    v35 += 3;
    for ( i = 0; i <= (v38 & 7); ++i )
    {
      v8 = 8121 * v37 + 28411;
      v37 = v8 % 134456;
    }
    i = 0;
    while ( i <= 4 )
    {
      user_r0[16 * v36 + i++] = ~v34 & 0x1F;
      v34 >>= 5;
    }
    ++v36;
  }
    printf("v35: %d\n", v35);
    printf("v36: %d\n", v36);
  for ( int k = 0; k < v36; ++k )
  {
    v32 = user_r0[k] | (32 * user_r0[k + 16]) | ( user_r0[k + 32] << 10) & 0xC00;
    v31 = (8 * user_r0[k + 48]) | (user_r0[k + 32] >> 2) & 7 | (user_r0[k + 64] << 8);
    for (int  m = 0; m <= 12; ++m )
    {
      v10 = v32 ^ ( (8 * v31) |  (v31 >> 12)) & 0x7FFF;
      v11 = ~((2 * v38) | (v38 >> (v35 - 1)));
      v25 = v10 ^ v11 & ((1 << v35) - 1);
      v32 = v31 & 0x7FFF;
      v31 = ( v10 ^  (v11 & ((1 << v35) - 1))) & 0x7FFF;
    }
    user_r0[k] = v32 & 0x1F;
    user_r0[k + 16] = (v32 >> 5) & 0x1F;
    user_r0[k + 32] = v31 & 0x1C | (v32 >> 10) & 3;
    user_r0[k + 48] = (v31 >> 5) & 0x1F;
    user_r0[k + 64] = (v31 >> 10) & 0x1F;
  }

    for ( int k = 0; k < 80; ++k )
    {
        printf("%d,", user_r0[k]);
    }
  }
```

After extracting each such array, a complete Python script was written to automate extracting each required password and generating the flag using the `flag_maker.py` script provided. <br><br>



<p style="font-size:22.4px">Solve script</p>

```py
from z3 import *
import hashlib

username_list = [
  'gdwAnDgwbRVnrJvEqzvs',
  'ZQdsfjHNgCpHYnOVcGvr',
  'PmJgHBtIpaWNEMKiDQYW',
  'OAmhVkxiUjUQWcmCCrVj',
  'ALdgOAnaBbMwhbXExKrN',
  'tqBXanGeFuaRSMDmwrAo',
  'etTQMfSiRlMbNSuEOFZo',
  'wceLFjLkBstBfQTtwnmv',
  'rBiaRSHGLToSvIAQhZIs',
  'ackTeRoASCkkkRUIBjmX',
  'UBFLQMizCtLCnnOjaLMa',
  'UwiBcAZEAJHKmZSrLqTB',
  'oYlcWeZwpEEejIGuCHSU',
  'txWHHXTtBXbckmRPxgCx',
  'mhPdqEbAligcqQCsHLGl',
  'UsIdCFPOqrXwsSMoqfIv',
  'OdSAfswQJnMyjOlqpmqJ',
  'eNKVZRlVwQCxWzDvUrUW',
  'dUVNMmEPDxRIdVRXzbKa',
  'iMBkfiyJxewhnvxDWXWB',
  'xlQgeOrNItMzSrkldUAV',
  'UPEfpiDmCeOzpXeqnFSC',
  'ispoleetmoreyeah1338',
  'dNcnRoRDFvfJbAtLraBd',
  'FKBEgCvSeebMGixUVdeI',
  'DfBrZwIrsHviSIbenmKy',
  'OvQEEDVvxzZGSgNOhaEW',
  'iNduNnptWlmAVsszvTIZ',
  'GvTcyPNIUuojKfdqCbIQ',
  'noAJKHffdaRrCDOpvMyj',
  'rAViEUMTbUByuosLYfMv',
  'YiECebDqMOwStHZyqyhF',
  'phHkOgbzfuvTWVbvRlyt',
  'arRzLiMFyEqSAHeemkXJ',
  'jvsYsTpHxvXCxdVyCHtM',
  'yOOsAYNxQndNLuPlMoDI',
  'qHRTGnlinezNZNUCFUld',
  'HBBRIZfprBYDWLZOIaAd',
  'kXWLSuNpCGxenDxYyalv',
  'EkrdIpWkDeVGOSPJNDVr',
  'pDXIOdNXHhehzlpbJYGs',
  'WMkwVDmkxpoGvuLvgESM',
  'aUwdXCDDUWlPQwadOliF',
  'WmlngotWTsikaXRDakbp',
  'thrZhzSRBzJFPrxKmetr',
  'TcurEDzLjepMrNwspPqd',
  'SScTJRokTraQbzQpwDTR',
  'PObUeTjQTwEflLQtPOJM',
  'LUDPGXGvuVFAYlMTTowZ',
  'UlTVDrBlCmXmFBmwLLKX']


xor_key_arr = [
    [27, 0, 10, 13, 8],
    [24, 15, 28, 6, 7],
    [18, 5, 12, 2, 4],
    [29, 31, 9, 19, 1],
    [30, 17, 11, 22, 25]
]


idx_arr = [16, 14, 13, 2, 11, 17, 21, 30, 7, 24, 18, 28, 26, 1, 12, 6, 31, 25, 0, 23, 20, 22, 8, 27, 4, 3, 19, 5, 9, 10, 29, 15]

possible_chars = list("23456789ABCDEFGHJKLMNPQRSTUVWXYZ")

convert_1d_2d = lambda l, x: [l[i:i+x] for i in range(0, len(l), x)]

def pass_check(pwd_list, user_r0):
    pwd_list = convert_1d_2d(pwd_list, 5)
    print("[*] Verifying password list")
    for k in range(5):
        for m in range(5):
            sum = 0
            for i in range(5):
                sum = (pwd_list[i][m] * user_r0[k][i] + sum) & 0x1F

            if k == m and sum != 1 or k != m and sum:
                return False
    return True


def retrieve_pass(pwd_list):
    print("[*] Retrieving password")
    pwd_list = convert_1d_2d(pwd_list, 5)


    res = [0]*5
    res[0] = pwd_list[0]
    for k in range(1, 5):
        res[k] = pwd_list[k][5-k:5]
        res[k] += pwd_list[k][:5-k]
    

    for k in range(5):
        for m in range(5):
            res[k][m] ^= xor_key_arr[k][m]


    for k in range(5):
        for m in range(5):
            res[k][m] = idx_arr.index(res[k][m])
    

    flag = ""
    for k in range(5):
        for m in range(5):
            flag += possible_chars[res[k][m]]

    flag = f"{flag[:5]}-{flag[5:10]}-{flag[10:15]}-{flag[15:20]}-{flag[20:25]}"
    
    return flag

def solve(user_r0):
    sol = Solver()
    pass_r0 = [[BitVec(f"pass_r0_{i}_{j}", 8) for j in range(5)] for i in range(5)]
    flag=[]
    for k in range(5):
        for m in range(5):
            sum = 0
            for i in range(5):
                sum = (pass_r0[i][m] * user_r0[k][i] + sum) & 0x1F
            if k == m:
                sol.add(sum == 1)
            else:
                sol.add(sum == 0)
    
    if sol.check()==sat:
        print("[+] sat")
        m = sol.model()
        for i in range(5):
            for j in range(5):
                flag.append(m[pass_r0[i][j]].as_long())
        
    else:
        print("[-] unsat")
    return flag
    

def read_file(filename):
    print("[*] Reading file:", filename)
    with open(filename, "r") as f:
        data = f.readlines()
    return data

def get_flag(username_list, pass_list):
    pairs = []
    for i in range(len(username_list)):
        pairs.append((username_list[i], pass_list[i]))
    return 'CTF{' + hashlib.sha1(b'|'.join(f'{u}:{p}'.encode('utf-8') for u, p in pairs)).hexdigest() + '}'

def main():
    user_arr_list = [eval(line) for line in read_file("user_r0.txt")]
    pass_list = []

    for i in range(len(username_list)):
        print(f"\n\n[*] Username: {username_list[i]}")
        user_r0 = convert_1d_2d(user_arr_list[i], 16)
        pwd_list = solve(user_r0)
        if pwd_list != []:
            res = pass_check(pwd_list, user_r0)
            
            password = retrieve_pass(pwd_list)
            print("[*] Password:", password)
            pass_list.append(password)
            if res:
                print("[+] Correct password")
            else:
                print("[-] Wrong password")
        else:
            print("[*] Password array not found")
    
    flag = get_flag(username_list, pass_list)
    print("[*] Flag:", flag)

main()
```




<br>

## Flag:
```CTF{991d90ed198acc794d6dacd7e304f761c142acab}```

