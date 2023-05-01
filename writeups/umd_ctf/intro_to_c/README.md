# Introduction to c 

There are two files for this challenge. One is a [png](https://drive.google.com/file/d/1oo9ANv-F6K8sbM0HqRmGApoXgDpdEE9A/view?usp=sharing) and the other a [.txt](https://drive.google.com/file/d/1m5vE_xSD6qQycDYR_Zz35hvWrRJz6YVy/view?usp=sharing) file.
<br>
<hr>

### Challenge Description
> "Welcome to CMSC216. Weeeeee have a lecture worksheet that the TAs will now hand out. You must write your name, student ID, and discussion session 
> **CORRECTLY** at the top of the worksheet. I have 3**69** students, so any time I need to spend finding out who to grade will cause YOU to lose 
> credit." 
> **(Larry Herman)**

<br>

<hr>
<br>
Initial analysis of the txt or the png file didn't take us anywhere.
The key values obviously had something to do with the image, but we couldn't figure out what it was. 

After sitting on it for a few hours, we had a couple theories on how it might be working. 
Initial theory was we might have to XOR the RGB values of the image we got (31x32) with the key values given to us, in the hopes that it might give us something useful. We used this script to extract the RGB values:

```py
from PIL import Image
im = Image.open('intro_to_c.png')
rgb_im = im.convert('RGB')
for i in range(31):
    for j in range(32):
        r, g, b = rgb_im.getpixel((j, i))
        print(f"PIXEL [{i},{j}] : VALUE RGB({r}, {g}, {b})")
```

This was saved in a file called [output.txt](https://drive.google.com/file/d/18cpq14GGTLlUufMuvn1G_Hti7Qe9cGcU/view?usp=sharing)

<br>

## The Solution 
<hr>


After one night's sleep, my [teammate](https://github.com/Chee-Tzu) had an idea: What if the RGB values of the image we got were mapped to the keys they gave?
It took us a couple of tries here and there, but implementation wise, we essentially built a script to map each key value from the output.txt to the key values given, and at the first occurrence where they were the same, append the ASCII value of that key into an array. In simple words, iterate through the RGB values of the image and append the ASCII value of its first occurrence in the keys list. 
This was the script we used for that:

```py
color_set= {
    0 : "RGB(0,0,0)",
    1 : "RGB(210,126,15)",
    2 : "RGB(164,252,30)",
    3 : "RGB(118,122,45)",
    4 : "RGB(72,248,60)",
    5 : "RGB(26,118,75)",
    6 : "RGB(236,244,90)",
    7 : "RGB(190,114,105)",
    8 : "RGB(144,240,120)",
    9 : "RGB(98,110,135)",
    10 : "RGB(52,236,150)",
    11 : "RGB(6,106,165)",
    12 : "RGB(216,232,180)",
    13 : "RGB(170,102,195)",
    14 : "RGB(124,228,210)",
    15 : "RGB(78,98,225)",
    16 : "RGB(32,224,240)",
    17 : "RGB(242,94,255)",
    18 : "RGB(196,220,14)",
    19 : "RGB(150,90,29)",
    20 : "RGB(104,216,44)",
    21 : "RGB(58,86,59)",
    22 : "RGB(12,212,74)",
    23 : "RGB(222,82,89)",
    24 : "RGB(176,208,104)",
    25 : "RGB(130,78,119)",
    26 : "RGB(84,204,134)",
    27 : "RGB(38,74,149)",
    28 : "RGB(248,200,164)",
    29 : "RGB(202,70,179)",
    30 : "RGB(156,196,194)",
    31 : "RGB(110,66,209)",
    32 : "RGB(64,192,224)",
    33 : "RGB(18,62,239)",
    34 : "RGB(228,188,254)",
    35 : "RGB(182,58,13)",
    36 : "RGB(136,184,28)",
    37 : "RGB(90,54,43)",
    38 : "RGB(44,180,58)",
    39 : "RGB(254,50,73)",
    40 : "RGB(208,176,88)",
    41 : "RGB(162,46,103)",
    42 : "RGB(116,172,118)",
    43 : "RGB(70,42,133)",
    44 : "RGB(24,168,148)",
    45 : "RGB(234,38,163)",
    46 : "RGB(188,164,178)",
    47 : "RGB(142,34,193)",
    48 : "RGB(96,160,208)",
    49 : "RGB(50,30,223)",
    50 : "RGB(4,156,238)",
    51 : "RGB(214,26,253)",
    52 : "RGB(168,152,12)",
    53 : "RGB(122,22,27)",
    54 : "RGB(76,148,42)",
    55 : "RGB(30,18,57)",
    56 : "RGB(240,144,72)",
    57 : "RGB(194,14,87)",
    58 : "RGB(148,140,102)",
    59 : "RGB(102,10,117)",
    60 : "RGB(56,136,132)",
    61 : "RGB(10,6,147)",
    62 : "RGB(220,132,162)",
    63 : "RGB(174,2,177)",
    64 : "RGB(128,128,192)",
    65 : "RGB(82,254,207)",
    66 : "RGB(36,124,222)",
    67 : "RGB(246,250,237)",
    68 : "RGB(200,120,252)",
    69 : "RGB(154,246,11)",
    70 : "RGB(108,116,26)",
    71 : "RGB(62,242,41)",
    72 : "RGB(16,112,56)",
    73 : "RGB(226,238,71)",
    74 : "RGB(180,108,86)",
    75 : "RGB(134,234,101)",
    76 : "RGB(88,104,116)",
    77 : "RGB(42,230,131)",
    78 : "RGB(252,100,146)",
    79 : "RGB(206,226,161)",
    80 : "RGB(160,96,176)",
    81 : "RGB(114,222,191)",
    82 : "RGB(68,92,206)",
    83 : "RGB(22,218,221)",
    84 : "RGB(232,88,236)",
    85 : "RGB(186,214,251)",
    86 : "RGB(140,84,10)",
    87 : "RGB(94,210,25)",
    88 : "RGB(48,80,40)",
    89 : "RGB(2,206,55)",
    90 : "RGB(212,76,70)",
    91 : "RGB(166,202,85)",
    92 : "RGB(120,72,100)",
    93 : "RGB(74,198,115)",
    94 : "RGB(28,68,130)",
    95 : "RGB(238,194,145)",
    96 : "RGB(192,64,160)",
    97 : "RGB(146,190,175)",
    98 : "RGB(100,60,190)",
    99 : "RGB(54,186,205)",
    100 : "RGB(8,56,220)",
    101 : "RGB(218,182,235)",
    102 : "RGB(172,52,250)",
    103 : "RGB(126,178,9)",
    104 : "RGB(80,48,24)",
    105 : "RGB(34,174,39)",
    106 : "RGB(244,44,54)",
    107 : "RGB(198,170,69)",
    108 : "RGB(152,40,84)",
    109 : "RGB(106,166,99)",
    110 : "RGB(60,36,114)",
    111 : "RGB(14,162,129)",
    112 : "RGB(224,32,144)",
    113 : "RGB(178,158,159)",
    114 : "RGB(132,28,174)",
    115 : "RGB(86,154,189)",
    116 : "RGB(40,24,204)",
    117 : "RGB(250,150,219)",
    118 : "RGB(204,20,234)",
    119 : "RGB(158,146,249)",
    120 : "RGB(112,16,8)",
    121 : "RGB(66,142,23)",
    122 : "RGB(20,12,38)",
    123 : "RGB(230,138,53)",
    124 : "RGB(184,8,68)",
    125 : "RGB(138,134,83)",
    126 : "RGB(92,4,98)",
    127 : "RGB(46,130,113)",
}
filename = "output.txt"

color_dict = {}
new_list = []

with open(filename, "r") as file:
    for line in file:
        line = line.strip()
        for key,value in color_set.items():
            if line == value:
                new_list.append(key)
                break

print(''.join([chr(i) for i in new_list]))
```


This gave us a C script as output. Compile and run that, and boom. Flag.
> UMDCTF{pu61ic_st@t1c_v0ID_m81n_s7r1ng_@rgs[]!!!}


```c
#include <stdio.h>
#define LEN(array) sizeof(array) / sizeof(*array)
#define SALT_1 97
#define SALT_2 4563246763

const long numbers[] = {4563246815, 4563246807, 4563246800, 4563246797, 4563246816, 4563246802, 4563246789, \
4563246780, 4563246783, 4563246850, 4563246843, 4563246771, 4563246765, 4563246825, 4563246781, 4563246784, \
4563246796, 4563246784, 4563246843, 4563246765, 4563246825, 4563246786, 4563246844, 4563246803, 4563246800, \
4563246825, 4563246775, 4563246852, 4563246843, 4563246778, 4563246825, 4563246781, 4563246849, 4563246782, \
4563246843, 4563246778, 4563246769, 4563246825, 4563246796, 4563246782, 4563246769, 4563246781, 4563246821, \
4563246823, 4563246827, 4563246827, 4563246827, 4563246791};

int main(void)
{
    size_t i;
    char undecyphered_char;

    for (i = 0; i < LEN(numbers); i++)
    {
        undecyphered_char = (char)((numbers[i] - SALT_2) ^ 97);

        printf("%c", undecyphered_char);
    }

    printf("\n");

    return 0;
}
```

Essentially what the author had done is, he took each character from this C script and assigned its ASCII value a certain RGB triplet. Then, in the same order as in the script, placed those in a file, and turned that into an actual PNG file. 

Very smart challenge, no clue how they come up with ideas like these xD.

### Author:
***th3mech4nic***
