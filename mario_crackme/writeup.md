
opened the binary in ida

looked at the flow of the main function, immediately noticed some symbols, so i took a look at the pseudocode

changed up some variable names to make stuff more readable, then saw a couple of conditions:
```
if ( strlen(password) != 9 || password[4] != 45 )
```
meaning password had to be 9 chars long and 4th char had to be '-'

similarly, 
```
if ( password[i] == 64 )
```
tried putting the first char as a '@', and 4th as a '-', worked

