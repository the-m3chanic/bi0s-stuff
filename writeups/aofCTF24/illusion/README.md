# illusion 

(**Author**: [hexamine22](https://github.com/hexamine22))

**quick walkthrough**:
[+] Parent process forks into child, child has a function for flag checking

[+] Viewing pseudocode alone is not very helpful for flag check function, viewing assembly shows different story (IDA optimisation)

[+] Parent has a `waitpid` call on the child, which returns a status as parameter signifying the current state of the child (in this case, whenever the child wants to send a signal, it is intercepted by this parent first through the call to `waitpid`)

[+] Parent makes some weird bitwise checks on the status received from child. Format of child is: `child_status >> 8 == signal_num`. (`status` is a 64 bit integer, of which 2nd lowest byte signifies signal of the child)

[+] If the signal received is `SEGMENTATION_FAULT`, the parent puts a random value inside `r8` (which is seeded with a known value), and increments `rip` by 8. We know the registers being manipulated because calling `ptrace` with `PTRACE_GETREGS` or `PTRACE_SETREGS` takes a structure as 4th argument, which if recovered in IDA will show the correct registers being manipulated. 

```
struct user_regs_struct
{
    unsigned long long int r15;
    unsigned long long int r14;
    unsigned long long int r13;
    unsigned long long int r12;
    unsigned long long int rbp;
    unsigned long long int rbx;
    unsigned long long int r11;
    unsigned long long int r10;
    unsigned long long int r9;
    unsigned long long int r8;
    unsigned long long int rax;
    unsigned long long int rcx;
    unsigned long long int rdx;
    unsigned long long int rsi;
    unsigned long long int rdi;
    unsigned long long int orig_rax;
    unsigned long long int rip;
    unsigned long long int cs;
    unsigned long long int eflags;
    unsigned long long int rsp;
    unsigned long long int ss;
    unsigned long long int fs_base;
    unsigned long long int gs_base;
    unsigned long long int ds;
    unsigned long long int es;
    unsigned long long int fs;
    unsigned long long int gs;
};
```

[+] We move on to the flag checking function inside child to see what could cause this segmentation fault, we notice instruction `mov rax, qword ptr ds:[0]`. And the random value put inside `r8` at this point by the parent is XORed with the byte we enter. 

[+] We can solve this in multiple ways - I did it in 2 ways: GDB scripting and emulation using Unicorn. Only the Unicorn script is attached. 

[+] Idea behind the script is we hook the instruction causing the segmentation fault, manually change register values, and continue execution. 