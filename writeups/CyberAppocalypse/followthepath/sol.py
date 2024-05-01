from capstone import * 
from unicorn import * 
from unicorn.x86_const import * 


cs = Cs(CS_ARCH_X86, CS_MODE_64)
emulator = Uc(UC_ARCH_X86, UC_MODE_64)
code = None 
disassembly = "" 
byteCount = 0
inpByte = ord('|')
flag = ""

baseAddr = 0x40000000
stackAddr = 0x10000000
progSize = 0x1000 * 0x1000 
stackSize = 0x1000 * 2


def checkIns(emulator, address, size, user_data):
    global disassembly, cs, byteCount, flag

    memory = emulator.mem_read(address, size)
    disassembly = next(cs.disasm(memory, size))

    # print(disassembly)

    # hook for instruction that moves our input byte into r8 
    if ("[r12 + rcx]" in str(disassembly)):
        # go to the next instruction, and place corresponding (dummy) input byte into r8
        rip = emulator.reg_read(UC_X86_REG_RIP) + 4
        emulator.reg_write(UC_X86_REG_RIP, rip)
        emulator.reg_write(UC_X86_REG_R8, inpByte)
    # hook for instructions that compare our input with the correct input
    elif ("cmp r8" in str(disassembly)):
        # read r8, get the value it is being xored with, and store, then increment rip to the next block, 
        # skipping past jumps as a result of comparison 
        r8 = emulator.reg_read(UC_X86_REG_R8)
        xorVal = disassembly.op_str.split(',')[1].strip()
        xorVal = int(xorVal, 16)
        correct = xorVal ^ r8 ^ inpByte
        flag += chr(correct)

        rip = emulator.reg_read(UC_X86_REG_RIP) + 16
        emulator.reg_write(UC_X86_REG_RIP, rip)


def initCode():
    global code 
    with open("code.bin", "rb") as f: 
        code = f.read()


def initEmulator():
    global emulator, cs 
    emulator.mem_map(baseAddr, baseAddr + progSize)
    emulator.mem_write(baseAddr, code)

    emulator.mem_map(stackAddr, stackSize)
    emulator.reg_write(UC_X86_REG_RSP, stackAddr + stackSize // 2)
    
    emulator.hook_add(UC_HOOK_CODE, checkIns)
    emulator.emu_start(baseAddr, baseAddr + len(code))

def main():
    initCode()
    initEmulator()

try:
    main()
except UcError as e:
    print(flag)
    print("[+] Finished")


