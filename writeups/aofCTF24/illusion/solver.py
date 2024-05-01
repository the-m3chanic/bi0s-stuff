from unicorn import * 
from unicorn.x86_const import * 
from random_values import random_values 
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


cs = Cs(CS_ARCH_X86, CS_MODE_64)
emulator = Uc(UC_ARCH_X86, UC_MODE_64)
stack_code = None
logic_code = None

disassembly = ""
curr_byte = 0

ADDR = 0X400000
STACK = 0X100000

STACK_SIZE = 2 * 0X1000 
MEM_SIZE = 0X1000 * 0X1000


def check_ins(emulator, address, size, user_data):
	global cs, disassembly, curr_byte
	memory = emulator.mem_read(address, size)
	disassembly = next(cs.disasm(memory, address))

	# print(disassembly)
	
	# skip the instruction if it causes a segfault 
	if ("mov rax, qword ptr [0]" in str(disassembly)): # segfault instruction where we need to act as parent 
		next_ins = emulator.reg_read(UC_X86_REG_RIP) + 8
		emulator.reg_write(UC_X86_REG_RIP, next_ins)
		rand = random_values[curr_byte]
		emulator.reg_write(UC_X86_REG_R8, rand)
		curr_byte += 1
	elif ("movzx eax, byte ptr [rax]" in str(disassembly)):
		next_ins = emulator.reg_read(UC_X86_REG_RIP) + 3
		emulator.reg_write(UC_X86_REG_RIP, next_ins)
		emulator.reg_write(UC_X86_REG_RAX, ord('|'))
	elif ("cmp edx, eax" in str(disassembly)):
		next_ins = emulator.reg_read(UC_X86_REG_RIP) + 11
		emulator.reg_write(UC_X86_REG_RIP, next_ins)
		edx = emulator.reg_read(UC_X86_REG_EDX)
		eax = emulator.reg_read(UC_X86_REG_EAX)
		print(chr(edx ^ eax ^ ord('|')), end = "")


def init_code():
	global stack_code, logic_code
	with open("code.bin", "rb") as f:
		stack_code = f.read()
    
	with open("code2.bin", "rb") as f:
		logic_code = f.read()




# function to initialise the emulator stack with the needed xor values 
def init_emu():
	global emulator
	emulator.mem_map(ADDR, MEM_SIZE)
	emulator.mem_write(ADDR, stack_code)
	emulator.mem_map(STACK, STACK_SIZE)

	emulator.reg_write(UC_X86_REG_RSP, STACK + STACK_SIZE//2)
	emulator.reg_write(UC_X86_REG_RBP, STACK + STACK_SIZE//2 + 448)

	emulator.hook_add(UC_HOOK_CODE, check_ins)
	emulator.emu_start(ADDR, ADDR + len(stack_code))
	

def add_logic():
	global emulator
	emulator.mem_write(ADDR + len(stack_code), logic_code)
	emulator.emu_start(ADDR, ADDR + len(logic_code))


def main():
	init_code()
	init_emu()
	add_logic()

try:
	main()
except UcError as e:
	print(f"\n[+] Finished")

