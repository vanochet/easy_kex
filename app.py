from dataclass import Dataclass
from pyautogui import alert
from unicorn import *
from unicorn.x86_const import *
from capstone import *
import struct


md = Cs(CS_ARCH_X86, CS_MODE_64)


def u32(data):
    return struct.unpack("I", data)[0]


def p32(num):
    return struct.pack("I", num)


def hook_code(_mu, address, size, _user_data):
    print('>>> Tracing instruction at 0x%x, instruction size = %d, value = %s'
          % (address+36, size, bytes(_user_data[0][address+36:][:size]).hex()))


def read_string(uc, address):
    ret = ""
    c = uc.mem_read(address, 1)[0]
    read_bytes = 1

    while c != 0x0:
        ret += chr(c)
        c = uc.mem_read(address + read_bytes, 1)[0]
        read_bytes += 1
    return ret


def hook_intr(uc, intno, _user_data):
    # only handle Linux syscall
    if intno != 0x80:
        print("got interrupt %x ???" % intno)
        uc.emu_stop()
        return

    eax = uc.reg_read(UC_X86_REG_EAX)
    eip = uc.reg_read(UC_X86_REG_EIP)

    if eax == 1:    # sys_exit
        print(">>> 0x%x: interrupt 0x%x, EAX = 0x%x" % (eip, intno, eax))
        uc.emu_stop()
    elif eax == 4:    # sys_write
        # ECX = buffer address
        ecx = uc.reg_read(UC_X86_REG_ECX)
        # EDX = buffer size
        edx = uc.reg_read(UC_X86_REG_EDX)
        try:
            buf = uc.mem_read(ecx, edx)
            print(">>> 0x%x: interrupt 0x%x, SYS_WRITE. buffer = 0x%x, size = %u, content = "
                  % (eip, intno, ecx, edx), end="")
            for i in buf:
                print("%c" % i, end="")
            print("")
        except UcError:
            print(">>> 0x%x: interrupt 0x%x, SYS_WRITE. buffer = 0x%x, size = %u, content = <unknown>\n"
                  % (eip, intno, ecx, edx))
    elif eax == 11:  # sys_write
        ebx = uc.reg_read(UC_X86_REG_EBX)
        filename = read_string(uc, ebx)
        print(">>> SYS_EXECV filename=%s" % filename)
    else:
        print(">>> 0x%x: interrupt 0x%x, EAX = 0x%x" % (eip, intno, eax))


class App:
    sysdata: Dataclass
    raw: bytes

    entry: int
    stack_top_orig: int
    stack_top: int
    mem: int
    iend: int
    code: bytes

    mu: Uc

    def __init__(self, data: Dataclass):
        self.sysdata = data

    def start(self):
        self.parse()
        self.exec()

    def exec(self):
        self.mu = Uc(UC_ARCH_X86, UC_MODE_32)
        self.mu.mem_map(0, self.mem)
        self.mu.mem_write(36, self.code)
        self.mu.reg_write(UC_X86_REG_RSP, self.stack_top)
        self.mu.reg_write(UC_X86_REG_RIP, self.entry)
        self.mu.hook_add(UC_HOOK_CODE, hook_code, user_data=[self.raw])
        self.mu.hook_add(UC_HOOK_INTR, hook_intr)
        for i in md.disasm(self.code, 36):
            print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        try:
            self.mu.emu_start(0, len(self.raw))
        except UcError:
            print("}}} cpu error")

    def parse(self):
        with open(self.sysdata.__file__, "rb") as f:
            self.raw = f.read()

        raw_header = self.raw[:36]

        if raw_header[:12] != b"MENUET01\x01\x00\x00\x00":
            alert(title="Error", text="not a kex file")

        self.entry = int.from_bytes(self.raw[12:][:4], 'little')
        self.iend = int.from_bytes(self.raw[16:][:4], 'little')
        self.mem = int.from_bytes(self.raw[20:][:4], 'little')
        self.stack_top = self.stack_top_orig = int.from_bytes(self.raw[24:][:4], 'little')
        self.code = self.raw[36:][:self.iend-36]
