import argparse
import struct
import sys
import os

sys.path.insert(1, os.path.join(os.path.dirname(__file__), '..', 'disas'))
from disas import GadgetFinder


class GadgetEmulator:
    """
    This is not a true emulator, but a dummy one that can mostly run gadgets, 
    this is helpful to create new gadgets for the ropcc
    """

    def __init__(self, rom, step=False) -> None:
        self._dis = GadgetFinder(rom)

        self._step = step

        # General purpose regs
        self._regs = bytearray(b'\x00' * 16)
        self._sp = 0

        # The ram range
        self._ram = bytearray(b'\x00' * int(0xE00))

        # flags
        self._c = 0
        self._z = 0
        self._s = 0
        self._ov = 0
        self._hv = 0

        # link 
        self._lr = 0
        self._lcsr = 0

    def reg_size(self, r: str):
        if r.startswith('QR'):
            return 8
        elif r.startswith('XR'):
            return 4
        elif r.startswith('ER'):
            return 2
        elif r.startswith('R'):
            return 1
        elif r in ['PC', 'LR', 'SP']:
            return 2
        else:
            assert False, f"Invalid register {r}"

    def read_reg(self, r: str) -> int:
        if r.startswith('QR'):
            return struct.unpack_from('<Q', self._regs, int(r[2:]))[0]
        elif r.startswith('XR'):
            return struct.unpack_from('<I', self._regs, int(r[2:]))[0]
        elif r.startswith('ER'):
            return struct.unpack_from('<H', self._regs, int(r[2:]))[0]
        elif r.startswith('R'):
            return struct.unpack_from('<B', self._regs, int(r[1:]))[0]
        elif r == 'PC':
            return self._dis.offset & 0xFFFF
        elif r == 'CSR':
            return self._dis.offset >> 16
        elif r == 'LR':
            return self._lr
        elif r == 'LCSR':
            return self._lcsr
        elif r == 'SP':
            return self._sp
        else:
            assert False, f"Invalid register {r}"

    def write_reg(self, r: str, value: int):
        if r.startswith('QR'):
            struct.pack_into('<Q' if value >= 0 else '<q', self._regs, int(r[2:]), value)
        elif r.startswith('XR'):
            struct.pack_into('<I' if value >= 0 else '<i', self._regs, int(r[2:]), value)
        elif r.startswith('ER'):
            struct.pack_into('<H' if value >= 0 else '<h', self._regs, int(r[2:]), value)
        elif r.startswith('R'):
            struct.pack_into('<B' if value >= 0 else '<b', self._regs, int(r[1:]), value)
        elif r == 'PC':
            self._dis.offset &= ~0xFFFF
            self._dis.offset |= (value & ~1) & 0xFFFF
        elif r == 'CSR':
            self._dis.offset &= 0xFFFF
            self._dis.offset |= (1 if (value & 1) else 0) << 16
        elif r == 'LCSR':
            self._lcsr = value & 1
        elif r == 'LR':
            self._lr = value & 0xFFFF
        elif r == 'SP':
            self._sp = value & 0xFFFF
        else:
            assert False, f"Invalid register {r}"

    def read_mem(self, addr: int) -> int:
        if 0x0000 <= addr < 0x8000:
            # Rom window
            return self._dis.binary[addr]
        elif 0x8000 <= addr < 0x8E00:
            # Ram area
            return self._ram[addr - 0x8000]
        elif 0x8E00 <= addr < 0xF000:
            # Unmapped area
            return 0x00
        elif 0xF000 <= addr < 0x10000:
            # SFR range
            assert False, "SFR Not implemented"
        else:
            # The rest is part of the image
            return self._dis.binary[addr]

    def read_int(self, addr: int, size: int) -> int:
        byts = ''
        for i in range(size):
            byts = hex(self.read_mem(addr + i))[2:].zfill(2) + byts
        return int(byts, 16)

    def write_mem(self, addr: int, value: int):
        # Can only write to ram, all other writes are invalid
        if 0x8000 <= addr < 0x8E00:
            self._ram[addr - 0x8000] = value
        else:
            assert False, f"attempted to write to invalid range {addr}"

    def eval_opr(self, opr: str) -> int:
        if opr.startswith('#'):
            return int(opr[1:])
        else:
            return self.read_reg(opr)

    def update_flags(self, res: int, bits: int, flags='zcso'):
        if 'z' in flags:
            self._z = res == 0
        if 'c' in flags:
            self._c = (res & (1 << bits)) != 0
        if 's' in flags:
            self._s = (res & (1 << (bits - 1))) != 0
        if 'o' in flags:
            self._ov = res >= (1 << bits)
        return res
    
    def step(self):
        pc, mnemonic, oprs = self._dis.disasm()
        self.eval_inst(pc, mnemonic, oprs)

    def eval_inst(self, pc, mnemonic, oprs):
        
        if self._step:
            print(hex(pc) + ': ' + mnemonic + ' ' + ', '.join(oprs))
            self.show()
            import ipdb; ipdb.set_trace()

        if mnemonic == 'ADD':
            op1 = self.eval_opr(oprs[0])
            op2 = self.eval_opr(oprs[1])
            res = op1 + op2
            self.update_flags(res, self.reg_size(oprs[0]) * 8)
            self.write_reg(oprs[0], res)

        elif mnemonic == 'SUB':
            op1 = self.eval_opr(oprs[0])
            op2 = self.eval_opr(oprs[1])
            res = op1 - op2
            self.update_flags(res, self.reg_size(oprs[0]) * 8)
            self.write_reg(oprs[0], res)

        elif mnemonic == 'MUL':
            op1 = self.eval_opr(oprs[0])
            op2 = self.eval_opr(oprs[1])
            res = op1 * op2
            self.update_flags(res, self.reg_size(oprs[0]) * 8)
            self.write_reg(oprs[0], res)

        elif mnemonic == 'DIV':
            op1 = self.eval_opr(oprs[0])
            op2 = self.eval_opr(oprs[1])
            res = op1 // op2
            self.update_flags(res, self.reg_size(oprs[0]) * 8)
            self.write_reg(oprs[0], res)

        elif mnemonic == 'POP':
            size = self.reg_size(oprs[0])
            value = self.read_int(self._sp, size)
            self.write_reg(oprs[0], value)
            self._sp += size

            if oprs[0] == 'PC':
                # also pop the csr
                value = self.read_mem(self._sp)
                self.write_reg('CSR', value)
                self._sp += 2
            
        elif mnemonic == 'CMP':
            op1 = self.eval_opr(oprs[0])
            op2 = self.eval_opr(oprs[1])
            self.update_flags(op1 - op2, self.reg_size(oprs[0]) * 8)

        elif mnemonic == 'ADDC':
            op1 = self.eval_opr(oprs[0])
            op2 = self.eval_opr(oprs[1])
            res = op1 + op2 + self._c
            self.update_flags(res, self.reg_size(oprs[0]) * 8)
            self.write_reg(oprs[0], res)

        elif mnemonic == 'SUBC':
            op1 = self.eval_opr(oprs[0])
            op2 = self.eval_opr(oprs[1])
            res = op1 - op2 - self._c
            self.update_flags(res, self.reg_size(oprs[0]) * 8)
            self.write_reg(oprs[0], res)

        elif mnemonic == 'CMPC':
            op1 = self.eval_opr(oprs[0])
            op2 = self.eval_opr(oprs[1])
            self.update_flags(op1 - op2 - self._c, self.reg_size(oprs[0]) * 8)

        elif mnemonic == 'BL':
            addr = self.eval_opr(oprs[0])

            # Save
            self.write_reg('LR', self.read_reg('PC'))
            self.write_reg('LCSR', self.read_reg('CSR'))

            # Write pc and csr
            self.write_reg('PC', addr)

            if oprs[0].endswith('h'):
                assert False, "Jump"

        elif mnemonic == 'RT':
            self.write_reg('CSR', self.read_reg('LCSR'))
            self.write_reg('PC', self.read_reg('LR'))

        elif mnemonic == 'NEG':
            op1 = self.eval_opr(oprs[0])
            op1 = (0 - op1) & 0xFF
            self.update_flags(op1, self.reg_size(oprs[0]))
            self.write_reg(oprs[0], op1)

        elif mnemonic == 'BRK':
            self.show()
            exit(0)

        elif mnemonic == 'MOV':
            op2 = self.eval_opr(oprs[1])
            self.write_reg(oprs[0], op2)
            self.update_flags(op2, self.reg_size(oprs[0]), 'zs') 

        elif mnemonic == 'ST':
            op1 = self.eval_opr(oprs[0])
            op2 = self.eval_opr(oprs[1][1:-1])
            size = self.reg_size(oprs[0])
            for _ in range(size):
                self.write_mem(op2, op1 & 0xFF)
                op1 >>= 8
                op2 += 1

        else:
            assert False, f"Unimplemented instruction {mnemonic}"

    def test_gadget(self, stack):
        # Init SP from the initial stack of the rom
        self._sp = self.read_int(0x0000, 2)

        # Push everything to the stack
        for val in stack:
            self._sp -= 1
            self.write_mem(self._sp, val)

        # Do the initial pop pc so we start the rop
        self.eval_inst(0, 'POP', ['PC'])

        # Let the user do whatever
        while True:
            self.step()

    def show(self):
        s = ''
        s += f'PC = {hex(self.read_reg("PC"))} | CSR = {self.read_reg("CSR")}\n'
        s += f'LR = {hex(self.read_reg("LR"))} | LCSR = {self.read_reg("LCSR")}\n'
        s += f'C = {self._c} | Z = {self._z} | S = {self._s} | OV = {self._ov} | HV = {self._hv}\n'
        for i in range(4):
            for j in range(4):
                s += f'R{i * 4 + j} = {hex(self.eval_opr(f"R{i * 4 + j}"))[2:].zfill(2)} '
            s += '\n'
        s += f'SP = {hex(self._sp)}\n'
        for i in range(-4, 2):
            addr = self._sp - i * 4
            s += f'\t{">" if i == 0 else " "} {hex(addr)}: {hex(self.read_int(addr, 4))[2:].zfill(8)}\n'
        print(s)
            

def parse_args():
    parser = argparse.ArgumentParser(description='Rop gadget debugger')
    parser.add_argument('-i', '--input', type=str, required=True, help='The rom file')
    parser.add_argument('-r', '--rop', type=str, help='The rop as hex')
    parser.add_argument('-s', '--step', action='store_true', help='Should ipdb be activated per step')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()

    # Fully read it 
    rom = open(args.input, 'rb').read()
    gad = GadgetEmulator(rom, step=args.step)

    if args.rop is None:
        rop = sys.stdin.read().strip()
    else:
        rop = args.rop

    gad.test_gadget(bytes.fromhex(rop))
