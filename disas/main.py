import argparse
import struct
import sys
import re


INSTRUCTIONS = [
    # Special: DSR Prefix Instructions
    ('11100011iiiiiiii', 'DSR<-', ['#{i}']),
    ('10010000dddd1111', 'DSR<-', ['R{d}']),
    ('1111111010011111', 'DSR<-', ['DSR']),

    # Arithmetic instructions
    ('1000nnnnmmmm0001', 'ADD', ['R{n}', 'R{m}']),
    ('0001nnnniiiiiiii', 'ADD', ['R{n}', '#{i}']),
    ('1111nnn0mmm00110', 'ADD', ['ER{n*2}', 'ER{m*2}']),
    ('1110nnn01iiiiiii', 'ADD', ['ER{n*2}', '#{i << 25 >> 25}']),
    ('1000nnnnmmmm0110', 'ADDC', ['R{n}', 'R{m}']),
    ('0110nnnniiiiiiii', 'ADDC', ['R{n}', '#{i}']),
    ('1000nnnnmmmm0010', 'AND', ['R{n}', 'R{m}']),
    ('0010nnnniiiiiiii', 'AND', ['R{n}', '#{i}']),
    ('1000nnnnmmmm0111', 'CMP', ['R{n}', 'R{m}']),
    ('0111nnnniiiiiiii', 'CMP', ['R{n}', '#{i}']),
    ('1000nnnnmmmm0101', 'CMPC', ['R{n}', 'R{m}']),
    ('0101nnnniiiiiiii', 'CMPC', ['R{n}', '#{i}']),
    ('1111nnn0mmm00101', 'MOV', ['ER{n*2}', 'ER{m*2}']),
    ('1110nnn00iiiiiii', 'MOV', ['ER{n*2}', '#{i}']),
    ('1000nnnnmmmm0000', 'MOV', ['R{n}', 'R{m}']),
    ('0000nnnniiiiiiii', 'MOV', ['R{n}', '#{i}']),
    ('1000nnnnmmmm0011', 'OR', ['R{n}', 'R{m}']),
    ('0011nnnniiiiiiii', 'OR', ['R{n}', '#{i}']),
    ('1000nnnnmmmm0100', 'XOR', ['R{n}', 'R{m}']),
    ('0100nnnniiiiiiii', 'XOR', ['R{n}', '#{i}']),
    ('1111nnn0mmm00111', 'CMP', ['ER{n*2}', 'ER{m*2}']),
    ('1000nnnnmmmm1000', 'SUB', ['R{n}', 'R{m}']),
    ('1000nnnnmmmm1001', 'SUBC', ['R{n}', 'R{m}']),

    # Shift Instructions
    ('1000nnnnmmmm1010', 'SLL', ['R{n}', 'R{m}']),
    ('1001nnnn0www1010', 'SLL', ['R{n}', '#{w}']),
    ('1000nnnnmmmm1011', 'SLLC', ['R{n}', 'R{m}']),
    ('1001nnnn0www1011', 'SLLC', ['R{n}', '#{w}']),
    ('1000nnnnmmmm1110', 'SRA', ['R{n}', 'R{m}']),
    ('1001nnnn0www1110', 'SRA', ['R{n}', '#{w}']),
    ('1000nnnnmmmm1100', 'SRL', ['R{n}', 'R{m}']),
    ('1001nnnn0www1100', 'SRL', ['R{n}', '#{w}']),
    ('1000nnnnmmmm1101', 'SRLC', ['R{n}', 'R{m}']),
    ('1001nnnn0www1101', 'SRLC', ['R{n}', '#{w}']),

    # Load/Store Instructions
    ('1001nnn000110010', 'L', ['ER{n*2}', '[EA]']),
    ('1001nnn001010010', 'L', ['ER{n*2}', '[EA+]']),
    ('1001nnn0mmm00010', 'L', ['ER{n*2}', '[ER{m*2}]']),
    ('1011nnn000DDDDDD', 'L', ['ER{n*2}', '{signedtohex(D, 6)}h[ER12]']),
    ('1011nnn001DDDDDD', 'L', ['ER{n*2}', '{signedtohex(D, 6)}h[ER14]']),
    ('1001nnnn00110000', 'L', ['R{n}', '[EA]']),
    ('1001nnnn01010000', 'L', ['R{n}', '[EA+]']),
    ('1001nnnnmmm00000', 'L', ['R{n}', '[ER{m*2}]']),
    ('1101nnnn00DDDDDD', 'L', ['R{n}', '{signedtohex(D, 6)}h[ER12]']),
    ('1101nnnn01DDDDDD', 'L', ['R{n}', '{signedtohex(D, 6)}h[ER14]']),
    ('1001nn0000110100', 'L', ['XR{n*4}', '[EA]']),
    ('1001nn0001010100', 'L', ['XR{n*4}', '[EA+]']),
    ('1001n00000110110', 'L', ['QR{n*8}', '[EA]']),
    ('1001n00001010110', 'L', ['QR{n*8}', '[EA+]']),
    ('1001nnn000110011', 'ST', ['ER{n*2}', '[EA]']),
    ('1001nnn001010011', 'ST', ['ER{n*2}', '[EA+]']),
    ('1001nnn0mmm00011', 'ST', ['ER{n*2}', '[ER{m*2}]']),
    ('1011nnn010DDDDDD', 'ST', ['ER{n*2}', '{signedtohex(D, 6)}h[ER12]']),
    ('1011nnn011DDDDDD', 'ST', ['ER{n*2}', '{signedtohex(D, 6)}h[ER14]']),
    ('1001nnnn00110001', 'ST', ['R{n}', '[EA]']),
    ('1001nnnn01010001', 'ST', ['R{n}', '[EA+]']),
    ('1001nnnnmmm00001', 'ST', ['R{n}', '[ER{m*2}]']),
    ('1101nnnn10DDDDDD', 'ST', ['R{n}', '{signedtohex(D, 6)}h[ER12]']),
    ('1101nnnn11DDDDDD', 'ST', ['R{n}', '{signedtohex(D, 6)}h[ER14]']),
    ('1001nn0000110101', 'ST', ['XR{n*4}', '[EA]']),
    ('1001nn0001010101', 'ST', ['XR{n*4}', '[EA+]']),
    ('1001n00000110111', 'ST', ['QR{n*8}', '[EA]']),
    ('1001n00001010111', 'ST', ['QR{n*8}', '[EA+]']),
    ('11100001iiiiiiii', 'ADD', ['SP', '#{signedtohex(i, 8)}']),
    ('10100000mmmm1111', 'MOV', ['ECSR', 'R{m}']),
    ('1010mmm000001101', 'MOV', ['ELR', 'ER{m*2}']),
    ('10100000mmmm1100', 'MOV', ['EPSW', 'R{m}']),
    ('1010nnn000000101', 'MOV', ['ER{n*2}', 'ELR']),
    ('1010nnn000011010', 'MOV', ['ER{n*2}', 'SP']),
    ('10100000mmmm1011', 'MOV', ['PSW', 'R{m}']),
    ('11101001iiiiiiii', 'MOV', ['PSW', '#{i}']),
    ('1010nnnn00000111', 'MOV', ['R{n}', 'ECSR']),
    ('1010nnnn00000100', 'MOV', ['R{n}', 'EPSW']),
    ('1010nnnn00000011', 'MOV', ['R{n}', 'PSW']),
    ('10100001mmm01010', 'MOV', ['SP', 'ER{m*2}']),

    # PUSH/POP Instructions
    ('1111nnn001011110', 'PUSH', ['ER{n*2}']),
    ('1111n00001111110', 'PUSH', ['QR{n*8}']),
    ('1111nnnn01001110', 'PUSH', ['R{n}']),
    ('1111nn0001101110', 'PUSH', ['XR{n*4}']),
    ('1111lep111001110', 'PUSH', ['{"LR, " if l==1 else ""}{"EPSW, " if e==1 else ""}{"ELR, " if p==1 else ""}EA']),
    ('1111le1011001110', 'PUSH', ['{"LR, " if l==1 else ""}{"EPSW, " if e==1 else ""}ELR']),
    ('1111l10011001110', 'PUSH', ['{"LR, " if l==1 else ""}EPSW']),
    ('1111100011001110', 'PUSH', ['LR']),
    ('1111nnn000011110', 'POP', ['ER{n*2}']),
    ('1111n00000111110', 'POP', ['QR{n*8}']),
    ('1111nnnn00001110', 'POP', ['R{n}']),
    ('1111nn0000101110', 'POP', ['XR{n*4}']),
    ('1111lep110001110', 'POP', ['{"LR, " if l==1 else ""}{"PSW, " if e==1 else ""}{"PC, " if p==1 else ""}EA']),
    ('1111le1010001110', 'POP', ['{"LR, " if l==1 else ""}{"PSW, " if e==1 else ""}PC']),
    ('1111l10010001110', 'POP', ['{"LR, " if l==1 else ""}PSW']),
    ('1111100010001110', 'POP', ['LR']),

    # Coprocessor Data Transfer Instructions
    ('1010nnnnmmmm1110', 'MOV', ['CR{n}', 'R{m}']),
    ('1111nnn000101101', 'MOV', ['CER{n*2}', '[EA]']),
    ('1111nnn000111101', 'MOV', ['CER{n*2}', '[EA+]']),
    ('1111nnnn00001101', 'MOV', ['CR{n}', '[EA]']),
    ('1111nnnn00011101', 'MOV', ['CR{n}', '[EA+]']),
    ('1111nn0001001101', 'MOV', ['CXR{n*4}', '[EA]']),
    ('1111nn0001011101', 'MOV', ['CXR{n*4}', '[EA+]']),
    ('1111n00001101101', 'MOV', ['CQR{n*8}', '[EA]']),
    ('1111n00001111101', 'MOV', ['CQR{n*8}', '[EA+]']),
    ('1010nnnnmmmm0110', 'MOV', ['R{n}', 'CR{m}']),
    ('1111mmm010101101', 'MOV', ['[EA]', 'CER{m*2}']),
    ('1111mmm010111101', 'MOV', ['[EA+]', 'CER{m*2}']),
    ('1111mmmm10001101', 'MOV', ['[EA]', 'CR{m}']),
    ('1111mmmm10011101', 'MOV', ['[EA+]', 'CR{m}']),
    ('1111mm0011001101', 'MOV', ['[EA]', 'CXR{m*4}']),
    ('1111mm0011011101', 'MOV', ['[EA+]', 'CXR{m*4}']),
    ('1111m00011101101', 'MOV', ['[EA]', 'CQR{m*8}']),
    ('1111m00011111101', 'MOV', ['[EA+]', 'CQR{m*8}']),

    # EA Register Data Transfer Instructions
    ('11110000mmm01010', 'LEA', ['[ER{m*2}]']),

    # ALU Instructions
    ('1000nnnn00011111', 'DAA', ['R{n}']),
    ('1000nnnn00111111', 'DAS', ['R{n}']),
    ('1000nnnn01011111', 'NEG', ['R{n}']),

    # Bit Access Instructions
    ('1010nnnn0bbb0000', 'SB', ['R{n}.{b}']),
    ('1010nnnn0bbb0010', 'RB', ['R{n}.{b}']),
    ('1010nnnn0bbb0001', 'TB', ['R{n}.{b}']),

    # PSW Access Instructions
    ('1110110100001000', 'EI', []),
    ('1110101111110111', 'DI', []),
    ('1110110110000000', 'SC', []),
    ('1110101101111111', 'RC', []),
    ('1111111011001111', 'CPLC', []),

    # Conditional Relative Branch Instructions
    ('11000000rrrrrrrr', 'BGE', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h']),
    ('11000001rrrrrrrr', 'BLT', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h']),
    ('11000010rrrrrrrr', 'BGT', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h']),
    ('11000011rrrrrrrr', 'BLE', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h']),
    ('11000100rrrrrrrr', 'BGES', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h']),
    ('11000101rrrrrrrr', 'BLTS', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h']),
    ('11000110rrrrrrrr', 'BGTS', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h']),
    ('11000111rrrrrrrr', 'BLES', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h']),
    ('11001000rrrrrrrr', 'BNE', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h']),
    ('11001001rrrrrrrr', 'BEQ', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h']),
    ('11001010rrrrrrrr', 'BNV', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h']),
    ('11001011rrrrrrrr', 'BOV', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h']),
    ('11001100rrrrrrrr', 'BPS', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h']),
    ('11001101rrrrrrrr', 'BNS', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h']),
    ('11001110rrrrrrrr', 'BAL', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h']),

    # Sign Extension Instruction
    ('1000mmm1nnn01111', 'EXTBW', ['ER{n*2}']),

    # Software Interrupt Instructions
    ('1110010100iiiiii', 'SWI', ['#{i}']),
    ('1111111111111111', 'BRK', []),

    #  Branch Instructions
    ('11110000nnn00010', 'B', ['ER{n*2}']),
    ('11110000nnn00011', 'BL', ['ER{n*2}']),

    # Multiplication and Division Instructions
    ('1111nnn0mmmm0100', 'MUL', ['ER{n*2}', 'R{m}']),
    ('1111nnn0mmmm1001', 'DIV', ['ER{n*2}', 'R{m}']),

    # Miscellaneous
    ('1111111000101111', 'INC', ['[EA]']),
    ('1111111000111111', 'DEC', ['[EA]']),
    ('1111111000011111', 'RT', []),
    ('1111111000001111', 'RTI', []),
    ('1111111010001111', 'NOP', []),

    # Load/Store Instructions
    ('EEEEEEEEDDDDDDDD1010nnn0mmm01000', 'L', ['ER{n*2}', '{tohex(E*256+D, 16)}h[ER{m*2}]']),
    ('EEEEEEEEDDDDDDDD1001nnn000010010', 'L', ['ER{n*2}', '0{tohex(E*256+D, 4)}h']),
    ('EEEEEEEEDDDDDDDD1001nnnnmmm01000', 'L', ['R{n}', '{tohex(E*256+D, 16)}h[ER{m*2}]']),
    ('EEEEEEEEDDDDDDDD1001nnnn00010000', 'L', ['R{n}', '0{tohex(E*256+D, 4)}h']),
    ('EEEEEEEEDDDDDDDD1010nnn0mmm01001', 'ST', ['ER{n*2}', '{tohex(E*256+D, 16)}h[ER{m*2}]']),
    ('EEEEEEEEDDDDDDDD1001nnn000010011', 'ST', ['ER{n*2}', '0{tohex(E*256+D, 4)}h']),
    ('EEEEEEEEDDDDDDDD1001nnnnmmm01001', 'ST', ['R{n}', '{tohex(E*256+D, 16)}h[ER{m*2}]']),
    ('EEEEEEEEDDDDDDDD1001nnnn00010001', 'ST', ['R{n}', '0{tohex(E*256+D, 4)}h']),

    # EA Register Data Transfer Instructions
    ('EEEEEEEEDDDDDDDD11110000mmm01011', 'LEA', ['{tohex(E*256+D, 16)}h[ER{m*2}]']),
    ('EEEEEEEEDDDDDDDD1111000000001100', 'LEA', ['0{tohex(E*256+D, 4)}h']),

    # Bit Access Instructions
    ('EEEEEEEEDDDDDDDD101000001bbb0000', 'SB', ['0{tohex(E*256+D, 4)}h.{b}']),
    ('EEEEEEEEDDDDDDDD101000001bbb0010', 'RB', ['0{tohex(E*256+D, 4)}h.{b}']),
    ('EEEEEEEEDDDDDDDD101000001bbb0001', 'TB', ['0{tohex(E*256+D, 4)}h.{b}']),

    # Branch Instructions
    ('DDDDDDDDCCCCCCCC1111gggg00000000', 'B', ['0{tohex(g, 1)}h:0{tohex(D*256+C, 4)}h']),
    ('DDDDDDDDCCCCCCCC1111gggg00000001', 'BL', ['0{tohex(g, 1)}h:0{tohex(D*256+C, 4)}h']),
]


class GadgetFinder:

    def __init__(self, binary):
        self.binary = binary
        self.offset = 0

    def match_pattern(self, inst, ptrn):
        inst = bin(inst)[2:].zfill(len(ptrn))
        args = {}

        # Go over the pattern
        for i in range(len(ptrn)):
            if ptrn[i] in '10':
                # Check if the constant is the same
                if ptrn[i] != inst[i]:
                    return None
            else:
                # Parse the variable
                if ptrn[i] not in args:
                    args[ptrn[i]] = ''
                args[ptrn[i]] += inst[i]

        # Parse the args to integers
        for arg in args:
            args[arg] = int(args[arg], 2)

        return args

    def get_next_word(self):
        value = struct.unpack_from("<H", self.binary, self.offset)[0]
        self.offset += 2
        return value

    def disasm(self):
        """
        Decodes an instruction into insn
        Returns: insn.size (=the size of the decoded instruction) or zero
        """

        pc = self.offset
        opcode = self.get_next_word()
        read_more = False

        for itype in range(len(INSTRUCTIONS)):
            ptrn, mnemonic, fmts = INSTRUCTIONS[itype]

            # Check if we need more
            if not read_more and len(ptrn) > 16:
                opcode = self.get_next_word() << 16 | opcode
                read_more = True

            # Try to parse
            args = self.match_pattern(opcode, ptrn)
            if args is None:
                continue

            # Parsed!
            def signedtohex(n, bitlen):
                bitlen -= 1
                is_pos = (n >> bitlen) == 0
                if not is_pos:
                    n = (2 << bitlen) - n
                retval = ''
                for x in range(bitlen):
                    retval = '0123456789abcdef'[n & 0xF] + retval
                    n >>= 4
                return retval if is_pos else '-' + retval

            oprs = []

            # resolve args
            args['signed'] = lambda x: struct.unpack('<b', struct.pack('<B', x))[0]
            args['tohex'] = lambda x, y: hex(x)[2:].zfill(y)
            args['signedtohex'] = signedtohex
            args['pc'] = pc
            for i in range(len(fmts)):
                # Resolve it
                opr = re.sub('{(.*?)}', lambda m: str(eval(m.group(1), args)), fmts[i])
                opr = opr.replace('Lh', 'h')
                oprs.append(opr)

            # We done here
            return pc, mnemonic, tuple(oprs)

        # Don't skip two instructions, only skip one
        self.offset -= 2
        return None

    def disasm_all(self):
        insts = []
        while self.offset < len(self.binary):
            insts.append(self.disasm())
        return insts

    def find_gadgets(self):
        print("Disasming everything")
        insts = self.disasm_all()

        found_normal = {}
        found_link = {}

        print("Searching for gadgets")
        i = 0
        while i < len(insts):
            if insts[i] is None:
                i += 1
                continue

            pc, mnemonic, oprs = insts[i]

            # These are not useful for us
            if pc < 0x1000 or pc > 0x1ffff:
                i += 1
                continue

            #
            # Normal gadgets
            #
            if mnemonic == 'POP' and oprs[0] == 'PC':
                if insts[i - 1] is not None:
                    full = (insts[i - 1][1], insts[i - 1][2])

                    # Add to the list
                    found_normal[full] = insts[i - 1][0]

                    # If found a link version we can remove it because we prefer
                    # non-link gadgets
                    if full in found_link:
                        del found_link[full]
                
            #
            # Link based gadgets
            #
            elif mnemonic == 'RT':
                if insts[i - 1] is not None:
                    full = (insts[i - 1][1], insts[i - 1][2])

                if full not in found_normal:
                    found_link[full] = insts[i - 1][0]

            i += 1

        return found_normal, found_link
        

def write_gadgets(gadgets, out):
    """
    Write gadgets in a sorted manner
    """
    things = []
    for gad in gadgets:
        things.append((hex(gadgets[gad]), gad))

    for i in sorted(things, key=lambda x: x[1]):
        out.write(i[0] + ' ' + i[1][0] + ' ' + ', '.join(i[1][1]))
        out.write('\n')


def parse_args():
    parser = argparse.ArgumentParser(description='Disassembler and Gadget finder for nX-U8/100')
    parser.add_argument('-i', '--input', type=str, required=True, help='The input file')
    parser.add_argument('-o', '--output', type=str, help='The output file (stdout if not specified)')
    parser.add_argument('--find-gadgets', action='store_true', help="Output a gadget file instead of full disasm")
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()

    # Fully read it 
    rom = open(args.input, 'rb').read()
    gad = GadgetFinder(rom)

    # Open the output 
    if args.output is not None:
        out = open(args.output, 'w')
    else:
        out = sys.stdout

    # Either find gadgets or do this
    if args.find_gadgets:
        normal_gad, link_gad = gad.find_gadgets()
        out.write('# POP PC\n')
        write_gadgets(normal_gad, out)
        out.write('#######################################\n')
        out.write('# RT\n')
        write_gadgets(link_gad, out)
    else:
        for pc, mnemonic, oprs in gad.disasm_all():
            if mnemonic is None:
                out.write(hex(pc) + '\n')
                out.write(hex(pc + 1) + '\n')
            else:
                out.write(hex(pc) + ' ' + mnemonic + ' ' + ', '.join(oprs) + '\n')
