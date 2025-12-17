import ida_ua
import ida_idp
import ida_nalt
import ida_lines
import ida_segregs

from patching.util.ida import *
import patching.keystone as keystone

TEST_KS_RESOLVER = False

class KeystoneAssembler(object):
    """
    An abstraction of a CPU-specific fixup layer to wrap Keystone.
    """

    # the mnemonic for an unconditional jump
    UNCONDITIONAL_JUMP = NotImplementedError

    # the list of known conditional jump mnemonics
    CONDITIONAL_JUMPS = []

    # a list of mnemonics that we KNOW are currently unsupported
    UNSUPPORTED_MNEMONICS = []

    # the number of instruction bytes to show in the patch preview pane
    MAX_PREVIEW_BYTES = 4

    _NO_OP_TYPE = ida_nalt.printop_t()

    def __init__(self, arch, mode):
        assert self.UNCONDITIONAL_JUMP != NotImplementedError, "Incomplete Assembler Implementation"

        self._arch = arch
        self._mode = mode
        self._ks = keystone.Ks(arch, mode)

        if TEST_KS_RESOLVER:
            self._ks.sym_resolver = self._ks_sym_resolver

        # Best-effort cache of NOP bytes (not all arch support "nop")
        self._NOP_BYTES = None
        self._NOP_SIZE = 0
        try:
            nb, _ = self._ks.asm('nop', as_bytes=True)
            if nb:
                self._NOP_BYTES = nb
                self._NOP_SIZE = len(nb)
        except Exception:
            self._NOP_BYTES = None
            self._NOP_SIZE = 0

    def _ks_sym_resolver(self, symbol, value):
        symbol = symbol.decode('utf-8')

        if 'AT_SPECIAL_AT' in symbol:
            symbol = symbol.replace('AT_SPECIAL_AT', '@')
        if 'QU_SPECIAL_QU' in symbol:
            symbol = symbol.replace('QU_SPECIAL_QU', '?')

        for sym_value, sym_real_name in resolve_symbol(self._ks_address, symbol):
            value[0] = sym_value
            return True

        return False

    def rewrite_symbols(self, assembly, ea):
        mnem, sep, ops = assembly.partition(' ')

        if mnem in KNOWN_PREFIXES:
            real_mnem, sep, ops = ops.partition(' ')
            mnem += ' ' + real_mnem

        symbols = scrape_symbols(ops)

        if len(symbols) > 10:
            print("Aborting symbol re-writing, too (%u) many potential symbols..." % (len(symbols)))
            return assembly

        prev_index = 0
        new_ops = ''

        for name, location in symbols:
            sym_start, sym_end = location

            for sym_value, sym_real_name in resolve_symbol(ea, name):
                sym_value_text = '0x%X' % sym_value
                new_ops += ops[prev_index:sym_start] + sym_value_text
                prev_index = sym_end
                break
            else:
                continue

        new_ops += ops[prev_index:]
        raw_assembly = mnem + sep + new_ops
        return raw_assembly

    def asm(self, assembly, ea=0, resolve=True):
        unaliased_assembly = self.unalias(assembly)

        if TEST_KS_RESOLVER:
            raw_assembly = unaliased_assembly
            raw_assembly = raw_assembly.replace('@', 'AT_SPECIAL_AT')
            raw_assembly = raw_assembly.replace('?', 'QU_SPECIAL_QU')
            self._ks_address = ea
        elif resolve:
            raw_assembly = self.rewrite_symbols(unaliased_assembly, ea)
        else:
            raw_assembly = unaliased_assembly

        try:
            asm_bytes, count = self._ks.asm(raw_assembly, ea, True)
            if asm_bytes is None:
                return bytes()
        except Exception:
            return bytes()

        return asm_bytes

    def is_conditional_jump(self, mnem):
        return bool(mnem.upper() in self.CONDITIONAL_JUMPS)

    def nop_buffer(self, start_ea, end_ea):
        """
        Generate a NOP buffer for the given address range.
        NOTE: for fixed-width ISAs user selection should normally be aligned;
              but we still fill full byte range to match UX expectations.
        """
        range_size = end_ea - start_ea
        if range_size <= 0:
            return bytes()

        nop_data = self._NOP_BYTES
        if not nop_data:
            nop_data = self.asm('nop', start_ea)

        if not nop_data:
            # last-resort: byte fill
            return b'\x00' * range_size

        nop_size = len(nop_data)
        count = (range_size + nop_size - 1) // nop_size
        return (nop_data * count)[:range_size]

    #--------------------------------------------------------------------------
    # Assembly Normalization
    #--------------------------------------------------------------------------

    def format_prefix(self, insn, prefix):
        return prefix

    def format_mnemonic(self, insn, mnemonic):
        return mnemonic

    def format_memory_op(self, insn, n):
        op_text = ida_ua.print_operand(insn.ea, n, 0, self._NO_OP_TYPE)
        return op_text

    def format_imm_op(self, insn, n):
        return ida_ua.print_operand(insn.ea, n)

    def format_assembly(self, ea):
        prefix, mnem, _ = get_disassembly_components(ea)
        if mnem is None:
            return ''

        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, ea)

        ops = []
        op_text = ''

        for op in insn.ops:
            if op.type in [ida_ua.o_reg, ida_ua.o_far, ida_ua.o_near]:
                op_text = ida_ua.print_operand(ea, op.n)
            elif op.type == ida_ua.o_void:
                break
            elif op.type in [ida_ua.o_displ, ida_ua.o_phrase]:
                op_text = ida_ua.print_operand(ea, op.n, 0, self._NO_OP_TYPE)
            elif op.type == ida_ua.o_imm:
                op_text = self.format_imm_op(insn, op.n)
            elif op.type == ida_ua.o_mem:
                op_text = self.format_memory_op(insn, op.n)
            else:
                op_text = ida_ua.print_operand(ea, op.n)

            if not (op.flags & ida_ua.OF_SHOW):
                continue

            ops.append(op_text)

        ops = list(map(ida_lines.tag_remove, filter(None, ops)))
        prefix = self.format_prefix(insn, prefix)
        mnem = self.format_mnemonic(insn, mnem)

        if prefix:
            mnem = prefix + ' ' + mnem

        text = '%s %s' % (mnem.ljust(7, ' '), ', '.join(ops))

        for banned in ['[offset ', '(offset ', ' offset ', ' short ', ' near ptr ', ' far ptr ', ' large ']:
            text = text.replace(banned, banned[0])

        return text.strip()

    def unalias(self, assembly):
        return assembly


#------------------------------------------------------------------------------
# x86 / x86_64
#------------------------------------------------------------------------------

class AsmX86(KeystoneAssembler):
    UNCONDITIONAL_JUMP = 'JMP'
    CONDITIONAL_JUMPS = [
        'JZ', 'JE', 'JNZ', 'JNE', 'JC', 'JNC',
        'JO', 'JNO', 'JS', 'JNS', 'JP', 'JPE',
        'JNP', 'JPO', 'JCXZ', 'JECXZ', 'JRCXZ',
        'JG', 'JNLE', 'JGE', 'JNL', 'JL', 'JNGE',
        'JLE', 'JNG', 'JA', 'JNBE', 'JAE', 'JNB',
        'JB', 'JNAE', 'JBE', 'JNA'
    ]
    UNSUPPORTED_MNEMONICS = [
        'ENDBR32', 'ENDBR64',
        'RDSSPD', 'RDSSPQ',
        'INCSSPD', 'INCSSPQ',
        'SAVEPREVSSP', 'RSTORSSP',
        'WRSSD', 'WRSSQ', 'WRUSSD', 'WRUSSQ',
        'SETSSBSY', 'CLRSSBSY',
        'MONITOR', 'MWAIT', 'MONITORX', 'MWAITX',
        'INVPCID',
        'REPE CMPSW',
    ]

    def __init__(self):
        arch = keystone.KS_ARCH_X86

        if ida_ida.inf_is_64bit():
            mode = keystone.KS_MODE_64
            self.MAX_PREVIEW_BYTES = 7
        elif ida_ida.inf_is_32bit_exactly():
            mode = keystone.KS_MODE_32
            self.MAX_PREVIEW_BYTES = 6
        else:
            mode = keystone.KS_MODE_16

        super(AsmX86, self).__init__(arch, mode)

    def format_mnemonic(self, insn, mnemonic):
        original = mnemonic.strip()
        mnemonic_u = original.upper()

        if mnemonic_u == 'RETN':
            return 'ret'
        if mnemonic_u == 'XLAT':
            return 'xlatb'

        return original

    def format_memory_op(self, insn, n):
        op_text = super(AsmX86, self).format_memory_op(insn, n)
        op_text = ida_lines.tag_remove(op_text)

        if '[' not in op_text:
            start, sep, remaining = op_text.partition(':')
            if sep and remaining and remaining[0] != ':':
                op_text = start + sep + '[' + remaining + ']'
            elif ' ptr ' in op_text:
                start, sep, remaining = op_text.partition(' ptr ')
                op_text = start + sep + '[' + remaining + ']'
            else:
                op_text = '[' + op_text + ']'

        if ' ptr ' in op_text and self._mode is keystone.KS_MODE_32:
            return op_text

        op = insn.ops[n]
        seg_reg = (op.specval & 0xFFFF0000) >> 16

        if seg_reg:
            seg_reg_name = ida_idp.ph.regnames[seg_reg]
            if seg_reg_name == 'cs':
                op_text = op_text.replace('cs:', '')
            elif seg_reg_name not in op_text:
                op_text = '%s:%s' % (seg_reg_name, op_text)

        if ' ptr ' in op_text:
            return op_text

        t_name = get_dtype_name(op.dtype, ida_ua.get_dtype_size(op.dtype))
        op_text = '%s ptr %s' % (t_name, op_text)
        return op_text

    def format_imm_op(self, insn, n):
        op_text = super(AsmX86, self).format_imm_op(insn, n)
        if '$+' in op_text:
            op_text = ida_ua.print_operand(insn.ea, n, 0, self._NO_OP_TYPE)
        return op_text

    def unalias(self, assembly):
        parts = list(filter(None, assembly.lower().split(' ')))
        full = ' '.join(parts)
        if not full:
            return assembly

        if full == 'int 3':
            return 'int3'

        if parts[-1] == 'movsd':
            if self._mode & keystone.KS_MODE_64:
                regs = ('rdi', 'rsi')
            else:
                regs = ('edi', 'esi')
            return assembly + ' dword ptr [%s], dword ptr [%s]' % regs

        return assembly


#------------------------------------------------------------------------------
# ARM / ARM64
#------------------------------------------------------------------------------

class AsmARM(KeystoneAssembler):
    UNCONDITIONAL_JUMP = 'B'
    CONDITIONAL_JUMPS = [
        # ARM
        'BEQ', 'BNE', 'BCC', 'BCS', 'BVC', 'BVS',
        'BMI', 'BPL', 'BHS', 'BLO', 'BHI', 'BLS',
        'BGE', 'BLT', 'BGT', 'BLE',
        # ARM64
        'B.EQ', 'B.NE', 'B.CS', 'B.CC', 'B.MI', 'B.PL',
        'B.VS', 'B.VC', 'B.HI', 'B.LS', 'B.GE', 'B.LT',
        'B.GT', 'B.LE', 'CBNZ', 'CBZ', 'TBZ', 'TBNZ'
    ]
    UNSUPPORTED_MNEMONICS = [
        'ADR', 'ADRL',
        'AUTDA', 'AUTDZA', 'AUTDB', 'AUTDZB',
        'AUTIA', 'AUTIA1716', 'AUTIASP', 'AUTIAZ', 'AUTIZA',
        'AUTIB', 'AUTIB1716', 'AUTIBSP', 'AUTIBZ', 'AUTIZB',
        'BLRAA', 'BLRAAZ', 'BLRAB', 'BLRABZ',
        'BRAA',  'BRAAZ', 'BRAB', 'BRABZ',
        'PACDA', 'PACDZA', 'PACDB', 'PACDZB', 'PACGA',
        'PACIA', 'PACIA1716', 'PACIASP', 'PACIAZ', 'PACIZA',
        'PACIB', 'PACIB1716', 'PACIBSP', 'PACIBZ', 'PACIZB',
        'RETAA', 'RETAB',
        'XPACD', 'XPACI', 'XPACLRI'
    ]

    def __init__(self):
        if ida_ida.inf_is_64bit():
            arch = keystone.KS_ARCH_ARM64
            mode = keystone.KS_MODE_BIG_ENDIAN if ida_ida.inf_is_be() else keystone.KS_MODE_LITTLE_ENDIAN
            self._ks_thumb = None
        else:
            arch = keystone.KS_ARCH_ARM
            if ida_ida.inf_is_be():
                mode = keystone.KS_MODE_ARM | keystone.KS_MODE_BIG_ENDIAN
                self._ks_thumb = keystone.Ks(arch, keystone.KS_MODE_THUMB | keystone.KS_MODE_BIG_ENDIAN)
            else:
                mode = keystone.KS_MODE_ARM | keystone.KS_MODE_LITTLE_ENDIAN
                self._ks_thumb = keystone.Ks(arch, keystone.KS_MODE_THUMB | keystone.KS_MODE_LITTLE_ENDIAN)

        super(AsmARM, self).__init__(arch, mode)

        self.__ARM_NOP_4, _ = self._ks.asm('NOP', as_bytes=True)
        if self._ks_thumb:
            self.__THUMB_NOP_2, _ = self._ks_thumb.asm('NOP', as_bytes=True)
            self.__THUMB_NOP_4, _ = self._ks_thumb.asm('NOP.W', as_bytes=True)

    def asm(self, assembly, ea=0, resolve=True):
        if self.is_thumb(ea):
            ks = self._ks
            self._ks = self._ks_thumb
            data = super(AsmARM, self).asm(assembly, ea, resolve)
            self._ks = ks
            return data

        return super(AsmARM, self).asm(assembly, ea, resolve)

    @staticmethod
    def is_thumb(ea):
        return bool(ida_segregs.get_sreg(ea, ida_idp.str2reg('T')) == 1)

    def nop_buffer(self, start_ea, end_ea):
        range_size = end_ea - start_ea
        if range_size < 0:
            return bytes()

        nop_list = []

        cur_ea = ida_bytes.get_item_head(start_ea)
        while cur_ea < end_ea:
            item_size = ida_bytes.get_item_size(cur_ea)

            if self.is_thumb(cur_ea):
                if item_size == 2:
                    nop_list.append(self.__THUMB_NOP_2)
                else:
                    nop_list.append(self.__THUMB_NOP_4)
            else:
                nop_list.append(self.__ARM_NOP_4)

            cur_ea += item_size

        return b''.join(nop_list)

    def format_memory_op(self, insn, n):
        op = insn.ops[n]

        if ida_idp.ph.regnames[op.reg] == 'PC':
            offset = (op.addr - insn.ea) - 8
            op_text = '[PC, #%s0x%X]' % ('-' if offset < 0 else '', abs(offset))
            return op_text

        elif self.is_thumb(insn.ea):
            offset = (op.addr - insn.ea) - 4 + (insn.ea % 4)
            op_text = '[PC, #%s0x%X]' % ('-' if offset < 0 else '', abs(offset))
            return op_text

        op_text = ida_lines.tag_remove(super(AsmARM, self).format_memory_op(insn, n))

        if op_text and op_text[0] == '=':
            op_text = '#0x%X' % op.addr

        return op_text

    def format_imm_op(self, insn, n):
        op_text = ida_ua.print_operand(insn.ea, n, 0, self._NO_OP_TYPE)
        return op_text

    def unalias(self, assembly):
        prefix, mnemonic, ops = parse_disassembly_components(assembly)
        if mnemonic.upper() == 'STMFA':
            return ' '.join([prefix, 'STMIB', ops])
        return assembly


#------------------------------------------------------------------------------
# PPC / PPC64
#------------------------------------------------------------------------------

class AsmPPC(KeystoneAssembler):
    UNCONDITIONAL_JUMP = 'B'
    CONDITIONAL_JUMPS = [
        'BEQ', 'BNE', 'BLT', 'BGT', 'BLE', 'BGE',
        'BNS', 'BSO', 'BUN', 'BNU',
        'BDNZ', 'BDZ'
    ]

    def __init__(self):
        arch = keystone.KS_ARCH_PPC
        mode = keystone.KS_MODE_PPC64 if ida_ida.inf_is_64bit() else keystone.KS_MODE_PPC32
        mode |= keystone.KS_MODE_BIG_ENDIAN if ida_ida.inf_is_be() else keystone.KS_MODE_LITTLE_ENDIAN
        super(AsmPPC, self).__init__(arch, mode)


#------------------------------------------------------------------------------
# MIPS / MIPS64
#------------------------------------------------------------------------------

class AsmMIPS(KeystoneAssembler):
    UNCONDITIONAL_JUMP = 'J'
    CONDITIONAL_JUMPS = [
        'BEQ', 'BNE', 'BEQL', 'BNEL',
        'BGTZ', 'BLEZ',
        'BGEZ', 'BLTZ',
        'BGEZL', 'BLTZL',
        'BC1T', 'BC1F'
    ]

    def __init__(self):
        arch = keystone.KS_ARCH_MIPS
        mode = keystone.KS_MODE_MIPS64 if ida_ida.inf_is_64bit() else keystone.KS_MODE_MIPS32
        mode |= keystone.KS_MODE_BIG_ENDIAN if ida_ida.inf_is_be() else keystone.KS_MODE_LITTLE_ENDIAN
        super(AsmMIPS, self).__init__(arch, mode)


#------------------------------------------------------------------------------
# SPARC / SPARC64
#------------------------------------------------------------------------------

class AsmSPARC(KeystoneAssembler):
    UNCONDITIONAL_JUMP = 'BA'
    CONDITIONAL_JUMPS = [
        'BE', 'BNE', 'BG', 'BGE', 'BL', 'BLE',
        'BGU', 'BLEU', 'BCC', 'BCS',
        'BPOS', 'BNEG', 'BVC', 'BVS',
        'BGEU', 'BLU'
    ]

    def __init__(self):
        arch = keystone.KS_ARCH_SPARC
        mode = keystone.KS_MODE_SPARC64 if ida_ida.inf_is_64bit() else keystone.KS_MODE_SPARC32
        mode |= keystone.KS_MODE_BIG_ENDIAN if ida_ida.inf_is_be() else keystone.KS_MODE_LITTLE_ENDIAN
        super(AsmSPARC, self).__init__(arch, mode)


#------------------------------------------------------------------------------
# System-Z (s390x)
#------------------------------------------------------------------------------

class AsmSystemZ(KeystoneAssembler):
    UNCONDITIONAL_JUMP = 'J'
    CONDITIONAL_JUMPS = [
        'JE', 'JNE', 'JZ', 'JNZ',
        'JL', 'JLE', 'JG', 'JGE',
        'JH', 'JNH', 'JO', 'JNO',
        'JP', 'JNP'
    ]

    def __init__(self):
        # systemz is big-endian in keystone
        super(AsmSystemZ, self).__init__(keystone.KS_ARCH_SYSTEMZ, keystone.KS_MODE_BIG_ENDIAN)


#------------------------------------------------------------------------------
# Hexagon
#------------------------------------------------------------------------------

class AsmHexagon(KeystoneAssembler):
    # Branch rewriting for Hexagon is non-trivial; keep ForceJump disabled.
    UNCONDITIONAL_JUMP = 'JUMP'
    CONDITIONAL_JUMPS = []

    def __init__(self):
        arch = keystone.KS_ARCH_HEXAGON
        mode = keystone.KS_MODE_BIG_ENDIAN if ida_ida.inf_is_be() else keystone.KS_MODE_LITTLE_ENDIAN
        super(AsmHexagon, self).__init__(arch, mode)


#------------------------------------------------------------------------------
# EVM
#------------------------------------------------------------------------------

class AsmEVM(KeystoneAssembler):
    # IMPORTANT: rewriting JUMPI->JUMP is unsafe (stack semantics), so ForceJump disabled.
    UNCONDITIONAL_JUMP = 'JUMP'
    CONDITIONAL_JUMPS = []

    def __init__(self):
        super(AsmEVM, self).__init__(keystone.KS_ARCH_EVM, 0)

    def nop_buffer(self, start_ea, end_ea):
        # EVM has no real NOP; JUMPDEST (0x5B) is the closest "does nothing and continues".
        range_size = end_ea - start_ea
        if range_size <= 0:
            return bytes()
        return b'\x5B' * range_size
