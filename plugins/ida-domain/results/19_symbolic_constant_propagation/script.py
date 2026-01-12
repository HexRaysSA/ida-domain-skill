# Exercise 19: Lightweight Symbolic-ish Constant Propagation for Decryption
# Implements a limited evaluator over functions to track register constants
# through arithmetic operations and resolve computed values.
# Supports both x86-64 and ARM64 architectures.

from collections import defaultdict

# ============================================================================
# Value Lattice: Represents the state of a value (constant, unknown, or range)
# ============================================================================
class Value:
    """Represents a value in our abstract interpretation."""

    UNKNOWN = object()  # Top of lattice - unknown value

    def __init__(self, val=None):
        self.val = val if val is not None else Value.UNKNOWN

    def is_known(self):
        return self.val is not Value.UNKNOWN

    def get(self):
        return self.val if self.is_known() else None

    def __repr__(self):
        if self.is_known():
            if isinstance(self.val, int):
                return f"Value(0x{self.val:x})"
            return f"Value({self.val})"
        return "Value(UNKNOWN)"

    def __eq__(self, other):
        if isinstance(other, Value):
            return self.val == other.val
        return False

    def __hash__(self):
        return hash(self.val) if self.is_known() else hash(None)


def mask_value(val, bits=64):
    """Mask value to specified bit width."""
    if val is None:
        return None
    return val & ((1 << bits) - 1)


# ============================================================================
# Symbolic Evaluator: Tracks register values through instruction execution
# ============================================================================
class SymbolicEvaluator:
    """Lightweight symbolic evaluator for constant propagation."""

    def __init__(self, db):
        self.db = db
        self.state = {}  # Register -> Value mapping
        self.memory = {}  # Address -> Value mapping for known memory reads
        self.resolutions = []  # Track resolved values
        self.arch = db.architecture.lower()

        # Determine architecture and set up register mappings
        if 'arm' in self.arch or 'aarch64' in self.arch:
            self.setup_arm64_registers()
        else:
            self.setup_x86_registers()

    def setup_arm64_registers(self):
        """Set up ARM64 register mappings."""
        # ARM64 general purpose registers (X0-X30, W0-W30)
        self.reg_parent = {}
        for i in range(31):
            x_reg = f"x{i}"
            w_reg = f"w{i}"
            self.reg_parent[x_reg] = x_reg
            self.reg_parent[w_reg] = x_reg

        # Special registers
        self.reg_parent['sp'] = 'sp'
        self.reg_parent['xzr'] = 'xzr'
        self.reg_parent['wzr'] = 'xzr'
        self.reg_parent['lr'] = 'x30'
        self.reg_parent['fp'] = 'x29'

    def setup_x86_registers(self):
        """Set up x86-64 register mappings."""
        self.reg_64 = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9',
                       'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rbp', 'rsp']
        self.reg_32 = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'r8d', 'r9d',
                       'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d', 'ebp', 'esp']
        self.reg_16 = ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'r8w', 'r9w',
                       'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w', 'bp', 'sp']
        self.reg_8 = ['al', 'bl', 'cl', 'dl', 'sil', 'dil', 'r8b', 'r9b',
                      'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b', 'bpl', 'spl']

        self.reg_parent = {}
        for i, r64 in enumerate(self.reg_64):
            self.reg_parent[r64] = r64
            self.reg_parent[self.reg_32[i]] = r64
            self.reg_parent[self.reg_16[i]] = r64
            if i < len(self.reg_8):
                self.reg_parent[self.reg_8[i]] = r64
        self.reg_parent['ah'] = 'rax'
        self.reg_parent['bh'] = 'rbx'
        self.reg_parent['ch'] = 'rcx'
        self.reg_parent['dh'] = 'rdx'

    def reset(self):
        """Reset evaluator state."""
        self.state = {}
        self.memory = {}

    def get_parent_reg(self, reg):
        """Get the parent 64-bit register name."""
        if reg is None:
            return None
        reg_lower = reg.lower()
        return self.reg_parent.get(reg_lower, reg_lower)

    def get_reg(self, reg):
        """Get value of a register."""
        if reg is None:
            return Value()
        parent = self.get_parent_reg(reg)
        if parent == 'xzr' or parent == 'wzr':
            return Value(0)  # Zero register always returns 0
        return self.state.get(parent, Value())

    def set_reg(self, reg, val):
        """Set value of a register."""
        if reg is None:
            return
        parent = self.get_parent_reg(reg)
        if parent == 'xzr' or parent == 'wzr':
            return  # Can't write to zero register
        if isinstance(val, Value):
            self.state[parent] = val
        else:
            self.state[parent] = Value(val)

    def invalidate_reg(self, reg):
        """Mark register as unknown."""
        if reg is None:
            return
        parent = self.get_parent_reg(reg)
        self.state[parent] = Value()

    def read_memory(self, addr, size):
        """Read a value from memory if it's in a known segment."""
        try:
            if size == 1:
                val = self.db.bytes.get_byte_at(addr)
            elif size == 2:
                val = self.db.bytes.get_word_at(addr)
            elif size == 4:
                val = self.db.bytes.get_dword_at(addr)
            elif size == 8:
                val = self.db.bytes.get_qword_at(addr)
            else:
                return Value()
            return Value(val)
        except:
            return Value()

    def is_data_segment(self, addr):
        """Check if address is in a data segment (.rodata, .data, etc.)."""
        try:
            seg = self.db.segments.get_at(addr)
            if seg:
                seg_name = self.db.segments.get_name(seg).lower()
                return any(s in seg_name for s in ['data', 'rodata', 'const', 'bss', 'got'])
        except:
            pass
        return False

    def evaluate_operand(self, insn, op_idx):
        """Evaluate an operand and return its value."""
        op = self.db.instructions.get_operand(insn, op_idx)
        if op is None:
            return Value()

        from ida_domain.operands import RegisterOperand, ImmediateOperand, MemoryOperand

        if isinstance(op, RegisterOperand):
            return self.get_reg(op.get_register_name())

        elif isinstance(op, ImmediateOperand):
            return Value(op.get_value())

        elif isinstance(op, MemoryOperand):
            # Try to compute the address
            addr = self.compute_memory_address(op, insn)
            if addr is not None and addr.is_known():
                # Read from known address
                size = op.size_bytes
                return self.read_memory(addr.get(), size)

        return Value()

    def compute_memory_address(self, op, insn):
        """Compute the effective address of a memory operand."""
        from ida_domain.operands import OperandType

        if op.type == OperandType.MEMORY:
            # Direct memory access
            return Value(op.get_address())

        elif op.type == OperandType.DISPLACEMENT:
            # Base + displacement
            disp = op.get_displacement() or 0
            phrase = op.get_phrase_number()

            # Get base register value
            base_val = Value()
            if phrase is not None:
                formatted = op.get_formatted_string()
                if formatted:
                    import re
                    # ARM64 format: [X0, #offset] or [X0]
                    # x86 format: [rax+offset]
                    regs = re.findall(r'\b([xw]\d+|[re]?[abcd]x|[re]?[sd]i|[re]?bp|[re]?sp|sp)\b',
                                      formatted.lower())
                    if regs:
                        base_val = self.get_reg(regs[0])

            if base_val.is_known():
                return Value(mask_value(base_val.get() + disp))

        return Value()

    def execute_instruction(self, insn):
        """Execute a single instruction and update state."""
        mnem = self.db.instructions.get_mnemonic(insn)
        if mnem is None:
            return

        mnem = mnem.lower()

        # Handle ARM64 instructions
        if 'arm' in self.arch or 'aarch64' in self.arch:
            self.execute_arm64_instruction(insn, mnem)
        else:
            self.execute_x86_instruction(insn, mnem)

    def execute_arm64_instruction(self, insn, mnem):
        """Execute ARM64 instructions."""
        from ida_domain.operands import RegisterOperand, ImmediateOperand, MemoryOperand

        if mnem in ['mov', 'movz', 'movn', 'movk']:
            self.handle_arm64_mov(insn, mnem)
        elif mnem == 'adr' or mnem == 'adrp':
            self.handle_arm64_adr(insn)
        elif mnem in ['ldr', 'ldrsw', 'ldrb', 'ldrh', 'ldrsb', 'ldrsh']:
            self.handle_arm64_ldr(insn)
        elif mnem in ['add', 'adds']:
            self.handle_arm64_add(insn)
        elif mnem in ['sub', 'subs']:
            self.handle_arm64_sub(insn)
        elif mnem in ['and', 'ands']:
            self.handle_arm64_and(insn)
        elif mnem in ['orr']:
            self.handle_arm64_orr(insn)
        elif mnem in ['eor']:
            self.handle_arm64_eor(insn)
        elif mnem in ['lsl', 'lsr', 'asr']:
            self.handle_arm64_shift(insn, mnem)
        elif mnem in ['mul', 'madd']:
            self.handle_arm64_mul(insn, mnem)
        elif mnem in ['bl', 'blr']:
            # Calls clobber volatile registers
            self.invalidate_arm64_caller_saved()
        elif mnem.startswith('b') or mnem.startswith('cb'):
            pass  # Branches don't change registers
        elif mnem in ['cmp', 'tst', 'cmn']:
            pass  # Comparisons don't change registers
        elif mnem == 'nop':
            pass
        elif mnem in ['stp', 'str', 'strb', 'strh']:
            pass  # Stores don't change tracked registers
        elif mnem in ['ldp']:
            # Load pair - invalidate both destinations
            op0 = self.db.instructions.get_operand(insn, 0)
            op1 = self.db.instructions.get_operand(insn, 1)
            if isinstance(op0, RegisterOperand):
                self.invalidate_reg(op0.get_register_name())
            if isinstance(op1, RegisterOperand):
                self.invalidate_reg(op1.get_register_name())
        else:
            # Unknown instruction - invalidate destination
            op = self.db.instructions.get_operand(insn, 0)
            if isinstance(op, RegisterOperand):
                self.invalidate_reg(op.get_register_name())

    def handle_arm64_mov(self, insn, mnem):
        """Handle ARM64 MOV variants."""
        from ida_domain.operands import RegisterOperand, ImmediateOperand

        dst = self.db.instructions.get_operand(insn, 0)
        if not isinstance(dst, RegisterOperand):
            return

        dst_name = dst.get_register_name()

        if mnem == 'mov':
            src_val = self.evaluate_operand(insn, 1)
            self.set_reg(dst_name, src_val)
        elif mnem == 'movz':
            # Move with zero
            src = self.db.instructions.get_operand(insn, 1)
            if isinstance(src, ImmediateOperand):
                self.set_reg(dst_name, Value(src.get_value()))
            else:
                self.invalidate_reg(dst_name)
        elif mnem == 'movn':
            # Move with NOT
            src = self.db.instructions.get_operand(insn, 1)
            if isinstance(src, ImmediateOperand):
                self.set_reg(dst_name, Value(~src.get_value() & 0xFFFFFFFFFFFFFFFF))
            else:
                self.invalidate_reg(dst_name)
        elif mnem == 'movk':
            # Move keep - only modifies part of register
            self.invalidate_reg(dst_name)

    def handle_arm64_adr(self, insn):
        """Handle ADR/ADRP instructions."""
        from ida_domain.operands import RegisterOperand, ImmediateOperand

        dst = self.db.instructions.get_operand(insn, 0)
        src = self.db.instructions.get_operand(insn, 1)

        if isinstance(dst, RegisterOperand) and isinstance(src, ImmediateOperand):
            self.set_reg(dst.get_register_name(), Value(src.get_value()))

    def handle_arm64_ldr(self, insn):
        """Handle LDR instructions."""
        from ida_domain.operands import RegisterOperand, MemoryOperand

        dst = self.db.instructions.get_operand(insn, 0)
        src = self.db.instructions.get_operand(insn, 1)

        if not isinstance(dst, RegisterOperand):
            return

        if isinstance(src, MemoryOperand):
            addr = self.compute_memory_address(src, insn)
            if addr and addr.is_known():
                val = self.read_memory(addr.get(), dst.size_bytes)
                self.set_reg(dst.get_register_name(), val)
                return

        self.invalidate_reg(dst.get_register_name())

    def handle_arm64_add(self, insn):
        """Handle ADD/ADDS instructions."""
        from ida_domain.operands import RegisterOperand

        dst = self.db.instructions.get_operand(insn, 0)
        if not isinstance(dst, RegisterOperand):
            return

        op_count = self.db.instructions.get_operands_count(insn)
        if op_count == 3:
            src1_val = self.evaluate_operand(insn, 1)
            src2_val = self.evaluate_operand(insn, 2)
        else:
            src1_val = self.evaluate_operand(insn, 0)
            src2_val = self.evaluate_operand(insn, 1)

        if src1_val.is_known() and src2_val.is_known():
            result = mask_value(src1_val.get() + src2_val.get())
            self.set_reg(dst.get_register_name(), Value(result))
        else:
            self.invalidate_reg(dst.get_register_name())

    def handle_arm64_sub(self, insn):
        """Handle SUB/SUBS instructions."""
        from ida_domain.operands import RegisterOperand

        dst = self.db.instructions.get_operand(insn, 0)
        if not isinstance(dst, RegisterOperand):
            return

        op_count = self.db.instructions.get_operands_count(insn)
        if op_count == 3:
            src1_val = self.evaluate_operand(insn, 1)
            src2_val = self.evaluate_operand(insn, 2)
        else:
            src1_val = self.evaluate_operand(insn, 0)
            src2_val = self.evaluate_operand(insn, 1)

        if src1_val.is_known() and src2_val.is_known():
            result = mask_value(src1_val.get() - src2_val.get())
            self.set_reg(dst.get_register_name(), Value(result))
        else:
            self.invalidate_reg(dst.get_register_name())

    def handle_arm64_and(self, insn):
        """Handle AND/ANDS instructions."""
        from ida_domain.operands import RegisterOperand

        dst = self.db.instructions.get_operand(insn, 0)
        if not isinstance(dst, RegisterOperand):
            return

        op_count = self.db.instructions.get_operands_count(insn)
        if op_count == 3:
            src1_val = self.evaluate_operand(insn, 1)
            src2_val = self.evaluate_operand(insn, 2)
        else:
            src1_val = self.evaluate_operand(insn, 0)
            src2_val = self.evaluate_operand(insn, 1)

        if src1_val.is_known() and src2_val.is_known():
            result = src1_val.get() & src2_val.get()
            self.set_reg(dst.get_register_name(), Value(result))
        else:
            self.invalidate_reg(dst.get_register_name())

    def handle_arm64_orr(self, insn):
        """Handle ORR instruction."""
        from ida_domain.operands import RegisterOperand

        dst = self.db.instructions.get_operand(insn, 0)
        if not isinstance(dst, RegisterOperand):
            return

        op_count = self.db.instructions.get_operands_count(insn)
        if op_count == 3:
            src1_val = self.evaluate_operand(insn, 1)
            src2_val = self.evaluate_operand(insn, 2)
        else:
            src1_val = self.evaluate_operand(insn, 0)
            src2_val = self.evaluate_operand(insn, 1)

        if src1_val.is_known() and src2_val.is_known():
            result = src1_val.get() | src2_val.get()
            self.set_reg(dst.get_register_name(), Value(result))
        else:
            self.invalidate_reg(dst.get_register_name())

    def handle_arm64_eor(self, insn):
        """Handle EOR (XOR) instruction."""
        from ida_domain.operands import RegisterOperand

        dst = self.db.instructions.get_operand(insn, 0)
        if not isinstance(dst, RegisterOperand):
            return

        op_count = self.db.instructions.get_operands_count(insn)
        if op_count == 3:
            src1_val = self.evaluate_operand(insn, 1)
            src2_val = self.evaluate_operand(insn, 2)
        else:
            src1_val = self.evaluate_operand(insn, 0)
            src2_val = self.evaluate_operand(insn, 1)

        if src1_val.is_known() and src2_val.is_known():
            result = src1_val.get() ^ src2_val.get()
            self.set_reg(dst.get_register_name(), Value(result))
        else:
            self.invalidate_reg(dst.get_register_name())

    def handle_arm64_shift(self, insn, mnem):
        """Handle LSL/LSR/ASR instructions."""
        from ida_domain.operands import RegisterOperand

        dst = self.db.instructions.get_operand(insn, 0)
        if not isinstance(dst, RegisterOperand):
            return

        op_count = self.db.instructions.get_operands_count(insn)
        if op_count == 3:
            src_val = self.evaluate_operand(insn, 1)
            shift_val = self.evaluate_operand(insn, 2)
        else:
            src_val = self.evaluate_operand(insn, 0)
            shift_val = self.evaluate_operand(insn, 1)

        if src_val.is_known() and shift_val.is_known():
            shift = shift_val.get() & 0x3F
            if mnem == 'lsl':
                result = mask_value(src_val.get() << shift)
            elif mnem == 'lsr':
                result = src_val.get() >> shift
            else:  # asr
                result = src_val.get() >> shift
            self.set_reg(dst.get_register_name(), Value(result))
        else:
            self.invalidate_reg(dst.get_register_name())

    def handle_arm64_mul(self, insn, mnem):
        """Handle MUL/MADD instructions."""
        from ida_domain.operands import RegisterOperand

        dst = self.db.instructions.get_operand(insn, 0)
        if not isinstance(dst, RegisterOperand):
            return

        if mnem == 'mul':
            src1_val = self.evaluate_operand(insn, 1)
            src2_val = self.evaluate_operand(insn, 2)
            if src1_val.is_known() and src2_val.is_known():
                result = mask_value(src1_val.get() * src2_val.get())
                self.set_reg(dst.get_register_name(), Value(result))
                return

        self.invalidate_reg(dst.get_register_name())

    def invalidate_arm64_caller_saved(self):
        """Invalidate caller-saved registers after a call (ARM64)."""
        for i in range(19):  # X0-X18 are caller-saved
            self.invalidate_reg(f"x{i}")

    def execute_x86_instruction(self, insn, mnem):
        """Execute x86 instructions."""
        # Previous x86 handling code
        if mnem == 'mov' or mnem == 'movabs':
            self.handle_mov(insn)
        elif mnem == 'lea':
            self.handle_lea(insn)
        elif mnem == 'xor':
            self.handle_xor(insn)
        elif mnem == 'add':
            self.handle_add(insn)
        elif mnem == 'sub':
            self.handle_sub(insn)
        elif mnem == 'and':
            self.handle_and(insn)
        elif mnem == 'or':
            self.handle_or(insn)
        elif mnem == 'shl' or mnem == 'sal':
            self.handle_shl(insn)
        elif mnem == 'shr' or mnem == 'sar':
            self.handle_shr(insn)
        elif mnem == 'imul' or mnem == 'mul':
            self.handle_mul(insn)
        elif mnem == 'movzx' or mnem == 'movsx' or mnem == 'movsxd':
            self.handle_movzx(insn)
        elif mnem in ['call', 'ret', 'syscall']:
            self.invalidate_caller_saved()
        else:
            op = self.db.instructions.get_operand(insn, 0)
            if op:
                from ida_domain.operands import RegisterOperand
                if isinstance(op, RegisterOperand):
                    self.invalidate_reg(op.get_register_name())

    def handle_mov(self, insn):
        dst = self.db.instructions.get_operand(insn, 0)
        src_val = self.evaluate_operand(insn, 1)
        from ida_domain.operands import RegisterOperand
        if isinstance(dst, RegisterOperand):
            self.set_reg(dst.get_register_name(), src_val)

    def handle_lea(self, insn):
        dst = self.db.instructions.get_operand(insn, 0)
        src = self.db.instructions.get_operand(insn, 1)
        from ida_domain.operands import RegisterOperand, MemoryOperand
        if isinstance(dst, RegisterOperand) and isinstance(src, MemoryOperand):
            addr = self.compute_memory_address(src, insn)
            self.set_reg(dst.get_register_name(), addr)

    def handle_xor(self, insn):
        dst = self.db.instructions.get_operand(insn, 0)
        src_val = self.evaluate_operand(insn, 1)
        dst_val = self.evaluate_operand(insn, 0)
        from ida_domain.operands import RegisterOperand
        if isinstance(dst, RegisterOperand):
            dst_name = dst.get_register_name()
            src_op = self.db.instructions.get_operand(insn, 1)
            if isinstance(src_op, RegisterOperand):
                if self.get_parent_reg(src_op.get_register_name()) == self.get_parent_reg(dst_name):
                    self.set_reg(dst_name, Value(0))
                    return
            if dst_val.is_known() and src_val.is_known():
                result = mask_value(dst_val.get() ^ src_val.get())
                self.set_reg(dst_name, Value(result))
            else:
                self.invalidate_reg(dst_name)

    def handle_add(self, insn):
        dst = self.db.instructions.get_operand(insn, 0)
        src_val = self.evaluate_operand(insn, 1)
        dst_val = self.evaluate_operand(insn, 0)
        from ida_domain.operands import RegisterOperand
        if isinstance(dst, RegisterOperand):
            if dst_val.is_known() and src_val.is_known():
                result = mask_value(dst_val.get() + src_val.get())
                self.set_reg(dst.get_register_name(), Value(result))
            else:
                self.invalidate_reg(dst.get_register_name())

    def handle_sub(self, insn):
        dst = self.db.instructions.get_operand(insn, 0)
        src_val = self.evaluate_operand(insn, 1)
        dst_val = self.evaluate_operand(insn, 0)
        from ida_domain.operands import RegisterOperand
        if isinstance(dst, RegisterOperand):
            if dst_val.is_known() and src_val.is_known():
                result = mask_value(dst_val.get() - src_val.get())
                self.set_reg(dst.get_register_name(), Value(result))
            else:
                self.invalidate_reg(dst.get_register_name())

    def handle_and(self, insn):
        dst = self.db.instructions.get_operand(insn, 0)
        src_val = self.evaluate_operand(insn, 1)
        dst_val = self.evaluate_operand(insn, 0)
        from ida_domain.operands import RegisterOperand
        if isinstance(dst, RegisterOperand):
            if dst_val.is_known() and src_val.is_known():
                result = mask_value(dst_val.get() & src_val.get())
                self.set_reg(dst.get_register_name(), Value(result))
            else:
                self.invalidate_reg(dst.get_register_name())

    def handle_or(self, insn):
        dst = self.db.instructions.get_operand(insn, 0)
        src_val = self.evaluate_operand(insn, 1)
        dst_val = self.evaluate_operand(insn, 0)
        from ida_domain.operands import RegisterOperand
        if isinstance(dst, RegisterOperand):
            if dst_val.is_known() and src_val.is_known():
                result = mask_value(dst_val.get() | src_val.get())
                self.set_reg(dst.get_register_name(), Value(result))
            else:
                self.invalidate_reg(dst.get_register_name())

    def handle_shl(self, insn):
        dst = self.db.instructions.get_operand(insn, 0)
        src_val = self.evaluate_operand(insn, 1)
        dst_val = self.evaluate_operand(insn, 0)
        from ida_domain.operands import RegisterOperand
        if isinstance(dst, RegisterOperand):
            if dst_val.is_known() and src_val.is_known():
                shift = src_val.get() & 0x3F
                result = mask_value(dst_val.get() << shift)
                self.set_reg(dst.get_register_name(), Value(result))
            else:
                self.invalidate_reg(dst.get_register_name())

    def handle_shr(self, insn):
        dst = self.db.instructions.get_operand(insn, 0)
        src_val = self.evaluate_operand(insn, 1)
        dst_val = self.evaluate_operand(insn, 0)
        from ida_domain.operands import RegisterOperand
        if isinstance(dst, RegisterOperand):
            if dst_val.is_known() and src_val.is_known():
                shift = src_val.get() & 0x3F
                result = dst_val.get() >> shift
                self.set_reg(dst.get_register_name(), Value(result))
            else:
                self.invalidate_reg(dst.get_register_name())

    def handle_mul(self, insn):
        op_count = self.db.instructions.get_operands_count(insn)
        from ida_domain.operands import RegisterOperand
        if op_count == 3:
            dst = self.db.instructions.get_operand(insn, 0)
            src_val = self.evaluate_operand(insn, 1)
            imm_val = self.evaluate_operand(insn, 2)
            if isinstance(dst, RegisterOperand):
                if src_val.is_known() and imm_val.is_known():
                    result = mask_value(src_val.get() * imm_val.get())
                    self.set_reg(dst.get_register_name(), Value(result))
                else:
                    self.invalidate_reg(dst.get_register_name())
        else:
            self.invalidate_reg('rax')
            self.invalidate_reg('rdx')

    def handle_movzx(self, insn):
        dst = self.db.instructions.get_operand(insn, 0)
        src_val = self.evaluate_operand(insn, 1)
        from ida_domain.operands import RegisterOperand
        if isinstance(dst, RegisterOperand):
            self.set_reg(dst.get_register_name(), src_val)

    def invalidate_caller_saved(self):
        for reg in ['rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11']:
            self.invalidate_reg(reg)


# ============================================================================
# Resolution Detector: Detects and reports resolved computed values
# ============================================================================
class Resolution:
    """Represents a resolved computed value."""

    def __init__(self, ea, expr, resolved_value, resolution_type, details=None):
        self.ea = ea
        self.expr = expr
        self.resolved_value = resolved_value
        self.resolution_type = resolution_type
        self.details = details or {}

    def __repr__(self):
        return f"Resolution(0x{self.ea:x}, {self.resolution_type}, 0x{self.resolved_value:x})"


def analyze_function(db, func, evaluator):
    """Analyze a single function for resolvable computed values."""
    resolutions = []
    func_name = db.functions.get_name(func)
    arch = db.architecture.lower()
    is_arm = 'arm' in arch or 'aarch64' in arch

    # Get flowchart for basic block analysis
    try:
        flowchart = db.functions.get_flowchart(func)
        if not flowchart:
            return resolutions
    except:
        return resolutions

    # Analyze each basic block
    for block in flowchart:
        evaluator.reset()

        # Execute instructions in the block
        try:
            for insn in block.get_instructions():
                mnem = db.instructions.get_mnemonic(insn)
                if mnem is None:
                    continue

                mnem_lower = mnem.lower()
                disasm = db.instructions.get_disassembly(insn) or ""

                # Check for interesting patterns before executing

                from ida_domain.operands import RegisterOperand, ImmediateOperand, MemoryOperand

                # 1. Check for computed call targets (ARM64: BLR, x86: call reg)
                if db.instructions.is_call_instruction(insn):
                    op = db.instructions.get_operand(insn, 0)

                    if isinstance(op, RegisterOperand):
                        val = evaluator.get_reg(op.get_register_name())
                        if val.is_known():
                            target = db.functions.get_at(val.get())
                            target_name = db.functions.get_name(target) if target else f"0x{val.get():x}"
                            resolutions.append(Resolution(
                                ea=insn.ea,
                                expr=disasm.strip(),
                                resolved_value=val.get(),
                                resolution_type="computed_call",
                                details={"target_name": target_name}
                            ))

                    elif isinstance(op, MemoryOperand):
                        addr = evaluator.compute_memory_address(op, insn)
                        if addr and addr.is_known():
                            target_val = evaluator.read_memory(addr.get(), 8)
                            if target_val.is_known():
                                target = db.functions.get_at(target_val.get())
                                target_name = db.functions.get_name(target) if target else f"0x{target_val.get():x}"
                                resolutions.append(Resolution(
                                    ea=insn.ea,
                                    expr=disasm.strip(),
                                    resolved_value=target_val.get(),
                                    resolution_type="computed_call_indirect",
                                    details={
                                        "table_address": addr.get(),
                                        "target_name": target_name
                                    }
                                ))

                # 2. Check for computed jumps (ARM64: BR, x86: jmp reg)
                if is_arm and mnem_lower == 'br':
                    op = db.instructions.get_operand(insn, 0)
                    if isinstance(op, RegisterOperand):
                        val = evaluator.get_reg(op.get_register_name())
                        if val.is_known():
                            resolutions.append(Resolution(
                                ea=insn.ea,
                                expr=disasm.strip(),
                                resolved_value=val.get(),
                                resolution_type="computed_jump"
                            ))

                # 3. Check for XOR/EOR decryption patterns
                if (is_arm and mnem_lower == 'eor') or (not is_arm and mnem_lower == 'xor'):
                    dst = db.instructions.get_operand(insn, 0)
                    if isinstance(dst, RegisterOperand):
                        dst_val = evaluator.evaluate_operand(insn, 0)
                        src_val = evaluator.evaluate_operand(insn, 1 if is_arm else 1)

                        # For 3-operand ARM: dst = src1 ^ src2
                        if is_arm and db.instructions.get_operands_count(insn) == 3:
                            src1_val = evaluator.evaluate_operand(insn, 1)
                            src2_val = evaluator.evaluate_operand(insn, 2)
                            if src1_val.is_known() and src2_val.is_known():
                                result = src1_val.get() ^ src2_val.get()
                                if 0x20 <= (result & 0xFF) <= 0x7E or result == 0:
                                    resolutions.append(Resolution(
                                        ea=insn.ea,
                                        expr=disasm.strip(),
                                        resolved_value=result,
                                        resolution_type="xor_decrypt",
                                        details={
                                            "decrypted_char": chr(result & 0xFF) if 0x20 <= (result & 0xFF) <= 0x7E else None
                                        }
                                    ))
                        elif not is_arm:
                            src = db.instructions.get_operand(insn, 1)
                            if isinstance(src, ImmediateOperand) and dst_val.is_known():
                                key = src.get_value()
                                result = dst_val.get() ^ key
                                if 0x20 <= (result & 0xFF) <= 0x7E:
                                    resolutions.append(Resolution(
                                        ea=insn.ea,
                                        expr=disasm.strip(),
                                        resolved_value=result,
                                        resolution_type="xor_decrypt",
                                        details={
                                            "key": key,
                                            "decrypted_char": chr(result & 0xFF)
                                        }
                                    ))

                # 4. Check for table lookups with known addresses
                load_mnems = ['ldr', 'ldrsw', 'ldrb', 'ldrh', 'ldrsb', 'ldrsh'] if is_arm else ['mov', 'movzx', 'movsx']
                if mnem_lower in load_mnems:
                    dst = db.instructions.get_operand(insn, 0)
                    src_idx = 1 if is_arm else 1
                    src = db.instructions.get_operand(insn, src_idx)

                    if isinstance(dst, RegisterOperand) and isinstance(src, MemoryOperand):
                        addr = evaluator.compute_memory_address(src, insn)
                        if addr and addr.is_known() and evaluator.is_data_segment(addr.get()):
                            size = dst.size_bytes if hasattr(dst, 'size_bytes') else 8
                            val = evaluator.read_memory(addr.get(), size)
                            if val.is_known():
                                resolutions.append(Resolution(
                                    ea=insn.ea,
                                    expr=disasm.strip(),
                                    resolved_value=val.get(),
                                    resolution_type="table_lookup",
                                    details={
                                        "table_address": addr.get(),
                                        "element_size": size
                                    }
                                ))

                # 5. Track address computations (ADRP/ADR, LEA)
                if is_arm and mnem_lower in ['adr', 'adrp']:
                    dst = db.instructions.get_operand(insn, 0)
                    src = db.instructions.get_operand(insn, 1)
                    if isinstance(dst, RegisterOperand) and isinstance(src, ImmediateOperand):
                        addr_val = src.get_value()
                        if evaluator.is_data_segment(addr_val):
                            resolutions.append(Resolution(
                                ea=insn.ea,
                                expr=disasm.strip(),
                                resolved_value=addr_val,
                                resolution_type="address_computation",
                                details={"is_data_ptr": True}
                            ))

                # 6. Check for switch/case table lookups (common pattern)
                if is_arm and mnem_lower == 'ldr':
                    # Pattern: LDR Xn, [Xbase, Xindex, LSL #3]
                    dst = db.instructions.get_operand(insn, 0)
                    src = db.instructions.get_operand(insn, 1)
                    if isinstance(src, MemoryOperand):
                        formatted = src.get_formatted_string()
                        if formatted and 'LSL' in formatted.upper():
                            addr = evaluator.compute_memory_address(src, insn)
                            if addr and addr.is_known():
                                val = evaluator.read_memory(addr.get(), 8)
                                if val.is_known():
                                    target_func = db.functions.get_at(val.get())
                                    target_name = db.functions.get_name(target_func) if target_func else None
                                    resolutions.append(Resolution(
                                        ea=insn.ea,
                                        expr=disasm.strip(),
                                        resolved_value=val.get(),
                                        resolution_type="switch_table_lookup",
                                        details={
                                            "table_address": addr.get(),
                                            "target_name": target_name
                                        }
                                    ))

                # Execute instruction to update state
                evaluator.execute_instruction(insn)

        except Exception as e:
            pass

    return resolutions


def main():
    """Main analysis function."""
    print("=" * 70)
    print("Exercise 19: Lightweight Symbolic Constant Propagation")
    print("=" * 70)
    print()
    print(f"Architecture: {db.architecture}")
    print(f"Binary: {db.module}")
    print()

    # Create evaluator
    evaluator = SymbolicEvaluator(db)

    # Collect all resolutions
    all_resolutions = []

    # Track statistics
    stats = {
        "functions_analyzed": 0,
        "total_resolutions": 0,
        "by_type": defaultdict(int)
    }

    # First, find test/target functions
    target_functions = []
    for func in db.functions:
        func_name = db.functions.get_name(func)
        # Include test_ functions, main, and functions with interesting patterns
        if (func_name.startswith("test_") or
            func_name == "main" or
            "dispatch" in func_name.lower() or
            "decrypt" in func_name.lower() or
            "deobfuscate" in func_name.lower() or
            "lookup" in func_name.lower() or
            "compute" in func_name.lower() or
            "handler" in func_name.lower() or
            "switch" in func_name.lower()):
            target_functions.append((func, func_name))

    # If no specific target functions found, analyze all non-library functions
    if not target_functions:
        for func in db.functions:
            func_name = db.functions.get_name(func)
            if not func_name.startswith("_") or func_name == "_start":
                target_functions.append((func, func_name))

    print(f"Analyzing {len(target_functions)} target functions...")
    print()

    for func, func_name in target_functions:
        stats["functions_analyzed"] += 1

        # Analyze the function
        resolutions = analyze_function(db, func, evaluator)

        if resolutions:
            print(f"Function: {func_name} (0x{func.start_ea:x})")
            print("-" * 50)

            for res in resolutions:
                stats["total_resolutions"] += 1
                stats["by_type"][res.resolution_type] += 1

                print(f"  [0x{res.ea:08x}] {res.resolution_type}")
                print(f"    Expression: {res.expr}")
                print(f"    Resolved value: 0x{res.resolved_value:x}", end="")

                # Add human-readable interpretation
                if res.resolution_type in ["computed_call", "computed_call_indirect"]:
                    print(f" -> {res.details.get('target_name', 'unknown')}")
                elif res.resolution_type == "xor_decrypt":
                    char = res.details.get('decrypted_char')
                    if char:
                        print(f" ('{char}')")
                    else:
                        print()
                elif res.resolution_type in ["table_lookup", "switch_table_lookup"]:
                    print(f" (from table at 0x{res.details.get('table_address', 0):x})")
                    if res.details.get('target_name'):
                        print(f"      -> {res.details['target_name']}")
                elif res.resolution_type == "address_computation":
                    print(" (data pointer)" if res.details.get('is_data_ptr') else "")
                else:
                    print()

                all_resolutions.append(res)

            print()

    # Print summary
    print("=" * 70)
    print("RESOLUTION SUMMARY")
    print("=" * 70)
    print()
    print(f"Functions analyzed: {stats['functions_analyzed']}")
    print(f"Total resolutions: {stats['total_resolutions']}")
    print()
    print("Resolutions by type:")
    for rtype, count in sorted(stats["by_type"].items(), key=lambda x: -x[1]):
        print(f"  {rtype}: {count}")

    print()
    print("=" * 70)
    print("DETAILED RESOLUTION REPORT")
    print("=" * 70)
    print()

    # Group resolutions by type for detailed report
    by_type = defaultdict(list)
    for res in all_resolutions:
        by_type[res.resolution_type].append(res)

    report_order = [
        "computed_call", "computed_call_indirect", "computed_jump",
        "switch_table_lookup", "xor_decrypt", "table_lookup",
        "address_computation", "arithmetic_result"
    ]

    for rtype in report_order:
        if rtype in by_type:
            resolutions = by_type[rtype]
            print(f"\n{rtype.upper().replace('_', ' ')} ({len(resolutions)} found)")
            print("-" * 50)

            for res in resolutions:
                func = db.functions.get_at(res.ea)
                func_name = db.functions.get_name(func) if func else "unknown"

                print(f"  0x{res.ea:08x} in {func_name}")
                print(f"    {res.expr}")
                print(f"    -> 0x{res.resolved_value:x}")

                if res.details:
                    for key, val in res.details.items():
                        if key == 'target_name' and val:
                            print(f"    Target: {val}")
                        elif isinstance(val, int):
                            print(f"    {key}: 0x{val:x}")
                        elif val is not None:
                            print(f"    {key}: {val}")


if __name__ == "__main__":
    main()
