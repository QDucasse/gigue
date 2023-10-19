from __future__ import annotations

import logging
import random
from typing import TYPE_CHECKING, Callable, Dict, List, Set, Tuple, Union

# Note: Needed to avoid circular imports (that should be covered with if
# TYPE_CHECKING...) BUT do not work when using pytest


if TYPE_CHECKING:
    from gigue.method import Method
    from gigue.pic import PIC

from gigue.constants import (
    CALL_TMP_REG,
    CALLEE_SAVED_REG,
    CMP_REG,
    HIT_CASE_REG,
    INSTRUCTION_WEIGHTS,
    RA,
    SP,
    X0,
)
from gigue.exceptions import InstructionAlignmentNotDefined, WrongOffsetException
from gigue.helpers import align
from gigue.instructions import (
    BInstruction,
    IInstruction,
    Instruction,
    JInstruction,
    RInstruction,
    SInstruction,
    UInstruction,
)

logger = logging.getLogger("gigue")


class InstructionBuilder:
    R_INSTRUCTIONS: List[str] = [
        "add",
        "addw",
        "andr",
        "mul",
        "mulh",
        "mulhsu",
        "mulhu",
        "mulw",
        "orr",
        "sll",
        "sllw",
        "slt",
        "sltu",
        "sra",
        "sraw",
        "srl",
        "srlw",
        "sub",
        "subw",
        "xor",
    ]
    I_INSTRUCTIONS: List[str] = [
        "addi",
        "addiw",
        "andi",
        "ori",
        "slti",
        "sltiu",
        "xori",
    ]
    I_INSTRUCTIONS_LOAD: List[str] = ["lb", "lbu", "ld", "lh", "lhu"]
    U_INSTRUCTIONS: List[str] = ["auipc", "lui"]
    S_INSTRUCTIONS: List[str] = ["sb", "sd", "sh", "sw"]
    B_INSTRUCTIONS: List[str] = ["beq", "bge", "bgeu", "blt", "bltu", "bne"]

    ALIGNMENT: Dict[str, int] = {
        "b": 1,
        "bu": 1,
        "h": 2,
        "hu": 2,
        "w": 4,
        "wu": 4,
        "d": 8,
    }

    # Helpers
    # \______

    @staticmethod
    def consolidate_bytes(instructions: List[Instruction]) -> bytes:
        return b"".join([instr.generate_bytes() for instr in instructions])

    @staticmethod
    def split_offset(offset: int, min_offset: int = 8) -> Tuple[int, int]:
        if abs(offset) < min_offset:
            raise WrongOffsetException(
                f"Call offset should be greater than {min_offset} (currently {offset})."
            )
        offset_low: int = offset & 0xFFF
        # The right part handles the low offset sign
        # extension (that should be mitigated)
        offset_high: int = (offset & 0xFFFFF000) + ((offset & 0x800) << 1)
        # print("offset: {}/{} -> olow: {} + ohigh: {}".format(
        #     hex(offset),
        #     hex(offset & 0xFFFFFFFF),
        #     hex(offset_low),
        #     hex(offset_high)
        # ))
        return offset_low, offset_high

    @classmethod
    def define_memory_access_alignment(cls, name: str) -> int:
        for key in InstructionBuilder.ALIGNMENT.keys():
            if name.endswith(key):
                return InstructionBuilder.ALIGNMENT[key]
        raise InstructionAlignmentNotDefined(
            f"Alignment for instruction {name} not defined."
        )

    # Specific instruction building
    # \___________________________

    @staticmethod
    def build_nop() -> Instruction:
        return IInstruction.nop()

    @staticmethod
    def build_ret() -> Instruction:
        return IInstruction.ret()

    # Random instruction building
    # \__________________________

    @staticmethod
    def build_random_r_instruction(
        registers: List[int], *args, **kwargs
    ) -> RInstruction:
        # Get instruction constructor
        name: str = random.choice(InstructionBuilder.R_INSTRUCTIONS)
        constr: Callable = getattr(RInstruction, name)
        # Choose registers
        rs1: int
        rs2: int
        rd: int
        [rs1, rs2, rd] = tuple(random.choices(registers, k=3))
        return constr(rd=rd, rs1=rs1, rs2=rs2)

    @staticmethod
    def build_random_i_instruction(
        registers: List[int], *args, **kwargs
    ) -> IInstruction:
        # Get instruction constructor
        name: str = random.choice(InstructionBuilder.I_INSTRUCTIONS)
        constr: Callable = getattr(IInstruction, name)
        # Choose registers
        rd: int
        rs1: int
        [rd, rs1] = tuple(random.choices(registers, k=2))
        # Choose immediate
        imm = random.randint(0, 0xFFF)
        return constr(rd=rd, rs1=rs1, imm=imm)

    @staticmethod
    def build_random_u_instruction(
        registers: List[int], *args, **kwargs
    ) -> UInstruction:
        # Get instruction constructor
        name: str = random.choice(InstructionBuilder.U_INSTRUCTIONS)
        constr: Callable = getattr(UInstruction, name)
        # Choose register
        rd: int = random.choice(registers)
        # Choose immediate
        imm: int = random.randint(0, 0xFFFFFFFF)
        return constr(rd=rd, imm=imm)

    @staticmethod
    def build_random_s_instruction(
        registers: List[int], data_reg: int, data_size: int, *args, **kwargs
    ) -> SInstruction:
        # Get instruction constructor
        name: str = random.choice(InstructionBuilder.S_INSTRUCTIONS)
        constr: Callable = getattr(SInstruction, name)
        # Choose registers
        # Note: sd, rs2, off(rs1) stores the contents of rs2
        # at the address in rs1 + offset
        rs1: int = data_reg
        rs2: int = random.choice(registers)
        try:
            # Choose immediate with correct alignment
            alignment: int = InstructionBuilder.define_memory_access_alignment(name)
            imm: int = align(random.randint(0, min(data_size - 8, 0x7FF)), alignment)
        except InstructionAlignmentNotDefined as err:
            logger.error(err)
            raise
        return constr(rs1=rs1, rs2=rs2, imm=imm)

    @staticmethod
    def build_random_l_instruction(
        registers: List[int], data_reg: int, data_size: int, *args, **kwargs
    ) -> IInstruction:
        # Get instruction constructor
        name: str = random.choice(InstructionBuilder.I_INSTRUCTIONS_LOAD)
        constr: Callable = getattr(IInstruction, name)
        # Choose registers
        # Note: ld, rd, off(rs1) loads the value at the address
        # stored in rs1 + off in rd
        rd: int = random.choice(registers)
        rs1: int = data_reg
        try:
            # Choose immediate with correct alignment
            alignment: int = InstructionBuilder.define_memory_access_alignment(name)
            imm: int = align(random.randint(0, min(data_size, 0x7FF)), alignment)
        except InstructionAlignmentNotDefined as err:
            logger.error(err)
            raise
        return constr(rd=rd, rs1=rs1, imm=imm)

    # TODO: There should be a better way?
    @classmethod
    def size_offset(cls, max_offset: int, call_size: int = 3) -> List[int]:
        granularity: int = call_size * 4
        possible_offsets: Set[int] = set([4, max_offset])
        for i in range(1, max_offset // granularity + 1):
            possible_offsets.add(i * granularity + max_offset % granularity)
        if max_offset % granularity == 8:
            possible_offsets.add(8)
        return list(possible_offsets)

    @staticmethod
    def build_random_j_instruction(
        registers: List[int], max_offset: int, call_size: int = 3, *args, **kwargs
    ) -> JInstruction:
        # Jump to stay in the method and keep aligment
        rd: int = random.choice(registers)
        offset: int = random.choice(
            InstructionBuilder.size_offset(max_offset, call_size)
        )
        return JInstruction.jal(rd, offset)

    @staticmethod
    def build_random_b_instruction(
        registers: List[int], max_offset: int, call_size: int = 3, *args, **kwargs
    ) -> BInstruction:
        # Get instruction Constructor
        name: str = random.choice(InstructionBuilder.B_INSTRUCTIONS)
        constr: Callable = getattr(BInstruction, name)
        # Choose registers
        rs1: int
        rs2: int
        [rs1, rs2] = random.choices(
            [0] + registers, k=2, weights=[50] + [5] * len(registers)
        )
        # Define branch offset
        offset: int = random.choice(
            InstructionBuilder.size_offset(max_offset, call_size)
        )
        return constr(rs1=rs1, rs2=rs2, imm=offset)

    @staticmethod
    def build_random_instruction(
        registers: List[int],
        max_offset: int,
        data_reg: int,
        data_size: int,
        call_size: int = 3,
        weights: List[int] = INSTRUCTION_WEIGHTS,
    ) -> Instruction:
        method_name: str = random.choices(
            [
                "build_random_r_instruction",
                "build_random_i_instruction",
                "build_random_u_instruction",
                "build_random_j_instruction",
                "build_random_b_instruction",
                "build_random_s_instruction",
                "build_random_l_instruction",
            ],
            weights,
        )[0]
        method: Callable = getattr(InstructionBuilder, method_name)
        instruction: Instruction = method(
            registers=registers,
            max_offset=max_offset,
            data_reg=data_reg,
            data_size=data_size,
            call_size=call_size,
        )
        return instruction

    # Element calls
    # \____________

    # Visitor to build either a PIC or method call (visitor!)
    @staticmethod
    def build_element_base_call(
        elt: Union[Method, PIC], offset: int
    ) -> List[Instruction]:
        return elt.accept_build_base_call(offset)

    # Visitor to build either a PIC or method call with trampolines (visitor!)
    @staticmethod
    def build_element_trampoline_call(
        elt: Union[Method, PIC], offset: int, call_trampoline_offset: int
    ) -> List[Instruction]:
        return elt.accept_build_trampoline_call(offset, call_trampoline_offset)

    @staticmethod
    def build_method_base_call(offset: int) -> List[Instruction]:
        # Base method, no trampolines
        try:
            # Split offset
            offset_low: int
            offset_high: int
            offset_low, offset_high = InstructionBuilder.split_offset(offset)
        except WrongOffsetException as err:
            logger.error(err)
            raise
        return [
            UInstruction.auipc(RA, offset_high),
            IInstruction.jalr(RA, RA, offset_low),
        ]

    @staticmethod
    def build_method_trampoline_call(
        offset: int, call_trampoline_offset: int
    ) -> List[Instruction]:
        # This method uses the trampoline to call/return from JIT elements
        # It is composed as follows:
        # 1. Compute RA and save it (in RA!)
        # 2. Compute the target address of the call and save it in CALL_TMP_REG
        # 3. Jump to the call jit elt trampoline
        # /!\ The trampoline offset is computed starting from the base address

        # 0x00 auipc ra, 0                          |  \
        # 0x04 addi  ra, ra, 0  0x14                | - > Generate return address
        # 0x08 auipc temp_call, off_high            |  \
        # 0x0c addi  temp_call, temp_call, off_low  | - > Generate call target
        # 0x10 j     call_tramp                     | - > Jump to the trampoline
        # 0x14 < RA should point here!
        try:
            # Split offset
            offset_low: int
            offset_high: int
            offset_low, offset_high = InstructionBuilder.split_offset(
                offset - 0x8, 0x14
            )
        except WrongOffsetException as err:
            logger.error(err)
            raise
        # Note: minimum offset size of call, mitigation two instructions before call
        return [
            # 1. Save RA
            UInstruction.auipc(RA, 0),
            IInstruction.addi(RA, RA, 0x14),
            # Note: 0x14 to aim at the end of this call (after j)
            # 2. Save target
            UInstruction.auipc(CALL_TMP_REG, offset_high),
            IInstruction.addi(CALL_TMP_REG, CALL_TMP_REG, offset_low),
            # 3. Jump to trampoline
            JInstruction.j(call_trampoline_offset - 0x10),
            # Note: -0x10 to mitigate the 4 previous instructions
        ]

    @staticmethod
    def build_pic_base_call(
        offset: int, hit_case: int, hit_case_reg: int = HIT_CASE_REG
    ) -> List[Instruction]:
        # Base method, no trampolines
        try:
            # Split offset
            offset_low: int
            offset_high: int
            offset_low, offset_high = InstructionBuilder.split_offset(offset - 4, 0xC)
        except WrongOffsetException as err:
            logger.error(err)
            raise
        # 1. Load hit case
        # 2. Jump to the PC-related PIC location
        return [
            IInstruction.addi(rd=hit_case_reg, rs1=X0, imm=hit_case),
            UInstruction.auipc(rd=RA, imm=offset_high),
            IInstruction.jalr(rd=RA, rs1=RA, imm=offset_low),
        ]

    @staticmethod
    def build_pic_trampoline_call(
        offset: int,
        call_trampoline_offset: int,
        hit_case: int,
        hit_case_reg: int = HIT_CASE_REG,
    ) -> List[Instruction]:
        # This method uses the trampoline to call/return from JIT elements
        # It is composed as follows:
        # 1. Needed case hit
        # 2/3. Jump to the PC-related PIC location
        try:
            # Split offset
            offset_low: int
            offset_high: int
            offset_low, offset_high = InstructionBuilder.split_offset(
                offset - 0xC, 0x18
            )
        except WrongOffsetException as err:
            logger.error(err)
            raise
        # Note: minimum offset size of call,
        #       mitigation of the three instructions before call
        return [
            # 1. Hit case
            IInstruction.addi(rd=hit_case_reg, rs1=X0, imm=hit_case),
            # 2. Save RA
            UInstruction.auipc(RA, 0),
            IInstruction.addi(RA, RA, 0x14),
            # Note: 0x14 to aim at the end of this call (after j)
            # 3. Save target
            UInstruction.auipc(CALL_TMP_REG, offset_high),
            IInstruction.addi(CALL_TMP_REG, CALL_TMP_REG, offset_low),
            # 4. Jump to trampoline
            JInstruction.j(call_trampoline_offset - 0x14),
            # Note: -0x14 to mitigate the 5 previous instructions
        ]

    # Specific structures
    # \__________________

    @staticmethod
    def build_loop(
        loop_nb: int,
        loop_reg: int,
        loop_body: List[Instruction],
    ) -> List[Instruction]:
        # Loop:
        #   1 - Load the loop_nb in the loop reg
        #   1 - Sub 1 from the loop reg
        #   2 - Add the loop body (should not touch the loop reg)
        #   3 - Branch back to the beginning if not reached
        instructions: List[Instruction] = [
            IInstruction.addi(rd=loop_reg, rs1=X0, imm=loop_nb),
            IInstruction.addi(rd=loop_reg, rs1=loop_reg, imm=-1),
        ]
        instructions += loop_body
        # TODO: Add check if it fits in the branch
        offset = -(len(instructions) - 2) * 4
        instructions.append(BInstruction.bne(rs1=X0, rs2=loop_reg, imm=offset))

        return instructions

    @staticmethod
    def build_switch_case(
        case_number: int,
        method_offset: int,
        hit_case_reg: int = HIT_CASE_REG,
        cmp_reg: int = CMP_REG,
    ) -> List[Instruction]:
        # Switch for one case:
        #   1 - Loading the value to compare in the compare register
        #   2 - Compare to the current case (should be in the hit case register)
        #   3 - Jump to the corresponding method if equal
        #   4 - Go to the next case if not
        # Note: beq is not used to cover a wider range (2Mb rather than 8kb)
        return [
            IInstruction.addi(rd=cmp_reg, rs1=X0, imm=case_number),
            BInstruction.bne(rs1=cmp_reg, rs2=hit_case_reg, imm=8),
            JInstruction.jal(rd=X0, imm=method_offset),
        ]

    @staticmethod
    def build_prologue(
        used_s_regs: int, local_var_nb: int, contains_call: bool
    ) -> List[Instruction]:
        # An example prologue would be:
        # addi sp sp -16 (+local vars)
        # sd s0 0(sp)
        # sd s1 4(sp)
        # sd s2 8(sp)
        # sd ra 12(sp)
        instructions: List[Instruction] = []
        stack_space: int = (
            used_s_regs + local_var_nb + (1 if contains_call else 0)
        ) * 8
        # Decrement sp by number of s registers + local variable space
        instructions.append(IInstruction.addi(rd=SP, rs1=SP, imm=-stack_space))
        # Store any saved registers used
        for i in range(used_s_regs):
            instructions.append(
                SInstruction.sd(rs1=SP, rs2=CALLEE_SAVED_REG[i], imm=i * 8)
            )
        # Store ra is a function call is made
        if contains_call:
            instructions.append(SInstruction.sd(rs1=SP, rs2=RA, imm=used_s_regs * 8))
        return instructions

    @staticmethod
    def build_epilogue(
        used_s_regs: int, local_var_nb: int, contains_call: bool
    ) -> List[Instruction]:
        # An example epilogue would be:
        # ld s0 0(sp)
        # ld s1 4(sp)
        # ld s2 8(sp)
        # ld ra 12(sp)
        # addi sp sp 16 (+local vars)
        # ret
        instructions: List[Instruction] = []
        stack_space: int = (
            used_s_regs + local_var_nb + (1 if contains_call else 0)
        ) * 8
        # Reload saved registers used
        for i in range(used_s_regs):
            instructions.append(
                IInstruction.ld(rd=CALLEE_SAVED_REG[i], rs1=SP, imm=i * 8)
            )
        # Reload ra (if necessary)
        if contains_call:
            instructions.append(IInstruction.ld(rd=RA, rs1=SP, imm=used_s_regs * 8))
        # Increment sp to previous value
        instructions.append(IInstruction.addi(rd=SP, rs1=SP, imm=stack_space))
        # Jump back to return address
        instructions.append(IInstruction.ret())
        return instructions

    @staticmethod
    def build_trampoline_epilogue(
        used_s_regs: int,
        local_var_nb: int,
        contains_call: bool,
        ret_trampoline_offset: int,
    ) -> List[Instruction]:
        # An example epilogue would be:
        # ld s0 0(sp)
        # ld s1 4(sp)
        # ld s2 8(sp)
        # ld ra 12(sp)
        # addi sp sp 16 (+local vars)
        # j ret_trampoline         <-- Changed instruction
        instructions: List[Instruction] = []
        stack_space: int = (
            used_s_regs + local_var_nb + (1 if contains_call else 0)
        ) * 8
        # Reload saved registers used
        for i in range(used_s_regs):
            instructions.append(
                IInstruction.ld(rd=CALLEE_SAVED_REG[i], rs1=SP, imm=i * 8)
            )
        # Reload ra (if necessary)
        if contains_call:
            instructions.append(IInstruction.ld(rd=RA, rs1=SP, imm=used_s_regs * 8))
        # Increment sp to previous value
        instructions.append(IInstruction.addi(rd=SP, rs1=SP, imm=stack_space))
        # Jump to the return trampoline
        instructions.append(
            JInstruction.j(ret_trampoline_offset - len(instructions) * 4)
        )
        return instructions

    # Trampoline-related
    # \_________________

    @staticmethod
    def build_pc_relative_reg_save(offset: int, register: int) -> List[Instruction]:
        # Save a pc-relative value in a given register.
        try:
            # Split offset
            offset_low: int
            offset_high: int
            offset_low, offset_high = InstructionBuilder.split_offset(offset)
        except WrongOffsetException as err:
            logger.error(err)
            raise
        return [
            UInstruction.auipc(register, offset_high),
            IInstruction.addi(register, register, offset_low),
        ]

    @staticmethod
    def build_call_jit_elt_trampoline() -> List[Instruction]:
        # The call JIT trampoline is used to call a JIT method/PIC (wow).
        # It does not do much without isolation solution set up (see RIMI builder!).
        # Note that:
        #  - The RA should be set by the caller.
        #  - The callee address is set in a dedicated register.
        return [IInstruction.jr(rs1=CALL_TMP_REG)]

    @staticmethod
    def build_ret_from_jit_elt_trampoline() -> List[Instruction]:
        # The ret JIT trampoline is used to return from a JIT method/PIC (wow).
        # It does not do much without isolation solution set up (see RIMI builder!).
        # Note that:
        #  - The RA should be set by the caller.
        return [IInstruction.ret()]
