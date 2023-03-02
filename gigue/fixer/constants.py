from gigue.constants import CustomInstructionInfo

FIXER_CMP_REG = 28  # t3

FIXER_INSTRUCTIONS_INFO = {
    # CFI tags
    "cficall": CustomInstructionInfo(
        name="cficall", custom_nb=0, xd=0, xs1=1, xs2=0, top7=0b0000000
    ),
    "cfiret": CustomInstructionInfo(
        name="cfiret", custom_nb=0, xd=1, xs1=0, xs2=0, top7=0b0000001
    ),
}
