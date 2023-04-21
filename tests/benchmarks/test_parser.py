# import logging

# import pytest

# from benchmarks.parser import LogParser

# logger = logging.getLogger(__name__)


# # IO errors
# # \__________


# def test_extract_addresses_from_dump_unknown_file():
#     parser = LogParser()
#     with pytest.raises(EnvironmentError):
#         parser.extract_from_rocket_log(
#             start_address=0, end_address=0, rocket_log_file="non_existing_file"
#         )


# def test_extract_addresses_from_exec_log_unknown_file():
#     parser = LogParser()
#     with pytest.raises(EnvironmentError):
#         parser.extract_from_dump(dump_file="non_existing_file")


# # Dump extraction
# # \________________

# dump_data: str = """
# 0000000080002570 <handle_trap>:
#     80002570:	000017b7          	lui	a5,0x1
#     80002574:	a7378793          	addi	a5,a5,-1421 # a73 <buflen.2836+0xa33>
#     80002578:	fffff717          	auipc	a4,0xfffff
#     8000257c:	a8f73423          	sd	a5,-1400(a4) # 80001000 <tohost>
#     80002580:	0000006f          	j	80002580 <handle_trap+0x10>

# 0000000080002584 <exit>:
#     80002584:	ff010113          	addi	sp,sp,-16
#     80002588:	00113423          	sd	ra,8(sp)
#     8000258c:	fd1ff0ef          	jal	ra,8000255c <tohost_exit>

# 0000000080002590 <abort>:
#     80002590:	10d00793          	li	a5,269
#     80002594:	fffff717          	auipc	a4,0xfffff
#     80002598:	a6f73623          	sd	a5,-1428(a4) # 80001000 <tohost>
#     8000259c:	0000006f          	j	8000259c <abort+0xc>

# 00000000800025a0 <printstr>:
#     800025a0:	00054783          	lbu	a5,0(a0)
#     800025a4:	f8010113          	addi	sp,sp,-128
#     800025a8:	03f10713          	addi	a4,sp,63
#     800025ac:	00050693          	mv	a3,a0
#     800025b0:	fc077713          	andi	a4,a4,-64
#     800025b4:	06078263          	beqz	a5,80002618 <printstr+0x78>
#     800025b8:	00050613          	mv	a2,a0
#     800025bc:	00150513          	addi	a0,a0,1
#     800025c0:	00054783          	lbu	a5,0(a0)

# 0000000080002a24 <gigue_start>:
#     80002a24:	fa810113          	addi	sp,sp,-88
#     80002a28:	00813023          	sd	s0,0(sp)
#     80002a2c:	00913423          	sd	s1,8(sp)
#     80002a30:	01213823          	sd	s2,16(sp)
#     80002a34:	01313c23          	sd	s3,24(sp)
#     80002a38:	03413023          	sd	s4,32(sp)
#     80002a3c:	03513423          	sd	s5,40(sp)
#     80002a40:	03613823          	sd	s6,48(sp)
#     80002a44:	03713c23          	sd	s7,56(sp)
#     80002a48:	05813023          	sd	s8,64(sp)
#     8000331c:	05810113          	addi	sp,sp,88
#     80003320:	00008067          	ret

# 00000000800102e4 <gigue_end>:
#     800102e4:	d8c0                	sw	s0,52(s1)
#     800102e6:	0000                	unimp

# 00000000800102e8 <main>:
#     800102e8:	00000f97          	auipc	t6,0x0
#     800102ec:	218f8f93          	addi	t6,t6,536 # 80010500 <tab>
# """


# def test_extract_addresses_from_dump(mocker):
#     mocker.patch("builtins.open", mocker.mock_open(read_data=dump_data))
#     parser = LogParser()
#     # Triggering the open will run into the mocked file!
#     (start_address, ret_address, end_address) = parser.extract_from_dump("mocked_data")
#     assert start_address == 0x80002A24
#     assert ret_address == 0x80003320
#     assert end_address == 0x800102E0


# # Exec logs extraction
# # \____________________

# exec_log_data: str = (
#     "using random seed 1681861037\n"
#     "This emulator compiled with JTAG Remote Bitbang client."
#     "To enable, use +jtag_rbb_enable=1.\n"
#     "Listening on port 46601\n"
#     "C0:    1114705 [1] pc=[0000000080002a24] W[r 2=0000000080030c28][1] "
#     "R[r 2=0000000080030c80] R[r 0=0000000000000000] inst=[fa810113] "
#     "addi    sp, sp, -88\n"
#     "C0:    1114738 [1] pc=[0000000080002a28] W[r 0=0000000000000000][0] "
#     "R[r 2=0000000080030c28] R[r 8=0000000000000000] inst=[00813023] "
#     "sd      s0, 0(sp)\n"
#     "C0:    1114739 [1] pc=[0000000080002a2c] W[r 0=0000000000000000][0] "
#     "R[r 2=0000000080030c28] R[r 9=0000000000000000] inst=[00913423] "
#     "sd      s1, 8(sp)\n"
#     "C0:    1114740 [1] pc=[0000000080002a30] W[r 0=0000000000000000][0] "
#     "R[r 2=0000000080030c28] R[r18=0000000080010d20] inst=[01213823] "
#     "sd      s2, 16(sp)\n"
#     "C0:    1114779 [1] pc=[0000000080002a34] W[r 0=0000000000000000][0] "
#     "R[r 2=0000000080030c28] R[r19=0000000000000000] inst=[01313c23] "
#     "sd      s3, 24(sp)\n"
#     "C0:    1114780 [1] pc=[0000000080002a38] W[r 0=0000000000000000][0] "
#     "R[r 2=0000000080030c28] R[r20=0000000000000001] inst=[03413023] "
#     "sd      s4, 32(sp)\n"
#     "C0:    1114781 [1] pc=[0000000080002a3c] W[r 0=0000000000000000][0] "
#     "R[r 2=0000000080030c28] R[r21=0000000080010d40] inst=[03513423] "
#     "sd      s5, 40(sp)\n"
#     "C0:    1114782 [1] pc=[0000000080002a40] W[r 0=0000000000000000][0] "
#     "R[r 2=0000000080030c28] R[r22=0000000000000000] inst=[03613823] "
#     "sd      s6, 48(sp)\n"
#     "C0:    1114783 [1] pc=[0000000080002a44] W[r 0=0000000000000000][0] "
#     "R[r 2=0000000080030c28] R[r23=0000000000000000] inst=[03713c23] "
#     "sd      s7, 56(sp)\n"
#     "C0:    1114784 [1] pc=[0000000080002a48] W[r 0=0000000000000000][0] "
#     "R[r 2=0000000080030c28] R[r24=0000000000000000] inst=[05813023] "
#     "sd      s8, 64(sp)\n"
#     "C0:    1114785 [1] pc=[0000000080002a4c] W[r 0=0000000000000000][0] "
#     "R[r 2=0000000080030c28] R[r25=0000000000000000] inst=[05913423] "
#     "sd      s9, 72(sp)\n"
#     "C0:    1114786 [1] pc=[0000000080002a50] W[r 0=0000000000000000][0] "
#     "R[r 2=0000000080030c28] R[r 1=00000000800102f4] inst=[04113823] "
#     "sd      ra, 80(sp)\n"
#     "C0:    1114787 [1] pc=[0000000080002a54] W[r 1=0000000080002a54][1] "
#     "R[r 0=0000000000000000] R[r 0=0000000000000000] inst=[00000097] "
#     "auipc   ra, 0x0\n"
#     "C0:    1114788 [1] pc=[0000000080002a58] W[r 1=0000000080002a68][1] "
#     "R[r 1=0000000080002a54] R[r 0=0000000000000000] inst=[01408093] "
#     "addi    ra, ra, 20\n"
#     "C0:    1114789 [1] pc=[0000000080002a5c] W[r 6=0000000080006a5c][1] "
#     "R[r 0=0000000000000000] R[r 0=0000000000000000] inst=[00004317] "
#     "auipc   t1, 0x4\n"
#     "C0:    1114790 [1] pc=[0000000080002a60] W[r 6=0000000080007004][1] "
#     "R[r 6=0000000080006a5c] R[r 0=0000000000000000] inst=[5a830313] "
#     "addi    t1, t1, 1448\n"
#     "C0:    1125572 [1] pc=[0000000080003308] W[r22=0000000000000000][1] "
#     "R[r 2=0000000080030c28] R[r 0=0000000000000000] inst=[03013b03] "
#     "ld      s6, 48(sp)\n"
#     "C0:    1125573 [1] pc=[000000008000330c] W[r23=0000000000000000][1] "
#     "R[r 2=0000000080030c28] R[r 0=0000000000000000] inst=[03813b83] "
#     "ld      s7, 56(sp)\n"
#     "C0:    1125574 [1] pc=[0000000080003310] W[r24=0000000000000000][1] "
#     "R[r 2=0000000080030c28] R[r 0=0000000000000000] inst=[04013c03] "
#     "ld      s8, 64(sp)\n"
#     "C0:    1125575 [1] pc=[0000000080003314] W[r25=0000000000000000][1] "
#     "R[r 2=0000000080030c28] R[r 0=0000000000000000] inst=[04813c83] "
#     "ld      s9, 72(sp)\n"
#     "C0:    1125576 [1] pc=[0000000080003318] W[r 1=00000000800102f4][1] "
#     "R[r 2=0000000080030c28] R[r 0=0000000000000000] inst=[05013083] "
#     "ld      ra, 80(sp)\n"
#     "C0:    1125577 [1] pc=[000000008000331c] W[r 2=0000000080030c80][1] "
#     "R[r 2=0000000080030c28] R[r 0=0000000000000000] inst=[05810113] "
#     "addi    sp, sp, 88\n"
#     "C0:    1125578 [1] pc=[0000000080003320] W[r 0=0000000080003324][1 ]"
#     "R[r 1=00000000800102f4] R[r 0=0000000000000000] inst=[00008067] "
#     "ret\n"
# )


# def extract_from_rocket_log(mocker):
#     mocker.patch("builtins.open", mocker.mock_open(read_data=exec_log_data))
#     parser = LogParser()
#     # Triggering the open will run into the mocked file!
#     (seed, start_cycle, end_cycle) = parser.extract_from_rocket_log(
#         start_address=0x80002A24, end_address=0x80003320, rocket_log_file="mocked_data"
#     )
#     assert seed == 1681861037
#     assert start_cycle == 1114705
#     assert end_cycle == 1125578
