# CS_ARCH_MIPS, CS_MODE_MIPS32, None
0x24,0x48,0xc7,0x00 = and $9, $6, $7
0x67,0x45,0xc9,0x30 = andi $9, $6, 17767
0x67,0x45,0xc9,0x30 = andi $9, $6, 17767
0x67,0x45,0x29,0x31 = andi $9, $9, 17767
0x21,0x30,0xe6,0x70 = clo $6, $7
0x20,0x30,0xe6,0x70 = clz $6, $7
0x84,0x61,0x33,0x7d = ins $19, $9, 6, 7
0x27,0x48,0xc7,0x00 = nor $9, $6, $7
0x25,0x18,0x65,0x00 = or $3, $3, $5
0x67,0x45,0xa4,0x34 = ori $4, $5, 17767
0x67,0x45,0xc9,0x34 = ori $9, $6, 17767
0x80,0x00,0x6b,0x35 = ori $11, $11, 128
0xc2,0x49,0x26,0x00 = rotr $9, $6, 7
0x46,0x48,0xe6,0x00 = rotrv $9, $6, $7
0xc0,0x21,0x03,0x00 = sll $4, $3, 7
0x04,0x10,0xa3,0x00 = sllv $2, $3, $5
0x2a,0x18,0x65,0x00 = slt $3, $3, $5
0x67,0x00,0x63,0x28 = slti $3, $3, 103
0x67,0x00,0x63,0x28 = slti $3, $3, 103
0x67,0x00,0x63,0x2c = sltiu $3, $3, 103
0x2b,0x18,0x65,0x00 = sltu $3, $3, $5
0xc3,0x21,0x03,0x00 = sra $4, $3, 7
0x07,0x10,0xa3,0x00 = srav $2, $3, $5
0xc2,0x21,0x03,0x00 = srl $4, $3, 7
0x06,0x10,0xa3,0x00 = srlv $2, $3, $5
0x26,0x18,0x65,0x00 = xor $3, $3, $5
0x67,0x45,0xc9,0x38 = xori $9, $6, 17767
0x67,0x45,0xc9,0x38 = xori $9, $6, 17767
0x0c,0x00,0x6b,0x39 = xori $11, $11, 12
0xa0,0x30,0x07,0x7c = wsbh $6, $7
0x27,0x38,0x00,0x01 = not $7, $8
0x20,0x48,0xc7,0x00 = add $9, $6, $7
0x67,0x45,0xc9,0x20 = addi $9, $6, 17767
0x67,0xc5,0xc9,0x24 = addiu $9, $6, -15001
0x67,0x45,0xc9,0x20 = addi $9, $6, 17767
0x67,0x45,0x29,0x21 = addi $9, $9, 17767
0x67,0xc5,0xc9,0x24 = addiu $9, $6, -15001
0x28,0x00,0x6b,0x25 = addiu $11, $11, 40
0x21,0x48,0xc7,0x00 = addu $9, $6, $7
0x00,0x00,0xc7,0x70 = madd $6, $7
0x01,0x00,0xc7,0x70 = maddu $6, $7
0x04,0x00,0xc7,0x70 = msub $6, $7
0x05,0x00,0xc7,0x70 = msubu $6, $7
0x18,0x00,0x65,0x00 = mult $3, $5
0x19,0x00,0x65,0x00 = multu $3, $5
0x22,0x48,0xc7,0x00 = sub $9, $6, $7
0xc8,0xff,0xbd,0x23 = addi $sp, $sp, -56
0x23,0x20,0x65,0x00 = subu $4, $3, $5
0xd8,0xff,0xbd,0x27 = addiu $sp, $sp, -40
0x22,0x30,0x07,0x00 = neg $6, $7
0x23,0x30,0x07,0x00 = negu $6, $7
0x21,0x38,0x00,0x01 = move $7, $8
