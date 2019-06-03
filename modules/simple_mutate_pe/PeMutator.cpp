#include <iostream>
#include <stdio.h>
#include <string.h>
#include "LDasm.h"
#include <windows.h>

#include "..\..\modules\run_pe\pe_hdrs_helper.h"

/* length_disasm */
static unsigned int length_disasm(void * opcode0) {

	unsigned char* opcode = (unsigned char*)opcode0;

	unsigned int flag = 0;
	unsigned int ddef = 4, mdef = 4;
	unsigned int msize = 0, dsize = 0;

	unsigned char op, modrm, mod, rm;

prefix:
	op = *opcode++;

	/* prefix */
	if (CHECK_PREFIX(op)) {
		if (CHECK_PREFIX_66(op)) ddef = 2;
		else if (CHECK_PREFIX_67(op)) mdef = 2;
		goto prefix;
	}

	/* two byte opcode */
	if (CHECK_0F(op)) {
		op = *opcode++;
		if (CHECK_MODRM2(op)) flag++;
		if (CHECK_DATA12(op)) dsize++;
		if (CHECK_DATA662(op)) dsize += ddef;
	}

	/* one byte opcode */
	else {
		if (CHECK_MODRM(op)) flag++;
		if (CHECK_TEST(op) && !(*opcode & 0x38)) dsize += (op & 1) ? ddef : 1;
		if (CHECK_DATA1(op)) dsize++;
		if (CHECK_DATA2(op)) dsize += 2;
		if (CHECK_DATA66(op)) dsize += ddef;
		if (CHECK_MEM67(op)) msize += mdef;
	}

	/* modrm */
	if (flag) {
		modrm = *opcode++;
		mod = modrm & 0xc0;
		rm = modrm & 0x07;
		if (mod != 0xc0) {
			if (mod == 0x40) msize++;
			if (mod == 0x80) msize += mdef;
			if (mdef == 2) {
				if ((mod == 0x00) && (rm == 0x06)) msize += 2;
			}
			else {
				if (rm == 0x04) rm = *opcode++ & 0x07;
				if (rm == 0x05 && mod == 0x00) msize += 4;
			}
		}
	}

	opcode += msize + dsize;

	return opcode - (unsigned char *)opcode0;
}

bool Mutate(BYTE* inBuf, DWORD SizeToMut, bool MutAll)
{
	int InstructionCount = 0;
	int MutationCount = 0;

	//check payload:
	IMAGE_NT_HEADERS32* payload_nt_hdr32 = get_nt_hrds32(inBuf);
	if (payload_nt_hdr32 == NULL) {
		printf("Invalid payload: %p\n", inBuf);
		return false;
	}

	const ULONGLONG base_code_addr = payload_nt_hdr32->OptionalHeader.BaseOfCode;
	SIZE_T payloadImageSize = payload_nt_hdr32->OptionalHeader.SizeOfImage;

	for (int i = base_code_addr; i < payloadImageSize - 16; i += length_disasm(&inBuf[i]))
	{
		if (length_disasm(&inBuf[i]) <= 0)
		{
			printf("%s \n", "Error Disassembling");
			return 0;
		}

		++InstructionCount;

		if (inBuf[i] == 0x55)
			if (inBuf[i + 1] == 0x8B)
				if (inBuf[i + 2] == 0xEC)
					if (inBuf[i + 3] == 0x83) // add esp, -x
						if (inBuf[i + 4] == 0xC4)
							if (((char)inBuf[i + 5] <= 0) && (inBuf[i + 5] != 0x80)) // -128 sux
								if (rand() % 2 || MutAll)
								{
									inBuf[i] = 0xC8;
									inBuf[i + 1] = -inBuf[i + 5];
									inBuf[i + 2] = 0;
									inBuf[i + 3] = 0;
									inBuf[i + 4] = 0x90;
									inBuf[i + 5] = 0x90;
									++MutationCount;

								}


		// enter
		if (inBuf[i] == 0x55)
			if (inBuf[i + 1] == 0x8B)
				if (inBuf[i + 2] == 0xEC)
					if (inBuf[i + 3] == 0x81) // add esp, xxxxxxxx
						if (inBuf[i + 4] == 0xC4)
							if ((inBuf[i + 7] == 0xFF) && (inBuf[i + 8] == 0xFF))
								if (rand() % 2 || MutAll)
								{
									inBuf[i] = 0xC8;
									long t = -((long)inBuf[i + 5] + (inBuf[i + 6] << 8));
									inBuf[i + 1] = t;
									inBuf[i + 2] = t >> 8;
									inBuf[i + 3] = 0;
									inBuf[i + 4] = 0x90;
									inBuf[i + 5] = 0x90;
									inBuf[i + 6] = 0x90;
									inBuf[i + 7] = 0x90;
									inBuf[i + 8] = 0x90;
									++MutationCount;
								}

		// enter
		if (inBuf[i] == 0x55)
			if (inBuf[i + 1] == 0x8B)
				if (inBuf[i + 2] == 0xEC)
					if (inBuf[i + 3] == 0x83) // sub esp, x
						if (inBuf[i + 4] == 0xEC)
							if ((signed)inBuf[i + 5] >= 0)
								if (rand() % 2 || MutAll)
								{
									inBuf[i] = 0xC8;
									inBuf[i + 1] = inBuf[i + 5];
									inBuf[i + 2] = 0;
									inBuf[i + 3] = 0;
									inBuf[i + 4] = 0x90;
									inBuf[i + 5] = 0x90;
									++MutationCount;
								}

		// mov esp, ebp
		// pop ebp
		// leave
		if (inBuf[i] == 0x8B)
			if (inBuf[i + 1] == 0xE5)
				if (inBuf[i + 2] == 0x5D)
					if (rand() % 2 || MutAll)
					{
						inBuf[i] == 0xC9;
						inBuf[i + 1] == 0x90;
						inBuf[i + 2] == 0x90;
						++MutationCount;
					}

		// Inverse ADD/SUB/AND/OR/XOR/MOV/CMP Reg1, Reg2
		if (inBuf[i] <= 0x3B || inBuf[i] == 0x8B || inBuf[i] == 0x89)
			if (inBuf[i] & 9 == 1)
				if (length_disasm(&inBuf[i]) == 2)
					if (inBuf[i + 1] & 0xC0 == 0xC0)
						if (rand() % 2 || MutAll)
						{
							++MutationCount;
							inBuf[i] ^= 2;
							BYTE reg1 = inBuf[i + 1] & 7;
							BYTE reg2 = ((inBuf[i + 1] & 0x38) >> 3);
							inBuf[i + 1] = (reg1 << 3) + 0xC0 + reg2;
						}

		//if (xxx==yyy)
	//001100xx 11xxxyyy     ; xor r1,r1
	//001010xx 11xxxyyy     ; sub r1,r1
		if (((inBuf[i + 1] & 0xC0) == 0xC0) && (((inBuf[i + 1] >> 3) & 7) == (inBuf[i + 1] & 7)))
			if (((inBuf[i] & 0xFC) == 0x30) || ((inBuf[i] & 0xFC) == 0x28))
				if (rand() % 2 || MutAll)
				{
					inBuf[i] ^= 0x30 ^ 0x28;
					++MutationCount;
				}

		//if (xxx==yyy)
		//0000100x 11xxxyyy     ; or r1,r1
		//1000010x 11xxxyyy     ; test r1,r1
		if (((inBuf[i + 1] & 0xC0) == 0xC0) && (((inBuf[i + 1] >> 3) & 7) == (inBuf[i + 1] & 7)))
			if (((inBuf[i] & 0xFE) == 0x08) || ((inBuf[i] & 0xFE) == 0x84))
				if (rand() % 2 || MutAll)
				{
					inBuf[i] ^= 0x08 ^ 0x84;
					++MutationCount;
				}

		// TEST Reg, Reg
	// AND Reg, Reg
		if (((inBuf[i] & 0xFE) == 0x20) || ((inBuf[i] & 0xFE) == 0x84))
			if (((inBuf[i + 1] & 0xC0) == 0xC0) && (((inBuf[i + 1] >> 3) & 7) == (inBuf[i + 1] & 7)))
				if (rand() % 2 || MutAll)
				{
					inBuf[i] ^= 0x20 ^ 0x84;
					++MutationCount;
				}

		//if (aaa==bbb)
		//if (ddd==aaa)
		//001100x1 11aaabbb     ; xor/sub r1,r1
		//100010x0 11cccddd     ; mov r1l,r2l
		//00001111 10110110 11aaaddd ; movzx r1,r2l
		if (((inBuf[i] & 0xFD) == 0x31) || ((inBuf[i] & 0xFD) == 0x29))
			if ((inBuf[i + 1] & 0xC0) == 0xC0)
				if ((inBuf[i + 3] & 0xC0) == 0xC0)
					if ((((inBuf[i + 1] >> 3) ^ inBuf[i + 1]) & 7) == 0)
						if ((inBuf[i + 1] & 7) < 4)
							if ((inBuf[i + 2] & 0xFD) == 0x88)
								if (((inBuf[i + 3] >> (inBuf[i + 2] == 0x88 ? 0 : 3)) & 7) == (inBuf[i + 1] & 7))
									if (rand() % 2 || MutAll)
									{
										++MutationCount;
										inBuf[i + 2] = 0xC0 |
											(inBuf[i + 1] & 0x38) |
											((inBuf[i + 3] >> (inBuf[i + 2] == 0x88 ? 3 : 0)) & 7);
										inBuf[i + 1] = 0xB6;
										inBuf[i] = 0x0F;
										inBuf[i + 3] = 0x90;
										if (rand() % 2 || MutAll)
										{
											inBuf[i + 3] = inBuf[i + 2];
											inBuf[i + 2] = inBuf[i + 1];
											inBuf[i + 1] = inBuf[i];
											inBuf[i] = 0x90;
										}
									}

		// mov r1, fs:[0]
		// xor r1,r1
		// mov r1,fs:[r1]
		if (inBuf[i] == 0x64)
			if (inBuf[i + 1] == 0x67)
				if (inBuf[i + 2] == 0x8B)
					if ((inBuf[i + 3] & 0xC7) == 0x06)
						if (inBuf[i + 4] == 0)
							if (inBuf[i + 5] == 0)
								if (rand() % 2 || MutAll)
								{
									++MutationCount;
									inBuf[i] = 0x33;
									inBuf[i + 1] = 0xC0 | (inBuf[i + 3] & 0x38) | (inBuf[i + 3] >> 3) & 7;
									inBuf[i + 2] = 0x64;
									inBuf[i + 4] = (inBuf[i + 3] & 0x38) >> 3;
									inBuf[i + 3] = 0x8B;
									inBuf[i + 5] = 0x90;
									if (rand() % 2 || MutAll)
									{
										inBuf[i + 5] = inBuf[i + 4];
										inBuf[i + 4] = inBuf[i + 3];
										inBuf[i + 3] = inBuf[i + 2];
										inBuf[i + 2] = inBuf[i + 1];
										inBuf[i + 1] = inBuf[i];
										inBuf[i] = 0x90;
									}
								}

		// mov eax, fs:[0]
		// xor eax,eax
		// mov eax, fs:[r1]
		if (inBuf[i] == 0x64)
			if (inBuf[i + 1] == 0x67)
				if (inBuf[i + 2] == 0xA1)
					if (inBuf[i + 3] == 0)
						if (inBuf[i + 4] == 0)
							if (rand() % 2 || MutAll)
							{
								++MutationCount;
								inBuf[i] = 0x33;
								inBuf[i + 1] = 0xC0;
								inBuf[i + 2] = 0x64;
								inBuf[i + 3] = 0x8B;
								inBuf[i + 4] = 0x00;
							}

		// or ecx,-1
		// xor ecx,ecx//dec ecx
		if (inBuf[i] == 0x83)
			if ((inBuf[i + 1] & 0xF8) == 0xC8)
				if (inBuf[i + 2] == 0xFF)
					if (rand() % 2 || MutAll)
					{
						++MutationCount;
						inBuf[i] = 0x33;
						BYTE t = inBuf[i + 1] & 7;
						inBuf[i + 1] = 0xC0 | t | (t << 3);
						inBuf[i + 2] = 0x48 | t;
					}
	}

	printf("\n\n %d Mutations Done!\n\n", MutationCount);
	return true;
}