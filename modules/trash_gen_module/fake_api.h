#pragma once
#include <stdint.h>

uint32_t fake_api_instruction_gen(uint32_t instruction, uint32_t api);

extern "C" {
	void __cdecl do_fake_instr(void);
}

extern "C" {
	uint32_t __stdcall do_Random_EAX(uint32_t min, uint32_t max);
}
