#pragma once

#include <Windows.h>
#include "ntddk.h"

//don't forget to load functions before use:
//load_ntdll_functions();

NTSTATUS (NTAPI *_NtUnmapViewOfSection) (
  IN HANDLE ProcessHandle,
  IN PVOID BaseAddress
 );


BOOL load_ntdll_functions(uintptr_t base, char* ntdll, char* NtUnmapViewOfSection)
{
    HMODULE hNtdll = LI_GET(base, GetModuleHandleA)(ntdll);
    if (hNtdll == NULL) return FALSE;
    
    _NtUnmapViewOfSection = (NTSTATUS (NTAPI *) (HANDLE, PVOID)) LI_GET(base, GetProcAddress)(hNtdll, NtUnmapViewOfSection);
    if (_NtUnmapViewOfSection == NULL) return FALSE;
    
    return TRUE;
}
