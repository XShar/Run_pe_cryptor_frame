#pragma once

bool create_new_process1(IN LPSTR path, OUT PROCESS_INFORMATION &pi)
{
	STARTUPINFOA si;
    memset(&si, 0, sizeof(STARTUPINFOA));
    si.cb = sizeof(STARTUPINFOA);

    memset(&pi, 0, sizeof(PROCESS_INFORMATION));	

	uintptr_t base_addr = reinterpret_cast<std::uintptr_t>(LI_FIND(LoadLibraryA)("kernel32.dll"));
	if (!LI_GET(base_addr, CreateProcessA)(
            NULL,
            path,
            NULL, //lpProcessAttributes
            NULL, //lpThreadAttributes
            FALSE, //bInheritHandles
            CREATE_SUSPENDED, //dwCreationFlags
            NULL, //lpEnvironment 
            NULL, //lpCurrentDirectory
            &si, //lpStartupInfo
            &pi //lpProcessInformation
        ))
    {
        printf("[ERROR] CreateProcess failed, Error = %x\n", GetLastError());
        return false;
    }
	printf("2\n");
    return true;
}
