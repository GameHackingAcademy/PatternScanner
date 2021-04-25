#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

unsigned char bytes[] = { 0x29, 0x42, 0x04 };

int main(int argc, char** argv) {
	HANDLE process_snapshot = 0;
	HANDLE module_snapshot = 0;
	PROCESSENTRY32 pe32 = { 0 };
	MODULEENTRY32 me32;

	DWORD exitCode = 0;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	me32.dwSize = sizeof(MODULEENTRY32);

	// The snapshot code is a reduced version of the example code provided by Microsoft at 
	// https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
	process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	Process32First(process_snapshot, &pe32);

	do {
		if (wcscmp(pe32.szExeFile, L"wesnoth.exe") == 0) {
			module_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
			HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, true, pe32.th32ProcessID);

			Module32First(module_snapshot, &me32);
			do {
				if (wcscmp(me32.szModule, L"wesnoth.exe") == 0) {
					unsigned char *buffer = (unsigned char*)calloc(1, me32.modBaseSize);
					DWORD bytes_read = 0;

					ReadProcessMemory(process, (void*)me32.modBaseAddr, buffer, me32.modBaseSize, &bytes_read);
					for (unsigned int i = 0; i < me32.modBaseSize - sizeof(bytes); i++) {
						for (int j = 0; j < sizeof(bytes); j++) {
							if (bytes[j] != buffer[i + j]) {
								break;
							}

							if (j + 1 == sizeof(bytes)) {
								printf("%x\n", i + (DWORD)me32.modBaseAddr);
							}
						}
					}

					free(buffer);
					break;
				}

			} while (Module32Next(module_snapshot, &me32));

			CloseHandle(process);
			break;
		}
	} while (Process32Next(process_snapshot, &pe32));

	return 0;
}
