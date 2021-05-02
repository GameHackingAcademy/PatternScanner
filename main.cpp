/*
A pattern scanner that will search a running Wesnoth process for the bytes 0x29 42 04. These bytes are the opcode for the sub instruction 
that is responsible for subtracting gold from a player when recruiting a unit. 

The scanner works by using CreateToolhelp32Snapshot to find the Wesnoth process and the main Wesnoth module. 
Once located, a buffer is created and the module's memory is read into that buffer. The module's memory mainly contains opcodes for instruction.

Once loaded, we loop through all the bytes in the buffer and search for our pattern. Once found, we print the offset.

The full explanation for how this code works is available at: https://gamehacking.academy/lesson/34
*/

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// Our opcode pattern to scan for inside the process
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
		// Only scan for patterns inside the Wesnoth process
		if (wcscmp(pe32.szExeFile, L"wesnoth.exe") == 0) {
			module_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
			
			// Retrieve a process handle so that we can read the game's memory
			HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, true, pe32.th32ProcessID);

			Module32First(module_snapshot, &me32);
			do {
				// Wesnoth is made up of many modules. For our example, we only want to scan the main executable module's code
				if (wcscmp(me32.szModule, L"wesnoth.exe") == 0) {
					// Due to the size of the code, dynamically create a buffer after determining the size
					unsigned char *buffer = (unsigned char*)calloc(1, me32.modBaseSize);
					DWORD bytes_read = 0;

					// Read the entire code block into our buffer
					ReadProcessMemory(process, (void*)me32.modBaseAddr, buffer, me32.modBaseSize, &bytes_read);
					
					// For each byte in the game's code, check to see if the pattern of bytes starts at the byte
					for (unsigned int i = 0; i < me32.modBaseSize - sizeof(bytes); i++) {
						for (int j = 0; j < sizeof(bytes); j++) {
							// If so, continue to check if all the bytes match. If one does not, exit the loop
							if (bytes[j] != buffer[i + j]) {
								break;
							}

							// If we are at the end of the loop, the bytes must all match
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
