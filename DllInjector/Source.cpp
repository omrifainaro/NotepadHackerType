#include <Windows.h>
#include <stdio.h>
#include <Shlwapi.h>

#pragma comment (lib, "Shlwapi.lib")

#define DLL_NAME "NotepadEnhancer.dll"
#define KERNEL32_DLL "kernel32.dll"
#define LOAD_LIBRARY_A "LoadLibraryA"

#define USER_BUFFER_LEN 1024

LPVOID getLoadLibraryA() {
	HMODULE hKernelDll = NULL;
	LPVOID lpLoadLibraryA = NULL;

	hKernelDll = LoadLibraryA(KERNEL32_DLL);
	if (!hKernelDll) {
		printf("Failed to load %s: error %d\n", KERNEL32_DLL, GetLastError());
		return NULL;
	}

	lpLoadLibraryA = GetProcAddress(hKernelDll, LOAD_LIBRARY_A);
	if (!lpLoadLibraryA) {
		printf("Failed to get proc address of %s: error %d\n", LOAD_LIBRARY_A, GetLastError());
	}

	FreeLibrary(hKernelDll);
	return lpLoadLibraryA;
}

BOOL injectDll(DWORD pid, char* dllPath, size_t size) {
	HANDLE hProc = NULL;
	LPVOID lpDllPath = NULL;
	SIZE_T bytesWritten = 0;
	BOOL iResult = 0;
	LPVOID lpLoadLibraryA = NULL;
	HANDLE hExThr = NULL;

	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProc) {
		printf("Failed to open process with pid %d: error %d\n", pid, GetLastError());
		goto CLEANUP;
	}

	lpDllPath = VirtualAllocEx(hProc, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!lpDllPath) {
		printf("Failed to virtual alloc memory in process: error %d\n", GetLastError());
		goto CLEANUP;
	}

	iResult = WriteProcessMemory(hProc, lpDllPath, dllPath, size, &bytesWritten);
	if (!iResult) {
		printf("Failed to write process memory: error %d\n", GetLastError());
		goto CLEANUP;
	}

	lpLoadLibraryA = getLoadLibraryA();
	if (!lpLoadLibraryA) { 
		goto CLEANUP;
	}

	hExThr = CreateRemoteThread(hProc, NULL, 0, 
		(LPTHREAD_START_ROUTINE)lpLoadLibraryA, 
		lpDllPath, 0, NULL);

	if (!hExThr) {
		printf("Failed to create remote thread: error %d\n", GetLastError());
		goto CLEANUP;
	}

	printf("Hurray! we successfuly injected the DLL in to %d\n", pid);
	return TRUE;
CLEANUP:
	if (lpDllPath) {
		VirtualFreeEx(hProc, lpDllPath, 0, MEM_RELEASE);
	}
	if (hProc != INVALID_HANDLE_VALUE && hProc != NULL) {
		CloseHandle(hProc);
	}
	return FALSE;
}

int main() {
	DWORD pid = 0;
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(STARTUPINFOA);
	char buffer[MAX_PATH];
	char dllPath[MAX_PATH + sizeof(DLL_NAME)];

	if (!GetCurrentDirectoryA(MAX_PATH, buffer)) {
		printf("Couldn't get working directory: %d!\n", GetLastError());
		return -1;
	}

	PathCombineA(dllPath, buffer, DLL_NAME);

	//snprintf(dllPath, MAX_PATH + sizeof(DLL_NAME), "%s\\%s", buffer, DLL_NAME);
	printf("Injecting %s, %d!\n", dllPath, strlen(dllPath) + 1);

	puts("Enter pid:");
	scanf_s("%d", &pid);

	// For testing:
	//CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi);
	//puts("Waiting to inject!");
	//Sleep(1000);
	//printf("Now injecting %p\n", pi.hThread);
	//pid = GetProcessId(pi.hProcess);
	

	printf("Injecting dll in to process: %d\n", pid);
	return injectDll(pid, dllPath, strlen(dllPath) + 1);
}