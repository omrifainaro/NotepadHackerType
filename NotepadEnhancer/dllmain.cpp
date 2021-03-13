// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

//#define HOOK_OFFSET (0x0007FF9988E4B20 - 0x0007FF9987B0000)
//#define HOOK_OFFSET (0x0007FF9D5643D10 - 0x0007FF9D5510000)
//#define HOOK_OFFSET 0x000000013A804
#define PAGE_SIZE 4096
#define PAGE_ALLIGN(x) ((x / PAGE_SIZE) * PAGE_SIZE)

// Used for the content of the hacker type
#define HACKER_TYPER_FN "C:\\Python27\\LICENSE.txt"
// Log file for debugging
#define LOG_FILE "notepadlog.txt"

BYTE functionMagic[] = {
	0x48, 0x89, 0x5c, 0x24, 0x18, 0x48, 0x89, 0x6c, 0x24, 0x20, 
	0x56, 0x57, 0x41, 0x56, 0x48, 0x83, 0xec, 0x30, 0x48, 0x8b, 
	0x5, 0xf, 0x96, 0xf, 0x0, 0x48, 0x33, 0xc4, 0x48, 0x89, 0x44, 
	0x24, 0x28, 0x8b, 0xfa, 0x89, 0x54, 0x24, 0x20, 0x48, 0x8b, 0xd9, 
	0xe8, 0xb9, 0xfb, 0xf1, 0xff, 0xf6, 0x43, 0x74, 0x4, 0x8b, 0xf0, 
	0xf, 0x85, 0xec, 0x1, 0x0, 0x0, 0x66, 0x83, 0xff, 0x1b, 0xf, 0x84,
	0xe2, 0x1, 0x0, 0x0, 0x66, 0x83, 0xff, 0x8, 0x75, 0xd, 0xf6, 0x83,
	0x94, 0x1, 0x0
};

/**
56                      push   rsi
51                      push   rcx
48 be 11 11 11 11 11    movabs rsi, 0x1111111111111111
11 11 11
48 b9 22 22 22 22 22    movabs rcx, 0x2222222222222222
22 22 22
48 8b 01                mov    rax, QWORD PTR [rcx]
48 01 c6                add    rsi, rax
8a 16                   mov    dl, BYTE PTR [rsi]
48 ff c0                inc    rax
48 89 01                mov    QWORD PTR [rcx], rax
59                      pop    rcx
5e                      pop    rsi
48 89 5c 24 18          mov    QWORD PTR [rsp+0x18], rbx
48 89 6c 24 20          mov    QWORD PTR [rsp+0x20], rbp
56                      push   rsi
57                      push   rdi
48 b8 33 33 33 33 33    movabs rax, 0x3333333333333333
33 33 33
ff e0                   jmp    rax
*/
BYTE shellcode[] = { 
	0x56, 0x51, 0x48, 0xBE, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 
	0x11, 0x11, 0x48, 0xB9, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 
	0x22, 0x22, 0x48, 0x8B, 0x01, 0x48, 0x01, 0xC6, 0x8A, 0x16, 
	0x48, 0xFF, 0xC0, 0x48, 0x89, 0x01, 0x59, 0x5E, 0x48, 0x89, 
	0x5C, 0x24, 0x18, 0x48, 0x89, 0x6C, 0x24, 0x20, 0x56, 0x57, 
	0x48, 0xB8, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 
	0xFF, 0xE0 
};

/**
48 b8 34 12 34 12 34    movabs rax,0x1234123412341234
12 34 12
ff e0                   jmp    rax
*/
BYTE trampoline[] = { 0x48, 0xB8, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0xFF, 0xE0 };

// File pointer
FILE* fp;

// The pointer to the data to write as the hacker typer
char* hackertyper = NULL;

// A global to be used for the indexing of the data
UINT32 pos = 0;


/// <summary>
/// Writes data to a log file, keeping track of the last line written
/// </summary>
/// <param name="format">like printf</param>
/// <param name="">the args to printf</param>
void log(const char* format, ...) {
	if (!fp)
		fp = fopen(LOG_FILE, "w");
	va_list args;
	va_start(args, format);
	vfprintf(fp, format, args);
	va_end(args);
	fflush(fp);
}

/// <summary>
/// Writes an array of elements as hex bytes to the log file
/// </summary>
/// <param name="arr">the array</param>
/// <param name="size">size of the array</param>
void log_array(BYTE arr[], SIZE_T size) {
	for (size_t i = 0; i < size; i++) {
		log("%02x ", arr[i]);
	}
	log("\n");
}

/// <summary>
/// Writes the trampoline in to memory
/// </summary>
/// <param name="func">The function to override with the rituch</param>
/// <param name="shellcodeAddr">The address of the shellcode to jump to</param>
/// <returns>Error code</returns>
int writeRituch(LPVOID func, LPVOID shellcodeAddr) {
	memcpy(&trampoline[2], &shellcodeAddr, sizeof(LPVOID));

	log("Rituch changed: ");
	log_array(trampoline, sizeof(trampoline));

	memcpy(func, trampoline, sizeof(trampoline)); // IMMA LE - This rituches the memory
	return 0;
}

/// <summary>
/// Finds an replaces the bytes in data from find to replace
/// </summary>
/// <param name="data">The data to change in place</param>
/// <param name="dataSize">size of data</param>
/// <param name="find">pattern to find in data</param>
/// <param name="replace">data to be written instead</param>
/// <param name="size">the size of find and replace!!!</param>
/// <returns>error code</returns>
int findAndReplace(BYTE* data, SIZE_T dataSize, BYTE* find, BYTE* replace, SIZE_T size) {
	for (size_t i = 0; i < dataSize; i++) {
		if (!memcmp(&data[i], find, size)) {
			memcpy(&data[i], replace, size);
			return 0;
		}
	}
	return 1;
}

/// <summary>
/// This changes the shellcode to the global pointers of the variables
/// </summary>
/// <param name="ret">A pointer to jump back to after the shellcode</param>
void shellcodeChanger(LPVOID ret) {
	int iret = 0;
	LPVOID ptr = &pos;
	ret = (LPVOID)((unsigned long long)ret + sizeof(trampoline));

	iret += findAndReplace(shellcode, sizeof(shellcode), (BYTE*)"\x11\x11\x11\x11\x11\x11\x11\x11", (BYTE*)&hackertyper, sizeof(LPVOID));
	iret += findAndReplace(shellcode, sizeof(shellcode), (BYTE*)"\x22\x22\x22\x22\x22\x22\x22\x22", (BYTE*)&ptr, sizeof(LPVOID));
	iret += findAndReplace(shellcode, sizeof(shellcode), (BYTE*)"\x33\x33\x33\x33\x33\x33\x33\x33", (BYTE*)&ret, sizeof(LPVOID));
	log("Sum of replacements: %d\n", iret);
}

/// <summary>
/// Allocates a RWX page in memory and writes our shellcode in to it
/// </summary>
/// <param name="ret">The address to return to</param>
/// <returns>address of shellcode</returns>
LPVOID allocateShellcode(LPVOID ret) {
	LPVOID ptr = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	shellcodeChanger(ret); // patches the shellcode with our global pointers

	log("Shellcode changed: ");
	log_array(shellcode, sizeof(shellcode));

	memcpy(ptr, shellcode, sizeof(shellcode)); // Writes the shellcode in to memory to be executed
	return ptr;
}

unsigned int findOffsetByMagic(LPVOID h, unsigned int max) {
	BYTE* data = (BYTE*)h;
	for (size_t i = 0; i < max; i++) {
		if (!memcmp(&data[i], functionMagic, sizeof(functionMagic))) {
			log("Found offset: %d\n", i);
			return i;
		}
	}
	return -1;
}

/// <summary>
/// Using the offset of the function from the dll base changes the protection to RWX
/// then writes the rituch that jumps to our shellcode
/// </summary>
/// <param name="h">base address of comctl32.dll</param>
/// <returns>Error code</returns>
int patchFunction(LPVOID h) {
	unsigned int hookOffset = findOffsetByMagic(h, 0xffffff);
	if (hookOffset > 0xffffff) {
		log("Couldn't fund function!\n");
		return -1;
	}
	LPVOID func = (LPVOID)((unsigned long long)h + hookOffset);
	DWORD oldProtect = 0;
	LPVOID shellcode = 0;

	if (!VirtualProtect((LPVOID)PAGE_ALLIGN((unsigned long long)func), PAGE_SIZE*3, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		log("Couldn't change the protection of the function to hook page: %d\n", GetLastError());
		return -1;
	}

	shellcode = allocateShellcode(func);
	log("Allocating shellcode: %#llx\n", shellcode);

	log("Writing rituch: %#llx\n", func);
	writeRituch(func, shellcode);
	log("Done!\n");

	return 0;
}

/// <summary>
/// This function finds the base address of comctl32.dll
/// then calls patchFunction with the base address to create the rituch
/// </summary>
/// <returns>Error code</returns>
int findAndPatchComctl32() {
	HMODULE h = LoadLibraryA("comctl32.dll");
	int ret = 0;

	if (!h) {
		ret = -1;
		log("Couldn't open comctl32.dll: %d\n", GetLastError());
		goto cleanup;
	}

	log("Successfully opened comctl32.dll: %#llx\n", h);
	patchFunction(h);
cleanup:
	if (h != NULL)
		FreeLibrary(h);
	return ret;
}

/// <summary>
/// Reads the data of the file in to the heap and sets hackertyper to point to it
/// </summary>
/// <param name="filename">filename to be read</param>
void readTheHackerTyperData(const char* filename) {
	FILE* fp2 = fopen(filename, "r");
	SIZE_T size = 0;

	log("File pointer created: %p\n", fp2);
	
	fseek(fp2, 0, SEEK_END);
	size = ftell(fp2);
	fseek(fp2, 0, SEEK_SET);

	hackertyper = (char*) malloc(size * sizeof(char));
	fread(hackertyper, sizeof(char), size, fp2);
	log("Read file: ");
	log_array((BYTE*)hackertyper, 10);
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		log("I am alive motha fucka!\n");
		readTheHackerTyperData(HACKER_TYPER_FN);
		findAndPatchComctl32();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}