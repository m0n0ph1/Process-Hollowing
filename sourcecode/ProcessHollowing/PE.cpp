#include "stdafx.h"
#include "windows.h"
#include "internals.h"
#include "pe.h"

HMODULE hNTDLL = nullptr;
_NtQueryInformationProcess ntQueryInformationProcess = nullptr;

bool InitializeNtQueryInformationProcess()
{
    hNTDLL = LoadLibraryA("ntdll");
    if (!hNTDLL)
        return false;

    FARPROC fpNtQueryInformationProcess = GetProcAddress(hNTDLL, "NtQueryInformationProcess");
    if (!fpNtQueryInformationProcess)
        return false;

    ntQueryInformationProcess = (_NtQueryInformationProcess)fpNtQueryInformationProcess;
    return true;
}

DWORD FindRemotePEB(HANDLE hProcess)
{
    if(!ntQueryInformationProcess)
    {
        if(!InitializeNtQueryInformationProcess())
            return 0;
    }

    PROCESS_BASIC_INFORMATION basicInfo = {0};
    DWORD dwReturnLength = 0;

    ntQueryInformationProcess(hProcess, 0, &basicInfo, sizeof(basicInfo), &dwReturnLength);
    return basicInfo.PebBaseAddress;
}

PEB* ReadRemotePEB(HANDLE hProcess)
{
    DWORD dwPEBAddress = FindRemotePEB(hProcess);
    if(!dwPEBAddress)
        return nullptr;

    PEB* pPEB = new PEB();

    if(!ReadProcessMemory(hProcess, (LPCVOID)dwPEBAddress, pPEB, sizeof(PEB), nullptr))
    {
        delete pPEB;
        return nullptr;
    }

    return pPEB;
}

PLOADED_IMAGE ReadRemoteImage(HANDLE hProcess, LPCVOID lpImageBaseAddress)
{
    BYTE* lpBuffer = new BYTE[BUFFER_SIZE];
    if(!ReadProcessMemory(hProcess, lpImageBaseAddress, lpBuffer, BUFFER_SIZE, nullptr))
    {
        delete[] lpBuffer;
        return nullptr;	
    }

    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)lpBuffer;
    PLOADED_IMAGE pImage = new LOADED_IMAGE();

    pImage->FileHeader = (PIMAGE_NT_HEADERS32)(lpBuffer + pDOSHeader->e_lfanew);
    pImage->NumberOfSections = pImage->FileHeader->FileHeader.NumberOfSections;
    pImage->Sections = (PIMAGE_SECTION_HEADER)(lpBuffer + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32));

    delete[] lpBuffer; // Avoid memory leak
    return pImage;
}
