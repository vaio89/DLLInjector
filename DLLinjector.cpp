#include <stdlib.h>
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <dos.h>

#define BUFSIZE 512

int main()
{
	DWORD pid = 0; //Target process Pid

	LPTHREAD_START_ROUTINE lpStartExecAddr = NULL;//Pointer of loadLibraryA() in the target process
	HANDLE hTargetProcHandle = NULL;  //Target process handle via OpenProcess()
	LPCTSTR lpcDll = NULL;
	CHAR path[50]; 
	TCHAR tcDllFullPath[BUFSIZE] = TEXT(""); //Char array to contain DLL Full path 

	printf("Vaio89 DLL Injector v%1.1f (%s)\n", 1.0, "x86");
	printf("https://github.com/vaio89/DLLInjector\n");
	printf(":)\n\n");

	printf("Target process PID:");
	scanf("%d", &pid);
	printf("DLL:");
	scanf("%s", path);
	lpcDll = path;

	GetFullPathName(path, BUFSIZE, tcDllFullPath, NULL);
	printf("DLL Full Path: %s\n", tcDllFullPath);

	printf("Step 0: Setting Debug Privileges...\n");

	TOKEN_PRIVILEGES priv = { 0 };
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
		{
			if (AdjustTokenPrivileges(hToken, false, &priv, 0, NULL, NULL) == 0)
			{
				printf("AdjustTokenPrivilege Error! [%u]\n", GetLastError());
			}
		}
		CloseHandle(hToken);
	}

	OSVERSIONINFO osverion;
	osverion.dwOSVersionInfoSize = sizeof(osverion);
	if (GetVersionEx(&osverion))
	{
		if (osverion.dwMajorVersion == 5)
		{
			printf("\t OS Version: Windows XP\n");
		}
	}
	printf("Step 1: Attaching to Target...\n");
	hTargetProcHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, 0, pid);
	if (hTargetProcHandle == NULL)
	{
		printf("[!] ERROR: Cannot Attach to the Process! [%u]\n", GetLastError());
		system("pause");
		return -1;
	}

	unsigned int writeLen = 0;
	LPVOID lpDllAddr = NULL;
	LPVOID lpWriteVal = NULL;
	LPVOID loadLibAddr = NULL;
	printf("Step 2: Allocating memory space for the DLL path\n");
	lpDllAddr = VirtualAllocEx(hTargetProcHandle, NULL, strlen(tcDllFullPath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE); //check later on
	if (lpDllAddr == NULL)
	{
		printf("[!] ERROR: Cannot Allocating memory space for the DLL path!\n");
		system("pause");
		return -1;
	}
	
	printf("Step 3: WriteProcessMemory() into 0x%08x\n", lpDllAddr);
	if (WriteProcessMemory(hTargetProcHandle, lpDllAddr, tcDllFullPath, strlen(tcDllFullPath), NULL) == 0)
	{
		printf("[!] WriteProcessMemory Failed [%u]\n", GetLastError());
		system("pause");
		return -1;
	}

	printf("Step 4-1: Looking for LoadLibrary in kernel32\n");
	loadLibAddr = (LPVOID)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
	if (loadLibAddr == NULL)
	{
		printf("\n[!] Failed to find LoadLibrary in Kernel32! Quiting...\n");
		system("pause");
		return -1;
	}
	printf("\t Found at 0x%08x\n", loadLibAddr);
	//(LPTHREAD_START_ROUTINE)loadLibAddr;
	printf("Step 4-2: Using CreateRemoteThread() to Create Thread\n");
	HANDLE rThread = NULL;
	rThread = CreateRemoteThread(hTargetProcHandle, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibAddr, (LPVOID *)lpDllAddr, 0, NULL);
	if (rThread == NULL) {
		printf("[!] CreateRemoteThread Failed! [%d] Exiting....\n", GetLastError());
		system("pause");
		return -1;
	}
	printf("\t Remote Thread created! [%d]\n", GetLastError());
	printf("\t Wait for the thread to finish...\n");
	WaitForSingleObject(rThread, INFINITE);
	
	CloseHandle(hTargetProcHandle);

	system("pause");
    return 0;
}

