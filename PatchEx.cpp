#include <iostream>
#include <Windows.h>
#include "patternscan.h"
#include "memhack.h"

void CreateProcess(const char* path, PROCESS_INFORMATION* pi) {
	STARTUPINFOA si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(pi, sizeof(PROCESS_INFORMATION));
	CreateProcessA(path, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, pi);
}

std::string RandomString(int len) {
	std::string str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	std::string newstr;
	int pos;
	while (newstr.size() != len) {
		pos = ((rand() % (str.size() - 1)));
		newstr += str.substr(pos, 1);
	}
	return newstr;
}

void SetColor(int text, int background) {
	HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hStdOut, (WORD)((background << 4) | text));
}

int main(int argc, char* argv[]) {
	srand(0);

	HWND console = GetConsoleWindow();
	RECT r;
	GetWindowRect(console, &r);
	SetConsoleTitleA(RandomString(10).c_str());
	MoveWindow(console, r.left, r.top, 320, 300, TRUE);
	SetWindowPos(console, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

	if (argc < 2) {
		SetColor(12, 0);
		std::cout << "Error: No path specified" << std::endl;
		SetColor(7, 0);
		Sleep(3000);
		return 0;
	}

	// GET EXE NAME
	std::string path = argv[1];
	std::string exeName = path.substr(path.find_last_of("\\") + 1);
	wchar_t* wexeName = new wchar_t[exeName.size() + 1];
	mbstowcs(wexeName, exeName.c_str(), exeName.size() + 1);
	
	// CREATE PROCESS AND SUSPEND
	SetColor(14, 0);
	PROCESS_INFORMATION pi;
	CreateProcess(argv[1], &pi);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
	std::cout << "PID: " << pi.dwProcessId << std::endl;
	Sleep(1);
	SuspendThread(pi.hThread);
	SetColor(14, 0);
	std::cout << "Process suspended\n\n";

	// GET ADDRESSES
	void* jmp1 = PatternScanExModule(hProcess, wexeName, wexeName, "\x75\x17\x48\x8D\x15\x00\x00\x00\x00", "xxxxx????");
	void* jmp2 = PatternScanExModule(hProcess, wexeName, wexeName, "\x74\x07\x48\x8D\x15\x00\x00\x00\x00", "xxxxx????");

	SetColor(14, 0);
	std::cout << "Addresses\n";
	SetColor(12, 0);
	if (jmp1 != nullptr) { SetColor(10, 0); }
	std::cout << "JMP1 Found --> " << std::hex << jmp1 << std::endl;
	
	SetColor(12, 0);
	if (jmp2 != nullptr) { SetColor(10, 0); }
	std::cout << "JMP2 Found --> " << std::hex << jmp2 << std::endl << std::endl;

	// PATCH OUR INSTRUCTIONS & RESUME
	SetColor(14, 0);
	std::cout << "Patches\n";
	
	SetColor(10, 0);
	PatchEx(hProcess, jmp1, (LPVOID)"\xEB\x0E", 2);
	std::cout << "[1/2] Success\n";
	PatchEx(hProcess, jmp2, (LPVOID)"\xEB\x07", 2);
	std::cout << "[2/2] Success\n\n";
	
	ResumeThread(pi.hThread);
	SetColor(14, 0);
	std::cout << "Process resumed\n\n";

	SetColor(10, 0);
	std::cout << "CRC32 bypassed\n";

	SetColor(12, 0);
	std::cout << "Closing in 5 seconds...\n";
	Sleep(5000);

	// CLEANUP
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	CloseHandle(hProcess);
	return 0;
}
