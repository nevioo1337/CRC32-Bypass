#include <iostream>
#include <Windows.h>

void PatchBytes(HANDLE hProcess, LPVOID lpAddress, LPVOID lpBuffer, SIZE_T nSize) {
	DWORD dwOldProtect, dwBkup;
	VirtualProtectEx(hProcess, lpAddress, nSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	WriteProcessMemory(hProcess, lpAddress, lpBuffer, nSize, NULL);
	VirtualProtectEx(hProcess, lpAddress, nSize, dwOldProtect, &dwBkup);
}

void CreateProcess(const char* path, PROCESS_INFORMATION* pi) {
	STARTUPINFOA si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(pi, sizeof(PROCESS_INFORMATION));
	CreateProcessA(path, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE | CREATE_SUSPENDED, NULL, NULL, &si, pi);
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
	MoveWindow(console, r.left, r.top, 500, 300, TRUE); // 500 width, 200 height
	SetWindowPos(console, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

	if (argc < 2) {
		SetColor(12, 0);
		std::cout << "Error: No path specified" << std::endl;
		SetColor(7, 0);
		Sleep(3000);
		return 0;
	}

	// CREATE PROCESS AND SUSPEND
	SetColor(14, 0);
	PROCESS_INFORMATION pi;
	CreateProcess(argv[1], &pi);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
	std::cout << "Process created and suspended\n\n";

	// PATCH OUR INSTRUCTIONS & RESUME
	SetColor(10, 0);
	PatchBytes(hProcess, (LPVOID)0x00007FF70D89155F, (LPVOID)"\xEB\x0E", 2);
	std::cout << "[1/2] Success\n";
	PatchBytes(hProcess, (LPVOID)0x00007FF70D891576, (LPVOID)"\xEB\x07", 2);
	std::cout << "[2/2] Success\n\n";

	SetColor(14, 0);
	std::cout << "Successfully patched jump instructions\n";
	ResumeThread(pi.hThread);
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