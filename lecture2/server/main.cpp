#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <strsafe.h>


#pragma comment (lib, "Ws2_32.lib")

#define MAX_THREADS 6
#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"

DWORD WINAPI ThreadSoketHandler(LPVOID lpParam);

typedef struct ThreadSocketData {
	SOCKET socket;
	int id;
} THREADSOCKETDATA, *PTHREADSOCKETDATA;

int __cdecl main(void)
{
	int error;
	int socketIndex = 0;
	int clientId = 1;
	DWORD dwThreadIdArray[MAX_THREADS];
	HANDLE  hThreadArray[MAX_THREADS];
	PTHREADSOCKETDATA pDataArray[MAX_THREADS];

	// Запускаем Winsock
	WSADATA wsaData;
	error = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (error != 0) {
		printf("WSAStartup failed with error: %d\n", error);
		return EXIT_FAILURE;
	}

	struct addrinfo hints;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	// Преобразуем адрес и номер порта
	struct addrinfo *localAddr = NULL;
	error = getaddrinfo(NULL, DEFAULT_PORT, &hints, &localAddr);
	if (error != 0) {
		printf("getaddrinfo failed with error: %d\n", error);
		WSACleanup();
		return EXIT_SUCCESS;
	}

	// Создаем SOCKET на котором будем принимать соединения
	SOCKET listenSocket = socket(localAddr->ai_family, localAddr->ai_socktype, localAddr->ai_protocol);
	if (listenSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(localAddr);
		WSACleanup();
		return EXIT_FAILURE;
	}

	// Привязываем сокет TCP к адресу и ждем подключения
	error = bind(listenSocket, localAddr->ai_addr, (int)localAddr->ai_addrlen);
	if (error == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(localAddr);
		closesocket(listenSocket);
		WSACleanup();
		return EXIT_FAILURE;
	}

	freeaddrinfo(localAddr);

	error = listen(listenSocket, SOMAXCONN);
	if (error == SOCKET_ERROR) {
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(listenSocket);
		WSACleanup();
		return EXIT_FAILURE;
	}
	printf("listen server port: %s\n", DEFAULT_PORT);

	// Принимаем соединение от клиента
	do {
		SOCKET clientSocket = accept(listenSocket, NULL, NULL);
		if (clientSocket == INVALID_SOCKET) {
			printf("accept failed with error: %d\n", WSAGetLastError());
		} else {
			pDataArray[socketIndex] = (PTHREADSOCKETDATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(THREADSOCKETDATA));
			pDataArray[socketIndex]->socket = clientSocket;
			pDataArray[socketIndex]->id = clientId;
			hThreadArray[socketIndex] = CreateThread(
				NULL,
				0,
				ThreadSoketHandler,
				pDataArray[socketIndex],
				0,
				&dwThreadIdArray[socketIndex]
			);
			if (hThreadArray[socketIndex] == NULL) {
				ExitProcess(3);
			}
			clientId++;
			socketIndex++;
		}

		if (socketIndex >= MAX_THREADS) {
			socketIndex = 0;
			WaitForMultipleObjects(MAX_THREADS, hThreadArray, TRUE, INFINITE);
			for (int i = 0; i < MAX_THREADS; i++) {
				CloseHandle(hThreadArray[i]);
				hThreadArray[i] = NULL;
				if (pDataArray[i] != NULL) {
					HeapFree(GetProcessHeap(), 0, pDataArray[i]);
					pDataArray[i] = NULL;
				}
			}
		}
	} while (socketIndex < MAX_THREADS);

	closesocket(listenSocket);
	WSACleanup();
	return EXIT_SUCCESS;
}

DWORD WINAPI ThreadSoketHandler(LPVOID lpParam) {
	HANDLE hStdout;
	int error;

	hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hStdout == INVALID_HANDLE_VALUE) {
		return 1;
	}

	PTHREADSOCKETDATA data;
	data = (PTHREADSOCKETDATA)lpParam;
	SOCKET clientSocket = data->socket;
	int clientId = data->id;
	printf("client #%d connection open\n", clientId);

	// Пытаемся получить данные, пока клиент не закроет соединение
	int bytesReceived = 0;
	char recvbuf[DEFAULT_BUFLEN];
	int recvbuflen = DEFAULT_BUFLEN;
	do {
		bytesReceived = recv(clientSocket, recvbuf, recvbuflen, 0);
		if (bytesReceived > 0) {
			// Отправляем сообщение обратно клиенту
			int bytesSent = send(clientSocket, recvbuf, bytesReceived, 0);
			if (bytesSent == SOCKET_ERROR) {
				printf("send failed with error: %d\n", WSAGetLastError());
				closesocket(clientSocket);
				return 1;
			}
			printf("Bytes sent: %d\n", bytesSent);
		}
		else if (bytesReceived == 0) {
			printf("client #%d connection close\n", clientId);
		} else {
			printf("recv failed with error: %d\n", WSAGetLastError());
			closesocket(clientSocket);
			return 1;
		}
	} while (bytesReceived > 0);

	// Закрываем соединение
	error = shutdown(clientSocket, SD_SEND);
	if (error == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(clientSocket);
		return 1;
	}

	// Очистка
	closesocket(clientSocket);
	return 0;
}