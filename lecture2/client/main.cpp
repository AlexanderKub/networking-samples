#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>


#pragma comment (lib, "Ws2_32.lib")
//#pragma comment (lib, "Mswsock.lib")
//#pragma comment (lib, "AdvApi32.lib")


#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"

int __cdecl main(int argc, char *argv[])
{
	// Проверка параметров командной строки
	if (argc != 2) {
		printf("usage: %s server-name\n", argv[0]);
		char t;
		scanf_s(&t);
		return EXIT_FAILURE;
	}

	int error;

	// Запускаем Winsock
	WSADATA wsaData;
	error = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (error != 0) {
		printf("WSAStartup failed with error: %d\n", error);
		return EXIT_FAILURE;
	}

	struct addrinfo hints;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Определяем адрес порт сервера
	struct addrinfo *serverAddr;
	error = getaddrinfo(argv[1], DEFAULT_PORT, &hints, &serverAddr);
	if (error != 0) {
		printf("getaddrinfo failed with error: %d\n", error);
		WSACleanup();
		return EXIT_FAILURE;
	}

	// Пытаемся подключиться к серверу по одному из опреденных адресов
	SOCKET clientSocket;
	for (struct addrinfo *ptr = serverAddr; ptr != NULL; ptr = ptr->ai_next) {

		// Пытаемся создать SOCKET для подключения
		clientSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (clientSocket == INVALID_SOCKET) {
			printf("socket failed with error: %ld\n", WSAGetLastError());
			WSACleanup();
			return EXIT_FAILURE;
		}

		// Осуществлем подключение
		error = connect(clientSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (error == SOCKET_ERROR) {
			closesocket(clientSocket);
			clientSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(serverAddr);

	if (clientSocket == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return EXIT_FAILURE;
	}

	// Отправляем пакет
	const char *sendbuf = "this is a test";
	int bytesSent = send(clientSocket, sendbuf, (int)strlen(sendbuf), 0);
	if (bytesSent == SOCKET_ERROR) {
		printf("send failed with error: %d\n", WSAGetLastError());
		closesocket(clientSocket);
		WSACleanup();
		return EXIT_FAILURE;
	}

	printf("Bytes Sent: %ld\n", bytesSent);

	// Закрываем отправляющую часть соединения, так как больше не собираемся отправлять данные
	error = shutdown(clientSocket, SD_SEND);
	if (error == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(clientSocket);
		WSACleanup();
		return EXIT_FAILURE;
	}

	// Пытаемся получить данные, пока сервер не закроет соединение
	int bytesReceived = 0;
	char recvbuf[DEFAULT_BUFLEN];
	int recvbuflen = DEFAULT_BUFLEN;
	do {
		bytesReceived = recv(clientSocket, recvbuf, recvbuflen, 0);
		if (bytesReceived > 0)
			printf("Bytes received: %d\n", bytesReceived);
		else if (bytesReceived == 0)
			printf("Connection closed\n");
		else
			printf("recv failed with error: %d\n", WSAGetLastError());
	} while (bytesReceived > 0);

	// Очистка
	closesocket(clientSocket);
	WSACleanup();

	return EXIT_SUCCESS;
}
