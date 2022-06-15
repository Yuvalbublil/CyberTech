#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define MAIL_GET 2
#define SETTINGS "settings.dat"

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include "WSAInitiliazer.h"

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include "json.hpp"

#define MAX_BUFF 4096

using json = nlohmann::json;

/**
* This function saves the content of the mail into:
*   %from%/%to%
* the file %to% will contain %data%
*/
void save_mail(const char* from, const char* subject, const char* data);

int main(int argc, char** argv)
{
    WSAInitiliazer wsa;//This guy makes sure every thing is intiliazed and cleaned up when needed
    int iResult = -1;
    uint32_t length = 0;
    SOCKET ConnectSocket = INVALID_SOCKET;
    std::string payload;
    // Connnect via IP
    struct addrinfo* result = NULL,
        * ptr = NULL,
        hints;
    json settings, j;
    // We will load the settings.dat file
    std::ifstream settingf(SETTINGS);
    if (settingf.is_open())
    {
        if (std::getline(settingf, payload))
        {
            settings = json::parse(payload);
        }
        else
        {
            std::cerr << "Settings file empty" << std::endl;
            return 1;
        }
    }
    else
    {
        std::cerr << "No settings file" << std::endl;
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    iResult = getaddrinfo(settings["server"].get<std::string>().c_str(), settings["port"].get<std::string>().c_str(), &hints, &result);
    if (iResult != 0) 
    {
        printf("getaddrinfo failed: %d\n", iResult);
        return 1;
    }

    // We get multiple options for the ip and port combo, we will go through them all
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
    {
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            printf("socket failed with error: %ld\n", WSAGetLastError());
            return 1;
        }
        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        printf("Unable to connect to server!\n");
        //WSACleanup();
        return 1;
    }

    // Now the fun begin we can start creating our packet
    j = json();
    j["ID"] = MAIL_GET;
    j["user"] = settings["user"];
    j["pass"] = settings["password"];
    payload = j.dump();
    //std::cout << "Sending: " << payload << std::endl;
    length = payload.length();

    iResult = send(ConnectSocket, (const char*) &length, sizeof(uint32_t), 0);
    if (iResult == SOCKET_ERROR || iResult != 4)
    {
        printf("send failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        return 1;
    }

    //printf("Bytes Sent: %ld\n", iResult);

    iResult = send(ConnectSocket, payload.c_str(), payload.length(), 0);
    if (iResult == SOCKET_ERROR || iResult != payload.length())
    {//No need to resend data ofcourse
        printf("send failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        return 1;
    }

    //("Bytes Sent: %ld\n", iResult);

    iResult = recv(ConnectSocket, (char*) &length, 4, 0);
    if(iResult != 4)
    {
        printf("send failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        return 1;
    }

    char* buffer = new char[length];
    iResult = recv(ConnectSocket, buffer, length, 0);
    buffer[length] = 0;
    std::cout << buffer << std::endl;
    j = json::parse(buffer);
    delete[] buffer;

    auto mails = j["mails"];
    for (auto begin = mails.begin(); begin != mails.end(); ++begin) 
    {
        std::cout << (*begin).dump() << std::endl;
        save_mail((*begin)["from"].get<std::string>().c_str(), (*begin)["subject"].get<std::string>().c_str(), (*begin)["data"].get<std::string>().c_str());
    }

    closesocket(ConnectSocket);
    return 0;
}

/**
	Look At this function please
**/
void save_mail(const char* from, const char* subject, const char* data)
{
    char buffer[MAX_BUFF] = { 0 }; // 4096
    sprintf(buffer, "if not exist \"%s\" mkdir \"%s\"", from, from);
    system(buffer);
    sprintf(buffer, "echo %s > \"%s\"/\"%s\"", data, from, subject);//Quick trick to quickly save files ;)
    //printf("%s\n", buffer);
    system(buffer);
}