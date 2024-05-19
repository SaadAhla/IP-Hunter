#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <winhttp.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")

#pragma warning(disable: 4996)
#define _CRT_SECURE_NO_WARNINGS

#define API_KEY "<Your API Key Here>" // Replace with your VirusTotal API key

void SetConsoleColor(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

void PrintIPAddress(DWORD ipAddr) {
    struct in_addr IpAddr;
    IpAddr.S_un.S_addr = ipAddr;
    const char* ipStr = inet_ntoa(IpAddr);
    printf("%s", ipStr);

    // Perform VirusTotal API lookup
    HINTERNET hSession = WinHttpOpen(L"VirusTotal IP Scanner",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession) {
        HINTERNET hConnect = WinHttpConnect(hSession, L"www.virustotal.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (hConnect) {
            wchar_t requestPath[256];
            swprintf(requestPath, 256, L"/api/v3/ip_addresses/%S", ipStr);
            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", requestPath,
                NULL, WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES,
                WINHTTP_FLAG_SECURE);
            if (hRequest) {
                wchar_t headers[256];
                swprintf(headers, 256, L"x-apikey: %S", API_KEY);
                WinHttpAddRequestHeaders(hRequest, headers, -1, WINHTTP_ADDREQ_FLAG_ADD);
                if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                    WINHTTP_NO_REQUEST_DATA, 0,
                    0, 0)) {
                    if (WinHttpReceiveResponse(hRequest, NULL)) {
                        DWORD dwSize = 0;
                        DWORD dwDownloaded = 0;
                        DWORD totalSize = 0;
                        LPSTR pszOutBuffer = NULL;

                        // Keep checking for data until there is nothing left.
                        do {
                            // Check for available data.
                            dwSize = 0;
                            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                                printf("Error %u in WinHttpQueryDataAvailable.\n",
                                    GetLastError());
                                break;
                            }

                            // Allocate space for the buffer.
                            pszOutBuffer = (LPSTR)realloc(pszOutBuffer, totalSize + dwSize + 1);
                            if (!pszOutBuffer) {
                                printf("Out of memory\n");
                                dwSize = 0;
                                break;
                            }

                            // Read the data.
                            if (!WinHttpReadData(hRequest, (LPVOID)(pszOutBuffer + totalSize),
                                dwSize, &dwDownloaded)) {
                                printf("Error %u in WinHttpReadData.\n", GetLastError());
                                break;
                            }

                            totalSize += dwDownloaded;
                        } while (dwSize > 0);

                        // Null-terminate the buffer.
                        if (pszOutBuffer) {
                            //printf("%s\n", pszOutBuffer);
                            pszOutBuffer[totalSize] = '\0';

                            // Manually parse JSON response to find "malicious" field under "last_analysis_stats"
                            const char* last_analysis_stats_key = "\"last_analysis_stats\":";
                            char* last_analysis_stats_ptr = strstr(pszOutBuffer, last_analysis_stats_key);
                            if (last_analysis_stats_ptr) {
                                const char* malicious_key = "\"malicious\":";
                                char* malicious_ptr = strstr(last_analysis_stats_ptr, malicious_key);
                                if (malicious_ptr) {
                                    malicious_ptr += strlen(malicious_key);
                                    int malicious_count = atoi(malicious_ptr);
                                    if (malicious_count > 2) {
                                        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                                        printf(" (malicious) [%d]", malicious_count);
                                    }
                                    else {
                                        SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                                        printf(" (safe) [%d]", malicious_count);
                                    }
                                }
                                else {
                                    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                                    printf(" (unknown)");
                                }
                            }
                            else {
                                SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                                printf(" (unknown)");
                            }
                            SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

                            // Free the memory allocated to the buffer.
                            free(pszOutBuffer);
                        }
                    }
                }
                WinHttpCloseHandle(hRequest);
            }
            WinHttpCloseHandle(hConnect);
        }
        WinHttpCloseHandle(hSession);
    }
}

int ListOutboundTCPConnections(DWORD processId) {
    PMIB_TCPTABLE2 pTcpTable;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    int hasConnections = 0;

    pTcpTable = (MIB_TCPTABLE2*)malloc(sizeof(MIB_TCPTABLE2));
    if (pTcpTable == NULL) {
        printf("Error allocating memory\n");
        return 0;
    }

    dwSize = sizeof(MIB_TCPTABLE2);
    if ((dwRetVal = GetTcpTable2(pTcpTable, &dwSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER) {
        free(pTcpTable);
        pTcpTable = (MIB_TCPTABLE2*)malloc(dwSize);
        if (pTcpTable == NULL) {
            printf("Error allocating memory\n");
            return 0;
        }
    }

    if ((dwRetVal = GetTcpTable2(pTcpTable, &dwSize, TRUE)) == NO_ERROR) {
        for (int i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
            MIB_TCPROW2 tcpRow = pTcpTable->table[i];

            if (tcpRow.dwOwningPid == processId && tcpRow.dwState == MIB_TCP_STATE_ESTAB) {
                struct in_addr remoteAddr;
                remoteAddr.S_un.S_addr = tcpRow.dwRemoteAddr;
                if (strcmp(inet_ntoa(remoteAddr), "127.0.0.1") == 0) {
                    continue; // Skip local connections to 127.0.0.1
                }

                if (!hasConnections) {
                    hasConnections = 1;
                }
                printf("\tLocal Port: %d\tRemote IP: ", ntohs((u_short)tcpRow.dwLocalPort));
                PrintIPAddress(tcpRow.dwRemoteAddr);
                printf("\n");
            }
        }
    }
    else {
        printf("GetTcpTable2 failed with %d\n", dwRetVal);
    }

    if (pTcpTable) {
        free(pTcpTable);
        pTcpTable = NULL;
    }

    return hasConnections;
}

void ListAllProcesses() {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot (of processes) failed: %d\n", GetLastError());
        return;
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process,
    // and exit if unsuccessful.
    if (!Process32First(hProcessSnap, &pe32)) {
        printf("Process32First failed: %d\n", GetLastError()); // Show cause of failure
        CloseHandle(hProcessSnap);          // Clean the snapshot object
        return;
    }

    // Now walk the snapshot of processes, and
    // display information about each process in turn.
    do {
        if (ListOutboundTCPConnections(pe32.th32ProcessID)) {
            _tprintf(TEXT("PROCESS NAME:  %s"), pe32.szExeFile);
            _tprintf(TEXT("\nProcess ID        = %d\n\n\n"), pe32.th32ProcessID);
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
}

int main(void) {
    ListAllProcesses();
    return 0;
}
