// DefenderEnDs.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <codecvt>
#include <locale>
#include <iostream>
#include <Windows.h>
#include <VersionHelpers.h>
#include <ShlObj.h>
#include <stdio.h>
#include <string>
#include "MpClient.h"
using namespace std;

//Function to convert LPCWSTR to wstring
string ConvertLPCWSTRToString(LPCWSTR LPCWStr) 
{
    //Create a converter object to convert between LPCWSTR and UTF-8 string.
    wstring_convert<codecvt_utf8_utf16<wchar_t> > converter;
    //1. Convert LPCWSTR to wstring; 2. to an std::string.
    return converter.to_bytes(wstring(LPCWStr));
}

int main(int argc, char* argv[])
{
    HKEY hkey;
    hkey = HKEY_LOCAL_MACHINE;
    WCHAR value[2048];
    PVOID pvData = value;
    DWORD size = sizeof(value);
    LSTATUS RegKey = RegGetValueW(hkey, L"SOFTWARE\\Microsoft\\Windows Defender", L"InstallLocation", RRF_RT_REG_SZ, NULL, pvData, &size);
    if (RegKey == ERROR_SUCCESS) {
        printf("[+]Windows Defender Install Location is %ls, Length %d\n", (PWSTR)pvData, size);
        LPCWSTR Path = (LPCWSTR)pvData;        
        LPCWSTR File = L"MpClient.dll";        
        string spath = ConvertLPCWSTRToString(Path);
        string sfile = ConvertLPCWSTRToString(File);
        string sfullpath = spath + sfile;
        printf("[+]Load from %s\n", sfullpath.c_str());

        // Initialize wstring object
        wstring mptemp = wstring(sfullpath.begin(), sfullpath.end());
        // Apply c_str() method on mptemp
        LPCWSTR FullPath = mptemp.c_str();
        HMODULE hMpClient = LoadLibraryW(FullPath);
        if (hMpClient == NULL) {
            printf("[-]Load MpClient.dll failed, Last error: %d\n", GetLastError());
            return -1;
        }
        else {
            printf("[+]MpClient.dll loaded success at 0x%p\n", hMpClient);
        }
        auto pWDStatus = (WDStatus)GetProcAddress(hMpClient, "WDStatus");
        if (pWDStatus == NULL) {
            printf("[-]Get WDStatus address failed, Last error: %d\n", GetLastError());
        }
        else {
            printf("[+]WDStatus at 0x%p\n", pWDStatus);
        }
        auto pWDEnable = (WDEnable)GetProcAddress(hMpClient, "WDEnable");
        if (pWDEnable == NULL) {
            printf("[-]Get WDEnable address failed, Last error: %d\n", GetLastError());
        }
        else {
            printf("[+]WDEnable at 0x%p\n", pWDEnable);
        }
        auto pMpWDEnable = (MpWDEnable)GetProcAddress(hMpClient, "MpWDEnable");
        if (pMpWDEnable == NULL) {
            printf("[-]Get MpWDEnable address failed, Last error: %d\n", GetLastError());
        }
        else {
            printf("[+]MpWDEnable at 0x%p\n", pMpWDEnable);
        }
        auto pMpErrorMessageFormat = (MpErrorMessageFormat)GetProcAddress(hMpClient, "MpErrorMessageFormat");
        if (pMpErrorMessageFormat == NULL) {
            printf("[-]Get MpErrorMessageFormat address failed, Last error: %d\n", GetLastError());
        }
        else {
            printf("[+]MpErrorMessageFormat at 0x%p\n", pMpErrorMessageFormat);
        }
        auto pMpFreeMemory = (MpFreeMemory)GetProcAddress(hMpClient, "MpFreeMemory");
        if (pMpFreeMemory == NULL) {
            printf("[-]Get MpFreeMemory address failed, Last error: %d\n", GetLastError());
        }
        else {
            printf("[+]MpFreeMemory at 0x%p\n", pMpFreeMemory);
        }
        auto pMpHandleClose = (MpHandleClose)GetProcAddress(hMpClient, "MpHandleClose");
        if (pMpHandleClose == NULL) {
            printf("[-]Get MpHandleClose address failed, Last error: %d\n", GetLastError());
        }
        else {
            printf("[+]MpHandleClose at 0x%p\n", pMpHandleClose);
        }
        auto pMpManagerOpen = (MpManagerOpen)GetProcAddress(hMpClient, "MpManagerOpen");
        if (pMpManagerOpen == NULL) {
            printf("[-]Get MpManagerOpen address failed, Last error: %d\n", GetLastError());
        }
        else {
            printf("[+]MpManagerOpen at 0x%p\n", pMpManagerOpen);
        }
        auto pMpManagerStatusQuery = (MpManagerStatusQuery)GetProcAddress(hMpClient, "MpManagerStatusQuery");
        if (pMpManagerStatusQuery == NULL) {
            printf("[-]Get MpManagerStatusQuery address failed, Last error: %d\n", GetLastError());
        }
        else {
            printf("[+]MpManagerStatusQuery at 0x%p\n", pMpManagerStatusQuery);
        }
        auto pMpManagerStatusQueryEx = (MpManagerStatusQueryEx)GetProcAddress(hMpClient, "MpManagerStatusQueryEx");
        if (pMpManagerStatusQueryEx == NULL) {
            printf("[-]Get MpManagerStatusQueryEx address failed, Last error: %d\n", GetLastError());
        }
        else {
            printf("[+]MpManagerStatusQueryEx at 0x%p\n", pMpManagerStatusQueryEx);
        }
        auto pMpManagerVersionQuery = (MpManagerVersionQuery)GetProcAddress(hMpClient, "MpManagerVersionQuery");
        if (pMpManagerVersionQuery == NULL) {
            printf("[-]Get MpManagerVersionQuery address failed, Last error: %d\n", GetLastError());
        }
        else {
            printf("[+]MpManagerVersionQuery at 0x%p\n", pMpManagerVersionQuery);
        }
        auto pMpScanControl = (MpScanControl)GetProcAddress(hMpClient, "MpScanControl");
        if (pMpScanControl == NULL) {
            printf("[-]Get MpScanControl address failed, Last error: %d\n", GetLastError());
        }
        else {
            printf("[+]MpScanControl at 0x%p\n", pMpScanControl);
        }
        auto pMpScanStart = (MpScanStart)GetProcAddress(hMpClient, "MpScanStart");
        if (pMpScanStart == NULL) {
            printf("[-]Get MpScanStart address failed, Last error: %d\n", GetLastError());
        }
        else {
            printf("[+]MpScanStart at 0x%p\n", pMpScanStart);
        }
        auto pMpThreatEnumerate = (MpThreatEnumerate)GetProcAddress(hMpClient, "MpThreatEnumerate");
        if (pMpThreatEnumerate == NULL) {
            printf("[-]Get MpThreatEnumerate address failed, Last error: %d\n", GetLastError());
        }
        else {
            printf("[+]MpThreatEnumerate at 0x%p\n", pMpThreatEnumerate);
        }
        auto pMpThreatOpen = (MpThreatOpen)GetProcAddress(hMpClient, "MpThreatOpen");
        if (pMpThreatOpen == NULL) {
            printf("[-]Get MpThreatOpen address failed, Last error: %d\n", GetLastError());
        }
        else {
            printf("[+]MpThreatOpen at 0x%p\n", pMpThreatOpen);
        }
        auto pMpThreatQuery = (MpThreatQuery)GetProcAddress(hMpClient, "MpThreatQuery");
        if (pMpThreatQuery == NULL) {
            printf("[-]Get MpThreatQuery address failed, Last error: %d\n", GetLastError());
        }
        else {
            printf("[+]MpThreatQuery at 0x%p\n", pMpThreatQuery);
        }
        auto pMpUpdateControl = (MpUpdateControl)GetProcAddress(hMpClient, "MpUpdateControl");
        if (pMpUpdateControl == NULL) {
            printf("[-]Get MpUpdateControl address failed, Last error: %d\n", GetLastError());
        }
        else {
            printf("[+]MpUpdateControl at 0x%p\n", pMpUpdateControl);
        }
        auto pMpUpdateStart = (MpUpdateStart)GetProcAddress(hMpClient, "MpUpdateStart");
        if (pMpUpdateStart == NULL) {
            printf("[-]Get MpUpdateStart address failed, Last error: %d\n", GetLastError());
        }
        else {
            printf("[+]MpUpdateStart at 0x%p\n", pMpUpdateStart);
        }
        MPHANDLE MpManagerHandle;
        MPHANDLE MpScanHandle;
        HRESULT ManagerState = pMpManagerOpen(0, &MpManagerHandle);
        if (FAILED(ManagerState)) {
            printf("[-]MpManagerOpen Failed. %d\n", ManagerState);
        }
        else {
            printf("[+]MpManagerOpen success.\n");
        }
        printf("[+]Command is %s\n", argv[1]);
        if (argc > 1 && strcmp(argv[1],"-Status") == 0) {
            printf("[+]Trying to get Windows Defender Status.\n");
            BOOL fEnable;
            BOOL* pfEnabled = &fEnable;
            HRESULT Execute = pWDStatus(pfEnabled);
            if (Execute == S_OK) {
                if (fEnable == TRUE) {
                    printf("[+]Windows Defender is Enabled\n");
                    goto _exit_;
                }
                if (fEnable == FALSE) {
                    printf("[+]Windows Defender is Disabled\n");
                    goto _exit_;
                }
                else {
                    printf("[-]Execute failed, %d\n", fEnable);
                    goto _exit_;
                }                
            }
            else {
                printf("[-]Execute failed, %d\n", Execute);
                goto _exit_;
            }
        }
        if (argc > 1 && strcmp(argv[1], "-Enable") == 0) {
            printf("[+]Trying to enable Windows Defender.\n"); 
            Try:
            HRESULT Action = pWDEnable(TRUE);
            if (Action == S_OK) {
                printf("[+]Windows Defender has been turned on successfully.\n");
                goto _exit_;
            }
            if (Action == E_ACCESSDENIED) {
                printf("[-]Action has been denied.\n");
                printf("Possible reasons:\n");
                printf("1.Application does not have sufficient permission - Please run as administrator or TrustedInstaller (if you could)(*^_^*).\n");
                printf("2.Application is flagged as a threat by Windows Defender signature database. - Add the application to exclusion or submit it to Microsoft.\n");
                printf("3.Application identity is not verifiable through digital signing. - Buy an EV certificate and signed this tool by it may help...maybe.\n");
                goto _exit_;
            }
            if (Action == HRESULT_FROM_WIN32(ERROR_ACCESS_DISABLED_BY_POLICY)) {
                printf("[-]Application request contradicts with the Windows Defender status set by group policy.\n");
                printf("[+]Trying to delete policy configurations in Registry..\n");
                HKEY rKey;
                LSTATUS KeyOpen = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_SET_VALUE, &rKey);
                if (KeyOpen == ERROR_SUCCESS) {
                    LSTATUS ValueDelete1 = RegDeleteValueW(rKey, L"DisableAntiSpyware");
                    LSTATUS ValueDelete2 = RegDeleteValueW(rKey, L"DisableAntiVirus");
                    if (ValueDelete1 == ERROR_SUCCESS && ValueDelete2 == ERROR_SUCCESS) {
                        printf("[+]Delete policy configs success\n");
                        RegCloseKey(rKey);
                        goto Try;
                    }
                    else {
                        printf("[-]Delete policy configs failed, you may need to delete them manually. This may caused by Tamper Protection.\n");
                        RegCloseKey(rKey);
                        goto _exit_;
                    }
                }
                else {
                    printf("[-]Open key failed, you may not have sufficient permission. Run as administrator may help. Please try again.\n");
                    goto _exit_;
                }
            }
            if (Action == E_NOTIMPL) {
                BOOL IsVersion = IsWindowsVersionOrGreater(10, 14393, 0);
                if (IsVersion == FALSE) {
                    printf("[-]WDEnable is not available on this version of Windows, trying MpWDEnable...\n");
                    printf("Notice: MpWDEnable is not a publicly available function, I use it here based on my reverse analysis.\n");
                    HRESULT ActionEx = pMpWDEnable(TRUE);
                    if (ActionEx == S_OK) {
                        printf("[+]Windows Defender has been turned on successfully.\n");
                        goto _exit_;
                    }
                    if (ActionEx == E_ACCESSDENIED) {
                        printf("[-]Action has been denied.\n");
                        printf("Possible reasons:\n");
                        printf("1.Application does not have sufficient permission - Please run as administrator or TrustedInstaller (if you could)(*^_^*).\n");
                        printf("2.Application is flagged as a threat by Windows Defender signature database. - Add the application to exclusion or submit it to Microsoft.\n");
                        printf("3.Application identity is not verifiable through digital signing. - Buy an EV certificate and signed this tool by it may help...maybe.\n");
                        goto _exit_;
                    }
                    if (ActionEx == HRESULT_FROM_WIN32(ERROR_ACCESS_DISABLED_BY_POLICY)) {
                        printf("[-]Application request contradicts with the Windows Defender status set by group policy.\n");
                        printf("[+]Trying to delete policy configurations in Registry..\n");
                        HKEY rKeyEx;
                        LSTATUS KeyOpenEx = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_SET_VALUE, &rKeyEx);
                        if (KeyOpenEx == ERROR_SUCCESS) {
                            LSTATUS ValueDelete3 = RegDeleteValueW(rKeyEx, L"DisableAntiSpyware");
                            LSTATUS ValueDelete4 = RegDeleteValueW(rKeyEx, L"DisableAntiVirus");
                            if (ValueDelete3 == ERROR_SUCCESS && ValueDelete4 == ERROR_SUCCESS) {
                                printf("[+]Delete policy configs success\n");
                                RegCloseKey(rKeyEx);
                                goto Try;
                            }
                            else {
                                printf("[-]Delete policy configs failed, you may need to delete them manually. This may caused by Tamper Protection.\n");
                                RegCloseKey(rKeyEx);
                                goto _exit_;
                            }
                        }
                        else {
                            printf("[-]Open key failed, you may not have sufficient permission. Run as administrator may help. Please try again.\n");
                            goto _exit_;
                        }
                    }
                    if (ActionEx == E_NOTIMPL) {
                        printf("[-]Action not supported.\n");
                        goto _exit_;
                    }
                    else {
                        printf("[-]Other error, %d\n", ActionEx);
                        goto _exit_;
                    }
                }
                if (IsVersion == TRUE) {
                    printf("[-]Other unkown error, function is not available now. May caused by antimalware platform itself.\n");
                    goto _exit_;
                }
                else {
                    printf("[-]Get Windows Version failed.\n");
                    goto _exit_;
                }
            }
            else {
                printf("[-]Other error, %d\n", Action);
            }
        }
        if (argc > 1 && strcmp(argv[1], "-Disable") == 0) {
            printf("[+]Trying to disable Windows Defender...\n");
        TryD:
            HRESULT ActionD = pWDEnable(FALSE);
            if (ActionD == S_OK) {
                printf("[+]Windows Defender has been turned off successfully.\n");
                goto _exit_;
            }
            if (ActionD == E_ACCESSDENIED) {
                printf("[-]Action has been denied.\n");
                printf("Possible reasons:\n");
                printf("1.Application does not have sufficient permission - Please run as administrator or TrustedInstaller (if you could)(*^_^*).\n");
                printf("2.Application is flagged as a threat by Windows Defender signature database. - Add the application to exclusion or submit it to Microsoft.\n");
                printf("3.Application identity is not verifiable through digital signing. - Buy an EV certificate and signed this tool by it may help...maybe.\n");
                goto _exit_;
            }
            if (ActionD == HRESULT_FROM_WIN32(ERROR_ACCESS_DISABLED_BY_POLICY)) {
                printf("[-]Application request contradicts with the Windows Defender status set by group policy.\n");
                printf("[+]Trying to delete policy configurations in Registry..\n");
                HKEY rKeyD;
                LSTATUS KeyOpenD = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_SET_VALUE, &rKeyD);
                if (KeyOpenD == ERROR_SUCCESS) {
                    LSTATUS ValueDelete5 = RegDeleteValueW(rKeyD, L"DisableAntiSpyware");
                    LSTATUS ValueDelete6 = RegDeleteValueW(rKeyD, L"DisableAntiVirus");
                    if (ValueDelete5 == ERROR_SUCCESS && ValueDelete6 == ERROR_SUCCESS) {
                        printf("[+]Delete policy configs success\n");
                        RegCloseKey(rKeyD);
                        goto TryD;
                    }
                    else {
                        printf("[-]Delete policy configs failed, you may need to delete them manually. This may caused by Tamper Protection.\n");
                        RegCloseKey(rKeyD);
                        goto _exit_;
                    }
                }
                else {
                    printf("[-]Open key failed, you may not have sufficient permission. Run as administrator may help. Please try again.\n");
                    goto _exit_;
                }
            }
            if (ActionD == E_NOTIMPL) {
                BOOL IsVersionD = IsWindowsVersionOrGreater(10, 14393, 0);
                if (IsVersionD == FALSE) {
                    printf("[-]WDEnable is not available on this version of Windows, trying MpWDEnable...\n");
                    printf("Notice: MpWDEnable is not a publicly available function, I use it here based on my reverse analysis.\n");
                    HRESULT ActionExD = pMpWDEnable(FALSE);
                    if (ActionExD == S_OK) {
                        printf("[+]Windows Defender has been turned off successfully.\n");
                        goto _exit_;
                    }
                    if (ActionExD == E_ACCESSDENIED) {
                        printf("[-]Action has been denied.\n");
                        printf("Possible reasons:\n");
                        printf("1.Application does not have sufficient permission - Please run as administrator or TrustedInstaller (if you could)(*^_^*).\n");
                        printf("2.Application is flagged as a threat by Windows Defender signature database. - Add the application to exclusion or submit it to Microsoft.\n");
                        printf("3.Application identity is not verifiable through digital signing. - Buy an EV certificate and signed this tool by it may help...maybe.\n");
                        goto _exit_;
                    }
                    if (ActionExD == HRESULT_FROM_WIN32(ERROR_ACCESS_DISABLED_BY_POLICY)) {
                        printf("[-]Application request contradicts with the Windows Defender status set by group policy.\n");
                        printf("[+]Trying to delete policy configurations in Registry..\n");
                        HKEY rKeyExD;
                        LSTATUS KeyOpenExD = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_SET_VALUE, &rKeyExD);
                        if (KeyOpenExD == ERROR_SUCCESS) {
                            LSTATUS ValueDelete7 = RegDeleteValueW(rKeyExD, L"DisableAntiSpyware");
                            LSTATUS ValueDelete8 = RegDeleteValueW(rKeyExD, L"DisableAntiVirus");
                            if (ValueDelete7 == ERROR_SUCCESS && ValueDelete8 == ERROR_SUCCESS) {
                                printf("[+]Delete policy configs success\n");
                                RegCloseKey(rKeyExD);
                                goto TryD;
                            }
                            else {
                                printf("[-]Delete policy configs failed, you may need to delete them manually. This may caused by Tamper Protection.\n");
                                RegCloseKey(rKeyExD);
                                goto _exit_;
                            }
                        }
                    }
                    if (ActionExD == E_NOTIMPL) {
                        printf("[-]Action not supported.\n");
                        goto _exit_;
                    }
                    else {
                        printf("[-]Other Error, %d\n", ActionExD);
                        goto _exit_;
                    }
                }
                if (IsVersionD == TRUE) {
                    printf("[-]Other unkown error, function is not available now. May caused by antimalware platform itself.\n");
                    goto _exit_;
                }
                else {
                    printf("[-]Get Windows Version failed.\n");
                    goto _exit_;
                }
            }
            else {
                printf("[-]Other Error, %d\n", ActionD);
                goto _exit_;
            }
        }
        _exit_:
        FreeLibrary(hMpClient);
        return 0;
    } 
    if (RegKey == ERROR_MORE_DATA) {
        printf("[-]No enough buffer");
        return -1;
    }
    if (RegKey == ERROR_FILE_NOT_FOUND) {
        printf("[-]Value not found\n");
        return -1;
    }
    if (RegKey == ERROR_INVALID_PARAMETER) {
        printf("[-]Invalid Parameter\n");
        return -1;
    }    
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
