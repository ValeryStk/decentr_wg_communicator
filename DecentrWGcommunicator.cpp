// This app is aimed to control wireguard.exe via files request response
// It gives the opportunity for other applications to run wireguard.exe and wg.exe without admin rights
/*
######################################################################################################
#                                                                                                    #
#                               WIREGUARD COMMUNICATOR                                               #
#                                                                                                    #
######################################################################################################
*/

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <algorithm>
#include <windows.h>
#include <filesystem>
#include <chrono>
#include "StdCapture.h"
#include <tlhelp32.h>
#include <strsafe.h>
#include <Shlobj.h>
#include <locale.h>
#include <codecvt>
#include<TCHAR.H>
#include "WinReg.hpp"
#pragma comment(lib, "Advapi32.lib")

using winreg::RegKey;
using winreg::RegException;
using winreg::RegExpected;
using std::vector;
using std::string;
using std::pair;
using std::wstring;
using std::cout;


namespace fs = std::filesystem;
using namespace std::chrono;

enum class WG_tunnel_states {

    UNDEFINED_ERROR,
    INSTALLED,
    UNINSTALLED

};

// wireguard commands            
constexpr auto WG_SHOW                    = "c:\\DecentrWG\\wg show";
constexpr auto UNINSTALL_TUNNEL_COMMAND   = "c:\\DecentrWG\\wireguard /uninstalltunnelservice wg98";
constexpr auto WIRE_GUARD_PATH            = "c:\\DecentrWG";
constexpr auto DECENTR_HOST_PATH          = "c:\\DecentrWG_config";
constexpr auto INSTALL_WG_TUNNEL          = "c:\\DecentrWG\\wireguard /installtunnelservice c:\\DecentrWG_config\\wg98.conf";
constexpr auto UNINSTALL_WG_TUNNEL        = "c:\\DecentrWG\\wireguard /uninstalltunnelservice wg98";
constexpr auto UPDATE_WG_STATE            = "c:\\DecentrWG\\wireguard /update";
constexpr auto TUNNEL_NAME                = "wg98";

// responses
constexpr auto UNDEFINED_ERROR_RESPONSE   = "undefined_error";
constexpr auto INSTALLED_RESPONSE         = "installed";
constexpr auto UNINSTALLED_RESPONSE       = "uninstalled";
constexpr auto EXITED_RESPONSE            = "exited";

// timeout for trying  uninstall tunnelservice wg98
constexpr auto TIMEOUT_MINUTES            =  5;

// communicative files pathes
const fs::path response_file     {"c:\\DecentrWG_config\\response.rspn"};
const fs::path request_file_path {"c:\\DecentrWG_config\\request.rqst"};

// functions
WG_tunnel_states isTunnelInstalled(string &response);
bool install_WG_tunnel();
bool uninstall_WG_tunnel();
void writeResponseFile(const string &response);
void hideWindow();
bool isProcessHasSingleInstance();
BOOL RegDel_value (HKEY hKeyRoot, LPCSTR lpSubKey, LPSTR lpValueName);
void cleanDecentrRegs();
void addRegKeyForJson();
void deleteUselessFiles();
void copyUpdatedFiles(const string resourcesPath);
string getHomeDecentrPath();


int main(int argc, char *argv[]) {

    if (argc >1) {
        
        //std::cout<<"ARGV: "<<argv[1]<<std::endl;
        hideWindow();
        cleanDecentrRegs();
        deleteUselessFiles();
        copyUpdatedFiles(argv[1]);
        exit(0);
    }
            
    if(!isProcessHasSingleInstance()) return EXIT_SUCCESS;
    
    // Hide this console window
    hideWindow();

    //Try to uninstall vpn wireguardtunnel wg98 if it was installed untill this app will get the first request or timeout
    auto start = high_resolution_clock::now();

    while(true){
    
    Sleep(200);
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<minutes>(stop - start);
    if (duration.count() > TIMEOUT_MINUTES) break;
    if(fs::exists(request_file_path))  break;
    if(uninstall_WG_tunnel()) break;

    }

    std::cout<<"Tunnel is uninstalled ......... ok";

    //Loop for watching request file from wg_host, run wireguard and write result to response file
    bool isRun = true;
    while (isRun) {

        Sleep(100);
        
        try {
            if (fs::exists(request_file_path)) {

                std::ifstream requestFile(request_file_path.string());
                
                if (requestFile.is_open())
                {
                    string requestMessage;
                    bool execution_result = false;
                    std::getline(requestFile, requestMessage);
                    
                    if (requestMessage == "install_wg_tunnel")     {
                        if(install_WG_tunnel()) writeResponseFile(INSTALLED_RESPONSE);
                        else writeResponseFile(UNDEFINED_ERROR_RESPONSE);
                    }
                    if (requestMessage == "uninstall_wg_tunnel")   { 
                        
                        if(uninstall_WG_tunnel()) writeResponseFile(UNINSTALLED_RESPONSE);
                        else writeResponseFile(UNDEFINED_ERROR_RESPONSE);
                    
                    }
                    if (requestMessage == "is_wgTunnel_installed") { 
                        
                        string response;  
                        WG_tunnel_states result = isTunnelInstalled(response);
                        switch (result) {

                        case WG_tunnel_states::INSTALLED:
                            std::cout << "Tunnel is installed: "   << response    << std::endl;
                            writeResponseFile(INSTALLED_RESPONSE);
                            break;

                        case WG_tunnel_states::UNDEFINED_ERROR:
                            std::cout << "WG show error: "         << response    << std::endl; 
                            writeResponseFile(UNDEFINED_ERROR_RESPONSE);
                            break;

                        case WG_tunnel_states::UNINSTALLED:
                            std::cout << "\nTunnel is uninstalled: " << response  << std::endl;
                            writeResponseFile(UNINSTALLED_RESPONSE);
                            break;
                        }
                                        
                    }
                    if (requestMessage == "stop"){
                        writeResponseFile(EXITED_RESPONSE);
                        isRun = false;
                    };
                                        
                    requestFile.close();
                    try{
                        fs::remove(request_file_path);
                    }catch(fs::filesystem_error e){
                       std::cout << e.what();
                    }

                }

            }
        }
        catch (fs::filesystem_error& e) {
        
            std::cout << e.what();
        
        }
       
    }
    return EXIT_SUCCESS;
}


WG_tunnel_states isTunnelInstalled(string& response) {

    StdCapture stc;
    stc.BeginCapture();
    int exeResult = system(WG_SHOW);
    stc.EndCapture();
    response = "";
    response = stc.GetCapture();
    if (exeResult != EXIT_SUCCESS)return WG_tunnel_states::UNDEFINED_ERROR;
    if(response.empty() || response.find(TUNNEL_NAME) == string::npos) return WG_tunnel_states::UNINSTALLED;
    return WG_tunnel_states::INSTALLED;

}

bool install_WG_tunnel()
{
    // before we install tunnel we have to check if vpn tunnel was uninstalled
    string response;
    int result = false;
    WG_tunnel_states state;
    state = isTunnelInstalled(response);
    switch (state) {
    
    case WG_tunnel_states::INSTALLED: {//in this case firstly we uninstall vpn tunnel  then install it again
        uninstall_WG_tunnel(); 
        break;
    }

    case WG_tunnel_states::UNDEFINED_ERROR: 
        return false;

    case WG_tunnel_states::UNINSTALLED:break;//there is nothing to do in this case
    
    }
    result = system(INSTALL_WG_TUNNEL);
    if(result == EXIT_SUCCESS) return true;
    return false;
}

bool uninstall_WG_tunnel()
{
    int exeCode = -1;
    bool result = false;
    string response = "";
    //Before uninstall we have to check that tunell is installed
    switch(isTunnelInstalled(response)){
    
    //in this case we will uninstall tunnel
    case WG_tunnel_states::INSTALLED :
        exeCode = system(UNINSTALL_WG_TUNNEL);
        if (exeCode == EXIT_SUCCESS) result = true;
        else result = false;
        Sleep(100);
        break;	
    
    case WG_tunnel_states::UNINSTALLED:
        result = true;
        break;

    case WG_tunnel_states::UNDEFINED_ERROR:
        result = false;
        break;		
    }	
    return result;
}

void writeResponseFile(const string& response)
{

    std::ofstream responseFile(response_file, std::ios::trunc);
    if(responseFile.is_open()){
    responseFile << response;
    responseFile.close();
    }
}


//base functions for tuning up
void hideWindow()
{
    HWND hWin = GetForegroundWindow();
    ShowWindow(hWin, SW_HIDE);
}

bool isProcessHasSingleInstance()
{
    
    int process_counter = 0;
     HANDLE hSnap;
                hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (hSnap == NULL)
                {
                    return 0;
                }
                PROCESSENTRY32 proc;            
              
                if (Process32First(hSnap, &proc))
                {
                    do{
                        //cout<<proc.szExeFile<<std::endl;
                        string check = proc.szExeFile;
                        if(check == "decentr_wg_communicator.exe") ++process_counter;
                    }while (Process32Next(hSnap, &proc));
                }

                //cout<<"process counter:"<<process_counter<<std::endl<<std::endl;
                if(process_counter > 1) {
                    //cout<<"Only one instance is possible for this application...";
                    return false;
                }
    
    return true;
}

BOOL RegDel_value (HKEY hKeyRoot, LPCSTR lpSubKey, LPSTR lpValueName)
{

    LONG     lResult;
    lResult = RegDeleteKeyValueA(hKeyRoot, lpSubKey, lpValueName);

    if (lResult == ERROR_SUCCESS) return TRUE;
    return FALSE;

}

void cleanDecentrRegs()
{
    string homePath = getHomeDecentrPath();
    
    vector<LPSTR> dec_reg_values = {

        (LPSTR)L"C:\\DecentrWG_config\\WG_decentr_host.exe",
        (LPSTR)L"C:\\DecentrWG_config\\WireguardUninstaller.exe",
        (LPSTR)homePath.c_str()
    };
    for(auto &it :dec_reg_values){
    BOOL res = RegDel_value(HKEY_CURRENT_USER,(LPCSTR)"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers",it);
    }
    
}

void addRegKeyForJson()
{
         // Set reg key for wireguard native messaging
          const std::u16string wire_guardJsonPath = u"c:\\DecentrWG_config\\wireguard.json";
          const BYTE* mb = reinterpret_cast<const BYTE*>(wire_guardJsonPath.c_str());
          HKEY key;
          if (RegCreateKeyEx(
                  HKEY_CURRENT_USER,
                  "Software\\Google\\Chrome\\NativeMessagingHosts\\com."
                  "decentr.wireguard",
                  0, NULL, 0, KEY_ALL_ACCESS, NULL, &key,
                  NULL) == ERROR_SUCCESS) {RegSetValueEx(key, NULL, 0, REG_SZ, mb,(wire_guardJsonPath.length() * sizeof(wchar_t)));
            RegCloseKey(key);
          } 

}

void deleteUselessFiles()
{
    string autoKill     = DECENTR_HOST_PATH;;
    string uninstaller  = DECENTR_HOST_PATH;
    autoKill.append("\\kill_vpn_task.exe");
    uninstaller.append("\\WG_decentr_host.exe");
    vector<fs::path> pathes = {autoKill,uninstaller};
    
    try{
        for(auto &it:pathes) fs::remove(it);
    }catch(fs::filesystem_error e){
        std::cout<< e.what();
    }
}

void copyUpdatedFiles(const string resourcesPath){

    //Create folders if they dont exist c:\\DecentrWG_config c:\\DecentrWG
    fs::create_directory(DECENTR_HOST_PATH);
    fs::create_directory(WIRE_GUARD_PATH);

    string wgSrcPath = resourcesPath;
    wgSrcPath.append("\\wg.exe");
    string wgDstnPath = WIRE_GUARD_PATH;
    wgDstnPath.append("\\wg.exe");

    string wireguardSrcPath = resourcesPath;
    wireguardSrcPath.append("\\wireguard.exe");
    string wireguardDstnPath = WIRE_GUARD_PATH;
    wireguardDstnPath.append("\\wireguard.exe");

    string decentr_wg_communicatorSrcPath = resourcesPath;
    decentr_wg_communicatorSrcPath.append("\\decentr_wg_communicator.exe");
    string decentr_wg_communicatorDstnPath = DECENTR_HOST_PATH;
    decentr_wg_communicatorDstnPath.append("\\decentr_wg_communicator.exe");

    string decentr_wg__host_SrcPath = resourcesPath;
    decentr_wg__host_SrcPath.append("\\WG_decentr_host.exe");
    string decentr_wg__host_DstnPath = DECENTR_HOST_PATH;
    decentr_wg__host_DstnPath.append("\\WG_decentr_host.exe");

    string wireguardJson_SrcPath = resourcesPath;
    wireguardJson_SrcPath.append("\\wireguard.json");
    string wireguardJson_DstnPath = DECENTR_HOST_PATH;
    wireguardJson_DstnPath.append("\\wireguard.json");

    vector<pair<string,string>> pathes = {
        
        {wgSrcPath, wgDstnPath},
        {wireguardSrcPath, wireguardDstnPath},
        {decentr_wg__host_SrcPath, decentr_wg__host_DstnPath},
        {wireguardJson_SrcPath, wireguardJson_DstnPath},
        {decentr_wg_communicatorSrcPath,decentr_wg_communicatorDstnPath}
    
    };

    for(auto &it:pathes){
        try{

            fs::copy(it.first,it.second,fs::copy_options::overwrite_existing);

        }catch(fs::filesystem_error e){

            std::cout<<e.what()<<std::endl;
        }
    }
}

string getHomeDecentrPath(){

    wstring path2Decentr = L"";
    WCHAR path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, path))) {

      path2Decentr = path; 
      path2Decentr.append(L"\\AppData\\Local\\Decentr\\Decentr\\Application\\decentr.exe");

      //setup converter
      using convert_type = std::codecvt_utf8<wchar_t>;
      std::wstring_convert<convert_type, wchar_t> converter;
 
      //use converter (.to_bytes: wstr->str, .from_bytes: str->wstr)
      string converted_str = converter.to_bytes( path2Decentr );
      return converted_str;
    }
    
  return "";
    
}

