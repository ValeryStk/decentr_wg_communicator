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
#pragma comment(lib, "Advapi32.lib")
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
#define TIMEOUT_MINUTES              5

// communicative files pathes
const fs::path response_file     {"c:\\DecentrWG_config\\response.rspn"};
const fs::path request_file_path {"c:\\DecentrWG_config\\request.rqst"};

// functions
WG_tunnel_states isTunnelInstalled(std::string &response);
bool install_WG_tunnel();
bool uninstall_WG_tunnel();
void writeResponseFile(const std::string &response);
void hideWindow();
bool isProcessHasSingleInstance();
BOOL RegDel_value (HKEY hKeyRoot, LPTSTR lpSubKey, LPSTR lpValueName);
void cleanDecentrRegs();
void deleteUselessFiles();
void copyUpdatedFiles(const std::string resourcesPath);

std::string pathToResources = "";
int main(int argc, char *argv[]) {

	if (argc >1) {
		std::cout<<"ARGV: "<<argv[1]<<std::endl;
		pathToResources = argv[1];
		cleanDecentrRegs();
	    deleteUselessFiles();

	}
	std::cout<<"To run wireguard communicator typy any key and press enter";
	char c;
	std::cin>>c;
	
	copyUpdatedFiles("C:\\Users\\vivir\\AppData\\Local\\Decentr\\Decentr\\Application\\100.3.4896.80\\Installer");
	

	if(!isProcessHasSingleInstance()) return EXIT_SUCCESS;
	
	// Hide this console window
	//hideWindow();
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

	//Loop for watching request files from wg_host, run wireguard and write results to response files
	bool isRun = true;
	while (isRun) {

		Sleep(100);
		
		try {
			if (fs::exists(request_file_path)) {

				std::ifstream requestFile(request_file_path.string());
				
				if (requestFile.is_open())
				{
					std::string requestMessage;
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
						
						std::string response;  
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


WG_tunnel_states isTunnelInstalled(std::string& response) {

	StdCapture stc;
	stc.BeginCapture();
	int exeResult = system(WG_SHOW);
	stc.EndCapture();
	response = "";
	response = stc.GetCapture();
	if (exeResult != EXIT_SUCCESS)return WG_tunnel_states::UNDEFINED_ERROR;
	if(response.empty() || response.find(TUNNEL_NAME) == std::string::npos) return WG_tunnel_states::UNINSTALLED;
	return WG_tunnel_states::INSTALLED;

}

bool install_WG_tunnel()
{
	// before we install tunnel we have to check if vpn tunnel was uninstalled
	std::string response;
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
	std::string response = "";
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

void writeResponseFile(const std::string& response)
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
                        //std::cout<<proc.szExeFile<<std::endl;
						std::string check = proc.szExeFile;
						if(check == "decentr_wg_communicator.exe") ++process_counter;
                    }while (Process32Next(hSnap, &proc));
                }

				std::cout<<"process counter:"<<process_counter<<std::endl<<std::endl;
				if(process_counter > 1) {
					std::cout<<"Only one instance is possible for this application...";
					char c;
					std::cin>>c;
					return false;}
	
	return true;
}

BOOL RegDel_value (HKEY hKeyRoot, LPTSTR lpSubKey, LPSTR lpValueName)
{
    LPTSTR   lpEnd;
    LONG     lResult;
    DWORD    dwSize;
    TCHAR    szName[MAX_PATH];
    HKEY     hKey;
    FILETIME ftWrite;

    lResult = RegDeleteKeyValueA(hKeyRoot, lpSubKey, lpValueName);

    if (lResult == ERROR_SUCCESS) return TRUE;
	return FALSE;

}

void cleanDecentrRegs()
{
	
	std::vector<LPTSTR> dec_reg_values = {
        (LPSTR)"C:\\DecentrWG_config\\WG_decentr_host.exe",
		(LPSTR)"C:\\DecentrWG_config\\WireguardUninstaller.exe",
		(LPSTR)"C:\\Program Files\\Decentr\\Decentr\\Application\\decentr.exe"
	};
	for(auto &it :dec_reg_values){
	BOOL res = RegDel_value(HKEY_CURRENT_USER,
		(LPTSTR)"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers",it
	);
	}
	
}

void deleteUselessFiles()
{
	std::string autoKill     = DECENTR_HOST_PATH;;
	std::string uninstaller  = DECENTR_HOST_PATH;
	autoKill.append("\\kill_vpn_task.exe");
	uninstaller.append("\\WG_decentr_host.exe");
	std::vector<fs::path> pathes = {autoKill,uninstaller};
	
	try{
		for(auto &it:pathes) fs::remove(it);
	}catch(fs::filesystem_error e){
		std::cout<< e.what();
	}
}

void copyUpdatedFiles(const std::string resourcesPath)
{
	//Create folders if they dont exist c:\\DecentrWG_config c:\\DecentrWG
	fs::create_directory(DECENTR_HOST_PATH);
	fs::create_directory(WIRE_GUARD_PATH);

	std::string wgSrcPath = resourcesPath;
	wgSrcPath.append("\\wg.exe");
	std::string wgDstnPath = WIRE_GUARD_PATH;
	wgDstnPath.append("\\wg.exe");

	std::string wireguardSrcPath = resourcesPath;
	wireguardSrcPath.append("\\wireguard.exe");
	std::string wireguardDstnPath = WIRE_GUARD_PATH;
	wireguardDstnPath.append("\\wireguard.exe");

	//std::string decentr_wg_communicatorSrcPath = pathToResources;
	//decentr_wg_communicatorSrcPath.append("\\decentr_wg_communicator.exe");
	//std::string decentr_wg_communicatorDstnPath = DECENTR_HOST_PATH;
	//decentr_wg_communicatorDstnPath.append("\\decentr_wg_communicator.exe");

    std::string decentr_wg__host_SrcPath = resourcesPath;
	decentr_wg__host_SrcPath.append("\\WG_decentr_host.exe");
	std::string decentr_wg__host_DstnPath = DECENTR_HOST_PATH;
	decentr_wg__host_DstnPath.append("\\WG_decentr_host.exe");

	std::string wireguardJson_SrcPath = resourcesPath;
	wireguardJson_SrcPath.append("\\wireguard.json");
	std::string wireguardJson_DstnPath = DECENTR_HOST_PATH;
	wireguardJson_DstnPath.append("\\wireguard.json");

	std::vector<std::pair<std::string,std::string>> pathes = {
		
		{wgSrcPath,wgDstnPath},
        {wireguardSrcPath,wireguardDstnPath},
		{decentr_wg__host_SrcPath,decentr_wg__host_DstnPath},
		{wireguardJson_SrcPath,wireguardJson_DstnPath}
	
	};
	for(auto &it:pathes){
		try{
			fs::copy(it.first,it.second,fs::copy_options::overwrite_existing);


		}catch(fs::filesystem_error e){
		std::cout<<e.what()<<std::endl;
		}
	}
}
