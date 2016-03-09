//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) 2006 Microsoft Corporation. All rights reserved.
//
//
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#define WIN32_LEAN_AND_MEAN

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif

#include <unknwn.h>
#include "CSampleCredential.h"
#include "guid.h"
#include <comdef.h>

// For HTTP response
#include <vector>
#include <iterator>

//#include <atlbase.h>
#include <AdsHlp.h>
#include <string>

//for user
#include <Iads.h>

//for domain
#include <DSRole.h>
#pragma comment(lib, "netapi32.lib")

//for dialogbox
#include <WinUser.h>
//#include <Windows.h>

//progressdialogbox
#include <Shlobj.h>

//for http
#include <winhttp.h>

//mac addr fetching
#include <winsock2.h>
#include <Iphlpapi.h>

//for sha1
#include <WinCrypt.h>

// for windows versions
//#include <VersionHelper.h> /* For windows 8 and above*/

//generating hash
#include "sha1.h"
#include <time.h>
//#include <WinCrypt.h>
#include <sstream>

#include <fstream>

#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

std::string get_adapter(PIP_ADAPTER_ADDRESSES aa)
{
	char buf[BUFSIZ];
	memset(buf, 0, BUFSIZ);
	WideCharToMultiByte(CP_ACP, 0, aa->FriendlyName, wcslen(aa->FriendlyName), buf, BUFSIZ, NULL, NULL);
	std::string adapter_name(buf);
	//printf("adapter_name:%s\n", buf);
	return adapter_name;
}
std::string get_addr(PIP_ADAPTER_UNICAST_ADDRESS ua)
{
	char buf[BUFSIZ];

	int family = ua->Address.lpSockaddr->sa_family;
	if(family == 2)
	{	
		memset(buf, 0, BUFSIZ);
		getnameinfo(ua->Address.lpSockaddr, ua->Address.iSockaddrLength, buf, sizeof(buf), NULL, 0,NI_NUMERICHOST);
	//printf("%s\n", buf);
		std::string address(buf);
		return address;
	}
	return "";
}

std::string get_ipaddress()
{
	DWORD rv, size;
	PIP_ADAPTER_ADDRESSES adapter_addresses, aa;
	PIP_ADAPTER_UNICAST_ADDRESS ua;

	rv = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &size);
	if (rv != ERROR_BUFFER_OVERFLOW) {
		//fprintf(stderr, "GetAdaptersAddresses() failed...");
		return "";
	}
	adapter_addresses = (PIP_ADAPTER_ADDRESSES)malloc(size);

	rv = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, adapter_addresses, &size);
	if (rv != ERROR_SUCCESS) {
		//fprintf(stderr, "GetAdaptersAddresses() failed...");
		free(adapter_addresses);
		return "";
	}
	std::string ADDRESS = "";
	for (aa = adapter_addresses; aa != NULL; aa = aa->Next) {
		std::string adapter = get_adapter(aa);
		if(adapter.compare("Local Area Connection") == 0){
			for (ua = aa->FirstUnicastAddress; ua != NULL; ua = ua->Next) {
				int family = ua->Address.lpSockaddr->sa_family;
				if(family == 2)
				{
					std::string address = get_addr(ua);
					return address;
				}				
			}
		}
		if(adapter.compare("Wireless Network Connection") == 0){
			for (ua = aa->FirstUnicastAddress; ua != NULL; ua = ua->Next) {
				int family = ua->Address.lpSockaddr->sa_family;
				if(family == 2)
				{
					std::string address = get_addr(ua);
					return address;
				}				
			}
		}
	}

	free(adapter_addresses);
	return "";
}

std::string _pszEmail, _pszVoicePhone, _pszSMSPhone;
std::string GetConfigOpt(std::string file, std::string key)
{
	std::string value;
	std::ifstream ifs(file);
	while(ifs.good())
	{
		std::string line;
		getline(ifs, line);
		if(line.find("#") == std::string::npos)
		{			
			if(line.find(key) != std::string::npos)
				value = line.substr(line.find("=")+2);
		}
	}
	return value;
}
void writeToLog(HRESULT hr)
{
	//TODO
	// finish formatting and writting HRESULT codes to a standard logging file for production
}

std::vector<std::string> split_string(LPSTR pszOutBuffer, std::string delim)
{
	std::vector<std::string> _s;
	//std::string s(pszOutBuffer);
	char *pch = strtok(pszOutBuffer, delim.c_str());
	if(pch != NULL)
		_s.push_back(pch);
	while(pch != NULL)
	{
		pch = strtok(NULL, delim.c_str());
		if(pch != NULL)
			_s.push_back(pch);
	}
	return _s;
}

std::string ws2s(const std::wstring& s)
{
    int len;
    int slength = (int)s.length() + 1;
    len = WideCharToMultiByte(CP_ACP, 0, s.c_str(), slength, 0, 0, 0, 0); 
    char* buf = new char[len];
    WideCharToMultiByte(CP_ACP, 0, s.c_str(), slength, buf, len, 0, 0); 
    std::string r(buf);
    delete[] buf;
    return r;
}

// Log any errors to our log file
void log_text_to_file(const std::string &EXTRA_MESSAGE, HRESULT hr)
{
	time_t t = time(NULL);
	char buffer[80];
	struct tm *timeinfo = localtime(&t);
	strftime(buffer, 80, "%c", timeinfo);

	std::string line;
	line.append(buffer);
	line.append("    ");
	line.append("aPersona Message: " + EXTRA_MESSAGE);
	line.append("    SYSTEM Error: ");	
	line.append(_com_error(hr).ErrorMessage());
	
	std::ofstream log_file("C:\\Program Files (x86)\\APersona\\aPersona Adaptive Multi-Factor Credential Provider v1.1.9 (x64) Setup\\log.txt", std::ios_base::out | std::ios_base::app);

	log_file << line << std::endl;
}

/*
	Checks to see if the string argument (user chosen domain) is the local machine name.  If so then the
	user has requested to authenticate locally and returns TRUE.
*/
bool isLocal(PWSTR d)
{
	WCHAR local[MAX_COMPUTERNAME_LENGTH+1];
	DWORD cch = ARRAYSIZE(local);
	GetComputerNameW(local, &cch);	
	
	if(d == NULL)
		return false;	
	if(wcslen(d) == 0)
	{
		return true;
	}
	if(wcscmp(d, local) == 0)
	{
		return true;
	}
	return false;
}

// Takes a PWSTR username from login and splits it into context and userid
PWSTR splitUsername(PWSTR u)
{
	PWSTR splitUser = NULL, splitDomain = NULL;
	if( wcsrchr(u, L'\\') != NULL )
	{
		splitUser = wcsrchr(u, L'\\') + 1;
	}
	else if( wcsrchr(u, L'\@') )
	{
		wchar_t* tok = wcstok(u, L"@");
		splitUser = tok;
	}
	else
		splitUser = u;
	return splitUser;
}
/*
Gets MAC Address
//TODO: http://stackoverflow.com/questions/13646621/how-to-get-mac-address-in-windows-with-c
*/
char* GetMacAddress()
{
	PIP_ADAPTER_INFO AdapterInfo;
	DWORD dwBufLen = sizeof(AdapterInfo);
	char* mac_addr = (char *)malloc(17);

	//allocating memory for getadapterinfo
	AdapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof(IP_ADAPTER_INFO));
	
	if(AdapterInfo == NULL){
		//TODO: error allocating memory, handle gracefully
		log_text_to_file("Error allocating memory when getting MAC Address", NULL);
	}

	//call to getadapterinfo to get size for dwbuflen
	if(GetAdaptersInfo(AdapterInfo,&dwBufLen) == ERROR_BUFFER_OVERFLOW){

		AdapterInfo = (IP_ADAPTER_INFO *) malloc(dwBufLen);

		if(AdapterInfo == NULL){
			//TODO: Error allocating memory for getadapters info, like above. handle gracefully.
		}
	}

	//get the mac addr
	if(GetAdaptersInfo(AdapterInfo,&dwBufLen) == NO_ERROR) {
			PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo; //Pointer to adapter info
		do{
			//copy over mac addr
			sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
			pAdapterInfo->Address[0], pAdapterInfo->Address[1],
			pAdapterInfo->Address[2], pAdapterInfo->Address[3],
			pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
			pAdapterInfo = pAdapterInfo->Next;
		} while(pAdapterInfo);
	}

	free(AdapterInfo);
	return mac_addr;
}

// Get the Domain name string
LPWSTR GetDomain()
{
	DSROLE_PRIMARY_DOMAIN_INFO_BASIC *info;
	DWORD dw;
	dw = DsRoleGetPrimaryDomainInformation(NULL, DsRolePrimaryDomainInfoBasic, (PBYTE*)&info);
	if(dw != ERROR_SUCCESS)
	{
		return NULL;
	}
	if(info->DomainNameDns == NULL)
	{
		return info->DomainNameFlat;
	}
	else
		return info->DomainNameFlat;
}
// CSampleCredential ////////////////////////////////////////////////////////

CSampleCredential::CSampleCredential():
_cRef(1),
	_pCredProvCredentialEvents(NULL)
{
	DllAddRef();

	ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
	ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
	ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

CSampleCredential::~CSampleCredential()
{
	/// ------------ TODO: May need to clear out the username field 
	if (_rgFieldStrings[SFI_PASSWORD])
	{
		// CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
		size_t lenPassword;
		HRESULT hr = StringCchLengthW(_rgFieldStrings[SFI_PASSWORD], 128, &(lenPassword));
		if (SUCCEEDED(hr))
		{
			SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));
		}
		else
		{
			// TODO: Determine how to handle count error here.
		}
	}
	for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
	{
		CoTaskMemFree(_rgFieldStrings[i]);
		CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
	}

	DllRelease();
}

// Initializes one credential with the field information passed in.
// Set the value of the SFI_USERNAME field to pwzUsername.
// Optionally takes a password for the SetSerialization case.
HRESULT CSampleCredential::Initialize(
	CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
	const FIELD_STATE_PAIR* rgfsp,
	PCWSTR pwzUsername,
	PCWSTR pwzDomain,
	PCWSTR pwzPassword
	)
{
	HRESULT hr = S_OK;

	_cpus = cpus;

	// Init local domain to NULL
	_pDomainName = NULL;
	_pszOTP = NULL;

	// Copy the field descriptors for each field. This is useful if you want to vary the 
	// field descriptors based on what Usage scenario the credential was created for.
	for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
	{
		_rgFieldStatePairs[i] = rgfsp[i];
		hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
	}

	// Initialize the String values of all the fields.
	if (SUCCEEDED(hr))
	{
		//hr = SHStrDupW(pwzUsername, &_rgFieldStrings[SFI_USERNAME]);
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_USERNAME]);
	}	
	if(SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(pwzPassword ? pwzPassword : L"", &_rgFieldStrings[SFI_PASSWORD]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
	}
	if (SUCCEEDED(hr))
    {
        //hr = SHStrDupW(GetDomain(), &_rgFieldStrings[SFI_DOMAIN]);
		wchar_t buf[80];
		wcscpy(buf, L"Log on to: ");
		wcscat(buf, GetDomain());
		hr = SHStrDupW(buf, &_rgFieldStrings[SFI_DOMAIN]);
    }

	return S_OK;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CSampleCredential::Advise(
	ICredentialProviderCredentialEvents* pcpce
	)
{
	if (_pCredProvCredentialEvents != NULL)
	{
		_pCredProvCredentialEvents->Release();
	}
	_pCredProvCredentialEvents = pcpce;
	_pCredProvCredentialEvents->AddRef();
	return S_OK;
}

// LogonUI calls this to tell us to release the callback.
HRESULT CSampleCredential::UnAdvise()
{
	if (_pCredProvCredentialEvents)
	{
		_pCredProvCredentialEvents->Release();
	}
	_pCredProvCredentialEvents = NULL;
	return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed).
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the 
// field definitions.  But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CSampleCredential::SetSelected(BOOL* pbAutoLogon)  
{
	*pbAutoLogon = FALSE;  

	return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT CSampleCredential::SetDeselected()
{
	HRESULT hr = S_OK;
	if (_rgFieldStrings[SFI_PASSWORD])
	{
		// CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
		size_t lenPassword;
		hr = StringCchLengthW(_rgFieldStrings[SFI_PASSWORD], 128, &(lenPassword));
		if (SUCCEEDED(hr))
		{
			SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));

			CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
			hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
		}

		if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
		{
			_pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, _rgFieldStrings[SFI_PASSWORD]);
			
			// Clear username
			hr = SHStrDupW(L"", &_rgFieldStrings[SFI_USERNAME]);
			_pCredProvCredentialEvents->SetFieldString(this, SFI_USERNAME, _rgFieldStrings[SFI_USERNAME]);

			// Clear OTP
			hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP]);
			_pCredProvCredentialEvents->SetFieldString(this, SFI_OTP, _rgFieldStrings[SFI_OTP]);
		}
	}

	return hr;
}

// Gets info for a particular field of a tile. Called by logonUI to get information to 
// display the tile.
HRESULT CSampleCredential::GetFieldState(
	DWORD dwFieldID,
	CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
	CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis
	)
{
	HRESULT hr;

	// Validate paramters.
	if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)) && pcpfs && pcpfis)
	{
		*pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
		*pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;

		hr = S_OK;
	}
	else
	{
		hr = E_INVALIDARG;
	}
	return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID.
HRESULT CSampleCredential::GetStringValue(
	DWORD dwFieldID, 
	PWSTR* ppwsz
	)
{
	HRESULT hr;

	// Check to make sure dwFieldID is a legitimate index.
	if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && ppwsz) 
	{
		// Make a copy of the string and return that. The caller
		// is responsible for freeing it.
		hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

// Gets the image to show in the user tile.
HRESULT CSampleCredential::GetBitmapValue(
	DWORD dwFieldID, 
	HBITMAP* phbmp
	)
{
	HRESULT hr;
	if ((SFI_TILEIMAGE == dwFieldID) && phbmp)
	{
		HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
		if (hbmp != NULL)
		{
			hr = S_OK;
			*phbmp = hbmp;
		}
		else
		{
			hr = HRESULT_FROM_WIN32(GetLastError());
		}
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be 
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT CSampleCredential::GetSubmitButtonValue(
	DWORD dwFieldID,
	DWORD* pdwAdjacentTo
	)
{
	HRESULT hr;

	// Validate parameters.
	if ((SFI_SUBMIT_BUTTON == dwFieldID) && pdwAdjacentTo)
	{
		// pdwAdjacentTo is a pointer to the fieldID you want the submit button to appear next to.
		//*pdwAdjacentTo = SFI_PASSWORD;
		*pdwAdjacentTo = SFI_OTP;
		hr = S_OK;
	}
	else
	{
		hr = E_INVALIDARG;
	}
	return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field.
HRESULT CSampleCredential::SetStringValue(
	DWORD dwFieldID, 
	PCWSTR pwz      
	)
{
	HRESULT hr;

	// Validate parameters.
	if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && 
		(CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft || 
		CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft)) 
	{
		/*** TODO!! At this point we need to detect the user attempting to change the default logon domain and we can adjust the 
		Text fields if needed to display that to the user.
		- For example if the user types .\ Then we know that the user requested a logon to the localhost and would set the Text to display the COMPUTERNAME
		- If they type DOMAIN\ then set the Text to be DOMAIN
		***/
		if(dwFieldID == SFI_OTP)
		{
			_pszOTP = _rgFieldStrings[SFI_OTP];			
		}
		
		if(dwFieldID == SFI_USERNAME)
		{
			PWSTR _p = wcsrchr(_rgFieldStrings[SFI_USERNAME], L'\\');
			if(_p != NULL)
			{
				wchar_t* tok = wcstok(_rgFieldStrings[SFI_USERNAME], L"\\");
				_p = tok;
				// Replace the text for SFI_DOMAIN
				wchar_t buf[80];
				wcscpy(buf, _p);
				if(wcslen(buf) == 1)
				{
					if(wcscmp(buf, L".") == 0)
					{
						// Set Log on to text to LOCALHOST
						wchar_t _b[80];
						wcscpy(_b, L"Log on to: ");
						WCHAR wsz[MAX_COMPUTERNAME_LENGTH+1];
						DWORD cch = ARRAYSIZE(wsz);
						GetComputerNameW(wsz, &cch);
						wcscat(_b, wsz);
						hr = _pCredProvCredentialEvents->SetFieldString(this, SFI_DOMAIN, _b);
						//std::wstring ws(_b);
						//std::vector<wchar_t> v(ws.begin(), ws.end());
						//_pDomainName = v.data();
						_pDomainName = _b;
					}
				}
				else
				{
					// Set log on to text of user entered DOMAIN
					wchar_t _b[80];
					wcscpy(_b, L"Log on to: ");
					wcscat(_b, _p);
					hr = _pCredProvCredentialEvents->SetFieldString(this, SFI_DOMAIN, _b);
					std::wstring ws(_b);
					std::vector<wchar_t> v(ws.begin(), ws.end());
					_pDomainName = v.data();
				}
			}
			else
			{
				// Reset local domain var
				_pDomainName = NULL;

				wchar_t _b[80];
				wcscpy(_b, L"Log on to: ");
				wcscat(_b, GetDomain());
				hr = _pCredProvCredentialEvents->SetFieldString(this, SFI_DOMAIN, _b);
			}
		}
		
		// Original code
		PWSTR* ppwszStored = &_rgFieldStrings[dwFieldID];
		CoTaskMemFree(*ppwszStored);
		hr = SHStrDupW(pwz, ppwszStored);		
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

//------------- 
// The following methods are for logonUI to get the values of various UI elements and then communicate
// to the credential about what the user did in that field.  However, these methods are not implemented
// because our tile doesn't contain these types of UI elements
HRESULT CSampleCredential::GetCheckboxValue(
	DWORD dwFieldID, 
	BOOL* pbChecked,
	PWSTR* ppwszLabel
	)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(pbChecked);
	UNREFERENCED_PARAMETER(ppwszLabel);

	return E_NOTIMPL;
}

HRESULT CSampleCredential::GetComboBoxValueCount(
	DWORD dwFieldID, 
	DWORD* pcItems, 
	DWORD* pdwSelectedItem
	)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(pcItems);
	UNREFERENCED_PARAMETER(pdwSelectedItem);
	return E_NOTIMPL;
}

HRESULT CSampleCredential::GetComboBoxValueAt(
	DWORD dwFieldID, 
	DWORD dwItem,
	PWSTR* ppwszItem
	)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(dwItem);
	UNREFERENCED_PARAMETER(ppwszItem);
	return E_NOTIMPL;
}

HRESULT CSampleCredential::SetCheckboxValue(
	DWORD dwFieldID, 
	BOOL bChecked
	)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(bChecked);

	return E_NOTIMPL;
}

HRESULT CSampleCredential::SetComboBoxSelectedValue(
	DWORD dwFieldId,
	DWORD dwSelectedItem
	)
{
	UNREFERENCED_PARAMETER(dwFieldId);
	UNREFERENCED_PARAMETER(dwSelectedItem);
	return E_NOTIMPL;
}

HRESULT CSampleCredential::CommandLinkClicked(DWORD dwFieldID)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	return E_NOTIMPL;
}
//------ end of methods for controls we don't have in our tile ----//

//	Returns a pointer to an IADsUser object that can be used to collect domain attributes for that user otherwise returns NULL if 
//	a failure occurs.
//
//	@param	pw	A PWSTR for the users password that is required to authenticate the search
//  @param	u	A PWSTR for the users username that is required to authenticate the search and what to search for
//  @param	hr	A HRESULT address to store the HRESULT of various IADs calls
//  @ret	_user	A IADsUser pointer
IADsUser* getIADsUser(PWSTR pw, PWSTR u, HRESULT& hr)
{
	IDirectorySearch *pDSSearch = NULL;
	IADsUser *_user = NULL;
	CoInitialize(NULL);
	/// WinNT - used to communicate with windows domain controllers.
	/// LDAP  - used to communicate with LDAP servers, such as Active Directory.
	// LDAP: - binds to root of LDAP namespace
	// LDAP://server01 - binds to specific server
	// LDAP://server01:333 - binds to specific server using designated port
	// LDAP://CN=Jeff Smith, CN=users, DC=blah, DC=com - bind to a specific object  /** Should probably default to this **/
	// LDAP://server01/CN=Jeff Smith, CN=users, DC=blah, DC=com - bind to specific object through specific server
	/*** If kerberos is required, then you have to use a server-less string, OR a fully qualified DNS server name such as 
	LDAP://server01.fabrikam.com/CN=Jeff Smith, CN=users, DC=fabrikam, DC=com
	***/
	/// ADs   - used to provde an IADsNamespaces implementation that can be used to enumerate all the ADSI providers installed on the client

	// Get the current Domain
	LPWSTR pszDomain = GetDomain();	
		
	wchar_t dbuf[64];
	if(pszDomain != NULL)
	{
		wchar_t dbuf[64];
		wcscpy(dbuf, L"LDAP://");
		wcscat(dbuf, pszDomain);
		hr = ADsOpenObject(dbuf, u, pw, ADS_SECURE_AUTHENTICATION, IID_IDirectorySearch, (void**)&pDSSearch);		
	}
	
	if(SUCCEEDED(hr))
	{
		// Search for the DistinguishedName
		LPWSTR pszAttr[] = {L"distinguishedname"};
		ADS_SEARCH_HANDLE hSearch;

		wchar_t buf[128];
		wcscpy(buf, L"(&(objectClass=user)(objectCategory=person)(sAMAccountName=");
		wcscat(buf, u);
		wcscat(buf, L"))");

		hr = pDSSearch->ExecuteSearch(buf, pszAttr, 1, &hSearch);
		if(!SUCCEEDED(hr))
		{
			//::MessageBoxA(NULL, _com_error(hr).ErrorMessage(), "APersona Active Directory Error", 0);
			log_text_to_file("aPersona Active Directory Error", hr);
			return NULL;
		}
		hr = pDSSearch->GetFirstRow(hSearch);
		if(!SUCCEEDED(hr))
		{
			//::MessageBoxA(NULL, _com_error(hr).ErrorMessage(), "APersona Active Directory Error", 0);
			log_text_to_file("aPersona Active Directory Error", hr);
			pDSSearch->Release();
			return NULL;
		}
		ADS_SEARCH_COLUMN column;
		hr = pDSSearch->GetColumn(hSearch, L"distinguishedName", &column);
		if(!SUCCEEDED(hr))
		{
			//::MessageBoxA(NULL, _com_error(hr).ErrorMessage(), "APersona Active Directory Error", 0);
			log_text_to_file("aPersona Active Directory Error", hr);
			pDSSearch->Release();
			return NULL;
		}
		PWSTR s = column.pADsValues->DNString;
		pDSSearch->Release();
				
		wchar_t _d[128];
		wcscpy(_d, L"LDAP://");
		wcscat(_d, s);
		hr = ADsOpenObject(_d, u, pw, ADS_SECURE_AUTHENTICATION, IID_IADsUser, (void**)&_user);
		if(!SUCCEEDED(hr))
		{
			//::MessageBoxA(NULL, _com_error(hr).ErrorMessage(), "APersona Active Directory Error", 0);
			log_text_to_file("aPersona Active Directory Error", hr);
			return NULL;
		}		
		return _user;
	}	
	else
		log_text_to_file("aPersona Active Directory Error", hr);
	return _user;
}

//Gets Processor ID
// @ret	procInfo a char pointer to the string processor id
char* GetProcessor() {
	char procInfo[10];

	//sys info struct
	SYSTEM_INFO _si;

	//get sysinfo
	GetSystemInfo(&_si);

	//get processor type
	sprintf(procInfo,  "%lu", _si.dwProcessorType);

	return procInfo;
}

// Returns a DWORD value for a given Registry key within the HKLM\SOFTWARE\APersona hive
DWORD GetKeyValueDword(std::string key)
{
	HKEY hApersonaKey = NULL;
	unsigned long dwType = REG_DWORD;
    DWORD dwBufferSize = 1024;
	DWORD sConfigValue;
	std::string sRoot = "SOFTWARE\\APersona\\";

	//Open the "Uninstall" key.
	HRESULT hr = RegOpenKeyEx(HKEY_LOCAL_MACHINE, sRoot.append(key).c_str(), 0, KEY_READ, &hApersonaKey);
	if(!SUCCEEDED(hr))
	{		
		//::MessageBoxA(NULL, _com_error(hr).ErrorMessage(), "APersona Registry Error", 0);
		log_text_to_file("aPersona Registry Error", hr);
		RegCloseKey(hApersonaKey);
	}
	hr = RegQueryValueEx(hApersonaKey, key.c_str(), NULL, &dwType, (LPBYTE)sConfigValue, &dwBufferSize);
	if(!SUCCEEDED(hr))
	{
		//::MessageBoxA(NULL, _com_error(hr).ErrorMessage(), "APersona Registry Error", 0);
		log_text_to_file("aPersona Registry Error", hr);
		RegCloseKey(hApersonaKey);
	}
	// Error check
	RegCloseKey(hApersonaKey);
				
	return sConfigValue;
}

// Reads a string value from a registry key in the HKLM\SOFTWARE\APersona hive
// @ret hr HRESULT containing any errors from the lookup
HRESULT GetKeyValue(std::string key, std::string& value)
{
	HKEY hApersonaKey = NULL;
	HKEY hConfigKey = NULL;
	DWORD dwType = KEY_ALL_ACCESS;
    DWORD dwBufferSize = 0;
	char sConfigValue[1024];//WCHAR sConfigValue[1024];
	std::string sRoot = "SOFTWARE\\APersona\\";

	//Open the "Uninstall" key.
	HRESULT hr = RegOpenKeyEx(HKEY_LOCAL_MACHINE, sRoot.append(key).c_str(), 0, KEY_READ, &hApersonaKey);
	if(SUCCEEDED(hr))
	{
		hr = RegQueryValueEx(hApersonaKey, key.c_str(), NULL,	&dwType, NULL, &dwBufferSize);
		if(SUCCEEDED(hr))
		{
			hr = RegQueryValueEx(hApersonaKey, key.c_str(), NULL,	&dwType, (LPBYTE)sConfigValue, &dwBufferSize);
			if(SUCCEEDED(hr))
			{
				RegCloseKey(hApersonaKey);
				std::string s(sConfigValue);
				value = s;
				return hr;
			}
			else
			{
				RegCloseKey(hApersonaKey);
				value = "";
				log_text_to_file("aPersona Registry Error reading key " + key, hr);
				//::MessageBoxA(NULL, _com_error(hr).ErrorMessage(), "APersona Registry Error", 0);
				return hr;
			}
		}
		else
		{
			RegCloseKey(hApersonaKey);
			value = "";
			log_text_to_file("aPersona Registry Error reading key " + key, hr);
			//::MessageBoxA(NULL, _com_error(hr).ErrorMessage(), "APersona Registry Error", 0);
			return hr;
		}
	}
	else
	{
		RegCloseKey(hApersonaKey);
		value = "";
		log_text_to_file("aPersona Registry Error reading key " + key, hr);
		//::MessageBoxA(NULL, _com_error(hr).ErrorMessage(), "APersona Registry Error", 0);
		return hr;
	}	
	return hr;
}

// Gets a list of installed applications and returns them as a single string which is used later
// to create a unique SHA256 hash
std::string GetInstalledApps()
{
	std::string list = "";
	HKEY hUninstKey = NULL;
    HKEY hAppKey = NULL;
    LPSTR sAppKeyName;
    LPSTR sSubKey;
    WCHAR sDisplayName[1024];
    LPCSTR sRoot = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    long lResult = ERROR_SUCCESS;
    DWORD dwType = KEY_ALL_ACCESS;
    DWORD dwBufferSize = 0;

    //Open the "Uninstall" key.
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, sRoot, 0, KEY_READ, &hUninstKey) != ERROR_SUCCESS)
    {
		//::MessageBoxA(NULL, _com_error(hr).ErrorMessage(), "APersona Registry Error", 0);
		//log_text_to_file("aPersona Registry Error reading list of installed applications", NULL);
        return "";
    }

    for(DWORD dwIndex = 0; lResult == ERROR_SUCCESS; dwIndex++)
    {
        //Enumerate all sub keys...
        dwBufferSize = sizeof(sAppKeyName);
        if((lResult = RegEnumKeyEx(hUninstKey, dwIndex, sAppKeyName,
            &dwBufferSize, NULL, NULL, NULL, NULL)) == ERROR_SUCCESS)
        {
            //Open the sub key.
            wsprintf(sSubKey, "%s\\%s", sRoot, sAppKeyName);
            if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, sSubKey, 0, KEY_READ, &hAppKey) != ERROR_SUCCESS)
            {
                RegCloseKey(hAppKey);
                RegCloseKey(hUninstKey);
				//log_text_to_file("aPersona Registry Error reading list of installed applications", NULL);
                return "";
            }

            //Get the display name value from the application's sub key.
            dwBufferSize = sizeof(sDisplayName);
            if(RegQueryValueEx(hAppKey, "DisplayName", NULL,
                &dwType, (unsigned char*)sDisplayName, &dwBufferSize) == ERROR_SUCCESS)
            {
                wprintf(L"%s\n", sDisplayName);
				std::wstring w(sDisplayName);
				std::string s(w.begin(), w.end());
				list.append(s);
            }
            else{
                //Display name value doe not exist, this application was probably uninstalled.
            }
            RegCloseKey(hAppKey);
        }
    }
    RegCloseKey(hUninstKey);
    return list;
}

// Get the unique CPU identifier and return it as a string which is used later to create
// a unique SHA256 hash
std::string GetCPUString()
{
	// Get extended ids.
    int CPUInfo[4] = {-1};
    __cpuid(CPUInfo, 0x80000000);
    unsigned int nExIds = CPUInfo[0];

    // Get the information associated with each extended ID.
    char CPUBrandString[0x40] = { 0 };
    for( unsigned int i=0x80000000; i<=nExIds; ++i)
    {
        __cpuid(CPUInfo, i);

        // Interpret CPU brand string and cache information.
        if  (i == 0x80000002)
        {
            memcpy( CPUBrandString,
            CPUInfo,
            sizeof(CPUInfo));
        }
        else if( i == 0x80000003 )
        {
            memcpy( CPUBrandString + 16,
            CPUInfo,
            sizeof(CPUInfo));
        }
        else if( i == 0x80000004 )
        {
            memcpy(CPUBrandString + 32, CPUInfo, sizeof(CPUInfo));
        }
	}
    return CPUBrandString;
}

enum HashType
{
  HashSha1, HashMd5, HashSha256
};
std::string GetTable()
{
	PMIB_TCPTABLE pTcpTable = (MIB_TCPTABLE*)malloc(sizeof(MIB_TCPTABLE));
	DWORD dwSize = sizeof(MIB_TCPTABLE);
	BOOL bOrder = true;
	char szRemoteAddr[128];
	struct in_addr IpAddr;
	std::string remoteAddress = "";

	DWORD dw = GetTcpTable(pTcpTable, &dwSize, bOrder);
	// Not enough space so resize
	if(dw == ERROR_INSUFFICIENT_BUFFER)
	{
		free(pTcpTable);
		pTcpTable = (MIB_TCPTABLE*)malloc(dwSize);
	}
	// Make second call to get actual table data now
	dw = GetTcpTable(pTcpTable, &dwSize, true);
	if(dw == NO_ERROR)
	{
		//printf("num of entries:%d\n", (int)pTcpTable->dwNumEntries);
		for(int i = 0; i < (int)pTcpTable->dwNumEntries; i++)
		{
			//std::ostringstream os, os1;
			//	os << (u_long)pTcpTable->table[i].dwRemoteAddr;//ntohs((u_short)pTcpTable->table[i].dwLocalPort)
			//	os1 << ntohs((u_short)pTcpTable->table[i].dwRemotePort) << " " << ntohs((u_short)pTcpTable->table[i].dwLocalPort);
			//	log_text_to_file("address " + os.str() + " "+ os1.str(), NULL);

			//if(pTcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB)
			//{				
				if(ntohs((u_short)pTcpTable->table[i].dwLocalPort) == 3389)
				{
					// Found a RDC ESTABLISHED connection
					IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwRemoteAddr;
					strcpy_s(szRemoteAddr, sizeof(szRemoteAddr), inet_ntoa(IpAddr));
					remoteAddress = szRemoteAddr;
				}
			//}			
		}
	}
	//printf("adapter_name:%s\n", "hi");
	//std::string remoteAddress(szRemoteAddr);
	return remoteAddress;
}

std::string GetMac(const char *DestIpString)
{
	IPAddr DestIp = 0;
	//IPAddr SrcIp = 0;
	ULONG MacAddr[2];
	ULONG PhysAddrLen = 6;
	DestIp = inet_addr(DestIpString);
	std::string MAC = "";
	BYTE *bPhysAddr;
	DWORD dw = SendARP(DestIp, 0, &MacAddr, &PhysAddrLen);
	if(dw == NO_ERROR)
	{
		bPhysAddr = (BYTE*)&MacAddr;
		if(PhysAddrLen)
		{
			char buf[80];
			for(int i = 0; i < (int)PhysAddrLen; i++)
			{
				if(i == (PhysAddrLen -1))
					sprintf(buf, "%.2X", (int)bPhysAddr[i]);
				else
					sprintf(buf, "%.2X-", (int)bPhysAddr[i]);
				MAC += buf;
			}
			//MAC += buf;
			return MAC;
		}
	}
	else
	{
		switch(dw)
		{
		case ERROR_GEN_FAILURE:
				break;
		case ERROR_INVALID_PARAMETER:
					break;
		case ERROR_INVALID_USER_BUFFER:
			break;
		case ERROR_BAD_NET_NAME:
			break;
		case ERROR_BUFFER_OVERFLOW:
			break;
		case ERROR_NOT_FOUND:
			break;
		default:
			break;

		}
	}
	return MAC;
}

std::string GetSaltText()
{
	HCRYPTPROV hProvider = NULL;
	if (!::CryptAcquireContextW(&hProvider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		return "";

	const DWORD dwLength = sizeof(unsigned int);
	BYTE pbBuffer[dwLength] = {};

	if (!::CryptGenRandom(hProvider, dwLength, pbBuffer))
	{
		::CryptReleaseContext(hProvider, 0);
		return "";
	}

	std::ostringstream oss;
	for (DWORD i = 0; i < dwLength; ++i){
		//std::cout << std::hex << *static_cast<unsigned int*>(pbBuffer[i]) << std::endl;
		oss.fill('0');
		oss.width(2);
		oss << std::hex << static_cast<const unsigned int>(pbBuffer[i]);
	}

	if (!::CryptReleaseContext(hProvider, 0))
		return "";
	//return oss.str();
	return "h2CRnuP40n9eFtMG5r8FivgCyGclwZRawJe363C9yzA=";
}

std::string GetHashText( const void * data, const size_t data_size, HashType hashType )
{
  HCRYPTPROV hProv = NULL;

  if ( ! CryptAcquireContext( &hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT ) ) {
    return "";
  }

  BOOL hash_ok = FALSE;
  HCRYPTPROV hHash = NULL;
  switch ( hashType ) {
  case HashSha1 : hash_ok = CryptCreateHash( hProv, CALG_SHA1, 0, 0, &hHash ); break;
  case HashMd5 : hash_ok = CryptCreateHash( hProv, CALG_MD5, 0, 0, &hHash ); break;
  case HashSha256 : hash_ok = CryptCreateHash( hProv, CALG_SHA_256, 0, 0, &hHash ); break;
  }

  if ( ! hash_ok ) {
    CryptReleaseContext(hProv, 0);
    return "";
  }

  if ( ! CryptHashData( hHash, static_cast<const BYTE *>(data), data_size, 0 ) ) {
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return "";
  }

  DWORD cbHashSize = 0, dwCount = sizeof(DWORD);
  if( ! CryptGetHashParam( hHash, HP_HASHSIZE, (BYTE *)&cbHashSize, &dwCount, 0 ) ) {
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return "";
  }

  std::vector<BYTE> buffer( cbHashSize );
  if ( ! CryptGetHashParam( hHash, HP_HASHVAL, reinterpret_cast<BYTE*>( &buffer[0] ), &cbHashSize, 0) ) {
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return "";
  }

  std::ostringstream oss;

  for ( std::vector<BYTE>::const_iterator iter = buffer.begin(); iter != buffer.end(); ++iter ) {
    oss.fill('0');
    oss.width(2);
    oss << std::hex << static_cast<const int>(*iter);
  }

  CryptDestroyHash(hHash);
  CryptReleaseContext(hProv, 0);
  return oss.str();
}

// Get the OS Version and return the String representation
std::string GetOSVersion()
{
	OSVERSIONINFO osvi;
    BOOL bIsWindowsXPorLater;

    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    GetVersionEx(&osvi);
	if(osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 0)
		return "Windows Vista";
	if(osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1)
		return "Windows XP";
	if(osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1)
		return "Windows 7";
	if(osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 2)
		return "Windows 8";
	if(osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 3)
		return "Windows 8.1";
	if(osvi.dwMajorVersion == 10 && osvi.dwMinorVersion == 0)
		return "Windows 10";
    return "Unknown";
    
	/* Below is for Windows 8 and above
	if (IsWindowsXPOrGreater())
    {
       return "Windows XP";// printf("XPOrGreater\n");
    }
    if (IsWindowsXPSP1OrGreater())
    {
        return "Windows XP SP1";//printf("XPSP1OrGreater\n");
    }
    if (IsWindowsXPSP2OrGreater())
    {
        return "Windows XP SP2";//printf("XPSP2OrGreater\n");
    }
    if (IsWindowsXPSP3OrGreater())
    {
        return "Windows XP SP3";//printf("XPSP3OrGreater\n");
    }
    if (IsWindowsVistaOrGreater())
    {
        return "Windows Vista";//printf("VistaOrGreater\n");
    }
    if (IsWindowsVistaSP1OrGreater())
    {
        return "Windows Vista SP1";//printf("VistaSP1OrGreater\n");
    }
    if (IsWindowsVistaSP2OrGreater())
    {
        return "Windows Vista SP2";//printf("VistaSP2OrGreater\n");
    }
    if (IsWindows7OrGreater())
    {
        return "Windows 7";//printf("Windows7OrGreater\n");
    }
    if (IsWindows7SP1OrGreater())
    {
       return "Windows 7 SP1";// printf("Windows7SP1OrGreater\n");
    }
    if (IsWindows8OrGreater())
    {
        return "Windows 8";//printf("Windows8OrGreater\n");
    }
    if (IsWindows8Point1OrGreater())
    {
        return "Windows 8.1";//printf("Windows8Point1OrGreater\n");
    }
    if (IsWindows10OrGreater())
    {
        return "Windows 10";//printf("Windows10OrGreater\n");
    }
    if (IsWindowsServer())
    {
        return "Server";//printf("Server\n");
    }
    else
    {
        //printf("Unknown\n");
		return "Unknown";
    }
	*/
}

// Builds a HTTP POST string that is passed to the APersona server
std::string buildAPersonaKey()
{
	std::string _ret;
		
	_ret = "{";
	_ret.append("\"apersonaKey\":\"");
			
	if(GetSystemMetrics(SM_REMOTESESSION) == 0) // Local
	{
		std::string cpu = GetCPUString() + GetSaltText();
		std::string apps = GetInstalledApps() + GetSaltText();

		std::string h1 = GetHashText(cpu.c_str(), strlen(cpu.c_str()), HashSha256);//getHash();
		std::string h2 = GetHashText(apps.c_str(), strlen(apps.c_str()), HashSha256);
		std::string m1 = GetHashText(h1.c_str(), strlen(h1.c_str()), HashMd5);
		std::string m2 = GetHashText(h2.c_str(), strlen(h2.c_str()), HashMd5);

		std::string apkeyHash = "";
		apkeyHash.append(m1);
		apkeyHash.append("-");
		apkeyHash.append(m2);
		apkeyHash.append("-mwin\"");
		
		_ret.append(apkeyHash);

		_ret.append(",\"ipAddress\":");
		std::string address = get_ipaddress();
		_ret.append("\"" + address + "\"");
	}
	else
	{
		std::string remoteAddress = GetTable();
		if(remoteAddress.length() > 0)
		{
			std::string remoteMACAddress = GetMac(remoteAddress.c_str());
			if(remoteMACAddress.length() > 0)
			{
				// Create hash from mac
				// hash-0-0-mwin
				std::string macHash = GetHashText(remoteMACAddress.c_str(), strlen(remoteMACAddress.c_str()), HashSha256);
				std::string md5MacHash = GetHashText(macHash.c_str(), strlen(macHash.c_str()), HashMd5);
				
				std::string apkeyHash = "";
				apkeyHash.append(md5MacHash);
				apkeyHash.append("-0-0-mwin\"");
				_ret.append(apkeyHash);

				_ret.append(",\"ipAddress\":");				
				_ret.append("\"" + remoteAddress + "\"");
			}
			else
			{
				// Use Remote IP Address to create hash
				std::string addHash = GetHashText(remoteAddress.c_str(), strlen(remoteAddress.c_str()), HashSha256);
				std::string md5AddHash = GetHashText(addHash.c_str(), strlen(addHash.c_str()), HashMd5);
				
				std::string apkeyHash = "";
				apkeyHash.append(md5AddHash);
				apkeyHash.append("-0-0-mwin\"");
				_ret.append(apkeyHash);

				_ret.append(",\"ipAddress\":");				
				_ret.append("\"" + remoteAddress + "\"");
			}
		}
		else
		{
			// No address found and thus no MAC can be found.  Log error and leave aPersona key blank..
			log_text_to_file("aPersona RDC Remote Address unable to resolve.", E_ABORT);
		}
	}
	//_ret.append(",\"ipAddress\":");
	//std::string address = get_ipaddress();
	//_ret.append("\"" + address + "\"");
	//PWSTR _tmp = getIADsNetAddress(u, p);
	//_ret.append(ws2s(_tmp));

	//_ret.append(",\"ipAddrPri\":");
	//_ret.append(ipAddressPrivate);

	_ret.append(",\"deviceType\":\"PC\"");

	_ret.append(",\"osInfo\":\"");
	std::string OS = GetOSVersion();	
	_ret.append(OS);
	_ret.append("\"");

	_ret.append("}");

	return _ret;
}
HRESULT buildHttpPostString(PWSTR u, PWSTR p, LPCSTR _key, DWORD _flag, DWORD _otpflag, PWSTR _otpcode, std::string& pszPostData )
{
	std::string _DATA;
	HRESULT hr;
		
	IADsUser *user = NULL;
	user = getIADsUser(p, u, hr);

	if(user == NULL)
	{
		//::MessageBoxA(NULL, _com_error(hr).ErrorMessage(), "APersona Active Directory Error", 0);
		log_text_to_file("aPersona Active Directory Error, IADsUser lookup failed for user: " + ws2s(u), NULL);
		return E_ABORT;//OutputWrite(L"User is null");
	}
		
	// add SAM name (login)
	_DATA = "id=";
	std::wstring ws = u;
	_DATA.append(ws2s(u));
	
	// add Email
	BSTR var;
	user->get_EmailAddress(&var);
	PWSTR _email = _email;
	_DATA.append("&u=");
	_DATA.append(ws2s(_email));

	_pszEmail = ws2s(_email);
			
	// add Security Policy License Key 
	_DATA.append("&l=");//PWSTR secpolkey = L"&l="; // + key
	_DATA.append(std::string(_key));//wcscat(_d, secpolkey);

	//One Time passcode
	VARIANT _phone;
	VARIANT otpMethod;
	//BSTR attr = SysAllocString(L"aPersonaOTP");
	hr = user->Get(L"aPersonaOTP", &otpMethod);
	std::string otpMethodString;
	int domainOTPFlag = -1; // Default is Email so we start this as 0 and adjust from there if needed
	
	if(SUCCEEDED(hr))
	{		
		otpMethodString = ws2s(otpMethod.bstrVal);
		
		if(otpMethodString.compare("e") == 0)
			domainOTPFlag = 0;
		if(otpMethodString.compare("s") == 0)
			domainOTPFlag = 1;
		if(otpMethodString.compare("v") == 0)
			domainOTPFlag = 2;
		
		if(domainOTPFlag != _otpflag)
		{
			// Overwrite the local registry setting to match the domain attribute for the user
			HKEY hApersonaKey;
			HRESULT hr = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\APersona\\otpm", 0, KEY_ALL_ACCESS, &hApersonaKey);
			LPCTSTR value = TEXT("otpm");
			LPCTSTR data;
			if(domainOTPFlag == 0)
				data = "0";
			if(domainOTPFlag == 1)
				data = "1";
			if(domainOTPFlag == 2)
				data = "2";
			hr = RegSetValueEx (hApersonaKey, value, 0, REG_SZ, (LPBYTE)data, strlen(data)+1);
		}
	}
	else
		log_text_to_file("aPersona Active Directory Error, failed to read aPersonaOTP attribute for user " + ws2s(u), NULL);
	
	if(domainOTPFlag > 0)
	{
		char buf[33];
		sprintf(buf, "%d", domainOTPFlag);
		
		if(domainOTPFlag == 1)//if(_otpflag == 1) // SMS
		{
			_DATA.append("&otpm=s");
			_DATA.append("&o=");
			std::wstring _otpws = _otpcode;
			_DATA.append(ws2s(_otpws));
	
			// Order for Voicemail attempts is Mobile -> Home -> Main profile phone number
			hr = user->get_TelephoneMobile(&_phone);
			if(!SUCCEEDED(hr))
			{
				log_text_to_file("aPersona Active Directory Error, failed to read Mobile Phonenumber for user " + ws2s(u), hr);
				hr = user->get_TelephoneHome(&_phone);
				if(!SUCCEEDED(hr))
				{
					log_text_to_file("aPersona Active Directory Error, failed to read Home Phonenumber for user " + ws2s(u), hr);
					hr = user->get_TelephoneNumber(&_phone);
					if(!SUCCEEDED(hr))
						log_text_to_file("aPersona Active Directory Error, failed to read Telephone Phonenumber for user " + ws2s(u), hr);
				}
			}		
			_pszSMSPhone = ws2s(_phone.bstrVal);
			_DATA.append("&p=");
			_DATA.append(_pszSMSPhone);

			//::MessageBoxA(NULL, "Got domain flag for SMS", "blah1", 0);
		}
		else if(domainOTPFlag == 2)//else if(_otpflag == 2) // Voicemail
		{
			_DATA.append("&otpm=v");
			_DATA.append("&o=");
			std::wstring _otpws = _otpcode;
			_DATA.append(ws2s(_otpws));
	
			// Order for Voicemail attempts is Mobile -> Home -> Main profile phone number
			hr = user->get_TelephoneMobile(&_phone);
			if(!SUCCEEDED(hr))
			{
				log_text_to_file("aPersona Active Directory Error, failed to read Mobile Phonenumber for user " + ws2s(u), hr);
				hr = user->get_TelephoneHome(&_phone);
				if(!SUCCEEDED(hr))
				{
					log_text_to_file("aPersona Active Directory Error, failed to read Home Phonenumber for user " + ws2s(u), hr);
					hr = user->get_TelephoneNumber(&_phone);
					if(!SUCCEEDED(hr))
						log_text_to_file("aPersona Active Directory Error, failed to read Telephone Phonenumber for user " + ws2s(u), hr);
				}
			}
			_pszVoicePhone = ws2s(_phone.bstrVal);
			_DATA.append("&p=");
			_DATA.append(_pszVoicePhone);

			//::MessageBoxA(NULL, "Got domain flag for Voice", "blah1", 0);
		}
		else // Default 
		{
			//::MessageBoxA(NULL, "Got domain flag for EMAIL", "blah1", 0);
		}
	}
	else
	{		
		// Use local registry setting for OTP method because the Domain attribute was not reachable or doesn't exist
		if(_otpflag == 1) // SMS
		{
			_DATA.append("&otpm=s");
			_DATA.append("&o=");
			std::wstring _otpws = _otpcode;
			_DATA.append(ws2s(_otpws));
	
			// Order for Voicemail attempts is Mobile -> Home -> Main profile phone number
			hr = user->get_TelephoneMobile(&_phone);
			if(!SUCCEEDED(hr))
			{
				log_text_to_file("aPersona Active Directory Error, failed to read Mobile Phonenumber for user " + ws2s(u), hr);
				hr = user->get_TelephoneHome(&_phone);
				if(!SUCCEEDED(hr))
				{
					log_text_to_file("aPersona Active Directory Error, failed to read Home Phonenumber for user " + ws2s(u), hr);
					hr = user->get_TelephoneNumber(&_phone);
					if(!SUCCEEDED(hr))
						log_text_to_file("aPersona Active Directory Error, failed to read Telephone Phonenumber for user " + ws2s(u), hr);
				}
			}		
			_pszSMSPhone = ws2s(_phone.bstrVal);

			_DATA.append("&p=");
			_DATA.append(_pszSMSPhone);
		}
		else if(_otpflag == 2) // Voicemail
		{
			_DATA.append("&otpm=v");
			_DATA.append("&o=");
			std::wstring _otpws = _otpcode;
			_DATA.append(ws2s(_otpws));
	
			// Order for Voicemail attempts is Mobile -> Home -> Main profile phone number
			hr = user->get_TelephoneMobile(&_phone);
			if(!SUCCEEDED(hr))
			{
				log_text_to_file("aPersona Active Directory Error, failed to read Mobile Phonenumber for user " + ws2s(u), hr);
				hr = user->get_TelephoneHome(&_phone);
				if(!SUCCEEDED(hr))
				{
					log_text_to_file("aPersona Active Directory Error, failed to read Home Phonenumber for user " + ws2s(u), hr);
					hr = user->get_TelephoneNumber(&_phone);
					if(!SUCCEEDED(hr))
						log_text_to_file("aPersona Active Directory Error, failed to read Telephone Phonenumber for user " + ws2s(u), hr);
				}
			}
			_pszVoicePhone = ws2s(_phone.bstrVal);
			
			_DATA.append("&p=");
			_DATA.append(_pszVoicePhone);
		}
		else // Default Email
		{			
		}
	}
	//_DATA.append("&p=");
	//_DATA.append(ws2s(_phone.bstrVal));
	
	// Identifier
	_DATA.append("&c=");
	std::string I;
	hr = GetKeyValue("one-time-trans-key", I);//GetConfigOpt("C:\\Program Files\\aPersona\\config.txt", "identifier");
	if(!SUCCEEDED(hr))
	{
		log_text_to_file("aPersona Registry Error, failed to read one time transaction key value", hr);
		return hr;
	}
	_DATA.append(I);

	//aPersona Key
	_DATA.append("&a=");
	_DATA.append(buildAPersonaKey());
	
	// Free up the IADsUser object
	user->Release();

	pszPostData = _DATA;
	//::MessageBoxA(NULL, _DATA.c_str(), "test", 0);
	return hr;
}
// Using WinHTTP make a connection to the ASM server and POST data
HRESULT apersonaHttpPost(LPSTR pszUserAgent, LPSTR pszServer, LPSTR pszPath, int pszPort, LPSTR pszPostData, LPSTR& response)
{
	// Holds the JSON response string from the Server.  If no connection is made then some preconfigured default strings will be
	// returned and dealt with accordingly
	//LPSTR _response;

	DWORD dwError = 0;
	std::vector<std::string> _s;
	HINTERNET hConnect = NULL, hRequest = NULL, m_hSession = NULL;
	
	wchar_t wcstrUserAgent[80];
	MultiByteToWideChar(CP_ACP, 0, pszUserAgent, -1, wcstrUserAgent, 80);
	
	m_hSession = WinHttpOpen(wcstrUserAgent,
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS,
		0);

	wchar_t wcstrServer[80];
	MultiByteToWideChar(CP_ACP, 0, pszServer, -1, wcstrServer, 80);

	hConnect = WinHttpConnect(m_hSession, wcstrServer, pszPort, 0);
	if (hConnect == NULL)
	{
		log_text_to_file("aPersona Error connecting to Server", NULL);
		return E_ABORT;
	}

	wchar_t wcstrPath[80];
	MultiByteToWideChar(CP_ACP, 0, pszPath, -1, wcstrPath, 80);

	hRequest = WinHttpOpenRequest(hConnect, L"POST", wcstrPath,
	 NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
	if (hRequest == NULL)
	{
		WinHttpCloseHandle(hConnect);
		log_text_to_file("aPersona Error connecting to Server", NULL);
		return E_ABORT;
	}

	DWORD dwOptionValue = WINHTTP_DISABLE_COOKIES;
	if (WinHttpSetOption(hRequest, WINHTTP_OPTION_DISABLE_FEATURE, &dwOptionValue,
	 sizeof(dwOptionValue)) != TRUE)
	{
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hRequest);
		log_text_to_file("aPersona Error setting HTTP options", NULL);
		return E_ABORT;
	}

//const CString cstrHeaders = _T("Cookie: JSESSIONID=") + cstrSession;
	LPCWSTR cstrHeaders = L"Content-Type: application/x-www-form-urlencoded";

	if (WinHttpAddRequestHeaders(hRequest, cstrHeaders, 47,
	    WINHTTP_ADDREQ_FLAG_ADD) != TRUE)
	{
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hRequest);
		log_text_to_file("aPersona Error adding HTTP request headers", NULL);
		return E_ABORT;
	}

	DWORD _len = strlen(pszPostData);

	if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, -1L, pszPostData, _len,
	    _len, 0) != TRUE)
	{
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hRequest);
		log_text_to_file("aPersona Error sending HTTP request to Server", NULL);
		//delete []_parmsc;
		return E_ABORT;
	}

	if (WinHttpReceiveResponse(hRequest, NULL) != TRUE)
	{
	    WinHttpCloseHandle(hConnect);
	    WinHttpCloseHandle(hRequest);
		log_text_to_file("aPersona Error reading HTTP response from Server", NULL);
		return E_ABORT;
	}

	DWORD dwCode, dwCodeSize;
	dwCodeSize = sizeof(DWORD);
	if(!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &dwCode, &dwCodeSize, NULL))
	{
	    WinHttpCloseHandle(hConnect);
	    WinHttpCloseHandle(hRequest);
		return E_ABORT;
	}
	
	DWORD dwSize;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer;
	do
	{
		dwSize = 0;
		if(!WinHttpQueryDataAvailable(hRequest, &dwSize))
			return E_ABORT;//GetLastError();
		pszOutBuffer = new char[dwSize+1];
		if(!pszOutBuffer)
		{
			return E_ABORT;//E_OUTOFMEMORY;
		}
		ZeroMemory(pszOutBuffer, dwSize+1);
		if(!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
		{
			return E_ABORT;//GetLastError();
		}
		if(!dwDownloaded)
			break;
		else
			response = pszOutBuffer;//split_string(pszOutBuffer, ",");
	}while(dwSize > 0);
		//OutputWrite((PWSTR)pszOutBuffer);
	delete [] pszOutBuffer;

	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hRequest);
		
	return S_OK;
}

// Takes a string, like an email address, and scrambles it somewhat by replacing chars with *
std::string ScrambleString(std::string s)
{
	std::string ret = s;
	size_t found;
	found = ret.find("@");
	if(found != std::string::npos)
	{
		// Email
		ret.replace(1, found-1, found-1, '*'); 
		return ret;
	}
	found = ret.find("-");
	if(found != std::string::npos)
	{
		// Phone
		found = ret.find_last_of("-");
		ret.replace(0, found-1, (found-1)+1, '*');
		return ret;
	}
	return s;
}
// A function handle entry point making it easier to seperate the program flow and debug
HRESULT funcHandle(PWSTR u, PWSTR p, PWSTR OTP)
{
	HRESULT hr;
	std::string KEY, URL; 

	hr = GetKeyValue("sec-pol-key", KEY);
	if(!SUCCEEDED(hr))
		return hr;
	hr = GetKeyValue("url", URL);
	if(!SUCCEEDED(hr))
		return hr;
		
	PWSTR splitDomain = NULL;
	
	// Build HTTP Post
	DWORD *_httpResult = NULL;	
	DWORD _flag = 0x0; // Initial login
	// _flag = 0x1; // Resend
	// _flag = 0x2; // Verify

	// Holds the servers response string (if any)
	LPSTR _serverResponse;

	// Name of the Application making the HTTP call, can be anything really at this point
	LPSTR pszUserAgent = "Apersona Windows 7 Client";

	// URL or IP address of the HTTP server you're posting to
	LPSTR pszServer;// = "rdu-kv.apersona.com"; 	
	size_t len = URL.length();
	pszServer = new char[len+1];
	URL._Copy_s(pszServer,len,len);
	pszServer[len]='\0';
	
	LPSTR pszKey;
	len = KEY.length();
	pszKey = new char[len+1];
	KEY._Copy_s(pszKey, len, len);
	pszKey[len] = '\0';
	
	// Initial PATH
	LPSTR pszPath;
	DWORD _otpflag;
	int OTPF = 0;
	std::string _s;
	hr = GetKeyValue("otpm", _s);//int OTPF = stoi(GetConfigOpt("C:\\Program Files (x86)\\aPersona\\config.txt", "otpmethod"));
	if(!SUCCEEDED(hr))
		return hr;
	OTPF = std::stoi(_s);
	_otpflag = OTPF;
	if(wcslen(OTP) == 0)//(OTP == NULL)
	{
		pszPath = "/apkv/extAuthenticate.kv";
		////_otpflag = 0x0;
		_flag = 0;
	}
	else
	{
		pszPath = "/apkv/extVerifyOtp.kv";
		_otpflag = 0x1;
		_flag = 2;
	}

	//DWORD _otpflag = 0x0; // ignore
	// _otpflag = 0x1; // SMS
	// _otpflag = 0x2; // Voicemail
			
	// Build initial Authentication POST string
	std::string pszPostData;
	hr = buildHttpPostString(u, p, pszKey, _flag, _otpflag, OTP, pszPostData );
	//if(pszPostData.empty())
	//	return E_INVALIDARG;
	if(!SUCCEEDED(hr))
	{
		log_text_to_file("aPersona Error building HTTP Post string", hr);
		return hr;
	}
	
	// Convert string to char*
	char *_parmsc = new char[pszPostData.length()+1];
	strcpy(_parmsc, pszPostData.c_str());

	// Read the port number
	int pszPort;
	std::string _sport;
	hr = GetKeyValue("port", _sport);
	if(!SUCCEEDED(hr))
		return E_INVALIDARG;
	pszPort = std::stoi(_sport);

	// Post string to Server
	hr = apersonaHttpPost(pszUserAgent, pszServer, pszPath, pszPort, _parmsc, _serverResponse);
	if(!SUCCEEDED(hr))
		return hr;
	delete []_parmsc;

	// The Domain may have changed the OTP Method in the registry so get the new flag
	OTPF = 0;	
	hr = GetKeyValue("otpm", _s);//int OTPF = stoi(GetConfigOpt("C:\\Program Files (x86)\\aPersona\\config.txt", "otpmethod"));
	if(!SUCCEEDED(hr))
		return hr;
	OTPF = std::stoi(_s);
	_otpflag = OTPF;
	
	// Parse Response -- code, message, info, identifier
	std::vector<std::string> _parsedResponse = split_string(_serverResponse, ",");
	if(!_parsedResponse.empty())
	{
		int code = stoi(_parsedResponse.at(0).substr(_parsedResponse.at(0).find(":")+1));
		std::string info = _parsedResponse.at(2).substr(_parsedResponse.at(2).find(":")+1);
		std::string message = _parsedResponse.at(1).substr(_parsedResponse.at(1).find(":")+1);
		std::string identifier = _parsedResponse.at(3).substr(_parsedResponse.at(3).find(":")+2);
		identifier.pop_back();
		identifier.pop_back();

		std::string scramEmail, scramPhone;
		scramEmail = ScrambleString(_pszEmail);
		if(_otpflag == 1)
			scramPhone = ScrambleString(_pszSMSPhone);
		if(_otpflag == 2)
			scramPhone = ScrambleString(_pszVoicePhone);
		switch(code)
			{
				case 403: // invalid API license
					//::MessageBox(NULL, info.c_str(), message.c_str(), 0);
					log_text_to_file("aPersona Error invalid API License: " + info, E_ABORT);
					return E_INVALIDARG;
					break;
				case 200: // ok -- EXIT to WINDOWS AUTHENTICATION
					{
						// Store the one time transaction key in the registry
						HKEY hApersonaKey;
						HRESULT hr = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\APersona\\one-time-trans-key", 0, KEY_ALL_ACCESS, &hApersonaKey);
						LPCTSTR value = TEXT("one-time-trans-key");
						LPCTSTR data = identifier.c_str();
						hr = RegSetValueEx (hApersonaKey, value, 0, REG_SZ, (LPBYTE)data, strlen(data)+1);
						
						return S_OK;
						break;
					}
				case 404: // error -- Some kind of error
					//::MessageBox(NULL, info.c_str(), message.c_str(), 0);
					log_text_to_file("aPersona Error: " + info, E_ABORT);
					return E_ABORT;
					break;
				case 401: // otp timeout -- flag = 1(resend)
					{
						std::string otp = "Your login requires verification. A One Time Passcode has been";
						if(_otpflag == 0){
							otp.append(" Emailed to you at:\n");
							otp.append(scramEmail);
						}
						else if(_otpflag == 1){
							otp.append(" Texted to you at:\n");
							otp.append(scramPhone);
						}
						else if(_otpflag == 2){
							otp.append(" Called to you at:\n");
							otp.append(scramPhone);
						}
						otp.append("\nPlease retrieve the Passcode and enter it to complete authentication.");
						::MessageBox(NULL, otp.c_str(), message.c_str(), 0);//::MessageBox(NULL, info.c_str(), message.c_str(), 0);
						return E_FAIL;
						break;
					}
				case 500:
					{
						//::MessageBox(NULL, info.c_str(), message.c_str(), 0);
						log_text_to_file("aPersona Error: " + info, E_ABORT);
						return E_INVALIDARG;
						break;
					}
				case 202:
					{
						// otp invalid, email sent with otp -- flag = 2(verify)
						std::string otp = "Your login requires verification. A One Time Passcode has been";
						if(_otpflag == 0){
							otp.append(" Emailed to you at:\n");
							otp.append(scramEmail);
						}
						else if(_otpflag == 1){
							otp.append(" Texted to you at:\n");
							otp.append(scramPhone);
						}
						else if(_otpflag == 2){
							otp.append(" Called to you at:\n");
							otp.append(scramPhone);
						}
						otp.append("\nPlease retrieve the Passcode and enter it to complete authentication.");
						::MessageBox(NULL, otp.c_str(), message.c_str(), 0);//::MessageBox(NULL, info.c_str(), message.c_str(), 0);
						return E_FAIL;
						break;
					}
				default:
					return E_ABORT;
					break;
			}			
	}
	
	//return hr;
	return S_OK;
}
// Collect the username and password into a serialized credential for the correct usage scenario 
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials 
// back to the system to log on.
/********************************************
Authentication is performed when this function returns.  We have chosen to do all secondary factor authentication here

STEPS
- Disable local apersona Y/N?
- Read in Registry Settings
- Read in LDAP attributes
- Build HTTP string
- Send HTTP string
- Deal with response
*********************************************/
HRESULT CSampleCredential::GetSerialization(
	CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
	CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, 
	PWSTR* ppwszOptionalStatusText, 
	CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
	)
{
	UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
	UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);

	HRESULT hr;
	
	// Local computer name
	WCHAR wsz[MAX_COMPUTERNAME_LENGTH+1];
	DWORD cch = ARRAYSIZE(wsz);

	// Domain forest flat name
	WCHAR wszDomain[MAX_PATH] = {0};	
	DWORD bufSize = MAX_PATH;

	// Local -- if either no network OR user requested domain is LOCALHOST
	if(_pDomainName == NULL)
		_pDomainName = GetDomain();//OutputWrite(L"DOMAIN NULL");
	if( isLocal(_pDomainName) )
	{
		if (GetComputerNameW(wsz, &cch))
		{
			PWSTR pwzProtectedPassword;
			hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[SFI_PASSWORD], _cpus, &pwzProtectedPassword);

			if (SUCCEEDED(hr))
			{
				KERB_INTERACTIVE_UNLOCK_LOGON kiul;
					
				// Initialize kiul with weak references to our credential.			
				hr = KerbInteractiveUnlockLogonInit(wsz, splitUsername( _rgFieldStrings[SFI_USERNAME] ), pwzProtectedPassword, _cpus, &kiul);	
				if (SUCCEEDED(hr))
				{
					// We use KERB_INTERACTIVE_UNLOCK_LOGON in both unlock and logon scenarios.  It contains a
					// KERB_INTERACTIVE_LOGON to hold the creds plus a LUID that is filled in for us by Winlogon
					// as necessary.
					hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);					
					if (SUCCEEDED(hr))
					{
						ULONG ulAuthPackage;
						hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);						
						if (SUCCEEDED(hr))
						{
							pcpcs->ulAuthenticationPackage = ulAuthPackage;
							pcpcs->clsidCredentialProvider = CLSID_CSampleProvider;
													
							// At this point the credential has created the serialized credential used for logon
							// By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
							// that we have all the information we need and it should attempt to submit the 
							// serialized credential.
							*pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;								
						}
					}
				}
				CoTaskMemFree(pwzProtectedPassword);				
			}
		}
		else
		{
			DWORD dwErr = GetLastError();
			hr = HRESULT_FROM_WIN32(dwErr);			
		}
		return hr; // needed?
	}
	// Domain -- if network AND user has not requested LOCALHOST
	else
	{
		PWSTR splitUser = splitUsername(_rgFieldStrings[SFI_USERNAME]);
		HRESULT hr = funcHandle(splitUser,_rgFieldStrings[SFI_PASSWORD], _rgFieldStrings[SFI_OTP]);						
		if(SUCCEEDED(hr))
		{
			// aPersona passed, so authenticate against the chosen domain (or default)
			if(GetComputerNameExW(ComputerNameDnsDomain, wszDomain, &bufSize))
			{
				DSROLE_PRIMARY_DOMAIN_INFO_BASIC *info;
				DWORD dw = DsRoleGetPrimaryDomainInformation(NULL, DsRolePrimaryDomainInfoBasic, (PBYTE*)&info);
				dw = DsRoleGetPrimaryDomainInformation(NULL, DsRolePrimaryDomainInfoBasic, (PBYTE*)&info);
				PWSTR splitDomain = NULL;
				if(info->DomainNameFlat != NULL)
				{
					splitDomain = info->DomainNameFlat;
				}			
				
				// Free up the memory from domain query
				DsRoleFreeMemory(info);
				
				PWSTR pwzProtectedPassword;
				hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[SFI_PASSWORD], _cpus, &pwzProtectedPassword);			
				if (SUCCEEDED(hr))
				{
					KERB_INTERACTIVE_UNLOCK_LOGON kiul;						
					
					hr = KerbInteractiveUnlockLogonInit(splitDomain, splitUser, pwzProtectedPassword, _cpus, &kiul);
			
					if (SUCCEEDED(hr))
					{
						hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
					
						if (SUCCEEDED(hr))
						{
							ULONG ulAuthPackage;
							hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
						
							if (SUCCEEDED(hr))
							{
								pcpcs->ulAuthenticationPackage = ulAuthPackage;
								pcpcs->clsidCredentialProvider = CLSID_CSampleProvider;
													
								*pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
							}						
						}					
					}					
					CoTaskMemFree(pwzProtectedPassword);
				}						
			}
			else
			{
				DWORD dwErr = GetLastError();
				hr = HRESULT_FROM_WIN32(dwErr);
				log_text_to_file("aPersona Error.", hr);
			}
		}
		else
		{
			// TODO::: 
			// deal with aPersona authentication failures here?
			if(hr != E_FAIL)
			{
				log_text_to_file("aPersona Error validating your account.", E_ABORT);
				::MessageBoxA(NULL, "There was a problem validating your account.  Please contact your System Administrator.", "APersona Message", 0);
			}
			return hr;
		}
	}	
	return hr;
}
struct REPORT_RESULT_STATUS_INFO
{
	NTSTATUS ntsStatus;
	NTSTATUS ntsSubstatus;
	PWSTR     pwzMessage;
	CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =
{
	{ STATUS_LOGON_FAILURE, STATUS_SUCCESS, L"Incorrect password or username.", CPSI_ERROR, },
	{ STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, L"The account is disabled.", CPSI_WARNING },
};



// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to 
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT CSampleCredential::ReportResult(
	NTSTATUS ntsStatus, 
	NTSTATUS ntsSubstatus,
	PWSTR* ppwszOptionalStatusText, 
	CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
	)
{
	*ppwszOptionalStatusText = NULL;
	*pcpsiOptionalStatusIcon = CPSI_NONE;

	DWORD dwStatusInfo = (DWORD)-1;

	// Look for a match on status and substatus.
	for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++)
	{
		if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus)
		{
			dwStatusInfo = i;
			break;
		}
	}

	if ((DWORD)-1 != dwStatusInfo)
	{
		if (SUCCEEDED(SHStrDupW(s_rgLogonStatusInfo[dwStatusInfo].pwzMessage, ppwszOptionalStatusText)))
		{
			*pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
		}
	}

	// If we failed the logon, try to erase the password field.
	if (!SUCCEEDED(HRESULT_FROM_NT(ntsStatus)))
	{
		if (_pCredProvCredentialEvents)
		{
			_pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, L"");
			_pCredProvCredentialEvents->SetFieldString(this, SFI_USERNAME, L"");
			_pCredProvCredentialEvents->SetFieldString(this, SFI_OTP, L"");
		}
	}

	// Since NULL is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
	// this function can't fail.
	return S_OK;
}
