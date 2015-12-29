//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) 2006 Microsoft Corporation. All rights reserved.
//
//

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include "CSampleCredential.h"
#include "guid.h"



//#include <atlbase.h>
#include <AdsHlp.h>
#include <string>
#include <comdef.h>

//for user
#include <Iads.h>

//for domain
#include <DSRole.h>
#pragma comment(lib, "netapi32.lib")

//for dialogbox
#include <WinUser.h>
#include <Windows.h>

//progressdialogbox
#include <Shlobj.h>

//for http
#include <winhttp.h>

//mac addr fetching
#include <Iphlpapi.h>

void DebugWrite(_com_error e)
{	
	FILE* f;
	f = _wfopen( L"C:\\Temp\\DEBUG.txt", L"a");
	if(f != NULL){ 
		fwrite(e.ErrorMessage(), sizeof(TCHAR), strlen(e.ErrorMessage()), f);
		//fwrite( e.ErrorMessage(), sizeof(WCHAR), wcslen(e.ErrorMessage().c_str()), f);
		fwrite( L"\n", sizeof(WCHAR), wcslen(L"\n"), f);
		fwrite( L"----------\n", sizeof(WCHAR), wcslen(L"----------\n"), f);
		fclose(f);
	}
}
void OutputWrite(PWSTR s)
{
	FILE* f;
	f = _wfopen( L"C:\\Temp\\G_out.txt", L"a");
	if(f != NULL){ 
		fwrite( s, sizeof(WCHAR), wcslen(s), f);
		fwrite( L"\n", sizeof(WCHAR), wcslen(L"\n"), f);
		fwrite( L"----------\n", sizeof(WCHAR), wcslen(L"----------\n"), f);
		fclose(f);
	}
}

LPWSTR ConcatLStrings(PWSTR p1, PWSTR p2)
{
	LPWSTR _ret = NULL;
	return _ret;
}

LPWSTR GetDomain()
{
	DSROLE_PRIMARY_DOMAIN_INFO_BASIC *info;
	DWORD dw;
	dw = DsRoleGetPrimaryDomainInformation(NULL, DsRolePrimaryDomainInfoBasic, (PBYTE*)&info);
	if(dw != ERROR_SUCCESS)
	{
		//wprintf(L"DsRoleGetPrimaryDomainInformation: %u\n", dw);
		//::MessageBoxA(NULL, "Non Error_Success", "DsRoleGetPrimaryDomainInformation", NULL);
		return L"";
	}
	if(info->DomainNameDns == NULL)
	{
		//wprintf(L"DomainNameDns is NULL\n");
		//::MessageBoxA(NULL, "DomainNameDns is NULL", "DsRoleGetPrimaryDomainInformation", NULL);
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
		*pdwAdjacentTo = SFI_PASSWORD;
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
					_pDomainName = _b;
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

void WriteADInfo(PWSTR pw, PWSTR u)
{
	HRESULT hr;
	IADs *pUser;
	IADsContainer *container = NULL;
	IDirectorySearch *pDSSearch = NULL;
	IADsUser *user = NULL;
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

	//hr = ADsGetObject(L"WinNT://contoso/u0270473,user", IID_IADs, (void**)&pUser);
	//hr = ADsGetObject(L"WinNT://contoso/u0270473", IID_IADsUser, (void**)&user);
	LPWSTR pszDomain = GetDomain();	

	/**** TODO !!!!!!!!!!!!!
	**/
	//if(_pDomainName != NULL)
	//{
	//	USE IT ^^^ 
	//}
	OutputWrite(u);
	OutputWrite(pw);
	wchar_t dbuf[64];
	if(pszDomain != NULL)
	{
		wchar_t dbuf[64];
		wcscpy(dbuf, L"LDAP://");
		wcscat(dbuf, GetDomain());
		hr = ADsOpenObject(dbuf, u, pw, ADS_SECURE_AUTHENTICATION, IID_IDirectorySearch, (void**)&pDSSearch);
		//hr = ADsOpenObject(L"LDAP://CN=seth walsh, CN=Users, DC=contoso, DC=local", u, pw, ADS_SECURE_AUTHENTICATION, IID_IADsUser, (void**)&user);
	}
	//else
	//	hr = ADsOpenObject(L"LDAP://WIN-OVRLRDKFKD3/CN=seth walsh, CN=Users, DC=contoso, DC=local", L"contoso.local\\u0270473", L"magic@69", ADS_SECURE_AUTHENTICATION, IID_IADsUser, (void**)&user);
	
	//hr = ADsOpenObject(L"LDAP://WIN-OVRLRDKFKD3/CN=seth walsh, CN=Users, DC=contoso, DC=local", L"contoso.local\\u0270473", L"magic@69", ADS_SECURE_AUTHENTICATION, IID_IADsUser, (void**)&user);
	//hr = ADsGetObject(L"LDAP://WIN-OVRLRDKFKD3/CN=seth walsh, CN=Users, DC=contoso, DC=local", IID_IADsUser, (void**)&user);
	//hr = ADsGetObject(L"WinNT://contoso", IID_IADsContainer, (void**)&container);

	//hr = ADsOpenObject(L"LDAP://WIN-OVRLRDKFKD3/CN=seth walsh, CN=Users, DC=contoso, DC=local", u, pw, ADS_SECURE_AUTHENTICATION, IID_IADsUser, (void**)&user);

	if(SUCCEEDED(hr))
	{
		BSTR bstrName;
		//OutputWrite(u);
		//OutputWrite(pw);

		// Search for the DistinguishedName
		LPWSTR pszAttr[] = {L"distinguishedname"};
		ADS_SEARCH_HANDLE hSearch;

		wchar_t buf[128];
		wcscpy(buf, L"(&(objectClass=user)(objectCategory=person)(sAMAccountName=");
		wcscat(buf, u);
		wcscat(buf, L"))");

		hr = pDSSearch->ExecuteSearch(buf, pszAttr, 1, &hSearch);
		if(!SUCCEEDED(hr))
			DebugWrite(_com_error(hr));
		hr = pDSSearch->GetFirstRow(hSearch);
		if(!SUCCEEDED(hr))
			DebugWrite(_com_error(hr));
		ADS_SEARCH_COLUMN column;
		hr = pDSSearch->GetColumn(hSearch, L"distinguishedName", &column);
		if(!SUCCEEDED(hr))
			DebugWrite(_com_error(hr));
		PWSTR s = column.pADsValues->DNString;
		pDSSearch->Release();
		OutputWrite(s);

		wchar_t _d[128];
		wcscpy(_d, L"LDAP://");
		//wcscat(_d, GetDomain());
		wcscat(_d, s);
		OutputWrite(_d);
		hr = ADsOpenObject(_d, u, pw, ADS_SECURE_AUTHENTICATION, IID_IADsUser, (void**)&user);
		if(!SUCCEEDED(hr))
			DebugWrite(_com_error(hr));
		//DSROLE_PRIMARY_DOMAIN_INFO_BASIC *info;
		//DWORD dw = DsRoleGetPrimaryDomainInformation(NULL, DsRolePrimaryDomainInfoBasic, (PBYTE*)&info);
		//if(info->MachineRole == DsRole_RoleMemberWorkstation)//DsRole_RoleStandaloneWorkstation)		
		
		// GetInfo Load property values
		VARIANT var;
		VariantInit(&var);
		LPWSTR pszAttrs[] = { L"EmailAddress" };
		DWORD dwNumber = sizeof(pszAttrs) / sizeof(LPWSTR);
		hr = ADsBuildVarArrayStr(pszAttrs, dwNumber, &var);
		if(!SUCCEEDED(hr))
			DebugWrite(_com_error(hr));

		hr = user->GetInfoEx(var, 0);
		if(!SUCCEEDED(hr))
			DebugWrite(_com_error(hr));
		VariantClear(&var);
			
		// Get property
		BSTR email;
		hr = user->get_EmailAddress(&email);
		if(!SUCCEEDED(hr))
			DebugWrite(_com_error(hr));
		else
			OutputWrite(email);

		//pUser->Release();
		VariantClear(&var);
		//pDSSearch->Release();
		user->Release();		
	}
	else
	{
		DebugWrite(_com_error(hr));
		OutputWrite(L"Failed to do the LDAP stuff");
	}
}/** MINE **/
void WriteSysInfo()
{
	//system info struct
	SYSTEM_INFO _si;

	//get sysinfo
	GetSystemInfo(&_si);

	char str[10];//;[] = _si.dwProcessorType;
	sprintf(str, "%lu", _si.dwProcessorType);
	DWORD bytesWritten;
	HANDLE _fh;
	_fh = CreateFile("C:\\Temp\\SYS_INFO.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(_fh, str, (DWORD)strlen(str), &bytesWritten, NULL);
	CloseHandle(_fh);
}

/*
Gets Processor ID
*/
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

		} while(pAdapterInfo);

	}

	free(AdapterInfo);
	return mac_addr;

}

/*
//////////////////////////////////////////////////////////////////////////
MINE - 
Grab user ID, email, OS, MAC, CPU

//////////////////////////////////////////////////////////////////////////
*/
void EnumerateUserInfo(PWSTR pw, PWSTR u, HWND hwndOwner,IProgressDialog * ppd)
{

	HRESULT hr;
	IADs *pUser;
	IADsContainer *container = NULL;
	IADsUser *user = NULL;
	CoInitialize(NULL);

	DWORD comp = 1;
	DWORD comp2 = 2;
	DWORD tot = 2;

	char* userMac;
	char* proccessorInfo;

	//create progress box
	//Start Progress Dialog and give it a title
	//ppd->StartProgressDialog(hwndOwner,NULL,PROGDLG_MODAL,NULL);
	//ppd->SetTitle(L"This Is A Progress Box");

	//set progress to 50 %
	//ppd->SetProgress(comp,tot);

	//sleep for two seconds to simulate "work"
	//Sleep(2000);		

	//check if cancel
	//if(ppd->HasUserCancelled())
	//{
	//	//if so close dialog box
	//	ppd->StopProgressDialog();
	//}


	//ldap call
	hr = ADsOpenObject(L"LDAP://WIN-G88HGCB68F5/CN=garin richards, CN=Users, DC=corp, DC=contoso, DC=local", u, pw, ADS_SECURE_AUTHENTICATION, IID_IADsUser, (void**)&user);

	//if ldap call successful
	if(SUCCEEDED(hr))
	{

		BSTR bstrName;

		// GetInfo Load property values
		VARIANT var;
		VariantInit(&var);
		LPWSTR pszAttrs[] = { L"EmailAddress" };
		DWORD dwNumber = sizeof(pszAttrs) / sizeof(LPWSTR);
		hr = ADsBuildVarArrayStr(pszAttrs, dwNumber, &var);

		/*
		Determine OS version
		*/

		//for OS version
		OSVERSIONINFO osvi;

		ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
		osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
		GetVersionEx(&osvi);

		DWORD major, minor;
		BSTR ver;

		//https://msdn.microsoft.com/en-us/library/windows/desktop/ms724833(v=vs.85).aspx
		major = osvi.dwMajorVersion;
		minor = osvi.dwMinorVersion;
		

		if( major == 10 && minor == 0)
			ver = L"Win10";
		else if (major == 6 && minor == 3)
			ver = L"Win8.1";
		else if (major == 6 && minor == 2)
			ver = L"Win8";
		else if (major == 6 && minor == 1)
			ver = L"Win7";
		else
			ver = L"NOTDEFINED";

		//get mac address
		userMac = GetMacAddress();
	
		//get CPU info
		proccessorInfo = GetProcessor();

		//get email 
		BSTR email;
		hr = user->get_EmailAddress(&email);
		BSTR id;
		hr = user->get_Name(&id);
		//get id/name
		//ht = user->get_Name(&name);
		//TODO: Does this authenticate out correctly and write out to file?
		//write email to file in C:\Temp\G_out.txt 
		OutputWrite(email);
		OutputWrite(id);


	}

	//set to 100% done
	//ppd->SetProgress(comp2,tot);
	
	 //close
	//ppd->StopProgressDialog();
}

// Using WinHTTP make a connection to the ASM server and POST data
BOOL ConnectASMServer(PWSTR data)
{
	HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
	BOOL bResults = FALSE;

	// Obtain a session handle
	hSession = WinHttpOpen(L"aPersona ASM Windows Authentication",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS,
		0);

	// Specify the HTTP server you are targeting
	if(hSession)
		hConnect = WinHttpConnect(hSession, L"www.asm-server.com", INTERNET_DEFAULT_HTTP_PORT, 0);

	// Create an HTTP Request Handle
	if(hConnect)
		hRequest = WinHttpOpenRequest(hConnect, L"PUT", L"/writetest.txt", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

	// Send a request
	if(hRequest)
		bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

	// ADDITIONAL CODE HERE

	// Errors
	if(!bResults)
		printf("Error %d\n", GetLastError());

	// Close open handles
	if(hRequest)WinHttpCloseHandle(hRequest);
	if(hConnect)WinHttpCloseHandle(hConnect);
	if(hSession)WinHttpCloseHandle(hSession);

	return bResults;
}

// Collect the username and password into a serialized credential for the correct usage scenario 
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials 
// back to the system to log on.
HRESULT CSampleCredential::GetSerialization(
	CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
	CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, 
	PWSTR* ppwszOptionalStatusText, 
	CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
	)
{
	/***
	
	***/
	UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
	UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);

	HRESULT hr;

	WCHAR wsz[MAX_COMPUTERNAME_LENGTH+1];
	DWORD cch = ARRAYSIZE(wsz);
	WCHAR wszDomain[MAX_PATH] = {0};	
	DWORD bufSize = MAX_PATH;
	BOOL _localLogin = true;
	DSROLE_PRIMARY_DOMAIN_INFO_BASIC *info;
	DWORD dw = DsRoleGetPrimaryDomainInformation(NULL, DsRolePrimaryDomainInfoBasic, (PBYTE*)&info);

	if(info->MachineRole == DsRole_RoleMemberWorkstation)//DsRole_RoleStandaloneWorkstation)
	{
		OutputWrite(L"Domain joined");
		_localLogin = false;
	}
	
	if(_localLogin)
	{
		/*** BELOW should be used for when the machine is not connected to a domain and you wish to use local login like normal ***/	
		if (GetComputerNameW(wsz, &cch))
		{
			OutputWrite(wsz);
			PWSTR pwzProtectedPassword;

			hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[SFI_PASSWORD], _cpus, &pwzProtectedPassword);

			if (SUCCEEDED(hr))
			{
				KERB_INTERACTIVE_UNLOCK_LOGON kiul;
				/*
				//////////////////////////////////////////////////////////////////////////
				MINE
				//////////////////////////////////////////////////////////////////////////
				*/
				/*
				WriteSysInfo();
				WriteADInfo(_rgFieldStrings[SFI_PASSWORD], _rgFieldStrings[SFI_USERNAME]);

				//get handle
				HWND hwndOwner = NULL;

				if (_pCredProvCredentialEvents)
				{
					_pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
				}

				//initialize Progress Dialog
				IProgressDialog * ppd;
				CoCreateInstance(CLSID_ProgressDialog, NULL, CLSCTX_INPROC_SERVER, 
					IID_IProgressDialog, (void **)&ppd);

				//calls function to get data about the user
				//EnumerateUserInfo(_rgFieldStrings[SFI_PASSWORD], _rgFieldStrings[SFI_USERNAME],hwndOwner,ppd);

				*/
				hr = S_OK;

				/*
				//////////////////////////////////////////////////////////////////////////
					END MINE
				//////////////////////////////////////////////////////////////////////////
				*/
				// Initialize kiul with weak references to our credential.			
				hr = KerbInteractiveUnlockLogonInit(wsz, _rgFieldStrings[SFI_USERNAME], pwzProtectedPassword, _cpus, &kiul);							
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
	}
	else
	{
		if(GetComputerNameExW(ComputerNameDnsDomain, wszDomain, &bufSize))
		{
			// Use the flat NETBIOS name which is either DOMAIN or WORKGROUP
			PWSTR splitDomain;
		
			if(info->DomainNameFlat != NULL)
			{
				splitDomain = info->DomainNameFlat;
			}
	
			// Split user and keep the actual username and not the domain name
			PWSTR splitUser = NULL;		
			// By convention USERNAME can come in the following formats:
			//	USERNAME
			//	USERNAME@DOMAIN
			//	DOMAIN\USERNAME
			if( wcsrchr(_rgFieldStrings[SFI_USERNAME], L'\\') != NULL )
			{
				splitUser = wcsrchr(_rgFieldStrings[SFI_USERNAME], L'\\') + 1;
			}
			else if( wcsrchr(_rgFieldStrings[SFI_USERNAME], L'\@') )
			{
				//splitUser = wcsrchr(_rgFieldStrings[SFI_USERNAME], L'@') + 1;
				wchar_t* tok = wcstok(_rgFieldStrings[SFI_USERNAME], L"@");
				splitUser = tok;
			}
			else
				splitUser = _rgFieldStrings[SFI_USERNAME];
					
			//OutputWrite(_rgFieldStrings[SFI_USERNAME]);
			WriteADInfo(_rgFieldStrings[SFI_PASSWORD], _rgFieldStrings[SFI_USERNAME]);
			//OutputWrite(splitDomain);
			//OutputWrite(splitUser);

			PWSTR pwzProtectedPassword;

			hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[SFI_PASSWORD], _cpus, &pwzProtectedPassword);

			if (SUCCEEDED(hr))
			{
				KERB_INTERACTIVE_UNLOCK_LOGON kiul;						
				// Initialize kiul with weak references to our credential.			

				hr = KerbInteractiveUnlockLogonInit(splitDomain, splitUser, pwzProtectedPassword, _cpus, &kiul);
			
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
	}
	// Free up the memory from domain query
	DsRoleFreeMemory(info);

	// return result
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
		}
	}

	// Since NULL is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
	// this function can't fail.
	return S_OK;
}
