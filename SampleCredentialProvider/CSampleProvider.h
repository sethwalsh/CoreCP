//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//

#include <credentialprovider.h>
#include <windows.h>
#include <strsafe.h>

#include "CSampleCredential.h"
#include "helpers.h"

#define MAX_CREDENTIALS 3
#define MAX_DWORD   0xffffffff        // maximum DWORD

class CSampleProvider : public ICredentialProvider, ICredentialProviderFilter // added Filter
{
  public:
    // IUnknown
    STDMETHOD_(ULONG, AddRef)()
    {
        return _cRef++;
    }
    
    STDMETHOD_(ULONG, Release)()
    {
        LONG cRef = _cRef--;
        if (!cRef)
        {
            delete this;
        }
        return cRef;
    }

    STDMETHOD (QueryInterface)(REFIID riid, void** ppv)
    {
		/**************
		Testing new IProviderFilter stuff
		***************/
		/*
        HRESULT hr;
        if (IID_IUnknown == riid || 
            IID_ICredentialProvider == riid)
        {
            *ppv = this;
            reinterpret_cast<IUnknown*>(*ppv)->AddRef();
            hr = S_OK;
        }
        else
        {
            *ppv = NULL;
            hr = E_NOINTERFACE;
        }
        return hr;
		*/
		HRESULT hr;
    if (IID_IUnknown == riid)
        {
        *ppv = this;
        AddRef();
        hr = S_OK;
        }
        else if (IID_ICredentialProvider == riid)
        {
        *ppv = static_cast<ICredentialProvider*>(this);
        AddRef();
        hr = S_OK;
        }
        else if (IID_ICredentialProviderFilter == riid)
    {
        *ppv = static_cast<ICredentialProviderFilter*>(this);
        AddRef();
        hr = S_OK;
    }
    else
    {
        *ppv = NULL;
        hr = E_NOINTERFACE;
    }
    return hr;
    }
  public:
	  //ICredentialProviderFilter
          /**
        * \brief method to filter CPProvider
        * \param cpus - CP usage scenario
        * \param dwFlags
        * \param rgclsidProviders
        * \param rgbAllow
        * \param cProviders
        * \return IFACEMETHODIMP
        */
        IFACEMETHODIMP Filter( 
            CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
            DWORD dwFlags,
            GUID *rgclsidProviders,
            BOOL *rgbAllow,
            DWORD cProviders);

        /**
        * \brief method to update remote logon credential
        * \param pcpcsIn - serialized logon credential
        * \param pcpcsOut - returned logon credential
        * \return IFACEMETHODIMP
        */
        IFACEMETHODIMP UpdateRemoteCredential( 
            const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsIn,
            CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsOut);
		/** END FILTER ADDITIONS 
		**/
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);

    IFACEMETHODIMP Advise(__in ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP GetFieldDescriptorCount(__out DWORD* pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex,  __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);

    IFACEMETHODIMP GetCredentialCount(__out DWORD* pdwCount,
                                      __out DWORD* pdwDefault,
                                      __out BOOL* pbAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex, 
                                   __out ICredentialProviderCredential** ppcpc);

    friend HRESULT CSampleProvider_CreateInstance(REFIID riid, __deref_out void** ppv);

  protected:
    CSampleProvider();
    __override ~CSampleProvider();
    
  private:
    
    HRESULT _EnumerateOneCredential(__in DWORD dwCredientialIndex,
                                    __in PCWSTR pwzUsername
                                    );
    HRESULT _EnumerateSetSerialization();

    // Create/free enumerated credentials.
    HRESULT _EnumerateCredentials();
    void _ReleaseEnumeratedCredentials();
    void _CleanupSetSerialization();


private:
    LONG              _cRef;
    CSampleCredential *_rgpCredentials[MAX_CREDENTIALS];  // Pointers to the credentials which will be enumerated by 
                                                          // this Provider.
    DWORD                                   _dwNumCreds;
    KERB_INTERACTIVE_UNLOCK_LOGON*          _pkiulSetSerialization;
    DWORD                                   _dwSetSerializationCred; //index into rgpCredentials for the SetSerializationCred
    bool                                    _bAutoSubmitSetSerializationCred;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO      _cpus;
};
