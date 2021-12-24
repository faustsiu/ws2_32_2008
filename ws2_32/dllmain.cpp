// dllmain.cpp : 定義 DLL 應用程式的進入點。
#include "stdafx.h"

#pragma pack(1)



#pragma data_seg (".ws2_hookdata")
int hookswitch = 0;
#pragma data_seg()

#define MAXPROC 500
HINSTANCE hLThis = 0;
HINSTANCE hLMod = 0;
HMODULE hWS2_Hack = 0;
HMODULE hWS2_Win = 0;
HMODULE hWS2_Hook = 0;
FARPROC ws2_32proc[MAXPROC];

// Hook 
#define HOOK_CONNECT 0x00
#define HOOK_SEND 0x01
#define HOOK_RECV 0x02
#define MAXHOOKFUNC 0x03
FARPROC hook_callout[MAXHOOKFUNC] = {NULL, NULL, NULL};

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		hWS2_Win = LoadLibrary("ws2_2008.dll");
		if (!hWS2_Win) return false;

		ws2_32proc[1-1]   =  GetProcAddress(hWS2_Win,"accept");  
		ws2_32proc[2-1]   =  GetProcAddress(hWS2_Win,"bind");  
		ws2_32proc[3-1]   =  GetProcAddress(hWS2_Win,"closesocket");  
		ws2_32proc[4-1]   =  GetProcAddress(hWS2_Win,"connect");  
		ws2_32proc[5-1]   =  GetProcAddress(hWS2_Win,"getpeername");  
		ws2_32proc[6-1]   =  GetProcAddress(hWS2_Win,"getsockname");  
		ws2_32proc[7-1]   =  GetProcAddress(hWS2_Win,"getsockopt");  
		ws2_32proc[8-1]   =  GetProcAddress(hWS2_Win,"htonl");  
		ws2_32proc[9-1]   =  GetProcAddress(hWS2_Win,"htons");  
		ws2_32proc[10-1]  =  GetProcAddress(hWS2_Win,"ioctlsocket");  
		ws2_32proc[11-1]  =  GetProcAddress(hWS2_Win,"inet_addr");  
		ws2_32proc[12-1]  =  GetProcAddress(hWS2_Win,"inet_ntoa");  
		ws2_32proc[13-1]  =  GetProcAddress(hWS2_Win,"listen");  
		ws2_32proc[14-1]  =  GetProcAddress(hWS2_Win,"ntohl");  
		ws2_32proc[15-1]  =  GetProcAddress(hWS2_Win,"ntohs");  
		ws2_32proc[16-1]  =  GetProcAddress(hWS2_Win,"recv");  
		ws2_32proc[17-1]  =  GetProcAddress(hWS2_Win,"recvfrom");  
		ws2_32proc[18-1]  =  GetProcAddress(hWS2_Win,"select");  
		ws2_32proc[19-1]  =  GetProcAddress(hWS2_Win,"send");  
		ws2_32proc[20-1]  =  GetProcAddress(hWS2_Win,"sendto");  
		ws2_32proc[21-1]  =  GetProcAddress(hWS2_Win,"setsockopt");  
		ws2_32proc[22-1]  =  GetProcAddress(hWS2_Win,"shutdown");  
		ws2_32proc[23-1]  =  GetProcAddress(hWS2_Win,"socket");  
		ws2_32proc[24-1]  =  GetProcAddress(hWS2_Win,"WSApSetPostRoutine");  
		ws2_32proc[25-1]  =  GetProcAddress(hWS2_Win,"FreeAddrInfoEx");  
		ws2_32proc[26-1]  =  GetProcAddress(hWS2_Win,"FreeAddrInfoExW");  
		ws2_32proc[27-1]  =  GetProcAddress(hWS2_Win,"FreeAddrInfoW");  
		ws2_32proc[28-1]  =  GetProcAddress(hWS2_Win,"GetAddrInfoExA");  
		ws2_32proc[29-1]  =  GetProcAddress(hWS2_Win,"GetAddrInfoExW");  
		ws2_32proc[30-1]  =  GetProcAddress(hWS2_Win,"GetAddrInfoW");  
		ws2_32proc[31-1]  =  GetProcAddress(hWS2_Win,"GetNameInfoW");  
		ws2_32proc[32-1]  =  GetProcAddress(hWS2_Win,"InetNtopW");  
		ws2_32proc[33-1]  =  GetProcAddress(hWS2_Win,"InetPtonW");  
		ws2_32proc[34-1]  =  GetProcAddress(hWS2_Win,"SetAddrInfoExA");  
		ws2_32proc[35-1]  =  GetProcAddress(hWS2_Win,"SetAddrInfoExW");  
		ws2_32proc[36-1]  =  GetProcAddress(hWS2_Win,"WPUCompleteOverlappedRequest");  
		ws2_32proc[37-1]  =  GetProcAddress(hWS2_Win,"WSAAccept");  
		ws2_32proc[38-1]  =  GetProcAddress(hWS2_Win,"WSAAddressToStringA");  
		ws2_32proc[39-1]  =  GetProcAddress(hWS2_Win,"WSAAddressToStringW");  
		ws2_32proc[40-1]  =  GetProcAddress(hWS2_Win,"WSAAdvertiseProvider");  
		ws2_32proc[41-1]  =  GetProcAddress(hWS2_Win,"WSACloseEvent");  
		ws2_32proc[42-1]  =  GetProcAddress(hWS2_Win,"WSAConnect");  
		ws2_32proc[43-1]  =  GetProcAddress(hWS2_Win,"WSAConnectByList");  
		ws2_32proc[44-1]  =  GetProcAddress(hWS2_Win,"WSAConnectByNameA");  
		ws2_32proc[45-1]  =  GetProcAddress(hWS2_Win,"WSAConnectByNameW");  
		ws2_32proc[46-1]  =  GetProcAddress(hWS2_Win,"WSACreateEvent");  
		ws2_32proc[47-1]  =  GetProcAddress(hWS2_Win,"WSADuplicateSocketA");  
		ws2_32proc[48-1]  =  GetProcAddress(hWS2_Win,"WSADuplicateSocketW");  
		ws2_32proc[49-1]  =  GetProcAddress(hWS2_Win,"WSAEnumNameSpaceProvidersA");  
		ws2_32proc[50-1]  =  GetProcAddress(hWS2_Win,"WSAEnumNameSpaceProvidersExA");  
		ws2_32proc[51-1]  =  GetProcAddress(hWS2_Win,"gethostbyaddr");  
		ws2_32proc[52-1]  =  GetProcAddress(hWS2_Win,"gethostbyname");  
		ws2_32proc[53-1]  =  GetProcAddress(hWS2_Win,"getprotobyname");  
		ws2_32proc[54-1]  =  GetProcAddress(hWS2_Win,"getprotobynumber");  
		ws2_32proc[55-1]  =  GetProcAddress(hWS2_Win,"getservbyname");  
		ws2_32proc[56-1]  =  GetProcAddress(hWS2_Win,"getservbyport");  
		ws2_32proc[57-1]  =  GetProcAddress(hWS2_Win,"gethostname");  
		ws2_32proc[58-1]  =  GetProcAddress(hWS2_Win,"WSAEnumNameSpaceProvidersExW");  
		ws2_32proc[59-1]  =  GetProcAddress(hWS2_Win,"WSAEnumNameSpaceProvidersW");  
		ws2_32proc[60-1]  =  GetProcAddress(hWS2_Win,"WSAEnumNetworkEvents");  
		ws2_32proc[61-1]  =  GetProcAddress(hWS2_Win,"WSAEnumProtocolsA");  
		ws2_32proc[62-1]  =  GetProcAddress(hWS2_Win,"WSAEnumProtocolsW");  
		ws2_32proc[63-1]  =  GetProcAddress(hWS2_Win,"WSAEventSelect");  
		ws2_32proc[64-1]  =  GetProcAddress(hWS2_Win,"WSAGetOverlappedResult");  
		ws2_32proc[65-1]  =  GetProcAddress(hWS2_Win,"WSAGetQOSByName");  
		ws2_32proc[66-1]  =  GetProcAddress(hWS2_Win,"WSAGetServiceClassInfoA");  
		ws2_32proc[67-1]  =  GetProcAddress(hWS2_Win,"WSAGetServiceClassInfoW");  
		ws2_32proc[68-1]  =  GetProcAddress(hWS2_Win,"WSAGetServiceClassNameByClassIdA");  
		ws2_32proc[69-1]  =  GetProcAddress(hWS2_Win,"WSAGetServiceClassNameByClassIdW");  
		ws2_32proc[70-1]  =  GetProcAddress(hWS2_Win,"WSAHtonl");  
		ws2_32proc[71-1]  =  GetProcAddress(hWS2_Win,"WSAHtons");  
		ws2_32proc[72-1]  =  GetProcAddress(hWS2_Win,"WSAInstallServiceClassA");  
		ws2_32proc[73-1]  =  GetProcAddress(hWS2_Win,"WSAInstallServiceClassW");  
		ws2_32proc[74-1]  =  GetProcAddress(hWS2_Win,"WSAIoctl");  
		ws2_32proc[75-1]  =  GetProcAddress(hWS2_Win,"WSAJoinLeaf");  
		ws2_32proc[76-1]  =  GetProcAddress(hWS2_Win,"WSALookupServiceBeginA");  
		ws2_32proc[77-1]  =  GetProcAddress(hWS2_Win,"WSALookupServiceBeginW");  
		ws2_32proc[78-1]  =  GetProcAddress(hWS2_Win,"WSALookupServiceEnd");  
		ws2_32proc[79-1]  =  GetProcAddress(hWS2_Win,"WSALookupServiceNextA");  
		ws2_32proc[80-1]  =  GetProcAddress(hWS2_Win,"WSALookupServiceNextW");  
		ws2_32proc[81-1]  =  GetProcAddress(hWS2_Win,"WSANSPIoctl");  
		ws2_32proc[82-1]  =  GetProcAddress(hWS2_Win,"WSANtohl");  
		ws2_32proc[83-1]  =  GetProcAddress(hWS2_Win,"WSANtohs");  
		ws2_32proc[84-1]  =  GetProcAddress(hWS2_Win,"WSAPoll");  
		ws2_32proc[85-1]  =  GetProcAddress(hWS2_Win,"WSAProviderCompleteAsyncCall");  
		ws2_32proc[86-1]  =  GetProcAddress(hWS2_Win,"WSAProviderConfigChange");  
		ws2_32proc[87-1]  =  GetProcAddress(hWS2_Win,"WSARecv");  
		ws2_32proc[88-1]  =  GetProcAddress(hWS2_Win,"WSARecvDisconnect");  
		ws2_32proc[89-1]  =  GetProcAddress(hWS2_Win,"WSARecvFrom");  
		ws2_32proc[90-1]  =  GetProcAddress(hWS2_Win,"WSARemoveServiceClass");  
		ws2_32proc[91-1]  =  GetProcAddress(hWS2_Win,"WSAResetEvent");  
		ws2_32proc[92-1]  =  GetProcAddress(hWS2_Win,"WSASend");  
		ws2_32proc[93-1]  =  GetProcAddress(hWS2_Win,"WSASendDisconnect");  
		ws2_32proc[94-1]  =  GetProcAddress(hWS2_Win,"WSASendMsg");  
		ws2_32proc[95-1]  =  GetProcAddress(hWS2_Win,"WSASendTo");  
		ws2_32proc[96-1]  =  GetProcAddress(hWS2_Win,"WSASetEvent");  
		ws2_32proc[97-1]  =  GetProcAddress(hWS2_Win,"WSASetServiceA");  
		ws2_32proc[98-1]  =  GetProcAddress(hWS2_Win,"WSASetServiceW");  
		ws2_32proc[99-1]  =  GetProcAddress(hWS2_Win,"WSASocketA");  
		ws2_32proc[100-1] =  GetProcAddress(hWS2_Win,"WSASocketW");  
		ws2_32proc[101-1] =  GetProcAddress(hWS2_Win,"WSAAsyncSelect");  
		ws2_32proc[102-1] =  GetProcAddress(hWS2_Win,"WSAAsyncGetHostByAddr");  
		ws2_32proc[103-1] =  GetProcAddress(hWS2_Win,"WSAAsyncGetHostByName");  
		ws2_32proc[104-1] =  GetProcAddress(hWS2_Win,"WSAAsyncGetProtoByNumber");  
		ws2_32proc[105-1] =  GetProcAddress(hWS2_Win,"WSAAsyncGetProtoByName");  
		ws2_32proc[106-1] =  GetProcAddress(hWS2_Win,"WSAAsyncGetServByPort");  
		ws2_32proc[107-1] =  GetProcAddress(hWS2_Win,"WSAAsyncGetServByName");  
		ws2_32proc[108-1] =  GetProcAddress(hWS2_Win,"WSACancelAsyncRequest");  
		ws2_32proc[109-1] =  GetProcAddress(hWS2_Win,"WSASetBlockingHook");  
		ws2_32proc[110-1] =  GetProcAddress(hWS2_Win,"WSAUnhookBlockingHook");  
		ws2_32proc[111-1] =  GetProcAddress(hWS2_Win,"WSAGetLastError");  
		ws2_32proc[112-1] =  GetProcAddress(hWS2_Win,"WSASetLastError");  
		ws2_32proc[113-1] =  GetProcAddress(hWS2_Win,"WSACancelBlockingCall");  
		ws2_32proc[114-1] =  GetProcAddress(hWS2_Win,"WSAIsBlocking");  
		ws2_32proc[115-1] =  GetProcAddress(hWS2_Win,"WSAStartup");  
		ws2_32proc[116-1] =  GetProcAddress(hWS2_Win,"WSACleanup");  
		ws2_32proc[117-1] =  GetProcAddress(hWS2_Win,"WSAStringToAddressA");
		ws2_32proc[118-1] =  GetProcAddress(hWS2_Win,"WSAStringToAddressW");
		ws2_32proc[119-1] =  GetProcAddress(hWS2_Win,"WSAUnadvertiseProvider");
		ws2_32proc[120-1] =  GetProcAddress(hWS2_Win,"WSAWaitForMultipleEvents");
		ws2_32proc[121-1] =  GetProcAddress(hWS2_Win,"WSCDeinstallProvider");
		ws2_32proc[122-1] =  GetProcAddress(hWS2_Win,"WSCEnableNSProvider");
		ws2_32proc[123-1] =  GetProcAddress(hWS2_Win,"WSCEnumProtocols");
		ws2_32proc[124-1] =  GetProcAddress(hWS2_Win,"WSCGetApplicationCategory");
		ws2_32proc[125-1] =  GetProcAddress(hWS2_Win,"WSCGetProviderInfo");
		ws2_32proc[126-1] =  GetProcAddress(hWS2_Win,"WSCGetProviderPath");
		ws2_32proc[127-1] =  GetProcAddress(hWS2_Win,"WSCInstallNameSpace");
		ws2_32proc[128-1] =  GetProcAddress(hWS2_Win,"WSCInstallNameSpaceEx");
		ws2_32proc[129-1] =  GetProcAddress(hWS2_Win,"WSCInstallProvider");
		ws2_32proc[130-1] =  GetProcAddress(hWS2_Win,"WSCInstallProviderAndChains");
		ws2_32proc[131-1] =  GetProcAddress(hWS2_Win,"WSCSetApplicationCategory");
		ws2_32proc[132-1] =  GetProcAddress(hWS2_Win,"WSCSetProviderInfo");  
                ws2_32proc[133-1] =  GetProcAddress(hWS2_Win,"WSCUnInstallNameSpace");  
                ws2_32proc[134-1] =  GetProcAddress(hWS2_Win,"WSCUpdateProvider");  
                ws2_32proc[135-1] =  GetProcAddress(hWS2_Win,"WSCWriteNameSpaceOrder");  
                ws2_32proc[136-1] =  GetProcAddress(hWS2_Win,"WSCWriteProviderOrder");  
                ws2_32proc[137-1] =  GetProcAddress(hWS2_Win,"WahCloseApcHelper");  
                ws2_32proc[138-1] =  GetProcAddress(hWS2_Win,"WahCloseHandleHelper");  
                ws2_32proc[139-1] =  GetProcAddress(hWS2_Win,"WahCloseNotificationHandleHelper");  
                ws2_32proc[140-1] =  GetProcAddress(hWS2_Win,"WahCloseSocketHandle");  
                ws2_32proc[141-1] =  GetProcAddress(hWS2_Win,"WahCloseThread");  
                ws2_32proc[142-1] =  GetProcAddress(hWS2_Win,"WahCompleteRequest");  
                ws2_32proc[143-1] =  GetProcAddress(hWS2_Win,"WahCreateHandleContextTable");  
                ws2_32proc[144-1] =  GetProcAddress(hWS2_Win,"WahCreateNotificationHandle");  
                ws2_32proc[145-1] =  GetProcAddress(hWS2_Win,"WahCreateSocketHandle");  
                ws2_32proc[146-1] =  GetProcAddress(hWS2_Win,"WahDestroyHandleContextTable");  
                ws2_32proc[147-1] =  GetProcAddress(hWS2_Win,"WahDisableNonIFSHandleSupport");  
                ws2_32proc[148-1] =  GetProcAddress(hWS2_Win,"WahEnableNonIFSHandleSupport");  
                ws2_32proc[149-1] =  GetProcAddress(hWS2_Win,"WahEnumerateHandleContexts");  
                ws2_32proc[150-1] =  GetProcAddress(hWS2_Win,"WahInsertHandleContext");  
                ws2_32proc[151-1] =  GetProcAddress(hWS2_Win,"__WSAFDIsSet");  
                ws2_32proc[152-1] =  GetProcAddress(hWS2_Win,"WahNotifyAllProcesses");  
                ws2_32proc[153-1] =  GetProcAddress(hWS2_Win,"WahOpenApcHelper");  
                ws2_32proc[154-1] =  GetProcAddress(hWS2_Win,"WahOpenCurrentThread");  
                ws2_32proc[155-1] =  GetProcAddress(hWS2_Win,"WahOpenHandleHelper");  
                ws2_32proc[156-1] =  GetProcAddress(hWS2_Win,"WahOpenNotificationHandleHelper");  
                ws2_32proc[157-1] =  GetProcAddress(hWS2_Win,"WahQueueUserApc");  
                ws2_32proc[158-1] =  GetProcAddress(hWS2_Win,"WahReferenceContextByHandle");  
                ws2_32proc[159-1] =  GetProcAddress(hWS2_Win,"WahRemoveHandleContext");  
                ws2_32proc[160-1] =  GetProcAddress(hWS2_Win,"WahWaitForNotification");  
                ws2_32proc[161-1] =  GetProcAddress(hWS2_Win,"WahWriteLSPEvent");  
                ws2_32proc[162-1] =  GetProcAddress(hWS2_Win,"freeaddrinfo");  
                ws2_32proc[163-1] =  GetProcAddress(hWS2_Win,"getaddrinfo");  
                ws2_32proc[164-1] =  GetProcAddress(hWS2_Win,"getnameinfo");  
                ws2_32proc[165-1] =  GetProcAddress(hWS2_Win,"inet_ntop");  
                ws2_32proc[166-1] =  GetProcAddress(hWS2_Win,"inet_pton");  
                ws2_32proc[500-1] =  GetProcAddress(hWS2_Win,"WEP");  


        if (hookswitch != 0)
		{
			hWS2_Hook = LoadLibrary ("ws2_hook.dll");
			if (hWS2_Hook)
			{
				hook_callout[HOOK_CONNECT] = GetProcAddress (hWS2_Hook, "hook_connect"); 
				hook_callout[HOOK_SEND] = GetProcAddress (hWS2_Hook, "hook_send"); 
				hook_callout[HOOK_RECV] = GetProcAddress (hWS2_Hook, "hook_recv"); 
			}
		}

				break;

	case DLL_PROCESS_DETACH:
		FreeLibrary(hWS2_Win);
		FreeLibrary(hWS2_Hook);
		hWS2_Hook = 0x00;
		break;
	}

	return TRUE;
}

extern "C" void __stdcall __socket_hook (int hswitch)
{
	hookswitch = hswitch;
}
extern "C" __declspec(naked) void __stdcall  __connect () 
{
	if (hook_callout[HOOK_CONNECT] != NULL) 
		__asm jmp hook_callout[HOOK_CONNECT * 4] 
	else 
		__asm jmp ws2_32proc[(4-1)*4] 
}
extern "C" __declspec(naked) void __stdcall  __send () 
{ 
	if (hook_callout[HOOK_SEND] != NULL) 
		__asm jmp hook_callout[HOOK_SEND * 4] 
	else 
		__asm jmp ws2_32proc[(19-1)*4] 
}
extern "C" __declspec(naked) void __stdcall  __recv () 
{
	if (hook_callout[HOOK_RECV] != NULL) 
		__asm jmp hook_callout[HOOK_RECV * 4] 
	else 
		__asm jmp ws2_32proc[(16-1)*4] 
}

extern "C" __declspec(naked) void __stdcall  __accept                                () { __asm {nop; 
jmp ws2_32proc[(1-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __bind                                  () { __asm {nop; 
jmp ws2_32proc[(2-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __closesocket                           () { __asm {nop; 
jmp ws2_32proc[(3-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __getpeername                           () { __asm {nop; 
jmp ws2_32proc[(5-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __getsockname                           () { __asm {nop; 
jmp ws2_32proc[(6-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __getsockopt                            () { __asm {nop; 
jmp ws2_32proc[(7-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __htonl                                 () { __asm {nop; 
jmp ws2_32proc[(8-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __htons                                 () { __asm {nop; 
jmp ws2_32proc[(9-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __ioctlsocket                           () { __asm {nop; 
jmp ws2_32proc[(10-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __inet_addr                             () { __asm {nop; 
jmp ws2_32proc[(11-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __inet_ntoa                             () { __asm {nop; 
jmp ws2_32proc[(12-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __listen                                () { __asm {nop; 
jmp ws2_32proc[(13-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __ntohl                                 () { __asm {nop; 
jmp ws2_32proc[(14-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __ntohs                                 () { __asm {nop; 
jmp ws2_32proc[(15-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __recvfrom                              () { __asm {nop; 
jmp ws2_32proc[(17-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __select                                () { __asm {nop; 
jmp ws2_32proc[(18-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __sendto                                () { __asm {nop; 
jmp ws2_32proc[(20-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __setsockopt                            () { __asm {nop; 
jmp ws2_32proc[(21-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __shutdown                              () { __asm {nop; 
jmp ws2_32proc[(22-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __socket                                () { __asm {nop; 
jmp ws2_32proc[(23-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSApSetPostRoutine                    () { __asm {nop; 
jmp ws2_32proc[(24-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __FreeAddrInfoEx                        () { __asm {nop; 
jmp ws2_32proc[(25-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __FreeAddrInfoExW                       () { __asm {nop; 
jmp ws2_32proc[(26-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __FreeAddrInfoW                         () { __asm {nop; 
jmp ws2_32proc[(27-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __GetAddrInfoExA                        () { __asm {nop; 
jmp ws2_32proc[(28-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __GetAddrInfoExW                        () { __asm {nop; 
jmp ws2_32proc[(29-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __GetAddrInfoW                          () { __asm {nop; 
jmp ws2_32proc[(30-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __GetNameInfoW                          () { __asm {nop; 
jmp ws2_32proc[(31-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __InetNtopW                             () { __asm {nop; 
jmp ws2_32proc[(32-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __InetPtonW                             () { __asm {nop; 
jmp ws2_32proc[(33-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __SetAddrInfoExA                        () { __asm {nop; 
jmp ws2_32proc[(34-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __SetAddrInfoExW                        () { __asm {nop; 
jmp ws2_32proc[(35-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WPUCompleteOverlappedRequest          () { __asm {nop; 
jmp ws2_32proc[(36-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAAccept                             () { __asm {nop; 
jmp ws2_32proc[(37-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAAddressToStringA                   () { __asm {nop; 
jmp ws2_32proc[(38-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAAddressToStringW                   () { __asm {nop; 
jmp ws2_32proc[(39-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAAdvertiseProvider                  () { __asm {nop; 
jmp ws2_32proc[(40-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSACloseEvent                         () { __asm {nop; 
jmp ws2_32proc[(41-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAConnect                            () { __asm {nop; 
jmp ws2_32proc[(42-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAConnectByList                      () { __asm {nop; 
jmp ws2_32proc[(43-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAConnectByNameA                     () { __asm {nop; 
jmp ws2_32proc[(44-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAConnectByNameW                     () { __asm {nop; 
jmp ws2_32proc[(45-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSACreateEvent                        () { __asm {nop; 
jmp ws2_32proc[(46-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSADuplicateSocketA                   () { __asm {nop; 
jmp ws2_32proc[(47-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSADuplicateSocketW                   () { __asm {nop; 
jmp ws2_32proc[(48-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAEnumNameSpaceProvidersA            () { __asm {nop; 
jmp ws2_32proc[(49-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAEnumNameSpaceProvidersExA          () { __asm {nop; 
jmp ws2_32proc[(50-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __gethostbyaddr                         () { __asm {nop; 
jmp ws2_32proc[(51-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __gethostbyname                         () { __asm {nop; 
jmp ws2_32proc[(52-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __getprotobyname                        () { __asm {nop; 
jmp ws2_32proc[(53-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __getprotobynumber                      () { __asm {nop; 
jmp ws2_32proc[(54-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __getservbyname                         () { __asm {nop; 
jmp ws2_32proc[(55-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __getservbyport                         () { __asm {nop; 
jmp ws2_32proc[(56-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __gethostname                           () { __asm {nop; 
jmp ws2_32proc[(57-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAEnumNameSpaceProvidersExW          () { __asm {nop; 
jmp ws2_32proc[(58-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAEnumNameSpaceProvidersW            () { __asm {nop; 
jmp ws2_32proc[(59-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAEnumNetworkEvents                  () { __asm {nop; 
jmp ws2_32proc[(60-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAEnumProtocolsA                     () { __asm {nop; 
jmp ws2_32proc[(61-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAEnumProtocolsW                     () { __asm {nop; 
jmp ws2_32proc[(62-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAEventSelect                        () { __asm {nop; 
jmp ws2_32proc[(63-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAGetOverlappedResult                () { __asm {nop; 
jmp ws2_32proc[(64-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAGetQOSByName                       () { __asm {nop; 
jmp ws2_32proc[(65-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAGetServiceClassInfoA               () { __asm {nop; 
jmp ws2_32proc[(66-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAGetServiceClassInfoW               () { __asm {nop; 
jmp ws2_32proc[(67-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAGetServiceClassNameByClassIdA      () { __asm {nop; 
jmp ws2_32proc[(68-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAGetServiceClassNameByClassIdW      () { __asm {nop; 
jmp ws2_32proc[(69-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAHtonl                              () { __asm {nop; 
jmp ws2_32proc[(70-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAHtons                              () { __asm {nop; 
jmp ws2_32proc[(71-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAInstallServiceClassA               () { __asm {nop; 
jmp ws2_32proc[(72-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAInstallServiceClassW               () { __asm {nop; 
jmp ws2_32proc[(73-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAIoctl                              () { __asm {nop; 
jmp ws2_32proc[(74-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAJoinLeaf                           () { __asm {nop; 
jmp ws2_32proc[(75-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSALookupServiceBeginA                () { __asm {nop; 
jmp ws2_32proc[(76-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSALookupServiceBeginW                () { __asm {nop; 
jmp ws2_32proc[(77-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSALookupServiceEnd                   () { __asm {nop; 
jmp ws2_32proc[(78-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSALookupServiceNextA                 () { __asm {nop; 
jmp ws2_32proc[(79-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSALookupServiceNextW                 () { __asm {nop; 
jmp ws2_32proc[(80-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSANSPIoctl                           () { __asm {nop; 
jmp ws2_32proc[(81-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSANtohl                              () { __asm {nop; 
jmp ws2_32proc[(82-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSANtohs                              () { __asm {nop; 
jmp ws2_32proc[(83-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAPoll                               () { __asm {nop; 
jmp ws2_32proc[(84-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAProviderCompleteAsyncCall          () { __asm {nop; 
jmp ws2_32proc[(85-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAProviderConfigChange               () { __asm {nop; 
jmp ws2_32proc[(86-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSARecv                               () { __asm {nop; 
jmp ws2_32proc[(87-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSARecvDisconnect                     () { __asm {nop; 
jmp ws2_32proc[(88-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSARecvFrom                           () { __asm {nop; 
jmp ws2_32proc[(89-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSARemoveServiceClass                 () { __asm {nop; 
jmp ws2_32proc[(90-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAResetEvent                         () { __asm {nop; 
jmp ws2_32proc[(91-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSASend                               () { __asm {nop; 
jmp ws2_32proc[(92-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSASendDisconnect                     () { __asm {nop; 
jmp ws2_32proc[(93-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSASendMsg                            () { __asm {nop; 
jmp ws2_32proc[(94-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSASendTo                             () { __asm {nop; 
jmp ws2_32proc[(95-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSASetEvent                           () { __asm {nop; 
jmp ws2_32proc[(96-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSASetServiceA                        () { __asm {nop; 
jmp ws2_32proc[(97-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSASetServiceW                        () { __asm {nop; 
jmp ws2_32proc[(98-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSASocketA                            () { __asm {nop; 
jmp ws2_32proc[(99-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSASocketW                            () { __asm {nop; 
jmp ws2_32proc[(100-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAAsyncSelect                        () { __asm {nop; 
jmp ws2_32proc[(101-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAAsyncGetHostByAddr                 () { __asm {nop; 
jmp ws2_32proc[(102-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAAsyncGetHostByName                 () { __asm {nop; 
jmp ws2_32proc[(103-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAAsyncGetProtoByNumber              () { __asm {nop; 
jmp ws2_32proc[(104-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAAsyncGetProtoByName                () { __asm {nop; 
jmp ws2_32proc[(105-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAAsyncGetServByPort                 () { __asm {nop; 
jmp ws2_32proc[(106-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAAsyncGetServByName                 () { __asm {nop; 
jmp ws2_32proc[(107-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSACancelAsyncRequest                 () { __asm {nop; 
jmp ws2_32proc[(108-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSASetBlockingHook                    () { __asm {nop; 
jmp ws2_32proc[(109-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAUnhookBlockingHook                 () { __asm {nop; 
jmp ws2_32proc[(110-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAGetLastError                       () { __asm {nop; 
jmp ws2_32proc[(111-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSASetLastError                       () { __asm {nop; 
jmp ws2_32proc[(112-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSACancelBlockingCall                 () { __asm {nop; 
jmp ws2_32proc[(113-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAIsBlocking                         () { __asm {nop; 
jmp ws2_32proc[(114-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAStartup                            () { __asm {nop; 
jmp ws2_32proc[(115-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSACleanup                            () { __asm {nop; 
jmp ws2_32proc[(116-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAStringToAddressA                   () { __asm {nop; 
jmp ws2_32proc[(117-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAStringToAddressW                   () { __asm {nop; 
jmp ws2_32proc[(118-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAUnadvertiseProvider                () { __asm {nop; 
jmp ws2_32proc[(119-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSAWaitForMultipleEvents              () { __asm {nop; 
jmp ws2_32proc[(120-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSCDeinstallProvider                  () { __asm {nop; 
jmp ws2_32proc[(121-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSCEnableNSProvider                   () { __asm {nop; 
jmp ws2_32proc[(122-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSCEnumProtocols                      () { __asm {nop; 
jmp ws2_32proc[(123-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSCGetApplicationCategory             () { __asm {nop; 
jmp ws2_32proc[(124-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSCGetProviderInfo                    () { __asm {nop; 
jmp ws2_32proc[(125-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSCGetProviderPath                    () { __asm {nop; 
jmp ws2_32proc[(126-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSCInstallNameSpace                   () { __asm {nop; 
jmp ws2_32proc[(127-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSCInstallNameSpaceEx                 () { __asm {nop; 
jmp ws2_32proc[(128-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSCInstallProvider                    () { __asm {nop; 
jmp ws2_32proc[(129-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSCInstallProviderAndChains           () { __asm {nop; 
jmp ws2_32proc[(130-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSCSetApplicationCategory             () { __asm {nop; 
jmp ws2_32proc[(131-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSCSetProviderInfo                    () { __asm {nop; 
jmp ws2_32proc[(132-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSCUnInstallNameSpace                 () { __asm {nop; 
jmp ws2_32proc[(133-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSCUpdateProvider                     () { __asm {nop; 
jmp ws2_32proc[(134-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSCWriteNameSpaceOrder                () { __asm {nop; 
jmp ws2_32proc[(135-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WSCWriteProviderOrder                 () { __asm {nop; 
jmp ws2_32proc[(136-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahCloseApcHelper                     () { __asm {nop; 
jmp ws2_32proc[(137-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahCloseHandleHelper                  () { __asm {nop; 
jmp ws2_32proc[(138-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahCloseNotificationHandleHelper      () { __asm {nop; 
jmp ws2_32proc[(139-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahCloseSocketHandle                  () { __asm {nop; 
jmp ws2_32proc[(140-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahCloseThread                        () { __asm {nop; 
jmp ws2_32proc[(141-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahCompleteRequest                    () { __asm {nop; 
jmp ws2_32proc[(142-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahCreateHandleContextTable           () { __asm {nop; 
jmp ws2_32proc[(143-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahCreateNotificationHandle           () { __asm {nop; 
jmp ws2_32proc[(144-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahCreateSocketHandle                 () { __asm {nop; 
jmp ws2_32proc[(145-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahDestroyHandleContextTable          () { __asm {nop; 
jmp ws2_32proc[(146-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahDisableNonIFSHandleSupport         () { __asm {nop; 
jmp ws2_32proc[(147-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahEnableNonIFSHandleSupport          () { __asm {nop; 
jmp ws2_32proc[(148-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahEnumerateHandleContexts            () { __asm {nop; 
jmp ws2_32proc[(149-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahInsertHandleContext                () { __asm {nop; 
jmp ws2_32proc[(150-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  ____WSAFDIsSet                          () { __asm {nop; 
jmp ws2_32proc[(151-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahNotifyAllProcesses                 () { __asm {nop; 
jmp ws2_32proc[(152-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahOpenApcHelper                      () { __asm {nop; 
jmp ws2_32proc[(153-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahOpenCurrentThread                  () { __asm {nop; 
jmp ws2_32proc[(154-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahOpenHandleHelper                   () { __asm {nop; 
jmp ws2_32proc[(155-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahOpenNotificationHandleHelper       () { __asm {nop; 
jmp ws2_32proc[(156-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahQueueUserApc                       () { __asm {nop; 
jmp ws2_32proc[(157-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahReferenceContextByHandle           () { __asm {nop; 
jmp ws2_32proc[(158-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahRemoveHandleContext                () { __asm {nop; 
jmp ws2_32proc[(159-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahWaitForNotification                () { __asm {nop; 
jmp ws2_32proc[(160-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WahWriteLSPEvent                      () { __asm {nop; 
jmp ws2_32proc[(161-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __freeaddrinfo                          () { __asm {nop; 
jmp ws2_32proc[(162-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __getaddrinfo                           () { __asm {nop; 
jmp ws2_32proc[(163-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __getnameinfo                           () { __asm {nop; 
jmp ws2_32proc[(164-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __inet_ntop                             () { __asm {nop; 
jmp ws2_32proc[(165-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __inet_pton                             () { __asm {nop; 
jmp ws2_32proc[(161-1)*4];
}}
extern "C" __declspec(naked) void __stdcall  __WEP                                   () { __asm {nop; 
jmp ws2_32proc[(500-1)*4];
}}                                                                                                               
                                                                                                                      