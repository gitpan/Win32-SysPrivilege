#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <aclapi.h>
#pragma comment(lib,"Shlwapi.lib")
typedef LONG (*pRtlAdjustPrivilege)(int,BOOL,BOOL,int*);
pRtlAdjustPrivilege RtlAdjPriv = NULL;

bool AdjustPrivilege(){
	HANDLE hNTDLL = LoadLibraryA("ntdll.dll");
	if(!hNTDLL)
		return FALSE;
	RtlAdjPriv = (pRtlAdjustPrivilege) GetProcAddress((HINSTANCE)hNTDLL,"RtlAdjustPrivilege");
	if(!RtlAdjPriv)
		return FALSE;
	{
		int prtn;
		RtlAdjPriv(20,1,0,&prtn);
	}
	FreeLibrary(hNTDLL);
	RtlAdjPriv = NULL;
	return TRUE;
}


DWORD GetProcessId(LPCTSTR szProcName){
  PROCESSENTRY32 pe;  
  DWORD dwPid;
  DWORD dwRet;
  BOOL bFound = 0;
  
  HANDLE hSP = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if(hSP){
    pe.dwSize = sizeof(pe);
    for(dwRet = Process32First(hSP, &pe);dwRet;dwRet = Process32Next(hSP, &pe)){
	if (StrCmpNI(szProcName, pe.szExeFile, strlen(szProcName)) == 0){
	        dwPid = pe.th32ProcessID;
	        bFound = 1;
	        break;
	}
    }
    CloseHandle(hSP);
    if (bFound == 1){
      return dwPid;
    }
  }
  return 0;
}

bool _SysRun(char* szProcessName){
  HANDLE hProcess;
  HANDLE hToken, hNewToken;
  DWORD dwPid;

  PACL pOldDAcl = NULL;
  PACL pNewDAcl = NULL;
  BOOL bDAcl;
  BOOL bDefDAcl;
  DWORD dwRet;

  PACL pSacl = NULL;
  PSID pSidOwner = NULL;
  PSID pSidPrimary = NULL;
  DWORD dwAclSize = 0;
  DWORD dwSaclSize = 0;
  DWORD dwSidOwnLen = 0;
  DWORD dwSidPrimLen = 0;

  DWORD dwSDLen;
  EXPLICIT_ACCESS ea;
  PSECURITY_DESCRIPTOR pOrigSd = NULL;
  PSECURITY_DESCRIPTOR pNewSd = NULL;

  STARTUPINFO si;
  PROCESS_INFORMATION pi;

  BOOL iRet = TRUE;

  if(!AdjustPrivilege()){
    iRet = FALSE;
    goto GC;
  }
  
  dwPid = GetProcessId("WINLOGON.EXE");
  if (!dwPid){
    iRet = FALSE;
    goto GC;
  }

  hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwPid);
  if (hProcess == NULL) {
    iRet = FALSE;
    goto GC;
  }

  if (!OpenProcessToken( hProcess, READ_CONTROL|WRITE_DAC, &hToken )) {
    iRet = FALSE;
    goto GC;
  }

  ZeroMemory(&ea, sizeof( EXPLICIT_ACCESS));
  BuildExplicitAccessWithName(&ea,"Everyone",TOKEN_ALL_ACCESS,GRANT_ACCESS,0);

  if (!GetKernelObjectSecurity(hToken,
                               DACL_SECURITY_INFORMATION,
                               pOrigSd,
                               0,
                               &dwSDLen)) {
    
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
      pOrigSd = (PSECURITY_DESCRIPTOR) HeapAlloc(GetProcessHeap(),
                                                 HEAP_ZERO_MEMORY,
                                                 dwSDLen);
      if(!pOrigSd) {
        iRet = FALSE;
        goto GC;
      }
      if (!GetKernelObjectSecurity(hToken,
                                   DACL_SECURITY_INFORMATION,
                                   pOrigSd,
                                   dwSDLen,
                                   &dwSDLen)) {
        iRet = FALSE;
        goto GC;
      }
    } else {
      iRet = FALSE;
      goto GC;
    }
  }

  if (!GetSecurityDescriptorDacl(pOrigSd, &bDAcl, &pOldDAcl, &bDefDAcl)) {
    iRet = FALSE;
    goto GC;
  }

  dwRet = SetEntriesInAcl(1, &ea, pOldDAcl, &pNewDAcl); 
  if (dwRet != ERROR_SUCCESS) {
    pNewDAcl = NULL;

    iRet = FALSE;
    goto GC;
  }

  if (!MakeAbsoluteSD(pOrigSd,
                      pNewSd,
                      &dwSDLen,
                      pOldDAcl,
                      &dwAclSize,
                      pSacl,
                      &dwSaclSize,
                      pSidOwner,
                      &dwSidOwnLen,
                      pSidPrimary,
                      &dwSidPrimLen)) {
    
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
      pOldDAcl = (PACL) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwAclSize);
      pSacl = (PACL) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwSaclSize);
      pSidOwner = (PSID) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwSidOwnLen);
      pSidPrimary = (PSID) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwSidPrimLen);
      pNewSd = (PSECURITY_DESCRIPTOR) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwSDLen);

      if (pOldDAcl == NULL || pSacl == NULL || pSidOwner == NULL || pSidPrimary == NULL ||  pNewSd == NULL ){
        iRet = FALSE;
        goto GC;
      }

      if (!MakeAbsoluteSD(pOrigSd, pNewSd, &dwSDLen, pOldDAcl, &dwAclSize, pSacl, &dwSaclSize, pSidOwner, &dwSidOwnLen, pSidPrimary, &dwSidPrimLen)){
        iRet = FALSE;
        goto GC;
      }
    }else{
      iRet = FALSE;
      goto GC;
    }
  }

  if (!SetSecurityDescriptorDacl( pNewSd, bDAcl, pNewDAcl, bDefDAcl)){
    iRet = FALSE;
    goto GC;
  }
  
  if (!SetKernelObjectSecurity( hToken, DACL_SECURITY_INFORMATION, pNewSd)) {
    iRet = FALSE;
    goto GC;
  }
  
  if (!OpenProcessToken( hProcess, TOKEN_ALL_ACCESS, &hToken))
  {
    iRet = FALSE;
    goto GC;
  }

  if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS,0,SecurityImpersonation,TokenPrimary,&hNewToken)){
    iRet = FALSE;
    goto GC;
  }


  ZeroMemory(&si, sizeof(STARTUPINFO));
  si.cb = sizeof(STARTUPINFO);

  ImpersonateLoggedOnUser(hNewToken);

  if (!CreateProcessAsUser(hNewToken,
                           0,
                           szProcessName,
                           0,
                           0,
                           0,
                           0,//NORMAL_PRIORITY_CLASS|CREATE_NEW_CONSOLE,
                           0,
                           0,
                           &si,
                           &pi))
  {
    iRet = FALSE;
    goto GC;
  }
  WaitForSingleObject(pi.hProcess, INFINITE);

GC:
  if (pOrigSd){HeapFree(GetProcessHeap(), 0, pOrigSd );}
  if (pNewSd){HeapFree(GetProcessHeap(), 0, pNewSd );}
  if (pSidPrimary) {HeapFree(GetProcessHeap(), 0, pSidPrimary);}
  if (pSidOwner){HeapFree(GetProcessHeap(), 0, pSidOwner);}
  if (pSacl) {HeapFree(GetProcessHeap(), 0, pSacl);}
  if (pOldDAcl) {HeapFree(GetProcessHeap(), 0, pOldDAcl);}

  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  CloseHandle(hToken);
  CloseHandle(hNewToken);
  CloseHandle(hProcess);
  return iRet;
}
