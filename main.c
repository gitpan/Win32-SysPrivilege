#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <aclapi.h>

typedef int (*pRtlAdjustPrivilege)(int,bool,bool,int*);
pRtlAdjustPrivilege RtlAdjPriv = NULL;

bool AdjustPrivileges(int iName){
	int *prtn;
	HMODULE ntdll = LoadLibrary("ntdll.dll");
	if(ntdll){
		RtlAdjPriv = (pRtlAdjustPrivilege) GetProcAddress(ntdll,"RtlAdjustPrivilege");
	}else{return 0;}
	if(RtlAdjPriv){
		RtlAdjPriv(iName,TRUE,FALSE,prtn);
	}else{return 0;}
	FreeLibrary(ntdll);
	return 1;
}

DWORD GetProcessId(LPCTSTR szProcName){
  PROCESSENTRY32 pe;  
  DWORD dwPid;
  DWORD dwRet;
  BOOL bFound = FALSE;
  
  HANDLE hSP = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSP){pe.dwSize = sizeof(pe);
    for (dwRet = Process32First(hSP, &pe);dwRet;dwRet = Process32Next(hSP, &pe)){
      if (StrCmpNI(szProcName, pe.szExeFile, strlen(szProcName)) == 0){
        dwPid = pe.th32ProcessID;
        bFound = TRUE;
        break;
      }
    }
    CloseHandle(hSP);
    if (bFound == TRUE){
      return dwPid;
    }
  }
  return 0x00;
}

BOOL SysRun(char* szProcessName){
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
  BOOL ret = TRUE;
  int i=2;
  for(;i<=30;i++){
  	AdjustPrivileges(i); 
  }
  if ((dwPid = GetProcessId("WINLOGON.EXE")) == 0) {
    ret = FALSE;
    goto Cleanup;
  }
  hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid);
  if (hProcess == NULL) {
    ret = FALSE;
    goto Cleanup;
  }
  if (!OpenProcessToken( hProcess, READ_CONTROL|WRITE_DAC, &hToken )) {
    ret = FALSE;
    goto Cleanup;
  }
  ZeroMemory(&ea, sizeof( EXPLICIT_ACCESS));
  BuildExplicitAccessWithName(&ea,"Everyone",TOKEN_ALL_ACCESS,GRANT_ACCESS,0);
  if (!GetKernelObjectSecurity(hToken,DACL_SECURITY_INFORMATION,pOrigSd,0,&dwSDLen)){
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER){
	      pOrigSd = (PSECURITY_DESCRIPTOR) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwSDLen);
		 if (pOrigSd == NULL) {
			ret = FALSE;
			goto Cleanup;
		}
		if (!GetKernelObjectSecurity(hToken,DACL_SECURITY_INFORMATION,pOrigSd,dwSDLen,&dwSDLen)){
        ret = FALSE;
        goto Cleanup;
      }
    }else{
      ret = FALSE;
      goto Cleanup;
    }
  }
  if(!GetSecurityDescriptorDacl(pOrigSd, &bDAcl, &pOldDAcl, &bDefDAcl)){
    ret = FALSE;
    goto Cleanup;
  }
  dwRet = SetEntriesInAcl(1, &ea, pOldDAcl, &pNewDAcl); 
  if (dwRet != ERROR_SUCCESS){
    pNewDAcl = NULL;
    ret = FALSE;
    goto Cleanup;
  }
  if (!MakeAbsoluteSD(pOrigSd,pNewSd,&dwSDLen,pOldDAcl,&dwAclSize,pSacl,&dwSaclSize,pSidOwner,&dwSidOwnLen,pSidPrimary,&dwSidPrimLen)){
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER){
      pOldDAcl = (PACL) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwAclSize);
      pSacl = (PACL) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwSaclSize);
      pSidOwner = (PSID) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwSidOwnLen);
      pSidPrimary = (PSID) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwSidPrimLen);
      pNewSd = (PSECURITY_DESCRIPTOR) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwSDLen);
      if(pOldDAcl == NULL||pSacl == NULL||pSidOwner == NULL||pSidPrimary == NULL||pNewSd == NULL){
        ret = FALSE;
        goto Cleanup;
      }
      if(!MakeAbsoluteSD(pOrigSd,pNewSd,&dwSDLen,pOldDAcl,&dwAclSize,pSacl,&dwSaclSize,pSidOwner,&dwSidOwnLen,pSidPrimary,&dwSidPrimLen)){
        ret = FALSE;
        goto Cleanup;
      }
    }else{
      ret = FALSE;
      goto Cleanup;
    }
  }
  if(!SetSecurityDescriptorDacl( pNewSd, bDAcl, pNewDAcl, bDefDAcl)){
    ret = FALSE;
    goto Cleanup;
  }
  if(!SetKernelObjectSecurity( hToken, DACL_SECURITY_INFORMATION, pNewSd)){
    ret = FALSE;
    goto Cleanup;
  }
  if(!OpenProcessToken( hProcess, TOKEN_ALL_ACCESS, &hToken)){
    ret = FALSE;
    goto Cleanup;
  }
  if(!DuplicateTokenEx(hToken,TOKEN_ALL_ACCESS,NULL,SecurityImpersonation,TokenPrimary,&hNewToken)){
    ret = FALSE;
    goto Cleanup;
  }
  ZeroMemory(&si, sizeof(STARTUPINFO));
  si.cb = sizeof(STARTUPINFO);
  ImpersonateLoggedOnUser(hNewToken);
  if (!CreateProcessAsUser(hNewToken,NULL,szProcessName,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi)){
    ret = FALSE;
    goto Cleanup;
  }
  WaitForSingleObject(pi.hProcess, INFINITE);
Cleanup:
  if(pOrigSd){
    HeapFree(GetProcessHeap(), 0, pOrigSd );
  }
  if(pNewSd){
    HeapFree(GetProcessHeap(), 0, pNewSd );
  }
  if(pSidPrimary){
    HeapFree(GetProcessHeap(), 0, pSidPrimary);
  }
  if(pSidOwner){
    HeapFree(GetProcessHeap(), 0, pSidOwner);
  }
  if(pSacl){
    HeapFree(GetProcessHeap(), 0, pSacl);
  }
  if(pOldDAcl){
    HeapFree(GetProcessHeap(), 0, pOldDAcl);
  }
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  CloseHandle(hToken);
  CloseHandle(hNewToken);
  CloseHandle(hProcess);
  return ret;
}
