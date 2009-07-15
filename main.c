#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <aclapi.h>
#pragma comment(lib,"Shlwapi.lib")
typedef LONG (*pRtlAdjustPrivilege)(int,BOOL,BOOL,int*);
pRtlAdjustPrivilege RtlAdjPriv = NULL;

int AdjustPrivilege(){
	HANDLE hNTDLL = LoadLibraryA("ntdll.dll");
	if(!hNTDLL)
		return 0;
	RtlAdjPriv = (pRtlAdjustPrivilege) GetProcAddress((HINSTANCE)hNTDLL,"RtlAdjustPrivilege");
	if(!RtlAdjPriv)
		return 0;
	{
		int prtn;
		RtlAdjPriv(20,1,0,&prtn);
	}
	return 1;
	FreeLibrary(hNTDLL);
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

int SysRun(char* szProcessName){
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

  BOOL iRet = 1;

  if(!AdjustPrivilege()){
    iRet = 0;
    goto Cleanup;
  }
  
  dwPid = GetProcessId("WINLOGON.EXE");
  if (!dwPid){
    printf("GetProcessId() failed!\n");   
    iRet = 0;
    goto Cleanup;
  }

  hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwPid);
  if (hProcess == NULL)
  {
    printf("OpenProcess() = %d\n", GetLastError() );   

    iRet = 0;
    goto Cleanup;
  }

  if (!OpenProcessToken( hProcess, READ_CONTROL|WRITE_DAC, &hToken ))
  {
    printf("OpenProcessToken() = %d\n", GetLastError());

    iRet = 0;
    goto Cleanup;
  }

  ZeroMemory(&ea, sizeof( EXPLICIT_ACCESS));
  BuildExplicitAccessWithName(&ea,
                             "Everyone",
                              TOKEN_ALL_ACCESS,
                              GRANT_ACCESS,
                              0);

  if (!GetKernelObjectSecurity(hToken,
                               DACL_SECURITY_INFORMATION,
                               pOrigSd,
                               0,
                               &dwSDLen))
  {
    
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
      pOrigSd = (PSECURITY_DESCRIPTOR) HeapAlloc(GetProcessHeap(),
                                                 HEAP_ZERO_MEMORY,
                                                 dwSDLen);
      if(!pOrigSd)
      {
      printf("HeapAlloc failed: pSd \n");

        iRet = 0;
        goto Cleanup;
      }
      if (!GetKernelObjectSecurity(hToken,
                                   DACL_SECURITY_INFORMATION,
                                   pOrigSd,
                                   dwSDLen,
                                   &dwSDLen))
      {
        printf("GetKernelObjectSecurity() = %d\n", GetLastError());
        iRet = 0;
        goto Cleanup;
      }
    }
    else
    {
      printf("GetKernelObjectSecurity() = %d\n", GetLastError());
      iRet = 0;
      goto Cleanup;
    }
  }

  if (!GetSecurityDescriptorDacl(pOrigSd, &bDAcl, &pOldDAcl, &bDefDAcl))
  {
    printf("GetSecurityDescriptorDacl() = %d\n", GetLastError());

    iRet = 0;
    goto Cleanup;
  }

  dwRet = SetEntriesInAcl(1, &ea, pOldDAcl, &pNewDAcl); 
  if (dwRet != ERROR_SUCCESS)
  {
    printf("SetEntriesInAcl() = %d\n", GetLastError()); 
    pNewDAcl = NULL;

    iRet = 0;
    goto Cleanup;
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
                      &dwSidPrimLen))
  {
    
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
      pOldDAcl = (PACL) HeapAlloc(GetProcessHeap(),
                                  HEAP_ZERO_MEMORY,
                                  dwAclSize);
      pSacl = (PACL) HeapAlloc(GetProcessHeap(),
                               HEAP_ZERO_MEMORY,
                               dwSaclSize);
      pSidOwner = (PSID) HeapAlloc(GetProcessHeap(),
                                   HEAP_ZERO_MEMORY,
                                   dwSidOwnLen);
      pSidPrimary = (PSID) HeapAlloc(GetProcessHeap(),
                                     HEAP_ZERO_MEMORY,
                                     dwSidPrimLen);
      pNewSd = (PSECURITY_DESCRIPTOR) HeapAlloc(GetProcessHeap(),
                                                HEAP_ZERO_MEMORY,
                                                dwSDLen);

      if (pOldDAcl == NULL||
          pSacl == NULL||
          pSidOwner == NULL||
          pSidPrimary == NULL||
          pNewSd == NULL )
      {
        printf("HeapAlloc SID or ACL failed!\n");

        iRet = 0;
        goto Cleanup;
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
                          &dwSidPrimLen))
      {
        printf("MakeAbsoluteSD() = %d\n", GetLastError());

        iRet = 0;
        goto Cleanup;
      }
    }
    else
    {
      printf("MakeAbsoluteSD() = %d\n", GetLastError());

      iRet = 0;
      goto Cleanup;
    }
  }

  if (!SetSecurityDescriptorDacl( pNewSd, bDAcl, pNewDAcl, bDefDAcl))
  {
    printf("SetSecurityDescriptorDacl() = %d\n", GetLastError());

    iRet = 0;
    goto Cleanup;
  }
  
  if (!SetKernelObjectSecurity( hToken, DACL_SECURITY_INFORMATION, pNewSd))
  {
    printf("SetKernelObjectSecurity() = %d\n", GetLastError());

    iRet = 0;
    goto Cleanup;
  }
  
  if (!OpenProcessToken( hProcess, TOKEN_ALL_ACCESS, &hToken))
  {
    printf("OpenProcessToken() = %d\n", GetLastError());   

    iRet = 0;
    goto Cleanup;
  }

  if (!DuplicateTokenEx(hToken,
                        TOKEN_ALL_ACCESS,
                        0,
                        SecurityImpersonation,
                        TokenPrimary,
                        &hNewToken))
  {
    printf("DuplicateTokenEx() = %d\n", GetLastError());   

    iRet = 0;
    goto Cleanup;
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
    printf("CreateProcessAsUser() = %d\n", GetLastError());   

    iRet = 0;
    goto Cleanup;
  }
  WaitForSingleObject(pi.hProcess, INFINITE);

Cleanup:
  if (pOrigSd)
  {
    HeapFree(GetProcessHeap(), 0, pOrigSd );
  }
  if (pNewSd)
  {
    HeapFree(GetProcessHeap(), 0, pNewSd );
  }
  if (pSidPrimary)
  {
    HeapFree(GetProcessHeap(), 0, pSidPrimary);
  }
  if (pSidOwner)
  {
    HeapFree(GetProcessHeap(), 0, pSidOwner);
  }
  if (pSacl)
  {
    HeapFree(GetProcessHeap(), 0, pSacl);
  }
  if (pOldDAcl)
  {
    HeapFree(GetProcessHeap(), 0, pOldDAcl);
  }

  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  CloseHandle(hToken);
  CloseHandle(hNewToken);
  CloseHandle(hProcess);
  return iRet;
}
