#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "main.c"

MODULE = Win32::SysPrivilege		PACKAGE = Win32::SysPrivilege		
int
_SysRun(char* szProcessName)

bool
_AdjustPrivilege(int PriName)
