use Win32::SysPrivilege;

print AdjustPrivilege(
	SeBackupPrivilege(),
	SeCreateTokenPrivilege(),
	SeAssignPrimaryTokenPrivilege(),
	SeLockMemoryPrivilege(),
	SeIncreaseQuotaPrivilege(),
	SeMachineAccountPrivilege(),
	SeTcbPrivilege(),
	SeSecurityPrivilege(),
	SeTakeOwnershipPrivilege(),
	SeLoadDriverPrivilege(),
	SeSystemProfilePrivilege(),
	SeSystemtimePrivilege(),
	SeProfileSingleProcessPrivilege(),
	SeIncreaseBasePriorityPrivilege(),
	SeCreatePagefilePrivilege(),
	SeCreatePermanentPrivilege(),
	SeBackupPrivilege(),
	SeRestorePrivilege(),
	SeShutdownPrivilege(),
	SeDebugPrivilege(),
	SeAuditPrivilege(),
	SeSystemEnvironmentPrivilege(),
	SeChangeNotifyPrivilege(),
	SeRemoteShutdownPrivilege(),
	SeUndockPrivilege(),
	SeSyncAgentPrivileg(),
	SeEnableDelegationPrivilege(),
	SeManageVolumePrivilege(),
	SeImpersonatePrivilege(),
	SeCreateGlobalPrivilege()
);
<>