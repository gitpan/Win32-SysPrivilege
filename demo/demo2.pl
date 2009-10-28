#Adjust All Privileges
use Win32::SysPrivilege;

print AdjustPrivilege(
	SeBackupPrivilege,
	SeCreateTokenPrivilege,
	SeAssignPrimaryTokenPrivilege,
	SeLockMemoryPrivilege,
	SeIncreaseQuotaPrivilege,
	SeMachineAccountPrivilege,
	SeTcbPrivilege,
	SeSecurityPrivilege,
	SeTakeOwnershipPrivilege,
	SeLoadDriverPrivilege,
	SeSystemProfilePrivilege,
	SeSystemtimePrivilege,
	SeProfileSingleProcessPrivilege,
	SeIncreaseBasePriorityPrivilege,
	SeCreatePagefilePrivilege,
	SeCreatePermanentPrivilege,
	SeBackupPrivilege,
	SeRestorePrivilege,
	SeShutdownPrivilege,
	SeDebugPrivilege,
	SeAuditPrivilege,
	SeSystemEnvironmentPrivilege,
	SeChangeNotifyPrivilege,
	SeRemoteShutdownPrivilege,
	SeUndockPrivilege,
	SeSyncAgentPrivilege,
	SeEnableDelegationPrivilege,
	SeManageVolumePrivilege,
	SeImpersonatePrivilege,
	SeCreateGlobalPrivilege
);
<>
