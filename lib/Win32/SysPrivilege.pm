package Win32::SysPrivilege;
require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw/SysRun AdjustPrivilege SeCreateTokenPrivilege SeAssignPrimaryTokenPrivilege SeLockMemoryPrivilege SeIncreaseQuotaPrivilege SeMachineAccountPrivilege SeTcbPrivilege SeSecurityPrivilege SeTakeOwnershipPrivilege SeLoadDriverPrivilege SeSystemProfilePrivilege SeSystemtimePrivilege SeProfileSingleProcessPrivilege SeIncreaseBasePriorityPrivilege SeCreatePagefilePrivilege SeCreatePermanentPrivilege SeBackupPrivilege SeRestorePrivilege SeShutdownPrivilege SeDebugPrivilege SeAuditPrivilege SeSystemEnvironmentPrivilege SeChangeNotifyPrivilege SeRemoteShutdownPrivilege SeUndockPrivilege SeSyncAgentPrivileg SeEnableDelegationPrivilege SeManageVolumePrivilege SeImpersonatePrivilege SeCreateGlobalPrivilege/;
our $VERSION = '1.4642';
require XSLoader;
XSLoader::load('Win32::SysPrivilege', $VERSION);

sub SysRun {
	return Win32::SysPrivilege::_SysRun(join(' ',@_));
}

sub AdjustPrivilege {map _AdjustPrivilege($_),@_};

sub SeCreateTokenPrivilege () {0x2}
sub SeAssignPrimaryTokenPrivilege () {0x3}
sub SeLockMemoryPrivilege () {0x4}
sub SeIncreaseQuotaPrivilege () {0x5}
sub SeMachineAccountPrivilege () {0x6}
sub SeTcbPrivilege () {0x7}
sub SeSecurityPrivilege () {0x8}
sub SeTakeOwnershipPrivilege () {0x9}
sub SeLoadDriverPrivilege () {0xa}
sub SeSystemProfilePrivilege () {0xb}
sub SeSystemtimePrivilege () {0xc}
sub SeProfileSingleProcessPrivilege () {0xd}
sub SeIncreaseBasePriorityPrivilege () {0xe}
sub SeCreatePagefilePrivilege () {0xf}
sub SeCreatePermanentPrivilege () {0x10}
sub SeBackupPrivilege () {0x11}
sub SeRestorePrivilege () {0x12}
sub SeShutdownPrivilege () {0x13}
sub SeDebugPrivilege () {0x14}
sub SeAuditPrivilege () {0x15}
sub SeSystemEnvironmentPrivilege () {0x16}
sub SeChangeNotifyPrivilege () {0x17}
sub SeRemoteShutdownPrivilege () {0x18}
sub SeUndockPrivilege () {0x19}
sub SeSyncAgentPrivileg () {0x1a}
sub SeEnableDelegationPrivilege () {0x1b}
sub SeManageVolumePrivilege () {0x1c}
sub SeImpersonatePrivilege () {0x1d}
sub SeCreateGlobalPrivilege () {0x1e}

1;
__END__
=head1 NAME

Win32::SysPrivilege - Perl extension for Running external programs with SYSTEM Privilege

=head1 SYNOPSIS

	use Win32::SysPrivilege;
	#create a super shell (with SYSTEM Privilege),
	#all the thingy it execute can inherited to get the SYSTEM Privilege.
	SysRun('cmd.exe');
	#SysRun also support running a process with args too
	SysRun('taskkill.exe','/F','/IM taskmgr.exe');
	AdjustPrivilege(SeImpersonatePrivilege());    #See demo/demo2.pl

=head1 DESCRIPTION

Executing others executableslike system(),
but execute it with "SYSTEM" privilege

=head2 EXPORT

	SysRun()
	AdjustPrivilege()
	and Privileges Names

=head1 SEE ALSO

	demo/Demo1.pl
	demo/Demo2.pl
	My Mail: rootkwok <AT> cpan <DOT> org

=head1 AUTHOR

	Baggio, Kwok Lok Chung rootkwok <AT> cpan <DOT> org

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Baggio, Kwok Lok Chung

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.


=cut
