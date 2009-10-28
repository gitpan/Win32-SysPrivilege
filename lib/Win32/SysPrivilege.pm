package Win32::SysPrivilege;
require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw/SysRun AdjustPrivilege/;
our $VERSION = '1.465';
require XSLoader;
XSLoader::load('Win32::SysPrivilege', $VERSION);

sub SysRun {
	return Win32::SysPrivilege::_SysRun(join(' ',@_));
}

sub AdjustPrivilege {map _AdjustPrivilege($_),@_};

BEGIN{
	my $caller = caller;
	*{$caller.'::SeCreateTokenPrivilege'} = sub {0x2};
	*{$caller.'::SeAssignPrimaryTokenPrivilege'} = sub {0x3};
	*{$caller.'::SeLockMemoryPrivilege'} = sub {0x4};
	*{$caller.'::SeIncreaseQuotaPrivilege'} = sub {0x5};
	*{$caller.'::SeMachineAccountPrivilege'} = sub {0x6};
	*{$caller.'::SeTcbPrivilege'} = sub {0x7};
	*{$caller.'::SeSecurityPrivilege'} = sub {0x8};
	*{$caller.'::SeTakeOwnershipPrivilege'} = sub {0x9};
	*{$caller.'::SeLoadDriverPrivilege'} = sub {0xA};
	*{$caller.'::SeSystemProfilePrivilege'} = sub {0xB};
	*{$caller.'::SeSystemtimePrivilege'} = sub {0xC};
	*{$caller.'::SeProfileSingleProcessPrivilege'} = sub {0xD};
	*{$caller.'::SeIncreaseBasePriorityPrivilege'} = sub {0xE};
	*{$caller.'::SeCreatePagefilePrivilege'} = sub {0xF};
	*{$caller.'::SeCreatePermanentPrivilege'} = sub {0x10};
	*{$caller.'::SeBackupPrivilege'} = sub {0x11};
	*{$caller.'::SeRestorePrivilege'} = sub {0x12};
	*{$caller.'::SeShutdownPrivilege'} = sub {0x13};
	*{$caller.'::SeDebugPrivilege'} = sub {0x14};
	*{$caller.'::SeAuditPrivilege'} = sub {0x15};
	*{$caller.'::SeSystemEnvironmentPrivilege'} = sub {0x16};
	*{$caller.'::SeChangeNotifyPrivilege'} = sub {0x17};
	*{$caller.'::SeRemoteShutdownPrivilege'} = sub {0x18};
	*{$caller.'::SeUndockPrivilege'} = sub {0x19};
	*{$caller.'::SeSyncAgentPrivilege'} = sub {0x1A};
	*{$caller.'::SeEnableDelegationPrivilege'} = sub {0x1B};
	*{$caller.'::SeManageVolumePrivilege'} = sub {0x1C};
	*{$caller.'::SeImpersonatePrivilege'} = sub {0x1D};
	*{$caller.'::SeCreateGlobalPrivilege'} = sub {0x1E};
}

1;
__END__
=head1 NAME

Win32::SysPrivilege - Perl extension for Adjusting Privileges

=head1 SYNOPSIS

	use Win32::SysPrivilege;
	#create a super shell (command prompt with SYSTEM Privilege),
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
