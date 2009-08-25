package Win32::SysPrivilege;
require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(SysRun);
our $VERSION = '1.464';
require XSLoader;
XSLoader::load('Win32::SysPrivilege', $VERSION);

sub SysRun {
	return Win32::SysPrivilege::_SysRun(join(' ',@_));
}
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

=head1 DESCRIPTION

Executing others executableslike system(),
but execute it with "SYSTEM" privilege

=head2 EXPORT

	SysRun()

=head1 SEE ALSO

	Demo.pl
	My Mail: rootkwok <AT> cpan <DOT> org

=head1 AUTHOR

	Baggio, Kwok Lok Chung rootkwok <AT> cpan <DOT> org

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Baggio, Kwok Lok Chung

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.


=cut
