package Win32::SysPrivilege;

require Exporter;

our @ISA = qw(Exporter);

our %EXPORT_TAGS = ( 'all' => [ qw() ] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw(SysRun);

our $VERSION = '1.462';

require XSLoader;
XSLoader::load('Win32::SysPrivilege', $VERSION);

sub SysRun {
	return Win32::SysPrivilege::_SysRun(join(' ',@_));
}
1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Win32::SysPrivilege - Perl extension for Running external programs with SYSTEM Privilege

=head1 SYNOPSIS

	use Win32::SysPrivilege;
	SysRun("taskmgr.exe");

=head1 DESCRIPTION

Executing others executableslike system(),
but execute it with "SYSTEM" privilege

=head2 EXPORT

	SysRun()

=head1 SEE ALSO

	My Mail: rootkwok <AT> cpan <DOT> org

=head1 AUTHOR

Baggio, Kwok Lok Chung rootkwok <AT> cpan <DOT> org

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Baggio, Kwok Lok Chung

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.


=cut
