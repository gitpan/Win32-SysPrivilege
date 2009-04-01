package Win32::SysPrivilege;

use 5.010000;
use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Win32::SysPrivilege ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '0.03';

require XSLoader;
XSLoader::load('Win32::SysPrivilege', $VERSION);

# Preloaded methods go here.

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Win32::SysPrivilege - Perl extension for Running external programs with SYSTEM Privilege

=head1 SYNOPSIS

  use Win32::SysPrivilege;
  Win32::SysPrivilege::CreateSystemProcess("blah blah blah");

=head1 DESCRIPTION

Executing others executableslike system(),
but execute it with "SYSTEM" privilege

=head2 EXPORT


=head1 SEE ALSO

Nothing

=head1 AUTHOR

Baggio, Kwok Lok Chung E<lt>lokchungk@hotmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Baggio, Kwok Lok Chung

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.


=cut
