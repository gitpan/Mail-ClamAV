package Mail::ClamAV;

use 5.006001;
use strict;
use warnings;
use Carp;

our $VERSION;
BEGIN {
    $VERSION = '0.06';
}

# guard against memory errors not being reported
our $Error = (' ' x 255);
$Error = undef;

require Exporter;
use IO::Handle;
our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration   use Mail::ClamAV ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
    retdbdir

    CL_EACCES
    CL_EBZIP
    CL_EFSYNC
    CL_EGZIP
    CL_EMALFDB
    CL_EMALFZIP
    CL_EMAXFILES
    CL_EMAXREC
    CL_EMAXSIZE
    CL_EMEM
    CL_ENULLARG
    CL_EOPEN
    CL_EPATSHORT
    CL_ERAR
    CL_ETMPDIR
    CL_ETMPFILE
    CL_EZIP
    CL_MIN_LENGTH
    CL_NUM_CHILDS

    CL_MAIL
    CL_ARCHIVE
    CL_RAW

    CL_VIRUS
    CL_CLEAN
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "&Mail::ClamAV::constant not defined" if $constname eq 'constant';
    my $val = constant($constname);
    no strict 'refs';
    *$AUTOLOAD = sub { $val };
    goto &$AUTOLOAD;
}

sub scan {
    my $self = shift;

    my $thing = shift;
    croak "No file argument to scan!" unless defined $thing;

    my $options = shift || 0;

    croak "Invalid number of options to scan()" if @_;

    my ($st, $num_scanned);
    if (
        (UNIVERSAL::isa($thing, 'GLOB')   or
         UNIVERSAL::isa(\$thing, 'GLOB')) and
        defined fileno($thing)
    )
    {
        IO::Handle::flush($thing);
        ($st, $num_scanned) = _scanfd($self, fileno($thing), $options);
    }
    else {
        croak "$thing does not exist" unless -e $thing;
        ($st, $num_scanned) = _scanfile($self, $thing, $options);
    }
    my $status = new Mail::ClamAV::Status;
    $status->error($st);
    $status->errno(0+$st);
    $status->clean($st == CL_CLEAN());
    $status->virus($st == CL_VIRUS());
    if ($status) {
        $status->count($num_scanned);
    }
    else {
        $status->count(0);
    }
    return $status;
}

sub scanbuff {
    my $self = shift;

    my $buff = shift;
    croak "No buffer defined" unless defined $buff;

    croak "Invalid arguments to scanbuff: @_" if @_;

    my $st = _scanbuff($self, $buff);
    my $status = new Mail::ClamAV::Status;
    $status->error($st);
    $status->errno(0+$st);
    $status->clean($st == CL_CLEAN());
    $status->virus($st == CL_VIRUS());
    if ($status) {
        $status->count(1);
    }
    else {
        $status->count(0);
    }
    return $status;
}


use Inline C => Config =>
    VERSION  => $VERSION,
    PREFIX   => 'clamav_perl_',
    NAME     => "Mail::ClamAV",
    LIBS     => "-lclamav";
# removed on install
BEGIN {
require "./config.pl";
}
# end removed on install
use Inline C => <<'END_OF_C';
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <clamav.h>

#define SvClam(MEM) ((struct clamav_perl *)SvIV(SvRV(MEM)))

static void error(int errcode);

struct clamav_perl {
    struct cl_node *root;
    struct cl_limits limits;
    struct cl_stat st;
    char is_dir;
    char *path;
    int signatures;
};

SV *clamav_perl_new(char *class, char *path)
{
    SV *self_ref, *self;
    struct stat st;
    struct clamav_perl *c;
    int status;

    Newz(0, c, 1, struct clamav_perl);
    if (stat(path, &st) != 0)
        croak("%s does not exist: %s\n", path, strerror(errno));

    /* set defaults for limits */
    c->limits.maxreclevel = 5;
    c->limits.maxfiles = 1000;
    c->limits.maxfilesize = 1024 * 1028 * 10; /* 10 Megs */

    if (S_ISDIR(st.st_mode)) {
        c->is_dir = 1;
        memset(&c->st, 0, sizeof(struct cl_stat));
        status = cl_statinidir(path, &c->st);
        c->path = strdup(path);
        if (status == 0)
            status = cl_loaddbdir(path, &c->root, &c->signatures);
    }
    else
        status = cl_loaddb(path, &c->root, &c->signatures);

    if (status != 0) {
        error(status);
        return &PL_sv_undef;
    }

    /* Bless my structs memory location into the object */
    self_ref = newSViv(0);
    self = newSVrv(self_ref, class);
    sv_setiv(self, (IV) c);
    SvREADONLY_on(self);
    return self_ref;
}

int clamav_perl_statchkdir(SV *self)
{
    int ret;
    struct clamav_perl *c = SvClam(self);
    if (c->is_dir == 0)
        croak("statchkdir() only works if a database directory was specified to new()");
    ret = cl_statchkdir(&c->st);
    cl_statfree(&c->st);
    cl_statinidir(c->path, &c->st);
}

char *clamav_perl_retdbdir()
{
    return cl_retdbdir();
}

void clamav_perl_buildtrie(SV *self)
{
    struct clamav_perl *c = SvClam(self);
    cl_buildtrie(c->root);
}

int clamav_perl_maxreclevel(SV *self, ...)
{
    Inline_Stack_Vars;
    if (Inline_Stack_Items > 1) {
        SV *max;
        if (Inline_Stack_Items > 2)
            croak("Invalid number of arguments to maxreclevel()");
        max = Inline_Stack_Item(2);
        SvClam(self)->limits.maxreclevel = SvIV(max);
    }
    return SvClam(self)->limits.maxreclevel;
}

int clamav_perl_maxfiles(SV *self, ...)
{
    Inline_Stack_Vars;
    if (Inline_Stack_Items > 1) {
        SV *max;
        if (Inline_Stack_Items > 2)
            croak("Invalid number of arguments to maxfiles()");
        max = Inline_Stack_Item(2);
        SvClam(self)->limits.maxfiles = SvIV(max);
    }
    return SvClam(self)->limits.maxfiles;
}

int clamav_perl_maxfilesize(SV *self, ...)
{
    Inline_Stack_Vars;
    if (Inline_Stack_Items > 1) {
        SV *max;
        if (Inline_Stack_Items > 2)
            croak("Invalid number of arguments to maxfilesize()");
        max = Inline_Stack_Item(2);
        SvClam(self)->limits.maxfilesize = SvIV(max);
    }
    return SvClam(self)->limits.maxfilesize;
}

void clamav_perl__scanbuff(SV *self, SV *buff)
{
    struct clamav_perl *c = SvClam(self);
    STRLEN len;
    int status;
    char *b, *msg;
    SV *smsg;
    Inline_Stack_Vars;

    Inline_Stack_Reset;

    b = SvPV(buff, len);
    status = cl_scanbuff(b, len, &msg, c->root);

    /* msg is some random memory if no virus was found */
    if (status == CL_VIRUS)
        smsg = sv_2mortal(newSVpv(msg, 0));
    else if (status == CL_CLEAN)
        smsg = sv_2mortal(newSVpv("Clean", 0));
    else
        smsg = sv_2mortal(newSVpv(cl_perror(status), 0));

    sv_setiv(smsg, (IV)status);
    SvIOK(smsg);
    Inline_Stack_Push(smsg);
    Inline_Stack_Done;
}

void DESTROY(SV *self)
{
    struct clamav_perl *c = SvClam(self);
    cl_freetrie(c->root);
    if (c->is_dir == 1)
        cl_statfree(&c->st);
    Safefree(c->path);
    Safefree(c);
}

void clamav_perl__scanfd(SV *self, int fd, int options)
{
    struct clamav_perl *c = SvClam(self);
    STRLEN len;
    int status;
    unsigned long int scanned;
    char *msg;
    SV *smsg, *sscanned;
    Inline_Stack_Vars;

    Inline_Stack_Reset;

    scanned = 0;
    status = cl_scandesc(fd, &msg, &scanned, c->root,
            &c->limits, options);
    if (scanned == 0)
        scanned = 1;

    smsg = sv_newmortal();
    sv_setiv(smsg, (IV)status);

    /* msg is some random memory if no virus was found */
    if (status == CL_VIRUS)
        sv_setpv(smsg, msg);
    else if (status == CL_CLEAN)
        sv_setpv(smsg, "Clean");
    else
        sv_setpv(smsg, cl_perror(status));

    SvIOK_on(smsg);
    Inline_Stack_Push(smsg);
    sscanned = sv_2mortal(newSViv(scanned));
    Inline_Stack_Push(sscanned);
    Inline_Stack_Done;
}

void clamav_perl__scanfile(SV *self, char *path, int options)
{
    struct clamav_perl *c = SvClam(self);
    STRLEN len;
    int status;
    unsigned long int scanned;
    char *msg;
    SV *smsg, *sscanned;
    Inline_Stack_Vars;

    Inline_Stack_Reset;

    scanned = 0;
    status = cl_scanfile(path, &msg, &scanned, c->root,
            &c->limits, options);
    if (scanned == 0)
        scanned = 1;

    smsg = sv_newmortal();
    sv_setiv(smsg, (IV)status);

    /* msg is some random memory if no virus was found */
    if (status == CL_VIRUS)
        sv_setpv(smsg, msg);
    else if (status == CL_CLEAN)
        sv_setpv(smsg, "Clean");
    else
        sv_setpv(smsg, cl_perror(status));

    SvIOK_on(smsg);
    Inline_Stack_Push(smsg);
    sscanned = sv_2mortal(newSViv(scanned));
    Inline_Stack_Push(sscanned);
    Inline_Stack_Done;
}

static void error(int errcode)
{
    char *e;
    SV *err = get_sv("Mail::ClamAV::Error", TRUE);

    sv_setiv(err, (IV)errcode);
    e = cl_perror(errcode);
    sv_setpv(err, e);
    SvIOK_on(err);
}

int clamav_perl_constant(char *name)
{
    if (strEQ("CL_EACCES", name)) return CL_EACCES;
    if (strEQ("CL_EBZIP", name)) return CL_EBZIP;
    if (strEQ("CL_EFSYNC", name)) return CL_EFSYNC;
    if (strEQ("CL_EGZIP", name)) return CL_EGZIP;
    if (strEQ("CL_EMALFDB", name)) return CL_EMALFDB;
    if (strEQ("CL_EMALFZIP", name)) return CL_EMALFZIP;
    if (strEQ("CL_EMAXFILES", name)) return CL_EMAXFILES;
    if (strEQ("CL_EMAXREC", name)) return CL_EMAXREC;
    if (strEQ("CL_EMAXSIZE", name)) return CL_EMAXSIZE;
    if (strEQ("CL_EMEM", name)) return CL_EMEM;
    if (strEQ("CL_ENULLARG", name)) return CL_ENULLARG;
    if (strEQ("CL_EOPEN", name)) return CL_EOPEN;
    if (strEQ("CL_EPATSHORT", name)) return CL_EPATSHORT;
    if (strEQ("CL_ERAR", name)) return CL_ERAR;
    if (strEQ("CL_ETMPDIR", name)) return CL_ETMPDIR;
    if (strEQ("CL_ETMPFILE", name)) return CL_ETMPFILE;
    if (strEQ("CL_EZIP", name)) return CL_EZIP;
    if (strEQ("CL_MIN_LENGTH", name)) return CL_MIN_LENGTH;
    if (strEQ("CL_NUM_CHILDS", name)) return CL_NUM_CHILDS;
    if (strEQ("CL_MAIL", name)) return CL_MAIL;
    if (strEQ("CL_ARCHIVE", name)) return CL_ARCHIVE;
    if (strEQ("CL_RAW", name)) return CL_RAW;
    if (strEQ("CL_VIRUS", name)) return CL_VIRUS;
    if (strEQ("CL_CLEAN", name)) return CL_CLEAN;
    croak("Invalid function %s", name);
}

END_OF_C

# For the return status of scan
package Mail::ClamAV::Status;
use strict;

use Class::Struct;

import Mail::ClamAV qw(CL_CLEAN CL_VIRUS);

use overload
    '""'   => sub { $_[0]->error },
    'cmp'  => sub { $_[2] ? $_[1] cmp "$_[0]" : "$_[0]" cmp $_[1] },
    'bool' => sub {
        $_[0]->errno == CL_CLEAN() or
        $_[0]->errno == CL_VIRUS()
    };

struct(
    'Mail::ClamAV::Status' => {
        errno  => '$',
        clean  => '$',
        virus  => '$',
        error  => '$',
        count  => '$'
    }
);

1;
__END__

=head1 NAME

Mail::ClamAV - Perl extension for the clamav virus scanner

=head1 SYNOPSIS

    use Mail::ClamAV qw/:all/;


    # $Mail::ClamAV::Error in numeric context return clamav's
    # error status code which corresponds to the constants which
    # can be exported
    my $c = new Mail::ClamAV("/path/to/directory/or/file")
        or die "Failed to load db: $Mail::ClamAV::Error (", 0+$Mail::;

    # You can get retdbdir() to get the database dir in
    # clamav's conf
    my $c = new Mail::ClamAV(retdbdir())
        or die "Failed to load db: $Mail::ClamAV::Error";

    # When database is loaded, you must create the proper trie with:
    $c->buildtrie;

    # check to see if we need to reload
    if ($c->statchkdir) {
        $c = new Mail::ClamAV(retdbdir());
        $c->buildtrie;
    }

    # Set some limits (only applies to scan())
    # Only relevant for archives
    $c->maxreclevel(4);
    $c->maxfiles(20);
    $c->maxfilesize(1024 * 1024 * 20); # 20 megs

    # Scan a buffer
    my $status = $c->scanbuff($buff);

    # Scan a filehandle (scandesc in clamav)
    # scan(FileHandle or path, Bitfield of options)
    my $status = $c->scan(FH, CL_ARCHIVE|CL_MAIL);

    # Scan a file (scanfile in clamav)
    my $status = $c->scan("/path/to/file.eml", CL_MAIL);

    # $status is an overloaded object
    die "Failed to scan: $status" unless $status;
    if ($status->virus) {
        print "Message is a virus: $status\n";
    }
    else {
        print "No virus found!\n";
    }


=head1 DESCRIPTION

Clam AntiVirus is an anti-virus toolkit for UNIX
L<http://clamav.elektrapro.com/>.  This module provide a simple interface to
its C API.

=head2 EXPORT

None by default.

=head2 Exportable constants

Options for scanning.

=over 1

=item CL_MAIL

enables mbox and Maildir scanning

WARNING WARNING WARNING
The MIME parsing in clamav is still beta quality code as of the time of this
writing [Tue Feb 10 10:09:56 PST 2004]. It B<will> segfault with certain emails.
This tested with current CVS of clamav.

=item CL_ARCHIVE

enables archive scanning

=item CL_RAW

disables archive scanning

=back

Status returns. These are the first item in the list returned by C<scan()> and
C<scanbuff()> when put into numeric context

=over 1

=item CL_CLEAN

no viruses found

=item CL_VIRUS

virus found, put the status in scalar context to see the type

These are the error status codes which you can get by putting
$Mail::ClamAV::Error in numeric context

=back

=over 1

=item CL_EMAXREC

Recursion limit exceeded.

=item CL_EMAXSIZE

File size limit exceeded.

=item CL_EMAXFILES

Files number limit exceeded.

=item CL_ERAR

RAR module failure.

=item CL_EZIP

Zip module failure.

=item CL_EMALFZIP

Malformed Zip detected.

=item CL_EGZIP

GZip module failure.

=item CL_ETMPFILE

Unable to create temporary file.

=item CL_ETMPDIR

Unable to create temporary directory.

=item CL_EFSYNC

Unable to synchronize file <-> disk.

=item CL_EMEM

Unable to allocate memory.

=item CL_EOPEN

Unable to open file or directory.

=item CL_EMALFDB

Malformed database.

=item CL_EPATSHORT

Too short pattern detected.

=item CL_ENULLARG

Null argument passed when initialized is required.

=back

=head2 Exportable functions

These function can be exported either individually or using the :all export
flags

=over 1

=item retdbdir

This function returns the path to the database directory specified when clamav
was compiled.

=back

=head1 METHODS

=head2 Settings

NOTE
These settings only apply to C<scan()> and archives (CL_ARCHIVE).

=over 1

=item maxreclevel

Sets the maximum recursion level [default 5].

=item maxfiles

Maximum number of files that will be scanned [default 1000].

=item maxfilesize

Maximum file size that will be scanned in bytes [default 10M].

=back

=head2 Scanning

All of these methods return a status object. This object is overloaded to make
things cleaner. In boolean context this will return false if there was an
error.  For example:
    my $status = $c->scan("foo.txt");
    die "Error scanning: $status" unless $status;

As you probably just noticed, $status in scalar context returns the error
message.  In addition to the overloading you just saw, $status has the
following methods:

=over 1

=item errno

The numeric value (if any) clamav returned.

=item clean

This will be true if the message was not a virus and an error did not occur.

=item virus

Returns true if the message is a virus.

=item error

Return the error message (if any). This is the same thing as quoting $status.

=item count

Returns the number of messages scanned. Only works with archives.

=back

=over 1

=item scan(FileHandle or Path, Bitfield of options)

C<scan()> takes a FileHanle or path and passed the file descriptor for that off
to clamav.  The second argument is a bitfield of options, CL_MAIL, CL_ARCHIVE
or CL_RAW L<"Exportable constants">.

This function returns the status object discussed earlier

=item scanbuff($buff)

scanbuff takes a raw buffer and scans it. No options are available for this
function (it is assumed you already unarchived or de-MIMEed the buffer and that
it is raw).

=back

=head2 Data Directory stats

If the path passed into C<new()> is a directory Mail::ClamAV will set things up
to check for updated database files. Calling the C<statchkdir()> will check the
database directory to the stats we have in memory. If anything has changed true
is returned, otherwise false.

NOTE: trying to use C<statchkdir()> when you passed in a database file instead
of directory will produce a fatal error.

C<statchkdir()> is useful for long running daemons that need to check to see if
it is time to reload the database. Reloading is simply getting a new
Mail::ClamAV object and initializing it.

=head1 SEE ALSO

The ClamAV API documentation L<http://www.clamav.net/doc/html-0.65/node44.html>

=head1 AUTHOR

Scott Beck E<lt>sbeck@gossamer-threads.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2003 by Gossamer Threads Inc. L<http://www.gossamer-threads.com>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.1 or,
at your option, any later version of Perl 5 you may have available.


=cut

