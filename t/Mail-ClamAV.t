# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Mail-ClamAV.t'

#########################

use Test::More tests => 4;
use strict;
BEGIN { use_ok('Mail::ClamAV') };

import Mail::ClamAV qw/:all/;

my $fail = 0;
foreach my $constname (qw(
	CL_ARCHIVE CL_CLEAN CL_EACCES CL_EBZIP CL_EFSYNC
	CL_EGZIP CL_EMALFDB CL_EMALFZIP CL_EMAXFILES CL_EMAXREC CL_EMAXSIZE
	CL_EMEM CL_ENULLARG CL_EOPEN CL_EPATSHORT CL_ERAR CL_ETMPDIR
	CL_ETMPFILE CL_EZIP CL_MAIL CL_MIN_LENGTH CL_NUM_CHILDS CL_RAW CL_VIRUS)) {
  next if (eval "my \$a = $constname; 1");
  if ($@ =~ /^Your vendor has not defined Mail::ClamAV macro $constname/) {
    print "# pass: $@";
  } else {
    print "# fail: $@";
    $fail = 1;
  }

}

ok( $fail == 0 , 'Constants' );

my $c = new Mail::ClamAV(retdbdir());
$c->buildtrie;
my $f = "t/virus.eml";
ok($c->scan($f, CL_MAIL())->virus, 'Scan File');
open my $fh, "<", $f;
ok($c->scan($fh, CL_MAIL())->virus, 'Scan FileHandle');

