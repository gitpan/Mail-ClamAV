use 5.006;

use lib '.';
use Inline::MakeMaker; # bundled

my $inc = join " ", (`clamav-config --cflags` =~ /(-I\S+)/g);
if ($?) {
    config_warn();
    $inc = '-I/usr/include';
}
else {
    chomp $inc;
}
my $version = `clamav-config --version`;
chomp $version;
if ($version < 0.90) {
    die "The clamav version you are using is too old. Please upgrade to atleast 0.90\n";
}

my $libs = `clamav-config --libs`;
if ($?) {
    config_warn();
    $libs = q(-lz -lbz2 -lgmp -lpthread);
}
else {
    chomp $libs;
}
$libs .= " -lclamav";

open my $fh, ">", "config.pl" or die "Could not open config.pl: $!";
print $fh <<END;
use Inline C => Config =>
    VERSION  => \$Mail::ClamAV::VERSION,
    PREFIX   => 'clamav_perl_',
    NAME     => "Mail::ClamAV",
    INC      => "$inc",
    LIBS     => "$libs";
1;
END
close $fh;

sub MY::top_targets {
    package MY;
    my $out = shift->SUPER::top_targets(@_);
    my $link_code = q{# Remove Inline::C configuration code
	@$(PERL) -n -i -e '$$a=1 if/^\s*#\s*removed on install.*/;print if!$$a;$$a=0if/^\s*#\s*end[^\n]*/;' blib/lib/Mail/ClamAV.pm
};
    $out =~ s/\n\n/\n\nremove_on_install:\n$link_code\n/;
    $out =~ s/all :: pure_all/all :: pure_all remove_on_install/;
    return $out;
}

my $warned = 0;
sub config_warn {
    unless ($warned) {
        $warned++;
        warn "WARNING ------------------------------------------------\n";
        warn "WARNING You have an older version of clamav or\n";
        warn "WARNING clamav-config is not in your path\n";
        warn "WARNING If you get compile errors you will either\n";
        warn "WARNING need to upgrade clamav to atleast 0.73\n";
        warn "WARNING or make sure clamav-config is in your path\n";
        warn "WARNING ------------------------------------------------\n";
    }
}

# NOTE: most of these options are ignored by Inline::MakeMaker
WriteMakefile(
    NAME                => 'Mail::ClamAV',
    VERSION_FROM        => 'ClamAV.pm', # finds $VERSION
    PREREQ_PM           => {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM    => 'ClamAV.pm', # retrieve abstract from module
       AUTHOR           => 'Scott Beck <sbeck@gossamer-threads.com>') : ()),
    LIBS                => ['-lclamav'],
    DEFINE              => '', # e.g., '-DHAVE_SOMETHING'
    PM                  => { 'ClamAV.pm' => 'blib/lib/Mail/ClamAV.pm' },
        # Un-comment this if you add C files to link with later:
    # 'OBJECT'          => '$(O_FILES)', # link all the C files too
);

