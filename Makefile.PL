use 5.006;
use Inline::MakeMaker;

my $libs = $ENV{LIBS} || '-lclamav';
my $inc = $ENV{INC} || '-I/usr/include';
$libs .= ' -lclamav' unless $libs =~ /-lclamav/;

open my $fh, ">", "config.pl" or die "Could not open config.pl: $!";
print $fh <<END;
use Inline C => Config =>
    VERSION  => \$VERSION,
    PREFIX   => 'clamav_perl_',
    NAME     => "Mail::ClamAV",
    OPTIMIZE => '-g',
    INC      => "$inc",
    LIBS     => "$libs";
1;
END
close $fh;

sub MY::install {
    package MY;
    my $out = shift->SUPER::install(@_);
    my $link_code = q{
	$(PERL) -n -i -e '$$a=1 if/^\s*#\s*removed on install.*/;print if!$$a;$$a=0if/^\s*#\s*end[^\n]*/;' $(INSTALLSITEARCH)/Mail/ClamAV.pm
};
    $out =~ s/(\n\npure_site_install ::(?:.(?!\n\n))+.)/\1$link_code/s;
    $out;
}

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

