use Inline C => Config =>
    VERSION  => $Mail::ClamAV::VERSION,
    PREFIX   => 'clamav_perl_',
    NAME     => "Mail::ClamAV",
    INC      => "-I/usr/include",
    LIBS     => "-L/usr/lib -lz -lbz2 -lgmp -lpthread";
1;
