use Inline C => Config =>
    VERSION  => $VERSION,
    PREFIX   => 'clamav_perl_',
    NAME     => "Mail::ClamAV",
    OPTIMIZE => '-g',
    INC      => "-I/usr/include",
    LIBS     => "-lclamav";
1;
