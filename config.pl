use Inline C => Config =>
    VERSION  => $VERSION,
    PREFIX   => 'clamav_perl_',
    NAME     => "Mail::ClamAV",
    OPTIMIZE => '-g',
    LIBS     => " -lclamav";
1;
