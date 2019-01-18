use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME            => 'Net::AS2',
    VERSION_FROM    => 'lib/Net/AS2.pm',
    PREREQ_PM       => {},
    ABSTRACT_FROM   => 'lib/Net/AS2.pm',
    AUTHOR          => 'Andrew Maguire <ajm@cpan.org>',
    LICENSE         => 'perl_5',
    PREREQ_PM       => {
        'Carp'           => 0,
        'Crypt::SMIME'   => 0,
        'LWP::UserAgent' => 0,
        'HTTP::Message'  => 0,
        'Digest::SHA'    => 0,
        'MIME::Base64'   => 0,
        'MIME::Tools'    => 0,
    },
);
