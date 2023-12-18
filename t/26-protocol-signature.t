use Test::More tests => 5;

use utf8;
use strict;
use warnings;

use Encode;

use File::Basename qw(dirname);
use Cwd            qw(abs_path);

use_ok('Net::AS2');

my $cert_dir = abs_path(dirname(__FILE__) . '/certificates');

my %config_1 = (
    CertificateDirectory => $cert_dir,
    MyId => 'Mr 1', MyKeyFile => 'test.1.key', MyCertificateFile => 'test.1.cert',
    PartnerId => 'Mr 2', PartnerCertificateFile => 'test.2.cert',
    PartnerUrl => 'http://example.com/dummy/a_2/msg',
    UserAgentClass => 'Mock::LWP::UserAgent',
);

my %config_2 = (
    CertificateDirectory => $cert_dir,
    MyId => 'Mr 2', MyKeyFile => 'test.2.key', MyCertificateFile => 'test.2.cert',
    PartnerId => 'Mr 1', PartnerCertificateFile => 'test.1.cert',
    PartnerUrl => 'http://example.com/dummy/a_1/msg',
    UserAgentClass => 'Mock::LWP::UserAgent',
);

subtest 'Signature required check' => sub {
    my $a1 = Net::AS2->new(%config_1, Mdn => 'sync', Signature => 0);
    my $a2 = Net::AS2->new(%config_2);

    local $Mock::LWP::UserAgent::response_handler = sub {
        my $req = shift;
        my $msg = $a2->decode_message($req->headers, $req->content);
        ok($msg->is_error, 'Message received with error');
        is($msg->error_status_text, 'insufficient-message-security');
        like($msg->error_plain_text, qr/signature/i);

        my $r = HTTP::Response->new(200, 'OK', [], '');
        return $r;
    };
    $a1->send("Test", 'Type' => 'text/plain');
};

subtest 'Signature optional pass' => sub {
    my $a1 = Net::AS2->new(%config_1, Mdn => 'sync');
    my $a2 = Net::AS2->new(%config_2, Signature => 0);

    local $Mock::LWP::UserAgent::response_handler = sub {
        my $req = shift;
        my $msg = $a2->decode_message($req->headers, $req->content);
        ok($msg->is_success, 'Message received successfully');

        my $r = HTTP::Response->new(200, 'OK', [], '');
        return $r;
    };
    $a1->send("Test", 'Type' => 'text/plain');
};

subtest 'Signature failed' => sub {
    my $a1 = Net::AS2->new(%config_1, Encryption => 0);
    my $a2 = Net::AS2->new(%config_1, Encryption => 0,
        MyId => $config_2{MyId}, PartnerId => $config_2{PartnerId},
    );

    local $Mock::LWP::UserAgent::response_handler = sub {
        my $req = shift;
        my $msg = $a2->decode_message($req->headers, $req->content);
        ok($msg->is_error, 'Message received with error');
        is($msg->error_status_text, 'insufficient-message-security');
        like($msg->error_plain_text, qr/unable to verify/i);

        my $r = HTTP::Response->new(200, 'OK', [], '');
        return $r;
    };
    $a1->send("Test", 'Type' => 'text/plain');
};

subtest 'Signature expired' => sub {
    my $a1 = Net::AS2->new(%config_1, Encryption => 0,
        MyKeyFile => 'expired.1.key', MyCertificateFile => 'expired.1.cert',
    );
    my $a2 = Net::AS2->new(%config_2, Encryption => 0);

    local $Mock::LWP::UserAgent::response_handler = sub {
        my $req = shift;
        my $msg = $a2->decode_message($req->headers, $req->content);
        ok($msg->is_error, 'Message received with error');
        is($msg->error_status_text, 'insufficient-message-security');
        like($msg->error_plain_text, qr/unable to verify/i);

        my $r = HTTP::Response->new(200, 'OK', [], '');
        return $r;
    };
    $a1->send("Test", 'Type' => 'text/plain');
};


package Mock::LWP::UserAgent;

use parent 'LWP::UserAgent';

use HTTP::Response;

our $response_handler;
our $last_request;

sub request
{
    my $class = shift;
    $last_request = shift;
    return $response_handler->($last_request)
        if $response_handler;
    return HTTP::Response->new(200, 'OK', ['Context-Text' => 'text/html'], '');
}

1;
