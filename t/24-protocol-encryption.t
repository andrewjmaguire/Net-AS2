use Test::More tests => 4;

use utf8;
use strict;
use warnings;

use Encode;
use HTTP::Response;
use_ok('Net::AS2');

my %config_1 = (
    MyId => 'Mr 1', MyKey => key(1), MyCertificate => cert(1),
    PartnerId => 'Mr 2', PartnerCertificate => cert(2),
    PartnerUrl => 'http://example.com/dummy/a_2/msg');

my %config_2 = (
    MyId => 'Mr 2', MyKey => key(2), MyCertificate => cert(2),
    PartnerId => 'Mr 1', PartnerCertificate => cert(1),
    PartnerUrl => 'http://example.com/dummy/a_1/msg');


subtest 'Encryption required check' => sub {
    my $a1 = Mock::Net::AS2->new(%config_1, Mdn => 'sync', Encryption => 0);
    my $a2 = Mock::Net::AS2->new(%config_2);

    local $Mock::LWP::UserAgent::response_handler = sub {
        my $req = shift;
        my $msg = $a2->decode_message(extract_headers($req), $req->content);
        ok($msg->is_error, 'Message received with error');
        is($msg->error_status_text, 'insufficient-message-security');
        ok($msg->error_plain_text =~ /encryption/i);

        my $r = HTTP::Response->new(200, 'OK', [], '');
        return $r;
    };
    $a1->send("Test", 'Type' => 'text/plain');
};

subtest 'Encryption optional pass' => sub {
    my $a1 = Mock::Net::AS2->new(%config_1, Mdn => 'sync');
    my $a2 = Mock::Net::AS2->new(%config_2, Encryption => 0);

    local $Mock::LWP::UserAgent::response_handler = sub {
        my $req = shift;
        my $msg = $a2->decode_message(extract_headers($req), $req->content);
        ok($msg->is_success, 'Message received successfully');

        my $r = HTTP::Response->new(200, 'OK', [], '');
        return $r;
    };
    $a1->send("Test", 'Type' => 'text/plain');
};

subtest 'Encryption failed' => sub {
    my $a1 = Mock::Net::AS2->new(%config_1);
    my $a2 = Mock::Net::AS2->new(%config_1,
        MyId => $config_2{MyId}, PartnerId => $config_2{PartnerId},
        Signature => 0
        );

    local $Mock::LWP::UserAgent::response_handler = sub {
        my $req = shift;
        my $msg = $a2->decode_message(extract_headers($req), $req->content);
        ok($msg->is_error, 'Message received with error');
        is($msg->error_status_text, 'decryption-failed');
        ok($msg->error_plain_text =~ /decrypt/i);

        my $r = HTTP::Response->new(200, 'OK', [], '');
        return $r;
    };
    $a1->send("Test", 'Type' => 'text/plain');
};


sub key {
    my $i = shift;

    local $/;
    open my $fh, '<', "t/test.$i.key";
    return <$fh>;
}

sub cert {
    my $i = shift;

    local $/;
    open my $fh, '<', "t/test.$i.cert";
    return <$fh>;
}

sub extract_headers
{
    my $req = shift;
    return
    {
        map {
            my $key = uc($_);
            $key =~ s/-/_/g;
            $key = 'HTTP_' . $key
                unless $key eq 'CONTENT_TYPE';

            ( $key => $req->header($_) )
        } ($req->header_field_names)
    };
}

package Mock::Net::AS2;
use base 'Net::AS2';

sub create_useragent
{
    return new Mock::LWP::UserAgent;
}

package Mock::LWP::UserAgent;
use base 'LWP::UserAgent';

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
