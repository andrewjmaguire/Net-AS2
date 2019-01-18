use Test::More tests => 5;

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


subtest 'Missing headers' => sub {
    my $a1 = Mock::Net::AS2->new(%config_1);

    my $msg = $a1->decode_message({}, '');
    ok($msg->is_error, 'Message received with error');
    is($msg->error_status_text, 'unexpected-processing-error');
    ok($msg->error_plain_text =~ /headers/i);
};

subtest 'Mismatch AS2 Id' => sub {
    my $a1 = Mock::Net::AS2->new(%config_1,);
    my $a2 = Mock::Net::AS2->new(%config_2, MyId => '_x', PartnerId => '_y');

    local $Mock::LWP::UserAgent::response_handler = sub {
        my $req = shift;
        my $msg = $a2->decode_message(extract_headers($req), $req->content);
        ok($msg->is_error, 'Message received with error');
        is($msg->error_status_text, 'authentication-failed');
        ok($msg->error_plain_text =~ /AS2-/i);

        my $r = HTTP::Response->new(200, 'OK', [], '');
        return $r;
    };
    $a1->send("Test", 'Type' => 'text/plain');
};

subtest 'Async MDN' => sub {
    my $a1 = Mock::Net::AS2->new(%config_1);
    my $a2 = Mock::Net::AS2->new(%config_2);

    my $msg = Net::AS2::Message->new("orig-id", "http://example.com/async_url", 1, "mic", "data", 'sha1');

    local $Mock::LWP::UserAgent::response_handler = sub {
        my $req = shift;
        my $mdn = $a1->decode_mdn(extract_headers($req), $req->content);
        ok($mdn->match_mic('mic', 'sha1'));
        ok($mdn->is_success, 'Message received with error');
        is($mdn->original_message_id, 'orig-id');

        my $r = HTTP::Response->new(200, 'OK', [], '');
        return $r;
    };
    $a2->send_async_mdn(Net::AS2::MDN->create_success($msg), "MDN ID");
};

subtest 'Async MDN Unparsable' => sub {
    my $a1 = Mock::Net::AS2->new(%config_1);

    my $mdn = $a1->decode_mdn({}, '');
    ok($mdn->is_unparsable, 'Message received with error');
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
