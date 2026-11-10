use v5.020;
use strict;
use warnings;
use Test::More;
use JSON::PP;
use VStats::TrafficClassifier;
my $C='VStats::TrafficClassifier';
my $J=JSON::PP->new->utf8->canonical;
my $url=$C->provider_registry->[0]{source_urls}[0];
sub snapshot {
    my ($time,$prefix)=@_;
    return {raw_json=>$J->encode({creationTime=>'fixture',prefixes=>[{ipv4Prefix=>$prefix//'192.0.2.0/24'}]}),
        attestation_json=>$J->encode({provider_id=>'google_common',source_url=>$url,retrieved_at=>$time})};
}
sub verifier {
    my (@s)=@_;
    return $C->evidence_verifier($J->encode({schema_version=>1,snapshots=>\@s}),format=>'jsonl');
}
sub event { return $J->encode({timestamp=>150,client=>'192.0.2.1',target=>'/',user_agent=>'Googlebot/2',@_}); }
my @bracket=(snapshot('1970-01-01T00:01:40Z'),snapshot('1970-01-01T00:03:20Z'));
my $verified=verifier(@bracket);
is_deeply($verified->classify_line(event()),{actor=>'verified_crawler',verification_outcome=>'verified'},'marker and covering matching ranges verify');
is(verifier()->classify_line(event())->{actor},'declared_crawler_or_tool','no evidence never upgrades a declaration');
is(verifier($bracket[0])->classify_line(event())->{actor},'declared_crawler_or_tool','one earlier snapshot cannot verify later traffic');
is(verifier($bracket[1])->classify_line(event())->{actor},'declared_crawler_or_tool','one current snapshot cannot verify older traffic');
is(verifier($bracket[0])->classify_line(event(timestamp=>100))->{actor},'verified_crawler','single exact-time snapshot retains established semantics');
for my $ua ('Mozilla/5.0',undef,'','XGooglebot/2','Googlebotling/2',"Googleb\x{17f}t/2",'Bytespider/1','curl/8') {
    isnt($verified->classify_line(event(user_agent=>$ua))->{actor},'verified_crawler','ownership or other markers alone cannot verify');
}
for my $client ('198.51.100.1','example.test','::ffff:192.0.2.1') {
    isnt($verified->classify_line(event(client=>$client))->{actor},'verified_crawler','wrong/nonliteral/mapped address not verified against IPv4');
}
for my $time (99,201) {isnt($verified->classify_line(event(timestamp=>$time))->{actor},'verified_crawler','outside evidence period not verified');}
my $changed=verifier($bracket[0],snapshot('1970-01-01T00:03:20Z','198.51.100.0/24'));
is($changed->classify_line(event())->{verification_outcome},'failed','both brackets must cover address');
my $stale=verifier($bracket[0],snapshot('1970-01-03T00:00:00Z'));
is($stale->classify_line(event())->{verification_outcome},'unavailable','gap limit enforced');
for my $bad ('garbage','{}','{"timestamp":150,"client":"192.0.2.1"}',"\xff",'x'x16385) {
    is($verified->classify_line($bad)->{actor},'unknown','unsupported input cannot become a verified exclusion');
}
is($verified->{counts}{lines_total},0,'streaming checks do not accumulate request state');
is(scalar @{$verified->{records}},0,'streaming checks retain no request records');
my $full=$C->new(config=>$C->config('{"schema_version":1}'),format=>'jsonl',snapshots=>[map {$C->snapshot($_->{raw_json},$_->{attestation_json})} @bracket],details=>1);
my @events=(event(),event(client=>'198.51.100.2'),event(user_agent=>'Mozilla/5.0'));
$full->feed($_."\n") for @events;
my $report=$full->finish;
is_deeply([map {$verified->classify_line($_)->{actor}} @events],[map {$_->{actor}} @{$report->{details}}],'native streaming and report labels agree');
for my $raw ('{}','{"schema_version":1,"snapshots":null}','{"schema_version":1,"snapshots":[],"extra":0}',
    '{"schema_version":1,"schema_version":1,"snapshots":[]}',
    $J->encode({schema_version=>1,snapshots=>[(@bracket)x17]}),
    $J->encode({schema_version=>1,snapshots=>[($bracket[0])x2]}),
    $J->encode({schema_version=>1,snapshots=>[{raw_json=>'{}',attestation_json=>'{}'}]})) {
    my $ok=eval {$C->evidence_verifier($raw);1};ok(!$ok,'invalid evidence bundle refused before use');
}
my $apache=$C->evidence_verifier($J->encode({schema_version=>1,snapshots=>\@bracket}),format=>'combined');
my $line='192.0.2.1 - - [01/Jan/1970:00:02:30 +0000] "GET / HTTP/1.1" 200 100 "-" "Googlebot/2"';
is($apache->classify_line($line."\r\n")->{actor},'verified_crawler','combined input uses timestamp and decoded marker');
done_testing;
