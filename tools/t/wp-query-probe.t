use v5.020;
use strict;
use warnings;
use Test::More;
use JSON::PP;
use VStats::TrafficClassifier;
my $C='VStats::TrafficClassifier';my $J=JSON::PP->new->utf8->canonical;
sub cfg {return $C->config($J->encode({schema_version=>1,wp_query_probe=>{enabled=>1,@_}}));}
sub rows {return [
    {timestamp=>100,client=>'192.0.2.1',host=>'example.test',method=>'GET',status=>404,target=>'/wp-content/plugins/example-plugin/readme.txt'},
    {timestamp=>101,client=>'192.0.2.1',host=>'example.test',method=>'GET',status=>200,target=>'/?wp_query=SECRET_SENTINEL'},
    {timestamp=>102,client=>'192.0.2.1',host=>'example.test',method=>'GET',status=>200,target=>'/ordinary'}];}
sub run {
    my ($rows,$cfg,$before,$after)=@_;my $e=$C->new(config=>$cfg//cfg(),format=>'jsonl',details=>1);
    $e->feed(join('',map {$J->encode($_)."\n"} @$rows));
    $e->add_context('before',join('',map {$J->encode($_)."\n"} @$before)) if $before;
    $e->add_context('after',join('',map {$J->encode($_)."\n"} @$after)) if $after;
    return $e->finish;
}
sub clone {return $J->decode($J->encode($_[0]));}
my $positive=run(rows());
is($positive->{behavior}{wp_query_probe_flagged_requests},2,'internal query and plugin enumeration corroborate');
is_deeply([map {$_->{wp_query_probe_flagged}?1:0} @{$positive->{details}}],[1,1,0],'only witnessed requests flagged');
ok(!grep({$_->{ip_expansion_eligible}} @{$positive->{details}}),'query witness never supplies IP/month expansion');
is($positive->{actors}{unknown},3,'behavior does not authenticate identity');
my $p=$positive->{details}[0]{wp_query_probe_evidence};
is_deeply([@{$p}{qw(requests query_requests plugin_requests)}],[2,1,1],'bounded numeric witness');
unlike($J->encode($p),qr/SECRET|wp_query|example-plugin/,'proof omits query keys, values and plugin name');
is(run(rows(),cfg(enabled=>0))->{behavior}{flagged_requests},0,'disabled rule retains traffic');
is(run(rows(),$C->config('{"schema_version":1}'))->{behavior}{flagged_requests},0,'CLI remains opt-in');
for my $case (
    ['different IPs',sub {$_[0][1]{client}='192.0.2.2'}],
    ['different hosts',sub {$_[0][1]{host}='other.test'}],
    ['outside window',sub {$_[0][1]{timestamp}=161}],
    ['readme by itself',sub {$_[0][1]{target}='/ordinary'}],
    ['query by itself',sub {$_[0][0]{target}='/ordinary'}],
    ['ordinary query name',sub {$_[0][1]{target}='/?q=wp_query'}],
    ['duplicate relevant key',sub {$_[0][1]{target}='/?wp_query=a&wp_query=b'}],
    ['double encoding',sub {$_[0][1]{target}='/?%2577p_query=a'}],
    ['missing value',sub {$_[0][1]{target}='/?wp_query'}],
    ['empty value',sub {$_[0][1]{target}='/?wp_query='}],
    ['different query endpoint',sub {$_[0][1]{target}='/docs?wp_query=a'}],
    ['static plugin asset',sub {$_[0][0]{target}='/wp-content/plugins/example-plugin/style.css'}],
    ['plugin substring collision',sub {$_[0][0]{target}='/docs/wp-content/plugins/example-plugin/readme.txt'}],
    ['missing status',sub {delete $_->{status} for @{$_[0]}}],
    ['robots fetch and homepage',sub {$_[0][0]{target}='/robots.txt';$_[0][1]{target}='/'}]
) {
    my $r=rows();$case->[1]->($r);is(run($r)->{behavior}{flagged_requests},0,$case->[0].' abstains');
}
my $encoded=rows();$encoded->[1]{target}='/?%77p_query=SECRET_SENTINEL';
is(run($encoded)->{behavior}{flagged_requests},2,'single-decode public query key recognized');
my $boundary=rows();$boundary->[1]{timestamp}=160;
is(run($boundary)->{behavior}{flagged_requests},2,'inclusive time boundary');
my $daily=rows();$daily->[0]{timestamp}=86399;$daily->[1]{timestamp}=86400;$daily->[2]{timestamp}=86401;
is(run([@$daily[1,2]],cfg(),[$daily->[0]])->{behavior}{flagged_requests},1,'prior-day witness does not inflate primary count');
is(run([$daily->[0]],cfg(),undef,[@$daily[1,2]])->{behavior}{flagged_requests},1,'after-day witness covers primary record');
my $selected=cfg();$selected->{exclude}=['suspected_automation'];$selected->{behavior_include}=[$positive->{details}[0]{request_id}];
is(run(rows(),$selected)->{adjusted_requests}{excluded},1,'request-ID inclusion still overrides');
for my $change (['window_seconds',3601],['query_keys',[]],['query_keys',['wp_query','wp_query']],
    ['query_keys',['wp_query[x]']],['query_paths',['/?x=y']],['plugin_prefixes',['/wp-content/plugins']]) {
    ok(!eval {cfg(@$change);1},'invalid query rule setting refused: '.$change->[0]);
}
for my $ua ('cve-2026-12345-poc','CVE-2027-1234567-PoC/1.0','Mozilla/5.0 (Android) cve-2026-12345-poc') {
    ok(VStats::TrafficClassifier::poc_marker_matches($ua),'bounded explicit PoC declaration');
}
for my $ua ('cve-2026-12345-pocBrowser','xcve-2026-12345-poc','cve-26-12345-poc','cve-2026-12345678-poc') {
    ok(!VStats::TrafficClassifier::poc_marker_matches($ua),'PoC marker collision refused');
}
done_testing;
