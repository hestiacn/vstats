use v5.020;
use strict;
use warnings;
use Test::More;
use JSON::PP;
use VStats::TrafficClassifier;
my $C='VStats::TrafficClassifier';my $J=JSON::PP->new->utf8->canonical;
sub config {return $C->config($J->encode({schema_version=>1,exclude=>['suspected_automation'],service_discovery=>{enabled=>1,@_}}));}
sub rows {return [map {+{timestamp=>100+$_,client=>'192.0.2.1',host=>'example.test',method=>'GET',status=>404,
    user_agent=>'SyntheticServiceClient/1',target=>(qw(/openapi.json /.well-known/mcp.json /llms.txt))[$_]}} 0..2];}
sub copy {return $J->decode($J->encode($_[0]));}
sub run {
    my ($rows,$config,$meta)=@_;my $engine=$C->new(config=>$config||config(),format=>'jsonl',details=>1,metadata=>$meta||{});
    $engine->feed(join('',map {$J->encode($_)."\n"} @$rows));return $engine->finish;
}
sub flags {return [map {$_->{service_discovery_flagged}?1:0} @{$_[0]{details}}];}
my $r=run(rows());is_deeply(flags($r),[1,1,1],'three independent missing families qualify');
is($r->{behavior}{service_discovery_flagged_requests},3,'independent match count');
ok(!grep({$_->{ip_expansion_eligible}} @{$r->{details}}),'service discovery never seeds IP/month expansion');
is($r->{adjusted_requests}{excluded},3,'selected probes removed');
for my $case (
 ['schema aliases are one family',sub {$_[0][0]{target}='/api/v1/swagger.json';$_[0][1]{target}='/openapi.yaml';$_[0][2]{target}='/swagger.json'}],
 ['ordinary metadata is insufficient',sub {$_[0][$_]{target}=(qw(/robots.txt /sitemap.xml /security.txt))[$_] for 0..2}],
 ['successful catch-all responses abstain',sub {$_->{status}=200 for @{$_[0]}}],
 ['redirect responses abstain',sub {$_[0][2]{status}=301}],
 ['different clients cannot corroborate',sub {$_[0][2]{client}='192.0.2.2'}],
 ['different hosts cannot corroborate',sub {$_[0][2]{host}='other.test'}],
 ['shared egress differing agents cannot corroborate',sub {$_[0][2]{user_agent}='OtherClient/1'}],
 ['unobserved host abstains',sub {delete $_->{host} for @{$_[0]}}],
 ['unobserved agent abstains',sub {delete $_->{user_agent} for @{$_[0]}}],
 ['unobserved status abstains',sub {delete $_->{status} for @{$_[0]}}],
 ['unobserved method abstains',sub {delete $_->{method} for @{$_[0]}}],
 ['outside window abstains',sub {$_[0][2]{timestamp}=161}],
 ['encoded separator is unsupported',sub {$_[0][2]{target}='/%2fllms.txt'}]
) {my $x=rows();$case->[1]->($x);is_deeply(flags(run($x)),[0,0,0],$case->[0]);}
my $edge=rows();$edge->[2]{timestamp}=160;is_deeply(flags(run($edge)),[1,1,1],'inclusive sixty-second boundary');
my $scope=rows();unshift @$scope,{%{$scope->[0]},timestamp=>20,target=>'/'};
splice @$scope,2,0,{%{$scope->[1]},timestamp=>101,target=>'/',status=>200};
push @$scope,{%{$scope->[0]},timestamp=>200};
is_deeply(flags(run($scope)),[0,1,0,1,1,0],'in-window entry and other visits never inherit probes');
my $redirect=rows();unshift @$redirect,{%{$redirect->[0]},timestamp=>99,status=>301};
is_deeply(flags(run($redirect)),[0,1,1,1],'redirect is not a second family witness');
my $mapped=rows();$mapped->[1]{client}='::ffff:192.0.2.1';is_deeply(flags(run($mapped)),[1,1,1],'strict canonical mapped address for new rule');
my $query=rows();$query->[0]{target}='/api/v2/openapi.json?token=PRIVATE_SENTINEL';
is_deeply(flags(run($query)),[1,1,1],'bounded decoded aliases ignore queries');
is_deeply(flags(run(rows(),config(enabled=>0))),[0,0,0],'checkbox disables rule');
for my $bad ({distinct_families=>2},{distinct_families=>5},{window_seconds=>0},{registry=>'arbitrary'}) {
    ok(!eval {config(%$bad);1},'unsupported registry or threshold rejected');
}
my $include=config();my $id=Digest::SHA::sha256_hex($J->encode(rows()->[0]));$include->{behavior_include}=[$id];
is(run(rows(),$include)->{adjusted_requests}{excluded},2,'request inclusion retains only selected probe');
my @legacy=map {+{timestamp=>100+$_,client=>'192.0.2.1',method=>$_==3?'POST':'GET',status=>$_?404:301,
    target=>(qw(/ /wp-content/themes/seotheme/db.php /wp-plain.php /wp-content/plugins/fix/up.php))[$_],
    user_agent=>$_?'SyntheticClient/1':undef}} 0..3;
my $legacy_cfg=$C->config($J->encode({schema_version=>1,backdoor_probe=>{enabled=>1}}));
my %metadata=map {Digest::SHA::sha256_hex($J->encode($legacy[$_]))=>{format=>$_?'combined':'common',
    vhost=>$_?'example.test':undef,scheme=>$_?'https':'http',client_source=>'socket_peer',
    user_agent=>$_?'value':'unobserved',referrer=>'unobserved'}} 0..3;
my $old=run(\@legacy,$legacy_cfg);my $provenance=run(\@legacy,$legacy_cfg,\%metadata);
is_deeply([map {$_->{backdoor_probe_flagged}} @{$provenance->{details}}],
    [map {$_->{backdoor_probe_flagged}} @{$old->{details}}],'vhost provenance never re-keys an existing detector');
ok(!grep({defined($_->{host})} @{$provenance->{details}}),'configured vhost never fabricates an observed Host field');
# A brute-force oracle enumerates all intervals, independently of sliding counters.
srand(7042);
for my $trial (1..35) {
    my @events=map {+{timestamp=>100+int(rand(100)),client=>'192.0.2.1',host=>'example.test',method=>'GET',status=>404,
        user_agent=>'SyntheticClient/1',target=>(qw(/openapi.json /swagger.json /.well-known/mcp.json /llms.txt /ordinary))[int(rand(5))]}} 0..14;
    my @expected=(0)x@events;
    my %family=('/openapi.json'=>1,'/swagger.json'=>1,'/.well-known/mcp.json'=>2,'/llms.txt'=>3);
    for my $a (@events) {for my $b (@events) {next if $a->{timestamp}>$b->{timestamp} || $b->{timestamp}-$a->{timestamp}>60;
        my @inside=grep {$family{$events[$_]{target}} && $events[$_]{timestamp}>=$a->{timestamp} && $events[$_]{timestamp}<=$b->{timestamp}} 0..$#events;
        my %f=map {$family{$events[$_]{target}}=>1} @inside;
        $expected[$_]=1 for keys(%f)>=3?@inside:();
    }}
    is_deeply(flags(run(\@events)),\@expected,'exhaustive interval oracle '.$trial);
}
done_testing;
