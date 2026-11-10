use v5.020;
use strict;
use warnings;
use Test::More;
use JSON::PP;
use Digest::SHA qw(sha256_hex);
use VStats::TrafficClassifier;
my $J=JSON::PP->new->utf8->canonical;my $C='VStats::TrafficClassifier';
sub rr {my($owner,$type,$data,$ttl)=@_;return {owner=>$owner,type=>$type,data=>$data,ttl=>$ttl//10};}
sub query {my($name,$type,@answers)=@_;return {qname=>$name,qtype=>$type,status=>'NOERROR',truncated=>0,answers=>\@answers};}
sub bundle {return {schema_version=>1,provider_id=>'internet_census',source_url=>'https://www.internet-census.org/home.html',
 source_document_fetched_at=>90,resolver=>{address=>'192.0.2.53',nonrewriting=>1},selection=>'Synthetic fixture only',
 observations=>[{client=>'192.0.2.1',completed_at=>100,queries=>[
 query('1.2.0.192.in-addr.arpa','PTR',rr('1.2.0.192.in-addr.arpa','PTR','unit.internet-census.org')),
 query('unit.internet-census.org','A',rr('unit.internet-census.org','A','192.0.2.1'))]}]};}
sub copy {return $J->decode($J->encode($_[0]));}
sub run {
 my($bundle,$time,$client,$options)=@_;$options||={};
 my $row={timestamp=>$time//101,client=>$client//'192.0.2.1',host=>'example.test',method=>'GET',status=>200,target=>'/',user_agent=>'Mozilla/5.0'};
 my $raw=$J->encode($row);my $meta={sha256_hex($raw)=>{format=>'combined',vhost=>'example.test',scheme=>'https',
   client_source=>$options->{untrusted}?'unknown':'socket_peer',user_agent=>'value',referrer=>'absent'}};
 my $cfg=$C->config($J->encode({schema_version=>1,exclude=>['suspected_automation'],operator_association=>{
   enabled=>1,retrospective_enabled=>$options->{retrospective}//0,retrospective_months=>$options->{months}||[]}}));
 my $engine=$C->new(config=>$cfg,format=>'jsonl',details=>1,metadata=>$meta,operator_evidence=>VStats::OperatorEvidence->new($J->encode($bundle)));
 $engine->feed($raw."\n");return $engine->finish;
}
my $r=run(bundle());is($r->{adjusted_requests}{excluded},1,'dated association enables exact request exclusion');
is($r->{details}[0]{actor},'unknown','operator evidence does not become authenticated actor identity');
ok(!$r->{details}[0]{ip_expansion_eligible},'association never seeds IP-month policy');
is($r->{details}[0]{operator_association}{state},'dated_association','dated evidence class explicit');
for my $case (
 ['spoofed forward address',sub {$_[0]{observations}[0]{queries}[1]{answers}[0]{data}='192.0.2.2'}],
 ['suffix collision',sub {$_[0]{observations}[0]{queries}[0]{answers}[0]{data}='unit.internet-census.org.attacker.test'}],
 ['lookalike suffix',sub {$_[0]{observations}[0]{queries}[0]{answers}[0]{data}='unit.notinternet-census.org'}],
 ['generic hosting PTR',sub {$_[0]{observations}[0]{queries}[0]{answers}[0]{data}='unit.cloud.example'}],
 ['off-chain forward RR',sub {$_[0]{observations}[0]{queries}[1]{answers}[0]{owner}='unrelated.internet-census.org'}],
 ['partial DNS chain',sub {$_[0]{observations}[0]{queries}[1]{truncated}=1}],
 ['failed DNS query',sub {$_[0]{observations}[0]{queries}[1]{status}='SERVFAIL'}],
 ['rewriting resolver',sub {$_[0]{resolver}{nonrewriting}=0}],
 ['legacy IPv4 source',sub {$_[0]{observations}[0]{client}='192.000.002.001'}],
 ['scoped source',sub {$_[0]{observations}[0]{client}='fe80::1%eth0'}],
 ['zero TTL',sub {$_[0]{observations}[0]{queries}[0]{answers}[0]{ttl}=0}],
 ['CNAME loop',sub {$_[0]{observations}[0]{queries}[1]{answers}=[rr('unit.internet-census.org','CNAME','loop.test'),rr('loop.test','CNAME','unit.internet-census.org')]}]
) {my $b=bundle();$case->[1]->($b);my $x=run($b);is($x->{adjusted_requests}{excluded},0,$case->[0]);ok(!$x->{details}[0]{operator_association},'unknown supplies no operator association');}
my $multi=bundle();unshift @{$multi->{observations}[0]{queries}[0]{answers}},rr('1.2.0.192.in-addr.arpa','PTR','unrelated.example');
is(run($multi)->{adjusted_requests}{excluded},1,'multiple PTRs evaluated independently');
my $alias=bundle();$alias->{observations}[0]{queries}[1]{answers}=[rr('unit.internet-census.org','CNAME','edge.provider.test',7),rr('edge.provider.test','A','192.0.2.1',20)];
is(run($alias,106)->{adjusted_requests}{excluded},1,'validated CNAME chain');
is(run($alias,107)->{adjusted_requests}{excluded},0,'smallest TTL caps reuse; expiry is exclusive');
my $long=bundle();$long->{observations}[0]{queries}[1]{answers}=[rr('unit.internet-census.org','CNAME','hop0.test'),(map {rr('hop'.$_ .'.test','CNAME','hop'.($_+1).'.test')} 0..8),rr('hop9.test','A','192.0.2.1')];
is(run($long)->{adjusted_requests}{excluded},0,'over-length CNAME chain abstains');
is(run(bundle(),100)->{adjusted_requests}{excluded},0,'tie at lookup timestamp is not dated evidence');
is(run(bundle(),99)->{details}[0]{operator_association}{state},'historical_candidate','earlier request is only retrospective candidate');
is(run(bundle(),110)->{adjusted_requests}{excluded},0,'expiry boundary abstains');
is(run(bundle(),111)->{adjusted_requests}{excluded},0,'expired observation abstains');
my $overlay=run(bundle(),99,undef,{retrospective=>1,months=>['1970-01']});
is($overlay->{adjusted_requests}{excluded},0,'historical overlay never alters default exclusion');
ok($overlay->{details}[0]{operator_inferred_excluded},'explicit selected-month inference is marked for separate overlay');
is(run(bundle(),99,undef,{retrospective=>1,months=>['1970-02']})->{adjusted_requests}{excluded},0,'other month never inherits inference');
is(run(bundle(),99,'192.0.2.2',{retrospective=>1,months=>['1970-01']})->{adjusted_requests}{excluded},0,'no CIDR or neighboring-address expansion');
is(run(bundle(),101,'::ffff:192.0.2.1')->{adjusted_requests}{excluded},1,'mapped IPv6 canonicalized for operator evidence only');
is(run(bundle(),101,undef,{untrusted=>1})->{adjusted_requests}{excluded},0,'unverified client-address provenance abstains');
my $later=bundle();my $ob=copy($later->{observations}[0]);$ob->{completed_at}=200;push @{$later->{observations}},$ob;
is(run($later,99)->{details}[0]{operator_association}{state},'historical_candidate','later lookup cannot backdate earlier identity');
my $failure=bundle();my $failed=copy($failure->{observations}[0]);$failed->{completed_at}=103;$failed->{queries}[0]{status}='SERVFAIL';push @{$failure->{observations}},$failed;
is(run($failure,104)->{adjusted_requests}{excluded},0,'new failed lookup invalidates cached reuse');
is(run(bundle(),99)->{details}[0]{operator_inference_candidate}{state},'inference_candidate',
    'pre-check request can expose a snapshot candidate without strict exclusion');
is(run(bundle(),111)->{details}[0]{operator_inference_candidate}{lookup_at},100,
    'expired DNS is retained only as an inference snapshot, not current validity');
is(run($later,99)->{details}[0]{operator_inference_candidate}{lookup_at},200,
    'inference uses the newest observation rather than historical ownership');
ok(!run($failure,99)->{details}[0]{operator_inference_candidate},
    'a later failed observation vetoes inference even for an earlier request');
my $tie=copy($later);my $bad_tie=copy($tie->{observations}[-1]);$bad_tie->{queries}[0]{status}='SERVFAIL';push @{$tie->{observations}},$bad_tie;
ok(!run($tie,99)->{details}[0]{operator_inference_candidate},'conflicting observations at the latest timestamp abstain');
ok(!run(bundle(),99,undef,{untrusted=>1})->{details}[0]{operator_inference_candidate},'inference requires trustworthy client provenance');
done_testing;
