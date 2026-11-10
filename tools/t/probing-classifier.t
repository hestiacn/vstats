use v5.020;
use strict;
use warnings;
use Test::More;
use JSON::PP;
use Digest::SHA qw(sha256_hex);
use VStats::TrafficClassifier;

my $C='VStats::TrafficClassifier'; my $J=JSON::PP->new->utf8->canonical;
my @ua=('Mozilla/5.0 (Windows NT 10.0) Chrome/126.0',
        'Mozilla/5.0 (Windows NT 10.0) Chrome/125.0',
        'Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0');
my %platform=($ua[0]=>'windows',$ua[1]=>'windows',$ua[2]=>'linux');
my %rule=(enabled=>1,window_seconds=>10,min_requests=>6,
          distinct_user_agents=>3,distinct_platforms=>2,paths=>['/account/sign-in','/api/users']);
sub cfg {return $C->config($J->encode({schema_version=>1,probing=>{%rule,@_}}));}
sub rows {return [map {+{timestamp=>100+$_,client=>'192.0.2.1',host=>'example.test',
    target=>'/account/sign-in',user_agent=>$ua[$_%3],status=>200}} 0..5];}
sub clone {return $J->decode($J->encode($_[0]));}
sub run {
    my ($events,$config,$format)=@_; $config//=cfg(); $format//='jsonl';
    my $raw=ref($events) eq 'ARRAY' ? join('',map {$J->encode($_)."\n"} @$events):$events;
    my $engine=$C->new(config=>$config,format=>$format,details=>1);
    while(length $raw){$engine->feed(substr($raw,0,11,''));}
    return ($engine->finish,$engine);
}
sub report {my ($r)=run(@_);return $r;}
sub flags {return [map {$_->{probing_flagged}?1:0} @{$_[0]{details}}];}
sub reject {my ($name,$code)=@_;ok(!eval {$code->();1},$name);}

my $positive=report(rows());
is($positive->{behavior}{probing_flagged_requests},6,'existing endpoint and all-200 responses can qualify');
is($positive->{behavior}{broad_flagged_requests},0,'broad rule remains independently disabled');
is($positive->{behavior}{flagged_requests},6,'probing contributes to behavioral union');
is($positive->{behavior}{eligible_requests},6,'eligible union counts each record once');
is($positive->{behavior}{merged_sequences},1,'one probing sequence');
is_deeply($positive->{actors},{unknown=>6,declared_crawler_or_tool=>0,verified_crawler=>0},'probing supplies no actor identity');
ok(!exists $positive->{adjusted_requests},'label alone supplies no exclusion');
for my $r (@{$positive->{details}}) {
    ok($r->{suspected_automation} && !$r->{broad_probing_flagged},'probing-only label is explicit');
    my $p=$r->{probing_evidence};ok($p->{from}<=$r->{timestamp} && $r->{timestamp}<=$p->{until},'witness covers participating request');
    is($p->{not_found_requests},0,'404 count is observed, not required or invented');
    ok(!$r->{behavior_evidence},'no fabricated broad-path witness');
}
is(report(rows(),$C->config('{"schema_version":1}'))->{behavior}{flagged_requests},0,'opt-in default preserves labels');
is(report(rows(),cfg(enabled=>0))->{behavior}{flagged_requests},0,'explicit disable');
is_deeply(report(rows(),cfg(enabled=>0))->{actors},$positive->{actors},'disable leaves identities unchanged');
for my $case (
    ['slow endpoint requests',sub {$_[0][$_]{timestamp}=100+$_*11 for 0..5}],
    ['one agent',sub {$_->{user_agent}=$ua[0] for @{$_[0]}}],
    ['one platform',sub {$_[0][$_]{user_agent}='Mozilla/5.0 (Windows) Chrome/'.(120+$_) for 0..5}],
    ['different clients',sub {$_[0][$_]{client}='192.0.2.'.($_+1) for 0..5}],
    ['different hosts',sub {$_[0][$_]{host}=$_<3?'a.test':'b.test' for 0..5}],
    ['ordinary paths',sub {$_->{target}='/ordinary' for @{$_[0]}}],
    ['unconfigured descendant',sub {$_->{target}='/api/users/123' for @{$_[0]}}],
    ['different case',sub {$_->{target}='/Account/sign-in' for @{$_[0]}}],
    ['trailing slash',sub {$_->{target}='/account/sign-in/' for @{$_[0]}}]
) {
    my $r=rows();$case->[1]->($r);is(report($r)->{behavior}{flagged_requests},0,$case->[0].' cannot supply the joint pattern');
}
my $short=rows();pop @$short;is(report($short)->{behavior}{flagged_requests},0,'below volume boundary');
my $edge=rows();$edge->[-1]{timestamp}=110;
is(report($edge)->{behavior}{flagged_requests},6,'window boundary inclusive');
$edge->[-1]{timestamp}=111;is(report($edge)->{behavior}{flagged_requests},0,'outside time boundary');
my $query=rows();$_->{target}='/account/%73ign-in?token=PRIVATE_SENTINEL' for @$query;
is(report($query)->{behavior}{flagged_requests},6,'supported normalization and query removal precede exact matching');
my $scope=rows();splice @$scope,3,0,{%{$scope->[0]},timestamp=>102,target=>'/style.css'};
unshift @$scope,{%{$scope->[0]},timestamp=>20};push @$scope,{%{$scope->[-1]},timestamp=>200};
is_deeply(flags(report($scope)),[0,1,1,1,0,1,1,1,0],'same-source asset and distant probes are not attributed');
is_deeply(flags(report([reverse @{rows()}])),[(1)x6],'out-of-order records retain request attribution');
my $two=rows();push @$two,map {+{%$_,timestamp=>$_->{timestamp}+100}} @{rows()};
is(report($two)->{behavior}{merged_sequences},2,'separate probing windows stay separate');
my $v6=rows();$v6->[$_]{client}=$_%2?'2001:db8::1':'2001:0DB8:0:0:0:0:0:1' for 0..5;
is(report($v6)->{behavior}{flagged_requests},6,'IPv6 spelling aliases share literal source');
my $mapped=rows();$mapped->[$_]{client}=$_<3?'192.0.2.1':'::ffff:192.0.2.1' for 0..5;
is(report($mapped)->{behavior}{flagged_requests},0,'mapped IPv6 and IPv4 remain distinct');
for my $case (
    ['missing status',sub {delete $_->{status} for @{$_[0]}}],
    ['missing agent',sub {delete $_->{user_agent} for @{$_[0]}}],
    ['unrecognized browser',sub {$_->{user_agent}='LocalFetch/1' for @{$_[0]}}],
    ['hostname client',sub {$_->{client}='client.example' for @{$_[0]}}],
    ['unsupported target',sub {$_->{target}='/account%2fsign-in' for @{$_[0]}}]
) {
    my $r=rows();$case->[1]->($r);my $p=report($r);
    is($p->{behavior}{flagged_requests},0,$case->[0].' supplies no probing evidence');
    is($p->{behavior}{insufficient_fields},6,$case->[0].' disclosed once');
}
my $apache='';for my $i(0..5){$apache.=sprintf('192.0.2.1 - - [01/Nov/2026:10:00:%02d +0000] "POST /account/sign-in?token=PRIVATE_SENTINEL HTTP/1.1" 200 100 "-" "%s"',$i,$ua[$i%3])."\n";}
is(report($apache,cfg(),'combined')->{behavior}{flagged_requests},6,'combined POST requests retain their exact target and status');
(my $common=$apache)=~s/ "-" "[^"\n]*"\n/\n/g;
is(report($common,cfg(),'common')->{behavior}{insufficient_fields},6,'common logs cannot invent browser claims');

my $overlap=rows();for my $i(0..5){$overlap->[$i]{target}=$i%2?'/api/users':'/account/sign-in';$overlap->[$i]{status}=$i<3?404:200;}
my $both=$C->config($J->encode({schema_version=>1,probing=>\%rule,exclude=>['suspected_automation'],
    behavior=>{enabled=>1,window_seconds=>10,min_requests=>6,distinct_user_agents=>3,distinct_platforms=>2,distinct_paths=>2,not_found_requests=>3}}));
my ($joint,$engine)=run($overlap,$both);
is_deeply([@{$joint->{behavior}}{qw(broad_flagged_requests probing_flagged_requests overlap_requests flagged_requests)}],[6,6,6,6],'overlap counts once in the union');
is($joint->{behavior}{eligible_requests},6,'overlapping eligibility counts once');
is($joint->{behavior}{flagged_source_groups},1,'overlapping source groups count once');
is($joint->{adjusted_requests}{excluded},6,'overlapping exclusion counts once');
ok(!grep({!$_->{behavior_evidence} || !$_->{probing_evidence}} @{$joint->{details}}),'overlap retains both independent witnesses');
is_deeply($engine->excluded_line_indices,[1..6],'selection contains each physical line once');
my $include=clone($both);$include->{behavior_include}=[sha256_hex($J->encode($overlap->[0]))];
my $kept=report($overlap,$include);is($kept->{adjusted_requests}{excluded},5,'one inclusion overrides both behavioral rules');
ok($kept->{details}[0]{behavior_included} && $kept->{details}[0]{behavior_evidence} && $kept->{details}[0]{probing_evidence},'included overlap retains both witnesses');
my $only=cfg();$only->{exclude}=['suspected_automation'];$only->{behavior_include}=[sha256_hex($J->encode(rows()->[0]))];
is(report(rows(),$only)->{adjusted_requests}{excluded},5,'probing-only override works');
my $actor=cfg();$actor->{exclude}=['suspected_automation','declared_crawler_or_tool'];$actor->{crawler_tokens}=['LocalFetch'];
my $ar=rows();$_->{user_agent}.=' LocalFetch/1' for @$ar;$actor->{behavior_include}=[sha256_hex($J->encode($ar->[0]))];
is(report($ar,$actor)->{adjusted_requests}{excluded},6,'behavior inclusion cannot override independent actor exclusion');
for my $bad (
    {enabled=>2},{enabled=>JSON::PP::true},{window_seconds=>0},{window_seconds=>3601},
    {min_requests=>1},{distinct_user_agents=>1},{distinct_user_agents=>7},
    {distinct_platforms=>1},{distinct_platforms=>6},{distinct_platforms=>4},
    {paths=>[]},{paths=>undef},{paths=>['/x','/x']},{paths=>['/x?token=1']},
    {paths=>['http://example.test/x']},{paths=>['/x#fragment']},{paths=>['/%78']},
    {paths=>['/a/../b']},{paths=>['/a%2fb']},{country=>'DE'}
) {reject('invalid probing configuration refused',sub {cfg(%$bad)});}
reject('null probing object refused',sub {$C->config('{"schema_version":1,"probing":null}')});
reject('configured paths obey the target-field cap',sub {$C->config($J->encode({schema_version=>1,probing=>\%rule,limits=>{target_bytes=>4}}))});
reject('endpoint list cap is enforced',sub {cfg(paths=>[map {'/probe'.$_} 0..2048])});
is(report(rows(),cfg(paths=>['/account/*']))->{behavior}{flagged_requests},0,'configuration paths are exact literals, not patterns');
my $limited=$C->config($J->encode({schema_version=>1,probing=>\%rule,limits=>{groups=>1}}));
my $groups=rows();$_->{user_agent}=$ua[0] for @$groups;$groups->[$_]{host}=$_<3?'a.test':'b.test' for 0..5;
reject('independent IP/host probing group cap enforced',sub {report($groups,$limited)});

# Independent exhaustive oracle: enumerate all intervals after filtering exact
# endpoint membership; no maximal windows, running counters or difference array.
sub oracle {
    my ($events)=@_;my @flag=(0)x@$events;my %groups;my %paths=map {$_=>1} @{$rule{paths}};
    for my $i(0..$#$events){my$r=$events->[$i];next if!$paths{$r->{target}};push @{$groups{$r->{client}."\0".$r->{host}}},$i;}
    for my $indices(values %groups){my@p=sort{$events->[$a]{timestamp}<=>$events->[$b]{timestamp}||$a<=>$b}@$indices;
        for my $left(0..$#p){for my $right($left..$#p){my@slice=@p[$left..$right];next if@slice<$rule{min_requests};
            next if$events->[$p[$right]]{timestamp}-$events->[$p[$left]]{timestamp}>$rule{window_seconds};
            my(%u,%systems);for my$i(@slice){$u{$events->[$i]{user_agent}}=1;$systems{$platform{$events->[$i]{user_agent}}}=1;}
            next if keys(%u)<$rule{distinct_user_agents}||keys(%systems)<$rule{distinct_platforms};$flag[$_]=1 for@slice;
        }}
    }return \@flag;
}
srand(180735);my($positive_trials,$negative_trials)=(0,0);
for my $trial(1..60){my@r=map{+{timestamp=>100+int(rand(22)),client=>$_<10?'192.0.2.1':'192.0.2.'.(1+int(rand(2))),
    host=>$_<10?'example.test':(int(rand(2))?'example.test':'other.test'),target=>int(rand(4))?'/account/sign-in':'/ordinary',
    user_agent=>$ua[int(rand(@ua))],status=>200}}0..15;
    my$expected=oracle(\@r);(grep{$_}@$expected)?$positive_trials++:$negative_trials++;
    is_deeply(flags(report(\@r)),$expected,'probing agrees with exhaustive interval oracle '.$trial);
}
ok($positive_trials && $negative_trials,'oracle cases cover positive and negative windows');
my $public=clone($positive);delete $public->{details};delete $public->{details_warning};
unlike(VStats::TrafficClassifier::canonical_json($public),qr/192\.0\.2\.1|Windows NT/,'aggregate contains no observed source or full browser records');
done_testing;
