use v5.020;
use strict;
use warnings;
use Test::More;
use JSON::PP;
use VStats::TrafficClassifier;
my $C='VStats::TrafficClassifier';my $J=JSON::PP->new->utf8->canonical;
my @ua=('Mozilla/5.0 (Windows NT 10.0) Chrome/126.0',
        'Mozilla/5.0 (Windows NT 10.0) Chrome/125.0',
        'Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0',
        'Mozilla/5.0 (Linux; Android 14) Chrome/126.0');
my %platform=($ua[0]=>'windows',$ua[1]=>'windows',$ua[2]=>'linux',$ua[3]=>'android');
my %rule=(enabled=>1,window_seconds=>10,min_requests=>6,distinct_user_agents=>3,
          distinct_platforms=>2,distinct_paths=>3,not_found_requests=>3);
sub config {return $C->config($J->encode({schema_version=>1,behavior=>{%rule,@_}}));}
sub rows {return [map {+{timestamp=>100+$_,client=>'192.0.2.1',host=>'example.test',
    target=>'/p'.($_%3),user_agent=>$ua[$_%3],status=>$_<3?404:200}} 0..5];}
sub run {
    my ($rows,$config,$format)=@_;$format//='jsonl';$config//=config();
    my $e=$C->new(config=>$config,format=>$format,details=>1);
    my $raw=ref($rows) eq 'ARRAY' ? join('',map {$J->encode($_)."\n"} @$rows):$rows;
    while(length $raw){$e->feed(substr($raw,0,13,''));}
    return $e->finish;
}
sub clone {return $J->decode($J->encode($_[0]));}
sub flags {return [map {$_->{suspected_automation}?1:0} @{$_[0]{details}}];}
sub reject {my ($name,$code)=@_;my $ok=eval {$code->();1};ok(!$ok,$name);}
my $positive=run(rows());
is($positive->{behavior}{flagged_requests},6,'joint source/host window flags all participating requests');
is($positive->{behavior}{merged_sequences},1,'overlapping windows form one sequence');
is($positive->{behavior}{actors}{unknown},6,'unknown identity may independently have behavioral evidence');
is_deeply($positive->{actors},{unknown=>6,declared_crawler_or_tool=>0,verified_crawler=>0},'behavior does not promote actor identity');
is_deeply(flags($positive),[(1)x6],'private details carry per-request flags');
ok(!exists($positive->{adjusted_requests}),'behavior never implicitly changes request comparison');
my $off=run(rows(),config(enabled=>0));
is($off->{behavior}{flagged_requests},0,'explicit disable');
is_deeply($off->{actors},$positive->{actors},'identity independent of enable switch');
is_deeply($off->{counts},$positive->{counts},'counts independent of enable switch');
is($off->{scanner_flagged_requests},$positive->{scanner_flagged_requests},'existing scanner evidence unchanged');
is(run(rows(),$C->config('{"schema_version":1}'))->{behavior}{enabled}?1:0,0,'backward-compatible opt-in default');
for my $case (
    ['slow requests',sub {$_[0][$_]{timestamp}=100+$_*11 for 0..5}],
    ['single user agent',sub {$_->{user_agent}=$ua[0] for @{$_[0]}}],
    ['one claimed platform',sub {$_[0][$_]{user_agent}='Mozilla/5.0 (Windows NT 10.0) Chrome/'.(120+$_) for 0..5}],
    ['one path',sub {$_->{target}='/' for @{$_[0]}}],
    ['no errors',sub {$_->{status}=200 for @{$_[0]}}],
    ['insufficient 404s',sub {$_[0][2]{status}=200}],
    ['different clients',sub {$_[0][$_]{client}='192.0.2.'.($_+1) for 0..5}],
    ['different hosts',sub {$_[0][$_]{host}=$_<3?'a.test':'b.test' for 0..5}]
) {
    my $r=rows();$case->[1]->($r);is(run($r)->{behavior}{flagged_requests},0,$case->[0].' alone cannot satisfy joint criteria');
}
my $edge=rows();$edge->[-1]{timestamp}=110;
is(run($edge)->{behavior}{flagged_requests},6,'window endpoint inclusive');
$edge->[-1]{timestamp}=111;
is(run($edge)->{behavior}{flagged_requests},0,'one second outside window cannot complete it');
my $bounded=rows();unshift @$bounded,{%{$bounded->[0]},timestamp=>20};push @$bounded,{%{$bounded->[-1]},timestamp=>200};
is_deeply(flags(run($bounded)),[0,(1)x6,0],'no attribution to unrelated requests outside qualifying span');
my $reverse=[reverse @{rows()}];is_deeply(flags(run($reverse)),[(1)x6],'out-of-order input sorted before window analysis');
my $separate=rows();push @$separate,map {+{%$_,timestamp=>$_->{timestamp}+100}} @{rows()};
is(run($separate)->{behavior}{merged_sequences},2,'disjoint windows remain separate');
my $v6=rows();$v6->[$_]{client}=$_%2?'2001:db8::1':'2001:0DB8:0:0:0:0:0:1' for 0..5;
is(run($v6)->{behavior}{flagged_requests},6,'equivalent IPv6 representations share a source group');
my $mapped=rows();$mapped->[$_]{client}=$_<3?'192.0.2.1':'::ffff:192.0.2.1' for 0..5;
is(run($mapped)->{behavior}{flagged_requests},0,'mapped IPv6 remains distinct from IPv4');
for my $case (
    ['missing status',sub {delete $_->{status} for @{$_[0]}}],
    ['missing UA',sub {delete $_->{user_agent} for @{$_[0]}}],
    ['unrecognized browser',sub {$_->{user_agent}='LocalFetch/1' for @{$_[0]}}],
    ['unbounded platform token',sub {$_->{user_agent}='Mozilla/5.0 (NotWindowsX) Chrome/126.0' for @{$_[0]}}],
    ['hostname client',sub {$_->{client}='client.example' for @{$_[0]}}],
    ['unsupported target',sub {$_->{target}='http://example.test/' for @{$_[0]}}]
) {
    my $r=rows();$case->[1]->($r);my $report=run($r);
    is($report->{behavior}{flagged_requests},0,$case->[0].' cannot supply evidence');
    is($report->{behavior}{insufficient_fields},6,$case->[0].' disclosed');
    is($report->{counts}{analyzed},6,$case->[0].' retains independent request accounting');
}
my $apache='';
for my $i (0..5) {$apache.=sprintf('192.0.2.1 - - [01/Nov/2026:10:00:%02d +0000] "GET /p%d HTTP/1.1" %d 100 "-" "%s"',$i,$i%3,$i<3?404:200,$ua[$i%3])."\n";}
is(run($apache,config(),'combined')->{behavior}{flagged_requests},6,'combined parser retains status and UA in correct fields');
(my $common=$apache)=~s/ "-" "[^"\n]*"\n/\n/g;
is(run($common,config(),'common')->{behavior}{insufficient_fields},6,'common log cannot invent browser identity');
for my $bad (
    {enabled=>2},{enabled=>JSON::PP::true},{window_seconds=>0},{window_seconds=>3601},
    {min_requests=>1},{min_requests=>100001},{distinct_user_agents=>1},{distinct_user_agents=>7},
    {distinct_platforms=>1},{distinct_platforms=>6},{distinct_paths=>1},{distinct_paths=>7},
    {not_found_requests=>1},{not_found_requests=>7},{enabled=>undef},{geography=>'AD'}
) {reject('invalid behavioral config refused',sub {config(%$bad)});}
my $selected=config();$selected->{exclude}=['suspected_automation'];
is(run(rows(),$selected)->{adjusted_requests}{excluded},6,'behavior exclusion requires explicit selector');
reject('null behavior object refused',sub {$C->config('{"schema_version":1,"behavior":null}')});
my $group_cap=$C->config($J->encode({schema_version=>1,behavior=>\%rule,limits=>{groups=>1}}));
my $groups=rows();$_->{user_agent}=$ua[0] for @$groups;$groups->[$_]{host}=$_<3?'a.test':'b.test' for 0..5;
reject('independent IP/host group cap enforced',sub {run($groups,$group_cap)});
for my $status (undef,'404',99,600,JSON::PP::true) {
    my $r=rows();$r->[0]{status}=$status;is(run($r)->{counts}{unparsed},1,'invalid optional JSONL status is unparsed');
}
my $excluded_cfg=$C->config($J->encode({schema_version=>1,hosts=>['other.test'],behavior=>\%rule}));
reject('out-of-scope host cannot supply behavioral evidence',sub {run(rows(),$excluded_cfg)});

# Independent exhaustive oracle: examine every consecutive interval, without
# frequency counters, maximal-window selection or difference-array coverage.
sub oracle {
    my ($events)=@_;my %groups;my @flag=(0)x@$events;
    for my $i (0..$#$events) {my $r=$events->[$i];push @{$groups{$r->{client}."\0".($r->{host}//'')}},$i;}
    for my $indices (values %groups) {
        my @p=sort {$events->[$a]{timestamp}<=>$events->[$b]{timestamp} || $a<=>$b} @$indices;
        for my $left (0..$#p) {for my $right ($left..$#p) {
            my @slice=@p[$left..$right];next if @slice<$rule{min_requests};
            next if $events->[$p[$right]]{timestamp}-$events->[$p[$left]]{timestamp}>$rule{window_seconds};
            my (%u,%p,%s);my $errors=0;
            for my $i (@slice) {my $r=$events->[$i];$u{$r->{user_agent}}=1;$p{$r->{target}}=1;$s{$platform{$r->{user_agent}}}=1;$errors++ if $r->{status}==404;}
            next if keys(%u)<$rule{distinct_user_agents} || keys(%s)<$rule{distinct_platforms}
                || keys(%p)<$rule{distinct_paths} || $errors<$rule{not_found_requests};
            $flag[$_]=1 for @slice;
        }}
    }
    return \@flag;
}
srand(44110);
my ($positive_oracles,$negative_oracles)=(0,0);
for my $trial (1..60) {
    my @r=map {+{timestamp=>100+int(rand(22)),client=>$_<10?'192.0.2.1':'192.0.2.'.(1+int(rand(2))),
        host=>$_<10?'example.test':(int(rand(2))?'example.test':'other.test'),
        target=>'/p'.int(rand(4)),user_agent=>$ua[int(rand(@ua))],status=>int(rand(2))?200:404}} 0..15;
    my $expected=oracle(\@r);my $has_flag=grep {$_} @$expected;
    $has_flag ? $positive_oracles++:$negative_oracles++;
    is_deeply(flags(run(\@r)),$expected,'optimized windows agree with exhaustive oracle '.$trial);
}
ok($positive_oracles>0 && $negative_oracles>0,'oracle corpus exercises positive and negative cases');
my $json=VStats::TrafficClassifier::canonical_json($positive);my $html=VStats::TrafficClassifier::html_report($positive);
like($html,qr/Suspected automation/,'HTML exposes new label');
like($html,qr/Exclusions require an explicit selection/,'HTML states explicit selection semantics');
is(VStats::TrafficClassifier::canonical_json($positive),$json,'rendering keeps report immutable');
delete $positive->{details};delete $positive->{details_warning};$json=VStats::TrafficClassifier::canonical_json($positive);
unlike($json,qr/192\.0\.2\.1|Windows NT|\/p0/,'aggregate output contains no source/UA/target records');
done_testing;
