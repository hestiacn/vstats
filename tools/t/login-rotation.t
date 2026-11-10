use v5.020;
use strict;
use warnings;
use Test::More;
use JSON::PP;
use VStats::TrafficClassifier;

my $C='VStats::TrafficClassifier';my $J=JSON::PP->new->utf8->canonical;
my @ua=('Mozilla/5.0 (Windows NT 10.0) Chrome/131.0',
    'Mozilla/5.0 (X11; Linux x86_64) Firefox/133.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/605.1');
sub cfg {return $C->config($J->encode({schema_version=>1,login_rotation=>{
    enabled=>1,login_paths=>['/account/sign-in'],@_}}));}
sub rows {
    my @rows;
    for my $i (0..2) {
        push @rows,map {+{timestamp=>1000+$i*3600+$_*2,client=>'192.0.2.1',
            host=>'example.test',target=>'/account/sign-in',status=>200,
            method=>$_?'POST':'GET',user_agent=>$ua[($i+$_)%3]}} 0..1;
    }
    return \@rows;
}
sub raw {return join('',map {$J->encode($_)."\n"} @{$_[0]});}
sub clone {return $J->decode($J->encode($_[0]));}
sub run {
    my ($rows,$cfg,$before,$after)=@_;
    my $engine=$C->new(config=>$cfg//cfg(),format=>'jsonl',details=>1);
    $engine->feed(raw($rows));
    $engine->add_context('before',raw($before)) if $before;
    $engine->add_context('after',raw($after)) if $after;
    return $engine->finish;
}
sub count {return run(@_)->{behavior}{login_rotation_flagged_requests};}
my $positive=run(rows());
is(count(rows()),6,'slow repeated cross-platform login pairs qualify');
is($positive->{behavior}{flagged_requests},6,'new rule contributes to deduplicated union');
is($positive->{behavior}{eligible_requests},6,'new rule contributes to eligibility');
is($positive->{behavior}{flagged_source_groups},1,'one source/host group');
is($positive->{behavior}{merged_sequences},1,'one overlapping sequence');
is($positive->{actors}{unknown},6,'pattern does not supply verified actor identity');
ok(!exists $positive->{adjusted_requests},'label by itself does not exclude');
for my $r (@{$positive->{details}}) {
    ok($r->{login_rotation_flagged} && $r->{suspected_automation},'private rule flag retained');
    my $proof=$r->{login_rotation_evidence};
    ok($proof->{from}<=$r->{timestamp} && $r->{timestamp}<=$proof->{until},'numeric witness covers request');
    is($proof->{pairs},3,'witness counts pairs');
    is($proof->{platform_switches},3,'witness counts within-pair changes');
}
is(count(rows(),$C->config('{"schema_version":1}')),0,'raw classifier remains opt-in');
is(count(rows(),cfg(enabled=>0)),0,'explicit disable preserves traffic');
for my $case (
    ['ordinary stable sessions behind a shared IP',sub {$_[0][2*$_+1]{user_agent}=$_[0][2*$_]{user_agent} for 0..2}],
    ['same-platform browser rotation',sub {$_->{user_agent}='Mozilla/5.0 (Windows) Chrome/'.(120+$_->{timestamp}) for @{$_[0]}}],
    ['one POST browser',sub {$_[0][2*$_+1]{user_agent}=$ua[0] for 0..2}],
    ['isolated sources',sub {$_[0][2*$_]{client}=$_[0][2*$_+1]{client}='192.0.2.'.($_+1) for 0..2}],
    ['different hosts',sub {$_[0][2*$_]{host}=$_[0][2*$_+1]{host}='site'.$_ .'.test' for 0..2}],
    ['unconfigured paths',sub {$_->{target}='/unconfigured' for @{$_[0]}}],
    ['POST-before-GET order',sub {$_->{method}=$_->{method} eq 'POST'?'GET':'POST' for @{$_[0]}}],
    ['missing method',sub {delete $_->{method} for @{$_[0]}}],
    ['missing status',sub {delete $_->{status} for @{$_[0]}}],
    ['missing browser evidence',sub {delete $_->{user_agent} for @{$_[0]}}],
    ['slow form submission',sub {$_[0][2*$_+1]{timestamp}+=29 for 0..2}],
    ['pairs outside rolling window',sub {$_->{timestamp}*=100 for @{$_[0]}}]
) {
    my $r=rows();$case->[1]->($r);is(count($r),0,$case->[0].' is insufficient');
}
my $few=rows();splice @$few,4;
my $sparse=run($few);
is($sparse->{behavior}{flagged_requests},4,'two separated switched visits supply an alternative witness');
ok(!grep({$_->{ip_expansion_eligible}} @{$sparse->{details}}),'sparse witness cannot trigger IP/month expansion');
my $one=clone($few);splice @$one,2;is(count($one),0,'one mismatched pair is insufficient');
my $single_switch=rows();$single_switch->[2*$_+1]{user_agent}=$single_switch->[2*$_]{user_agent} for 0..1;
$single_switch->[4]{user_agent}=$ua[0];$single_switch->[5]{user_agent}=$ua[2];
my $diverse=run($single_switch);
is($diverse->{behavior}{flagged_requests},6,'diverse POST browsers with one in-pair change qualify');
ok(!grep({$_->{ip_expansion_eligible}} @{$diverse->{details}}),'diversity-only witness cannot trigger IP/month expansion');
my $burst=clone($few);$burst->[$_]{timestamp}=1000+$_ for 0..3;
is(count($burst),0,'two switches in one short burst are not separated visits');
ok(!grep({!$_->{ip_expansion_eligible} || !$_->{login_rotation_evidence}{ip_expansion_eligible}} @{$positive->{details}}),
    'original stronger witness preserves configured IP policy eligibility');
for my $barrier ('/style.css','/unsupported%2fpath',undef) {
    my $r=rows();
    for my $i (reverse 0..2) {
        my $b={%{$r->[2*$i]},timestamp=>$r->[2*$i]{timestamp}+1,target=>$barrier//'/account/sign-in'};
        delete $b->{user_agent} if !defined $barrier;
        splice @$r,2*$i+1,0,$b;
    }
    is(count($r),0,'intervening parsed request breaks adjacency');
}
is(count([reverse @{rows()}]),6,'time sort retains original request attribution');
my $v6=rows();$v6->[$_]{client}=$_%2?'2001:db8::1':'2001:0DB8:0:0:0:0:0:1' for 0..5;
is(count($v6),6,'equivalent IPv6 spellings share a source');
my $mapped=rows();$mapped->[$_]{client}=$_%2?'::ffff:192.0.2.1':'192.0.2.1' for 0..5;
is(count($mapped),0,'mapped IPv6 and IPv4 do not pool');
my $queries=rows();$_->{target}='/account/%73ign-in?token=PRIVATE_SENTINEL' for @$queries;
is(count($queries),6,'supported normalization strips query secrets before exact matching');
my $extra=rows();push @$extra,{%{$extra->[0]},timestamp=>20000,target=>'/ordinary'};
is_deeply([map {$_->{login_rotation_flagged}?1:0} @{run($extra)->{details}}],[(1)x6,0],'unpaired pages are not relabelled');
my $boundary=rows();$boundary->[-1]{timestamp}=1000+86400;
$boundary->[-2]{timestamp}=$boundary->[-1]{timestamp}-30;
is(count($boundary),6,'pair timeout and complete witness window are inclusive');
$boundary->[-1]{timestamp}++;is(count($boundary),4,'outside boundary retains only earlier qualifying pairs');
my $daily=rows();$_->{timestamp}+=83000 for @$daily;
my @before=grep {$_->{timestamp}<86400} @$daily;
my @after=grep {$_->{timestamp}>=86400} @$daily;
is(count(\@after,cfg(),\@before),4,'before-day context supplies evidence without inflating primary counts');
is(count(\@before,cfg(),undef,\@after),2,'after-day context supplies evidence without inflating primary counts');
my $excluded=cfg();$excluded->{exclude}=['suspected_automation'];
is(run(rows(),$excluded)->{adjusted_requests}{excluded},6,'explicit behavioral selection excludes paired requests');
$excluded->{behavior_include}=[$positive->{details}[0]{request_id}];
my $included=run(rows(),$excluded);
is($included->{adjusted_requests}{excluded},5,'request inclusion overrides new behavioral exclusion');
ok($included->{details}[0]{login_rotation_evidence},'inclusion retains the witness');
my $joint_rows=rows();
# Keep each GET before its POST with three distinct, close pair timestamps.
for my $i (0..5) {$joint_rows->[$i]{timestamp}=1000+$i*2;}
my $joint_cfg=cfg();$joint_cfg->{probing}={enabled=>1,window_seconds=>60,min_requests=>6,
    distinct_user_agents=>3,distinct_platforms=>2,paths=>['/account/sign-in']};
my $joint=run($joint_rows,$joint_cfg);
is_deeply([@{$joint->{behavior}}{qw(probing_flagged_requests login_rotation_flagged_requests flagged_requests overlap_requests)}],
    [6,6,6,6],'new and existing rules retain independent evidence without double counting');
is($C->analysis_window(cfg()),86400,'daily publisher halo covers complete rolling window');
for my $change (['pair_seconds',301],['window_seconds',86401],['min_pairs',1],
    ['min_platform_switches',1],['min_platform_switches',4],['distinct_user_agents',4],
    ['distinct_platforms',1],['login_paths',[]],['login_paths',['/a?token=x']],
    ['login_paths',['/a','/a']]) {
    ok(!eval {cfg($change->[0]=>$change->[1]);1},'invalid rotation setting refused: '.$change->[0]);
}
like(VStats::TrafficClassifier::html_report($positive),qr/login browser rotation: 6/,'aggregate HTML reports new rule');
done_testing;
