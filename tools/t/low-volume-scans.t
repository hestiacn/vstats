use v5.020;
use strict;
use warnings;
use Test::More;
use JSON::PP;
use VStats::TrafficClassifier;
my $C='VStats::TrafficClassifier';my $J=JSON::PP->new->utf8->canonical;
my @ua=('Mozilla/5.0 (Windows) Chrome/131.0','Mozilla/5.0 (Windows) Firefox/133.0',
        'Mozilla/5.0 (Linux) Chrome/131.0','Mozilla/5.0 (Macintosh) Firefox/133.0');
sub cfg {my ($kind,@rest)=@_;return $C->config($J->encode({schema_version=>1,$kind=>{enabled=>1,@rest}}));}
sub event {return {timestamp=>100,client=>'192.0.2.1',host=>'example.test',method=>'GET',status=>200,user_agent=>$ua[0],target=>'/',@_};}
sub rows {
    my ($kind)=@_;my @rows;
    if ($kind eq 'head_scan') {
        @rows=map {event(timestamp=>100+$_,method=>'HEAD',target=>'/candidate'.($_%6),status=>$_<4?404:200)} 0..11;
    } elsif ($kind eq 'sensitive_scan') {
        my @path=qw(/.env /.git/config /.svn/wc.db);
        @rows=map {event(timestamp=>100+$_,target=>$path[$_],status=>[200,403,404]->[$_])} 0..2;
    } else {
        @rows=map {event(timestamp=>100+$_,target=>$_<4?'/'.'?author='.($_+1).'&private=SECRET_SENTINEL':
            $_%2?'/index.php?rest_route=%2Fwp%2Fv2%2Fusers':'/wp-json/wp/v2/users',
            user_agent=>$ua[$_%4],status=>$_<4?404:200)} 0..7;
    }
    return \@rows;
}
sub clone {return $J->decode($J->encode($_[0]));}
sub raw {return join('',map {$J->encode($_)."\n"} @{$_[0]});}
sub run {
    my ($events,$cfg,$before,$after,$details)=@_;$details//=1;
    my $e=$C->new(config=>$cfg,format=>'jsonl',details=>$details);$e->feed(raw($events));
    $e->add_context('before',raw($before)) if $before;$e->add_context('after',raw($after)) if $after;
    return $e->finish;
}
for my $kind (qw(head_scan sensitive_scan wp_enumeration)) {
    my $r=rows($kind);my $n=@$r;my $positive=run($r,cfg($kind));
    is($positive->{behavior}{$kind.'_flagged_requests'},$n,"$kind positive pattern");
    is($positive->{behavior}{flagged_requests},$n,'union counts each request once');
    is($positive->{actors}{unknown},$n,'pattern does not authenticate a crawler identity');
    ok(!exists $positive->{adjusted_requests},'selection is explicit');
    for my $d (@{$positive->{details}}) {
        my $p=$d->{$kind.'_evidence'};
        ok($d->{$kind.'_flagged'} && $p->{from}<=$d->{timestamp} && $p->{until}>=$d->{timestamp},'covering numeric rule witness');
        ok(!exists $p->{author} && !exists $p->{target},'witness does not retain identifiers or targets');
    }
    is(run($r,$C->config('{"schema_version":1}'))->{behavior}{flagged_requests},0,'CLI rules remain opt-in');
    is(run($r,cfg($kind,enabled=>0))->{behavior}{flagged_requests},0,'explicit disable');
    for my $case (
        ['hostname client',sub {$_->{client}='client.example' for @{$_[0]}}],
        ['distinct sources',sub {$_[0][$_]{client}='192.0.2.'.($_+1) for 0..$#{$_[0]}}],
        ['distinct hosts',sub {$_[0][$_]{host}='site'.$_ .'.test' for 0..$#{$_[0]}}],
        ['missing status',sub {delete $_->{status} for @{$_[0]}}],
        ['out of window',sub {$_[0][$_]{timestamp}=100+$_*61 for 0..$#{$_[0]}}]
    ) {
        my $v=clone($r);$case->[1]->($v);is(run($v,cfg($kind))->{behavior}{flagged_requests},0,$kind.' '.$case->[0].' abstains');
    }
    my $few=clone($r);pop @$few;
    is(run($few,cfg($kind))->{behavior}{flagged_requests},0,'volume boundary enforced');
    is(run([reverse @$r],cfg($kind))->{behavior}{flagged_requests},$n,'time sorting preserves attribution');
    my $v6=clone($r);$v6->[$_]{client}=$_%2?'2001:db8::1':'2001:0DB8:0:0:0:0:0:1' for 0..$#$v6;
    is(run($v6,cfg($kind))->{behavior}{flagged_requests},$n,'canonical IPv6 source grouping');
    my $day=clone($r);$_->{timestamp}=86400+$_->{timestamp}-100-int($n/2) for @$day;
    my @before=grep {$_->{timestamp}<86400} @$day;my @after=grep {$_->{timestamp}>=86400} @$day;
    is(run(\@after,cfg($kind),\@before)->{behavior}{flagged_requests},scalar(@after),'before-day evidence does not inflate primary counts');
    is(run(\@before,cfg($kind),undef,\@after)->{behavior}{flagged_requests},scalar(@before),'after-day evidence does not inflate primary counts');
    my $config=cfg($kind);$config->{exclude}=['suspected_automation'];
    $config->{behavior_include}=[$positive->{details}[0]{request_id}];
    my $kept=run($r,$config);is($kept->{adjusted_requests}{excluded},$n-1,'inclusion overrides behavioral exclusion');
    ok($kept->{details}[0]{$kind.'_evidence'},'override keeps evidence');
    my $aggregate=run($r,cfg($kind),undef,undef,0);
    unlike(VStats::TrafficClassifier::canonical_json($aggregate),qr/SECRET_SENTINEL|author=|192\.0\.2\.1/,'aggregate does not expose query or source data');
}
my $head=rows('head_scan');$_->{method}='GET' for @$head;
is(run($head,cfg('head_scan'))->{behavior}{flagged_requests},0,'GET requests cannot supply a HEAD sweep');
$head=rows('head_scan');$_->{status}=200 for @$head;
is(run($head,cfg('head_scan'))->{behavior}{flagged_requests},0,'successful HEAD checks alone abstain');
$head=rows('head_scan');$_->{target}.='.css' for @$head;
is(run($head,cfg('head_scan'))->{behavior}{flagged_requests},0,'asset HEAD checks abstain');
my $sensitive=rows('sensitive_scan');$_->{target}='/docs'.$_->{target} for @$sensitive;
is(run($sensitive,cfg('sensitive_scan'))->{behavior}{flagged_requests},0,'sensitive paths are exact, not substrings');
for my $case (
    ['same author',sub {$_->{target}=~s/author=[0-9]+/author=1/ for @{$_[0]}}],
    ['no user API',sub {$_[0][$_]{target}='/?author='.($_+1) for 4..7}],
    ['one browser',sub {$_->{user_agent}=$ua[0] for @{$_[0]}}],
    ['missing browser',sub {delete $_->{user_agent} for @{$_[0]}}],
    ['duplicate query keys',sub {$_->{target}.='&author=999' for @{$_[0]}}],
    ['malformed author',sub {$_->{target}=~s/author=[0-9]+/author=%ZZ/ for @{$_[0]}}],
    ['encoded author delimiter',sub {$_->{target}=~s/author=[0-9]+/author=1%26other%3D2/ for @{$_[0]}}],
    ['no missing resources',sub {$_->{status}=200 for @{$_[0]}}]
) {
    my $v=rows('wp_enumeration');$case->[1]->($v);
    is(run($v,cfg('wp_enumeration'))->{behavior}{flagged_requests},0,'enumeration '.$case->[0].' abstains');
}
my $ordinary=[map {event(timestamp=>100+$_,target=>['/','/contact','/about','/services','/team','/news','/work','/favicon.ico']->[$_])} 0..7];
my $all=$C->config('{"schema_version":1,"head_scan":{"enabled":1},"sensitive_scan":{"enabled":1},"wp_enumeration":{"enabled":1}}');
is(run($ordinary,$all)->{behavior}{flagged_requests},0,'fast successful page walk and favicon are insufficient');
my $both=rows('head_scan');my @secrets=qw(/.env /.env.local /.env.backup /.git/config /.git-credentials /.svn/wc.db);
$both->[$_]{target}=$secrets[$_%6] for 0..11;
my $union=run($both,$all);
is_deeply([@{$union->{behavior}}{qw(head_scan_flagged_requests sensitive_scan_flagged_requests flagged_requests overlap_requests)}],
    [12,12,12,12],'overlapping patterns retain independent witnesses and deduplicate');
for my $bad (['head_scan',window_seconds=>3601],['head_scan',distinct_paths=>13],
    ['sensitive_scan',paths=>[]],['sensitive_scan',paths=>['/.env','/.env']],
    ['sensitive_scan',paths=>['/.env?x=1']],['wp_enumeration',author_paths=>[]],
    ['wp_enumeration',distinct_platforms=>1],['wp_enumeration',distinct_author_ids=>8]) {
    ok(!eval {cfg(@$bad);1},'invalid bounded rule configuration refused');
}
done_testing;
