use v5.020;
use strict;
use warnings;
use Test::More;
use JSON::PP;
use VStats::TrafficClassifier;
my $C='VStats::TrafficClassifier';my $J=JSON::PP->new->utf8->canonical;
sub cfg {my ($kind,@rest)=@_;return $C->config($J->encode({schema_version=>1,$kind=>{enabled=>1,@rest}}));}
sub event {return {timestamp=>100,client=>'192.0.2.1',host=>'example.test',method=>'GET',status=>200,
    target=>'/',user_agent=>'Mozilla/5.0 (Windows) Chrome/131.0',@_};}
sub rows {
    my ($kind)=@_;my @probes=$kind eq 'backdoor_probe'
        ? (event(timestamp=>108,target=>'/wp-content/themes/seotheme/db.php',status=>404),
           event(timestamp=>109,target=>'/wp-plain.php',method=>'POST',status=>404),
           event(timestamp=>110,target=>'/wp-content/plugins/fix/up.php',status=>301))
        : (event(timestamp=>108,target=>'/mcp?token=SECRET_SENTINEL',method=>'POST',status=>404,user_agent=>'python-httpx/0.28.1'),
           event(timestamp=>109,target=>'/sse',status=>410,user_agent=>'python-httpx/0.28.1'));
    return [event(timestamp=>1),event(),event(timestamp=>101,target=>'/contact'),@probes,
        event(timestamp=>120,target=>'/favicon.ico')];
}
sub raw {return join('',map {$J->encode($_)."\n"} @{$_[0]});}
sub clone {return $J->decode($J->encode($_[0]));}
sub run {
    my ($rows,$cfg,$before,$after)=@_;my $e=$C->new(config=>$cfg,format=>'jsonl',details=>1);
    $e->feed(raw($rows));$e->add_context('before',raw($before)) if $before;
    $e->add_context('after',raw($after)) if $after;return $e->finish;
}
for my $kind (qw(backdoor_probe protocol_probe)) {
    my $rows=rows($kind);my $n=$kind eq 'backdoor_probe'?4:3;my $positive=run($rows,cfg($kind));
    is($positive->{behavior}{$kind.'_flagged_requests'},$n,"$kind includes nearby entry and probe requests");
    is($positive->{behavior}{flagged_requests},$n,'union counts once');
    is_deeply([map {$_->{$kind.'_flagged'}?1:0} @{$positive->{details}}],[0,1,0,(1)x($n-1),0],
        'old entry, unrelated content and later entry retained');
    ok(!grep({$_->{ip_expansion_eligible}} @{$positive->{details}}),'burst cannot supply an IP/month trigger');
    for my $r (grep {$_->{$kind.'_flagged'}} @{$positive->{details}}) {
        my $p=$r->{$kind.'_evidence'};
        ok($p->{from}<=$r->{timestamp} && $r->{timestamp}<=$p->{until},'numeric witness covers each flagged request');
        is($p->{entry_requests},1,'one corroborated entry request');
        is($p->{probe_requests},$n-1,'only explicit probes count toward threshold');
        unlike($J->encode($p),qr/SECRET|python-httpx|192\.0\.2|wp-plain/,'proof omits query values, raw identities and targets');
    }
    is(run($rows,cfg($kind,enabled=>0))->{behavior}{flagged_requests},0,'explicit disable');
    is(run($rows,$C->config('{"schema_version":1}'))->{behavior}{flagged_requests},0,'raw CLI opt-in');
    for my $case (
        ['separate source',sub {$_[0][3]{client}='192.0.2.2'}],
        ['separate host',sub {$_[0][3]{host}='other.test'}],
        ['missing method',sub {delete $_[0][3]{method}}],
        ['missing status',sub {delete $_[0][3]{status}}],
        ['unsupported target',sub {$_[0][3]{target}='/unsupported%2fpath'}],
        ['unconfigured target',sub {$_[0][3]{target}='/unconfigured'}],
        ['only successful responses',sub {$_->{status}=200 for @{$_[0]}}],
        ['redirects do not establish missing endpoints',sub {$_->{status}=301 for @{$_[0]}}],
        ['probes outside window',sub {$_[0][3]{timestamp}=40}],
        ['homepage and favicon only',sub {$_->{target}=$_->{timestamp}%2?'/favicon.ico':'/' for @{$_[0]}}],
        ['robots and page walk only',sub {$_[0][$_]{target}=$_==3?'/robots.txt':'/page'.$_ for 0..$#{$_[0]}}]
    ) {
        my $v=clone($rows);$case->[1]->($v);
        is(run($v,cfg($kind))->{behavior}{flagged_requests},0,$kind.' '.$case->[0].' abstains');
    }
    my $no_entry=run($rows,cfg($kind,entry_paths=>[]));
    is($no_entry->{behavior}{flagged_requests},$n-1,'optional entry inclusion can be disabled');
    my $other_source=clone($rows);$other_source->[1]{client}='192.0.2.2';
    is(run($other_source,cfg($kind))->{behavior}{flagged_requests},$n-1,'entry from another source is retained');
    my $boundary=clone($rows);$boundary->[1]{timestamp}=$boundary->[-2]{timestamp}-60;
    is(run($boundary,cfg($kind))->{behavior}{flagged_requests},$n,'entry lookback boundary inclusive');
    $boundary->[1]{timestamp}--;
    is(run($boundary,cfg($kind))->{behavior}{flagged_requests},$n-1,'entry outside lookback retained');
    is(run([reverse @$rows],cfg($kind))->{behavior}{flagged_requests},$n,'sorting preserves request attribution');
    my $v6=clone($rows);$v6->[$_]{client}=$_%2?'2001:db8::1':'2001:0DB8:0:0:0:0:0:1' for 0..$#$v6;
    is(run($v6,cfg($kind))->{behavior}{flagged_requests},$n,'equivalent IPv6 sources pool');
    my $split=clone($rows);$_->{timestamp}+=86292 for @$split;
    my @before=grep {$_->{timestamp}<86400} @$split;my @after=grep {$_->{timestamp}>=86400} @$split;
    is(run(\@after,cfg($kind),\@before)->{behavior}{flagged_requests},$n-1,'before context supplies entry without inflating primary counts');
    is(run(\@before,cfg($kind),undef,\@after)->{behavior}{flagged_requests},1,'after context covers the primary entry');
    my $selected=cfg($kind);$selected->{exclude}=['suspected_automation'];
    $selected->{behavior_include}=[$positive->{details}[1]{request_id}];
    my $kept=run($rows,$selected);
    is($kept->{adjusted_requests}{excluded},$n-1,'request-ID override retains a burst entry');
    ok($kept->{details}[1]{$kind.'_evidence'},'override preserves evidence');
    for my $change (['window_seconds',3601],['entry_paths',['/?secret=x']],['entry_paths',['/','/']]) {
        ok(!eval {cfg($kind,@$change);1},'invalid burst setting refused: '.$change->[0]);
    }
}
my $back=rows('backdoor_probe');$_->{method}='GET' for @$back;
is(run($back,cfg('backdoor_probe'))->{behavior}{flagged_requests},0,'backdoor pattern requires POST corroboration');
$back=rows('backdoor_probe');$_->{target}='/wp-plain.php' for @$back[3..5];
is(run($back,cfg('backdoor_probe'))->{behavior}{flagged_requests},0,'one repeated path is insufficient');
my $proto=rows('protocol_probe');$_->{user_agent}='Mozilla/5.0 (Windows) Chrome/131.0' for @$proto;
is(run($proto,cfg('protocol_probe'))->{behavior}{flagged_requests},0,'browser headers alone are insufficient');
for my $token ('Xpython-httpx','python-httpx_custom','python-httpx-suffix') {
    $proto=rows('protocol_probe');$_->{user_agent}=$token.'/1' for @$proto;
    is(run($proto,cfg('protocol_probe'))->{behavior}{flagged_requests},0,'tool marker collision abstains');
}
$proto=rows('protocol_probe');$proto->[3]{method}='GET';$proto->[4]{method}='POST';
is(run($proto,cfg('protocol_probe'))->{behavior}{flagged_requests},0,'endpoint method roles are required');
for my $change (['paths',[]],['min_requests',1],['distinct_paths',1],['not_found_requests',1],['post_requests',0]) {
    ok(!eval {cfg('backdoor_probe',@$change);1},'invalid backdoor setting refused: '.$change->[0]);
}
for my $change (['post_paths',[]],['get_paths',[]],['tool_tokens',[]],['tool_tokens',['Chrome']],
        ['post_paths',['/sse']],['entry_paths',['/mcp']]) {
    ok(!eval {cfg('protocol_probe',@$change);1},'invalid protocol setting refused: '.$change->[0]);
}
done_testing;
