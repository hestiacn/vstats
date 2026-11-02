use v5.020;
use strict;
use warnings;
use Test::More;
use JSON::PP;
use Digest::SHA qw(sha256_hex);
use VStats::TrafficClassifier;
my $C='VStats::TrafficClassifier'; my $J=JSON::PP->new->utf8->canonical;
my $ua='Mozilla/5.0 (Linux; Android 8) Chrome/60.0';
sub rows {
    return [map {+{timestamp=>100+int($_/2),client=>'192.0.2.1',host=>'app.example.test',
        target=>'/probe/'.($_%20).'?private=SECRET',status=>$_<10?404:200,user_agent=>$ua}} 0..29];
}
sub config {
    my (%extra)=@_;
    return $C->config($J->encode({schema_version=>1,rapid_scan=>{enabled=>1},%extra}));
}
sub report {
    my ($records,$cfg,$format)=@_; $cfg//=config(); $format//='jsonl';
    my $e=$C->new(config=>$cfg,format=>$format,details=>1);
    my $raw=ref($records) ? join('',map {$J->encode($_)."\n"} @$records):$records;
    $e->feed($raw); return $e->finish;
}
sub flagged {return $_[0]{behavior}{rapid_scan_flagged_requests};}
my $positive=report(rows());
is(flagged($positive),30,'single browser qualifies with coincident volume, content paths and 404s');
is($positive->{behavior}{flagged_requests},30,'rapid rule participates in suspicion union');
is($positive->{behavior}{broad_flagged_requests},0,'independent broad rule remains disabled');
is($positive->{behavior}{probing_flagged_requests},0,'independent endpoint rule remains disabled');
is($positive->{behavior}{merged_sequences},1,'one rapid sequence');
is_deeply($positive->{actors},{unknown=>30,declared_crawler_or_tool=>0,verified_crawler=>0},'heuristic supplies no actor identity');
for my $r (@{$positive->{details}}) {
    ok($r->{rapid_scan_flagged} && $r->{suspected_automation} && !$r->{broad_probing_flagged} && !$r->{probing_flagged},'flags identify the actual rule');
    my $p=$r->{rapid_scan_evidence};
    ok($p->{from}<=$r->{timestamp} && $r->{timestamp}<=$p->{until},'witness covers the flagged request');
    ok($p->{requests}>=30 && $p->{distinct_paths}>=20 && $p->{not_found_requests}>=10 && $p->{until}-$p->{from}<=60,'witness meets every configured condition');
    is($p->{distinct_user_agents},1,'one user-agent is observed, not a rotation condition');
    is($p->{distinct_platforms},1,'one platform is observed, not an eligibility condition');
}
is(flagged(report(rows(),$C->config('{"schema_version":1}'))),0,'new rule is opt-in');
is(flagged(report(rows(),config(rapid_scan=>{enabled=>0}))),0,'explicit disable works');
my $short=rows();pop @$short;is(flagged(report($short)),0,'request count below threshold');
my $few=rows();$_->{target}='/p'.($_->{timestamp}%19) for @$few;
is(flagged(report($few)),0,'path diversity below threshold');
my $success=rows();$_->{status}=200 for @$success;is(flagged(report($success)),0,'fast ordinary successful page browsing is insufficient');
my $errors=rows();$errors->[0]{status}=403;is(flagged(report($errors)),0,'only actual 404s satisfy error threshold');
my $edge=rows();$edge->[-1]{timestamp}=160;is(flagged(report($edge)),30,'inclusive window boundary');
$edge->[-1]{timestamp}=161;is(flagged(report($edge)),0,'one second outside window cannot combine all requests');
my $slow=rows();$slow->[$_]{timestamp}=100+$_*3 for 0..$#$slow;is(flagged(report($slow)),0,'sparse requests do not become a rapid scan');
my $assets=rows();$assets->[$_]{target}='/asset'.$_ .($_%2?'.CSS':'.png') for 0..$#$assets;
is(flagged(report($assets)),0,'ordinary asset errors cannot qualify');
is(report($assets)->{behavior}{rapid_scan_rule}{asset_requests},30,'ignored assets are accounted separately');
my $mixed=rows();push @$mixed,map {+{%$_,target=>'/asset'.$_->{timestamp}.'.js'}} @{rows()};
my $mix=report($mixed);is(flagged($mix),30,'asset requests neither contribute nor receive the request flag');
ok(!grep({$_->{rapid_scan_flagged}} grep {$_->{normalized_target}=~/\.js\z/} @{$mix->{details}}),'ordinary assets remain independently unflagged');
my $none=rows();$_->{user_agent}=undef for @$none;my $no_ua=report($none);
is(flagged($no_ua),30,'missing browser claims do not hide path/error evidence');
is($no_ua->{details}[0]{rapid_scan_evidence}{distinct_user_agents},0,'no invented user-agent for missing fields');
is($no_ua->{details}[0]{rapid_scan_evidence}{distinct_platforms},0,'no invented platform for missing fields');
my $common=join('',map {'192.0.2.1 - - [02/Oct/2026:10:00:'.sprintf('%02d',$_). ' +0000] "GET /p'.($_%20).' HTTP/1.1" '.($_<10?404:200)." 10\n"} 0..29);
is(flagged(report($common,config(),'common')),30,'common logs retain usable path/status evidence');
for my $case (['hostname',sub {$_[0]{client}='client.example.test'}],['missing status',sub {delete $_[0]{status}}],['unsupported target',sub {$_[0]{target}='https://elsewhere.test/' }]) {
    my $r=rows();$case->[1]->($_) for @$r;my $v=report($r);
    is(flagged($v),0,$case->[0].' cannot supply rapid evidence');
    is($v->{behavior}{rapid_scan_rule}{insufficient_fields},30,$case->[0].' is disclosed');
}
my $hosts=rows();$hosts->[$_]{host}='other.example.test' for 0..14;
is(flagged(report($hosts)),0,'different hosts cannot pool a threshold');
my $sources=rows();$sources->[$_]{client}='198.51.100.1' for 0..14;
is(flagged(report($sources)),0,'different IPs cannot pool a threshold');
my $ipv6=rows();$ipv6->[$_]{client}=$_%2?'2001:db8::1':'2001:0db8:0:0:0:0:0:1' for 0..$#$ipv6;
is(flagged(report($ipv6)),30,'equivalent IPv6 spellings share canonical evidence');
my $mapped=rows();$mapped->[$_]{client}='::ffff:192.0.2.1' for 0..14;
is(flagged(report($mapped)),0,'mapped IPv6 does not merge into IPv4');
my @ua=('Mozilla/5.0 (Windows) Chrome/121','Mozilla/5.0 (Windows) Chrome/120','Mozilla/5.0 (X11; Linux) Firefox/121','Mozilla/5.0 (Macintosh) Safari/605');
my $login=[map {+{timestamp=>100+$_*20,client=>'192.0.2.2',target=>'/account/sign-in',status=>302,user_agent=>$ua[$_%4]}} 0..29];
my $fast_config=$C->config($J->encode({schema_version=>1,probing=>{enabled=>1,paths=>['/account/sign-in']}}));
is(report($login,$fast_config)->{behavior}{flagged_requests},0,'slow endpoint sequence stays below short-window volume');
my $sustained_config=$C->config($J->encode({schema_version=>1,probing=>{enabled=>1,window_seconds=>900,paths=>['/account/sign-in']}}));
my $sustained=report($login,$sustained_config);is($sustained->{behavior}{probing_flagged_requests},30,'configurable longer window detects sustained rotating endpoint probes');
is($sustained->{details}[0]{probing_evidence}{not_found_requests},0,'no invented login failure or missing-endpoint requirement');
my $all=rows();$all->[$_]{user_agent}=$ua[$_%4] for 0..$#$all;
my $joint_cfg=config(exclude=>['suspected_automation'],behavior=>{enabled=>1,min_requests=>30,distinct_paths=>20},probing=>{enabled=>1,paths=>[map {'/probe/'.$_} 0..19]});
my $joint=report($all,$joint_cfg);
is_deeply([@{$joint->{behavior}}{qw(broad_flagged_requests probing_flagged_requests rapid_scan_flagged_requests overlap_requests flagged_requests)}],[30,30,30,30,30],'three-rule overlap counts each request once');
ok(!grep({!$_->{behavior_evidence} || !$_->{probing_evidence} || !$_->{rapid_scan_evidence}} @{$joint->{details}}),'three independent witnesses are retained');
$joint_cfg->{behavior_include}=[$joint->{details}[0]{request_id}];my $kept=report($all,$joint_cfg);
is($kept->{adjusted_requests}{excluded},29,'request-ID exception overrides behavioral union');
ok($kept->{details}[0]{behavior_included} && $kept->{details}[0]{rapid_scan_evidence},'exception retains rapid evidence');
my $caps=config(limits=>{groups=>1});my $two=rows();$_->{user_agent}=undef for @$two;
push @$two,map {+{%$_,client=>'192.0.2.2'}} @$two;
ok(!eval {report($two,$caps);1},'rapid source/host groups respect resource cap even with no UA');
for my $bad (undef,[],{enabled=>2},{window_seconds=>0},{window_seconds=>3601},{min_requests=>1},{min_requests=>29,distinct_paths=>30},{not_found_requests=>31},{distinct_paths=>1},{unknown=>1}) {
    ok(!eval {$C->config($J->encode({schema_version=>1,rapid_scan=>$bad}));1},'invalid rapid configuration fails closed');
}
my $aggregate=$C->new(config=>config(),format=>'jsonl');$aggregate->feed(join('',map {$J->encode($_)."\n"} @{rows()}));my $public=$aggregate->finish;
ok(!exists($public->{details}),'aggregate has no request records');
my $html=VStats::TrafficClassifier::html_report($public);like($html,qr/rapid content-path probing: 30/,'HTML names new rule separately');
unlike($html,qr/192\.0\.2\.1|SECRET|Mozilla\/5/,'aggregate HTML does not leak observed IP, queries or raw UA');
done_testing;
