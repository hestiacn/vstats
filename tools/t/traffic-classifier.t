use v5.020;
use strict;
use warnings;
use Test::More;
use JSON::PP ();
use Encode qw(encode);
use Cwd qw(abs_path);
use Socket qw(AF_INET AF_INET6);
use VStats::TrafficClassifier;
my $C='VStats::TrafficClassifier';
my $J=JSON::PP->new->utf8->canonical;
sub cfg { return $C->config($J->encode({schema_version=>1,@_})); }
sub event { return {timestamp=>100,client=>'192.0.2.1',target=>'/',user_agent=>'Mozilla/5.0',@_}; }
sub run {
    my ($config,$events,$snapshots,$details,$format)=@_;
    my $engine=$C->new(config=>$config,format=>$format//'jsonl',snapshots=>$snapshots//[],details=>$details);
    my $raw=ref($events) eq 'ARRAY' ? join('',map {$J->encode($_)."\n"} @$events):$events;
    # Seven-byte chunks deliberately split UTF-8, escapes, CRLF and tokens.
    while (length $raw) { $engine->feed(substr($raw,0,7,'')); }
    return $engine->finish;
}
sub refuses { my ($name,$code)=@_; my $ok=eval {$code->();1}; ok(!$ok,$name); }
my $default=cfg(); is_deeply($default,$C->defaults,'canonical defaults');
my @tokens=('Bytespider/1','Bytespider;','(bytespider)','Googlebot/2.1','python-requests/2','curl/8');
for my $ua (@tokens) { is(run(cfg(),[event(user_agent=>$ua)])->{actors}{declared_crawler_or_tool},1,'marker declares'); }
for my $ua (undef,'','Mozilla/5.0','XBytespider/1','Bytespiderling','Bytespider.foo',"Byte\x{17f}pider/1","Bytespider\x{a0}x") {
    is(run(cfg(),[event(user_agent=>$ua)])->{actors}{unknown},1,'weak UA unknown');
}
is(run(cfg(crawler_tokens=>[]),[event(user_agent=>'Googlebot/2')])->{actors}{declared_crawler_or_tool},1,'registry declares');
is(run(cfg(crawler_tokens=>['LocalFetch']),[event(user_agent=>'LocalFetch/1')])->{actors}{declared_crawler_or_tool},1,'local token');
is(run(cfg(crawler_tokens=>['LocalFetch']),[event(user_agent=>'curl/1')])->{actors}{unknown},1,'token replacement');
for my $key (qw(schema_version hosts crawler_tokens probe_families site_references scanner verification limits exclude)) {
    refuses("null config $key",sub {$C->config($J->encode({schema_version=>1,$key=>undef}))});
}
for my $bad ('{"schema_version":1,"extra":0}','{"schema_version":"1"}','{"schema_version":1.0}','{"schema_version":1e0}','{"schema_version":-0}',
    '{"schema_version":1,"schema_version":1}','{"schema_version":1,"scanner":{"distinct_paths":3,"distinct_\\u0070aths":3}}') {
    refuses('strict config lexical/type/duplicate/unknown rejection',sub {$C->config($bad)});
}
for my $patch (
    [crawler_tokens=>['Mozilla']],[crawler_tokens=>['Chrome']],[crawler_tokens=>['bot.*']],[crawler_tokens=>['x','X']],
    [scanner=>{distinct_paths=>0}],[scanner=>{window_seconds=>3601}],[scanner=>{distinct_paths=>2,distinct_families=>3}],
    [scanner=>{distinct_paths=>'3'}],[scanner=>{distinct_paths=>JSON::PP::true}],[scanner=>{unknown=>1}],
    [verification=>{max_gap_seconds=>604801}],[exclude=>['unknown']],[exclude=>['scanner_flagged','scanner_flagged']],
    [limits=>{input_bytes=>67108865}],[limits=>{records=>0}],[limits=>{groups=>'1'}],
    [hosts=>['example.test','EXAMPLE.TEST.']],[hosts=>['192.0.2.1']],[hosts=>['under_score.test']],[hosts=>['example.test:80']]
) { refuses('bad configuration refused',sub {cfg(@$patch)}); }
for my $p ('/a?x=1','/a#b','//a','http://example.test/a','*','a','/a/../b','/./x','/a//b','/a%2fb','/a%5cb','/a%00','/a%2','/a%252e','/a%3fb','/a%23b',"/\x{e9}") {
    my $normal=VStats::TrafficClassifier::normalize_target($p);
    if ($p eq '/a?x=1' || $p eq '/a#b') { is($normal,'/a','strip query/fragment'); }
    else { ok(!defined $normal,'unsafe target'); }
}
is(VStats::TrafficClassifier::normalize_target('/%2eenv?x=%oops'),'/.env','single decode');
is(VStats::TrafficClassifier::normalize_target('/A/'),' /A/' =~ s/^ //r,'case/trailing slash');
my @families=(
    {id=>'environment',paths=>['/.env','/config.php'],absent_from=>0,absent_until=>1000},
    {id=>'git',paths=>['/.git/config'],absent_from=>0,absent_until=>1000},
);
sub probes {return cfg(probe_families=>\@families,@_);}
my @sequence=(event(timestamp=>100,target=>'/.env'),event(timestamp=>130,target=>'/config.php'),event(timestamp=>160,target=>'/.git/config'),event(timestamp=>140,target=>'/ordinary'));
my $s=run(probes(),\@sequence,[],1);
is($s->{scanner_flagged_requests},3,'members at <=60s');
is($s->{merged_scanner_sequences},1,'one sequence');
is_deeply([map {$_->{scanner_flagged}?1:0} @{$s->{details}}],[1,1,1,0],'earlier probes only');
is($s->{actors}{unknown},4,'scanner != actor');
my @outside=map {{%$_}} @sequence; $outside[2]{timestamp}=161;
is(run(probes(),\@outside)->{scanner_flagged_requests},0,'61s rejected');
is(run(probes(),[map {event(timestamp=>100,target=>'/.env')} 1..5])->{scanner_flagged_requests},0,'distinct paths');
my @onefamily=@families; $onefamily[1]={%{$families[1]},id=>'other'};
is(run(cfg(probe_families=>[{id=>'one',paths=>['/.env','/config.php','/.git/config'],absent_from=>0,absent_until=>1000}]),\@sequence)->{scanner_flagged_requests},0,'distinct families');
for my $field (qw(client user_agent)) {
    my @split=map {{%$_}} @sequence; $split[2]{$field}= $field eq 'client'?'192.0.2.2':'different';
    is(run(probes(),\@split)->{scanner_flagged_requests},0,'group isolation');
}
my @missing=map {{%$_,user_agent=>undef}} @sequence;
is(run(probes(),\@missing)->{scanner_insufficient_fields},4,'missing UA count');
is(run(probes(),\@missing)->{scanner_flagged_requests},0,'missing UA ungrouped');
is(run(probes(site_references=>[{path=>'/.env',from=>120,until=>120}]),\@sequence)->{scanner_flagged_requests},0,'reference exemption');
my @partial=map {{%$_}} @families; $partial[0]{absent_until}=159;
my $inactive=run(cfg(probe_families=>\@partial),\@sequence);
is($inactive->{scanner_flagged_requests},0,'absence coverage');
is(scalar @{$inactive->{probes}{inactive_families}},1,'inactive status');
refuses('path uniqueness',sub {cfg(probe_families=>[ @families,{id=>'duplicate',paths=>['/.env'],absent_from=>0,absent_until=>1000}])});
refuses('path normal form',sub {cfg(probe_families=>[{id=>'x',paths=>['/%2eenv'],absent_from=>0,absent_until=>1000}])});
my @declared=map {{%$_,user_agent=>'Bytespider;'}} @sequence;
my $excluded=run(probes(exclude=>['declared_crawler_or_tool','scanner_flagged']),\@declared);
is_deeply([@{$excluded->{adjusted_requests}}{qw(original excluded remaining)}],[4,4,0],'exclusion union');
is(run(probes(exclude=>['scanner_flagged']),\@sequence)->{adjusted_requests}{remaining},1,'scanner exclusion');
ok(!exists run(probes(),\@sequence)->{adjusted_requests},'no default exclusion');

# Independent interval oracle: spans, members, union; no shared helpers.
sub oracle {
    my ($records,$P,$F,$W)=@_; my %family=('/.env'=>'environment','/config.php'=>'environment','/.git/config'=>'git');
    my @probes=sort {$a->{timestamp}<=>$b->{timestamp}} grep {exists $family{$_->{target}}} @$records;
    my (%flag,@spans);
    for my $a (0..$#probes) {for my $b ($a..$#probes) {
        next if $probes[$b]{timestamp}-$probes[$a]{timestamp}>$W;
        my (%paths,%families);
        for my $i ($a..$b) {$paths{$probes[$i]{target}}=1; $families{$family{$probes[$i]{target}}}=1;}
        next if keys(%paths)<$P || keys(%families)<$F;
        $flag{$probes[$_]{identity}}=1 for $a..$b;
        push @spans,[$probes[$a]{timestamp},$probes[$b]{timestamp}];
    }}
    my ($count,$end)=(0,undef);
    for my $span (sort {$a->[0]<=>$b->[0] || $a->[1]<=>$b->[1]} @spans) {
        if (!defined($end) || $span->[0]>$end) {$count++;$end=$span->[1];}
        elsif ($span->[1]>$end) {$end=$span->[1];}
    }
    return (scalar(keys %flag),$count);
}
my @paths=('/.env','/config.php','/.git/config'); my @times=(0,60,61);
my $oracle_ok=1;
# Exhaustive 9^3=729 three-record fixtures, not sampled.
for my $code (0..728) {
    my $n=$code; my @r;
    for my $i (0..2) {my $v=$n%9;$n=int($n/9);push @r,event(timestamp=>100+$times[int($v/3)],target=>$paths[$v%3],identity=>$i);}
    my ($expected,$seq)=oracle(\@r,3,2,60);
    delete $_->{identity} for @r;
    my $actual=run(probes(),\@r);
    $oracle_ok &&= $actual->{scanner_flagged_requests}==$expected && $actual->{merged_scanner_sequences}==$seq;
}
ok($oracle_ok,'729 exhaustive oracle controls');
my @long=(map {event(timestamp=>100+$_*30,target=>$paths[$_%3],identity=>$_)} 0..5);
push @long,map {event(timestamp=>500+$_*30,target=>$paths[$_%3],identity=>$_+6)} 0..2;
my ($ef,$es)=oracle(\@long,3,2,60); delete $_->{identity} for @long;
my $lr=run(probes(),\@long); is_deeply([$lr->{scanner_flagged_requests},$lr->{merged_scanner_sequences}],[$ef,$es],'chain/union oracle');
my $reversed=run(probes(),[reverse @long]); is_deeply([$reversed->{scanner_flagged_requests},$reversed->{merged_scanner_sequences}],[$ef,$es],'permutation');
my $sensitive=run(probes(scanner=>{distinct_paths=>1,distinct_families=>1,window_seconds=>1}),[event(target=>'/.env')]);
is($sensitive->{scanner_flagged_requests},1,'custom thresholds');ok($sensitive->{effective}{scanner_nondefault},'nondefault flag');

# Independent CIDR oracle: IPv4 integers, not prefix strings.
my @cidrs=('192.0.2.0/24','198.51.100.128/25'); my $index=VStats::TrafficClassifier::cidr_index(\@cidrs);
my $cidr_ok=1;
for my $last (0..255) {
    for my $third (99,100,101) {
        my $ip="198.51.$third.$last"; my $number=198*16777216+51*65536+$third*256+$last;
        my $start=198*16777216+51*65536+100*256+128;
        my $expected=($number>=$start && $number<$start+128)?1:0;
        $cidr_ok &&= VStats::TrafficClassifier::cidr_contains($index,$ip)==$expected;
    }
}
ok($cidr_ok,'IPv4 oracle');
my $v6=VStats::TrafficClassifier::cidr_index(['2001:db8::/32']);
ok(VStats::TrafficClassifier::cidr_contains($v6,'2001:db8:ffff::1'),'IPv6 inside');
ok(!VStats::TrafficClassifier::cidr_contains($v6,'2001:db9::'),'IPv6 outside');
ok(!VStats::TrafficClassifier::cidr_contains($index,'::ffff:192.0.2.1'),'IPv4-mapped split');
for my $bad ('192.0.2.1/24','2001:db8::1/32','192.0.2.0/33','2001:db8::/129','hostname/24') {refuses('invalid CIDR refused',sub {VStats::TrafficClassifier::cidr_index([$bad])});}
sub snap {
    my ($t,$prefix,$creation)=@_;
    return $C->snapshot($J->encode({creationTime=>$creation//'provider timestamp',prefixes=>[{ipv4Prefix=>$prefix//'192.0.2.0/24'},{ipv6Prefix=>'2001:db8::/32'}]}),$J->encode({provider_id=>'google_common',source_url=>'https://developers.google.com/static/crawling/ipranges/common-crawlers.json',retrieved_at=>$t}));
}
my $a=snap('1970-01-01T00:01:30Z'); my $b=snap('1970-01-01T00:01:50Z');
my $google=event(user_agent=>'Googlebot/2');
is(run(cfg(),[$google],[$a,$b])->{actors}{verified_crawler},1,'brackets verify');
is(run(cfg(),[$google],[$a])->{verification_outcomes}{unavailable},1,'one-sided unavailable');
is(run(cfg(),[event(timestamp=>90,user_agent=>'Googlebot/2')],[$a])->{actors}{verified_crawler},1,'exact timestamp');
is(run(cfg(verification=>{max_gap_seconds=>19}),[$google],[$a,$b])->{verification_outcomes}{unavailable},1,'gap unavailable');
is(run(cfg(verification=>{max_gap_seconds=>20}),[$google],[$a,$b])->{actors}{verified_crawler},1,'gap inclusive');
my $outside=snap('1970-01-01T00:01:50Z','198.51.100.0/24');
is(run(cfg(),[$google],[$a,$outside])->{verification_outcomes}{failed},1,'bracket intersection');
is(run(cfg(),[event(client=>'2001:db8::1',user_agent=>'Googlebot/2')],[$a,$b])->{actors}{verified_crawler},1,'IPv6 bracket');
is(run(cfg(),[event(client=>'name.test',user_agent=>'Googlebot/2')],[$a,$b])->{verification_outcomes}{unavailable},1,'hostname unavailable');
is(run(cfg(),[event(client=>'::ffff:192.0.2.1',user_agent=>'Googlebot/2')],[$a,$b])->{verification_outcomes}{failed},1,'mapped-IP failed');
is(run(cfg(),[event()],[$a,$b])->{actors}{unknown},1,'IP alone unknown');
refuses('duplicate evidence timestamp refused',sub {run(cfg(),[$google],[$a,$a])});
for my $bad (
    [{creationTime=>'x',prefixes=>[]},{provider_id=>'google_common',source_url=>'https://developers.google.com/static/crawling/ipranges/common-crawlers.json',retrieved_at=>'1970-01-01T00:01:30Z'}],
    [{creationTime=>'x',prefixes=>[{ipv4Prefix=>'2001:db8::/32'}]},{provider_id=>'google_common',source_url=>'https://developers.google.com/static/crawling/ipranges/common-crawlers.json',retrieved_at=>'1970-01-01T00:01:30Z'}],
    [{creationTime=>'x',prefixes=>[{ipv4Prefix=>'192.0.2.0/24'}]},{provider_id=>'other',source_url=>'https://example.test/',retrieved_at=>'1970-01-01T00:01:30Z'}]
) { refuses('bad provider evidence refused',sub {$C->snapshot(map {$J->encode($_)} @$bad)}); }
my $hosted=run(cfg(hosts=>['EXAMPLE.TEST.']),[event(host=>'example.test'),event(host=>'other.test'),event()]);
is_deeply([@{$hosted->{counts}}{qw(parsed host_missing out_of_scope analyzed)}],[3,1,1,1],'host scope counts');
refuses('hostless refused',sub {run(cfg(hosts=>['example.test']),[event()])});
my $invalidhost=$J->encode(event(host=>'bad_host'))."\n".$J->encode(event())."\n";
is(run(cfg(),$invalidhost)->{counts}{unparsed},1,'invalid host');
my $common='192.0.2.1 - - [01/Jan/1970:01:01:40 +0100] "GET / HTTP/1.1" 200 10';
for my $slot (0..2) {
    for my $token ("\xC3\xA0","\xC3\x85","\x0B") {
        my @prefix=('192.0.2.1','-','-');$prefix[$slot]=$token;
        my $line=$common;$line =~ s/\A[^ ]+ - - /join(' ',@prefix).' '/e;
        is(run(cfg(),$line."\n".$common."\n",[],0,'common')->{counts}{parsed},2,"space/tab token $slot");
    }
}
my $crlf=run(cfg(),$common."\r\n",[],1,'common');
is($crlf->{input}{period}{from},100,'timezone/CRLF');
is($crlf->{actors}{unknown},1,'common UA unknown');
my $combined=$common.' "-" "Bytespider;"';
is(run(cfg(),$combined."\n",[],0,'combined')->{actors}{declared_crawler_or_tool},1,'combined UA');
my $escaped=$common.' "a\\tref" "Bytespider\\x3b\\tvalue"';
is(run(cfg(),$escaped."\n",[],1,'combined')->{details}[0]{user_agent},"Bytespider;\tvalue",'Apache decode');
my $bad_date=$common; $bad_date =~ s{01/Jan}{31/Feb};
is(run(cfg(),$bad_date."\n".$common."\n",[],0,'common')->{counts}{unparsed},1,'calendar refusal');
my $lexemes="{\"timestamp\":1e2,\"client\":\"192.0.2.1\",\"target\":\"/\"}\n".$J->encode(event())."\n";
is(run(cfg(),$lexemes)->{counts}{unparsed},1,'timestamp lexemes');
my $dup="{\"timestamp\":100,\"client\":\"192.0.2.1\",\"target\":\"/\",\"t\\u0061rget\":\"/\"}\n".$J->encode(event())."\n";
is(run(cfg(),$dup)->{counts}{unparsed},1,'duplicate keys');
# Differential strings/Unicode/containers via PP.
for my $path ('/'.('a'x70000),'/'.('\u0061'x40000)) {
    my $raw='{"schema_version":1,"site_references":[{"path":"'.$path.'","from":0,"until":1}]}';
    my $expected=$J->decode($raw)->{site_references};
    is_deeply($C->config($raw)->{site_references},$expected,'long JSON path vs PP');
}
for my $object ({a=>'quote"\\',b=>[0,1,undef,JSON::PP::true]}, {a=>"\x{e9}",b=>{c=>'\u0061'}}, {a=>'not a key: "x"',b=>['a:b']}) {
    is_deeply(VStats::TrafficClassifier::strict_json($J->encode($object)),$J->decode($J->encode($object)),'JSON vs PP');
}
my $caps=cfg(limits=>{line_bytes=>256,ua_bytes=>64,target_bytes=>64});
my $oversized=('x'x1000)."\r\n".$J->encode(event())."\n";
my $over=run($caps,$oversized);is_deeply([@{$over->{counts}}{qw(lines_total unparsed oversized parsed)}],[2,1,1,1],'oversize discard');
my $field_over=$J->encode(event(user_agent=>'A'x65))."\n".$J->encode(event())."\n";
is(run($caps,$field_over)->{counts}{oversized},1,'field cap');
refuses('malformed quota',sub {run(cfg(limits=>{records=>1}),"malformed\n".$J->encode(event())."\n")});
refuses('byte quota',sub {run(cfg(limits=>{input_bytes=>1}),[event()])});
refuses('all-host groups',sub {run(cfg(hosts=>['example.test'],limits=>{groups=>1}),[event(host=>'other.test'),event(host=>'example.test',client=>'192.0.2.2')])});
my $hostperiod=run(probes(hosts=>['example.test']),[map {{%$_,host=>'example.test'}} @sequence,event(timestamp=>2000,host=>'other.test')]);
is($hostperiod->{scanner_flagged_requests},0,'all-parsed period');
my $xss=event(user_agent=>'<script>alert(1)</script>',target=>'/<img>');
my $private=run(cfg(),[$xss],[],1);my $html=VStats::TrafficClassifier::html_report($private);
unlike($html,qr/<script>|<img>/,'HTML escaping');like($html,qr/&lt;script&gt;/,'opt-in details');
my $summary=run(cfg(),[$xss]);my $json=VStats::TrafficClassifier::canonical_json($summary);
unlike($json,qr/alert\(1\)|192\.0\.2\.1|\/<img>/,'default privacy');
is(VStats::TrafficClassifier::canonical_json(run(cfg(),[$xss])),$json,'determinism');
is_deeply([map {$summary->{counts}{$_}} qw(lines_total blank unparsed parsed)],[1,0,0,1],'line identity');
is(eval {my $e=$C->new(config=>cfg(),format=>'jsonl');$e->feed($J->encode(event())."\n");$e->finish;$e->finish;1},undef,'single finish');
my $root=abs_path(__FILE__);$root =~ s{/tools/t/[^/]+\z}{};
our $Debug=0;require "$root/wwwroot/cgi-bin/lib/robots.pm";
for my $ua ('Bytespider','Bytespider;', 'XBytespider/1','Bytespiderling',"Byte\x{17f}pider/1","Bytespider\x{a0}x",'Mobile_(Bytespider;_x)') {
    is(VStats::TrafficClassifier::marker_matches($ua,'Bytespider'),BytespiderRobotID($ua)?1:0,'shared boundary');
}
# Resource bounds; independent IPv6 hextet arithmetic.
refuses('config byte cap',sub {$C->config(' 'x1048577)});
refuses('token cardinality bounded',sub {cfg(crawler_tokens=>[map {'Tool'.$_} 1..129])});
refuses('token length bounded',sub {cfg(crawler_tokens=>['A'x65])});
refuses('family cap',sub {cfg(probe_families=>[map {{id=>'f'.$_,paths=>['/f'.$_],absent_from=>0,absent_until=>1000}} 1..65])});
refuses('path cap',sub {cfg(probe_families=>[{id=>'x',paths=>[map {'/p'.$_} 1..2049],absent_from=>0,absent_until=>1000}])});
refuses('reference cap',sub {cfg(site_references=>[map {{path=>'/r'.$_,from=>0,until=>1000}} 1..2049])});
refuses('reference uniqueness',sub {cfg(site_references=>[{path=>'/a',from=>0,until=>1},{path=>'/a',from=>2,until=>3}])});
refuses('deep JSON refused',sub {VStats::TrafficClassifier::strict_json(('['x40).'0'.(']'x40))});
refuses('snapshot cap',sub {run(cfg(),[$google],[($a)x33])});
refuses('provider raw byte cap',sub {$C->snapshot(' 'x2097153,'{}')});
refuses('attestation byte cap',sub {$C->snapshot('{}',' 'x16385)});
my $v6_oracle_ok=1;
for my $n (0..128) {
    my @network=(0x2001,0xdb8,0,0,0,0,0,0);
    for my $word (0..7) {
        my $kept=$n-$word*16;
        $network[$word]=0 if $kept<=0;
        $network[$word]&=((0xffff << (16-$kept)) & 0xffff) if $kept>0 && $kept<16;
    }
    my $address=join(':',map {sprintf '%x',$_} @network);
    my $idx=VStats::TrafficClassifier::cidr_index([$address.'/'.$n]);
    for my $bit (0,($n ? $n-1:0),($n<128?$n:127),127) {
        my @candidate=@network;$candidate[int($bit/16)] ^= 1 << (15-$bit%16);
        my $ip=join(':',map {sprintf '%x',$_} @candidate);
        my $expected=$bit<$n ? 0:1;
        $v6_oracle_ok &&= VStats::TrafficClassifier::cidr_contains($idx,$ip)==$expected;
    }
}
ok($v6_oracle_ok,'IPv6 all-prefix oracle');
my $exact=$J->encode(event());$exact.=' 'x(256-length($exact));
is(run($caps,$exact."\r\n")->{counts}{parsed},1,'CRLF cap boundary');
my $overboundary=run($caps,$exact." \n".$J->encode(event())."\n");
is($overboundary->{counts}{oversized},1,'cap+1 oversized');
my $same_config=cfg();my $before=$J->encode($same_config);run($same_config,[event()]);is($J->encode($same_config),$before,'config immutable');
VStats::TrafficClassifier::html_report($summary);is(VStats::TrafficClassifier::canonical_json($summary),$json,'report immutable');
my $provider_xss=snap('1970-01-01T00:01:40Z',undef,'<svg onload="x">');
unlike(VStats::TrafficClassifier::html_report(run(cfg(),[$google],[$provider_xss])),qr/<svg/,'metadata escaped');
is(VStats::TrafficClassifier::normalize_target('/a%20b'),'/a b','encoded SP allowed');
is(VStats::TrafficClassifier::normalize_target('/a b'),'/a b','literal SP accepted');
ok(!defined VStats::TrafficClassifier::normalize_target('/a%7F'),'DEL remains refused');
ok(cfg(probe_families=>[{id=>'space',paths=>['/a b'],absent_from=>0,absent_until=>1000}]),'SP probe');
refuses('encoded config refused',sub {cfg(probe_families=>[{id=>'space',paths=>['/a%20b'],absent_from=>0,absent_until=>1000}])});
is(run(cfg(),[event(target=>'/a%20b')])->{unsupported_targets},0,'encoded SP supported');
refuses('decoded key alias rejected',sub {VStats::TrafficClassifier::strict_json('{"a":1,"\u0061":2}')});
# P6 refusal table independent of implementation regexes.
my ($raw_ascii,$encoded_ascii)=(1,1);
for my $octet (0..127) {
    my $char=chr($octet);my $path='/a'.$char.'b';
    my $expected=($octet>=32 && $octet<=126 && $octet!=37 && $octet!=92)
        ? (($octet==35 || $octet==63)?'/a':$path):undef;
    my $actual=VStats::TrafficClassifier::normalize_target($path);
    $raw_ascii &&= defined($expected)?defined($actual) && $actual eq $expected:!defined($actual);
    my $percent='/a'.sprintf('%%%02X',$octet).'b';
    my $allowed=$octet>=32 && $octet<=126 && !grep {$_==$octet} (35,37,47,63,92);
    my $decoded=VStats::TrafficClassifier::normalize_target($percent);
    $encoded_ascii &&= $allowed ? defined($decoded) && $decoded eq $path:!defined($decoded);
}
ok($raw_ascii,'raw ASCII refusal table');
ok($encoded_ascii,'encoded ASCII refusal table');
for my $replacement (':01:60 +0100',':01:40 +2400',':01:40 +0060') {
    my $bad=$common;$bad =~ s/:01:40 \+0100/$replacement/;
    is(run(cfg(),$bad."\n".$common."\n",[],0,'common')->{counts}{unparsed},1,'second/offset refusal');
}
refuses('snapshot leap second refused',sub {snap('1970-01-01T23:59:60Z')});
my $epoch_cross='192.0.2.1 - - [31/Dec/1969:23:00:00 -0100] "GET / HTTP/1.1" 200 1';
is(eval {run(cfg(),$epoch_cross."\n",[],0,'common')->{input}{period}{from}},0,'epoch crossing');
done_testing;
