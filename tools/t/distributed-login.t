use v5.020;
use strict;
use warnings;
use Test::More;
use JSON::PP;
use Digest::SHA qw(sha256_hex);
use POSIX qw(floor);
use Socket qw(AF_INET AF_INET6 inet_pton);
use VStats::TrafficClassifier;
my $C='VStats::TrafficClassifier';my $J=JSON::PP->new->utf8->canonical;
my %rule=(enabled=>1,window_seconds=>60,login_paths=>['/account/login'],admin_paths=>['/admin']);
sub config {return $C->config($J->encode({schema_version=>1,distributed_login=>{%rule,@_}}));}
sub clone {return $J->decode($J->encode($_[0]));}
sub rows {
    my @out;
    for my $ip (1..3) {
        my @uas=('Mozilla/5.0 (Windows) Chrome/126','Mozilla/5.0 (Linux) Firefox/128',
            "Mozilla/5.0 (Macintosh) Safari/60$ip","Mozilla/5.0 (Windows) Chrome/13$ip");
        for my $i(0..9) {push @out,{timestamp=>100+$i,client=>"192.0.2.$ip",host=>'example.test',status=>200,
            method=>$i<4?'POST':'GET',target=>$i<4?'/account/login':'/admin',
            user_agent=>$i<4?$uas[$i]:'Mozilla/5.0 (Macintosh) Safari/999'};}
    }
    return \@out;
}
sub run {
    my ($rows,$config)=@_;$config//=config();my $e=$C->new(config=>$config,format=>'jsonl',details=>1);
    my $raw=join('',map {$J->encode($_)."\n"} @$rows);
    while(length $raw){$e->feed(substr($raw,0,17,''));}
    return $e->finish;
}
sub ids {return [sort map {$_->{request_id}} grep {$_->{distributed_login_flagged}} @{$_[0]{details}}];}
my $positive=run(rows());
is($positive->{behavior}{distributed_login_flagged_requests},30,'repeated rotating sources qualify together');
is($positive->{behavior}{flagged_requests},30,'new rule joins union once');
is($positive->{behavior}{merged_sequences},1,'overlapping fixed windows merge');
is_deeply($positive->{actors},{unknown=>30,declared_crawler_or_tool=>0,verified_crawler=>0},'campaign is no identity proof');
is(run(rows(),config(enabled=>0))->{behavior}{flagged_requests},0,'feature opt-out');
is(run(rows(),$C->config('{"schema_version":1}'))->{behavior}{flagged_requests},0,'upstream default is opt-in');
for my $r (@{$positive->{details}}) {
    my $p=$r->{distributed_login_evidence};ok($p->{from}<=$r->{timestamp} && $r->{timestamp}<=$p->{until},'covering campaign witness');
    is_deeply([@{$p}{qw(requests distinct_sources post_requests distinct_user_agents source_requests source_post_requests source_shared_user_agents)}],
        [30,3,12,8,10,4,2],'pool evidence is separate from this source contribution');
    my %byid=map {$_->{request_id}=>$_} @{$positive->{details}};
    my ($post,$get)=@byid{@{$p}{qw(sequence_post_request_id sequence_follow_request_id)}};
    ok($post && $get && $post->{source_key} eq $r->{source_key} && $get->{source_key} eq $r->{source_key} &&
        $post->{method} eq 'POST' && $get->{method} eq 'GET' && $post->{timestamp}<=$get->{timestamp},'source sequence IDs resolve independently');
}
for my $case (
    ['missing methods',sub {delete $_->{method} for @{$_[0]}}],
    ['missing status',sub {delete $_->{status} for @{$_[0]}}],
    ['single platform',sub {$_->{user_agent}=~s/Linux|Macintosh/Windows/g for @{$_[0]}}],
    ['one-off POST source',sub {$_[0][$_]{method}='GET' for 1..3}],
    ['different hosts',sub {$_->{host}='site'.substr($_->{client},-1).'.test' for @{$_[0]}}],
    ['no follow-up',sub {for (@{$_[0]}) {$_->{method}='POST';$_->{target}='/account/login';}}],
    ['unconfigured paths',sub {$_->{target}='/elsewhere' for @{$_[0]}}],
    ['ambiguous encoded slash',sub {$_->{target}='/account%2flogin' for @{$_[0]}}],
    ['POSTs without browser claim',sub {$_->{user_agent}='Fetch/1' for grep {$_->{method} eq 'POST'} @{$_[0]}}],
    ['coherent ordinary admin flow',sub {$_[0][4]{user_agent}=$_[0][0]{user_agent}}],
    ['separate windows',sub {$_->{timestamp}+=100*substr($_->{client},-1) for @{$_[0]}}],
    ['no shared POST agents',sub {$_->{user_agent}.=' local-'.$_->{client} for @{$_[0]}}]
) {
    my $r=rows();$case->[1]->($r);is(run($r)->{behavior}{distributed_login_flagged_requests},0,$case->[0].' cannot qualify a campaign');
}
my $stable=rows();push @$stable,{%{$stable->[0]},timestamp=>90}, {%{$stable->[0]},timestamp=>91,method=>'GET',target=>'/admin'};
my $abstain=run($stable);is($abstain->{behavior}{distributed_login_flagged_requests},0,'coherent flow outside candidate bucket vetoes entire source/input');
is($abstain->{behavior}{distributed_login_rule}{stable_flow_source_groups},1,'stable-flow abstention disclosed');
my $extra=rows();push @$extra,{%{$extra->[0]},client=>'198.51.100.100',method=>'GET',target=>'/admin'},
    {%{$extra->[0]},client=>'198.51.100.101',method=>'POST'},
    {%{$extra->[0]},target=>'/style.css',method=>'GET'};
my $extra_report=run($extra);is_deeply([map {$_->{distributed_login_flagged}?1:0} @{$extra_report->{details}}],[(1)x30,0,0,0],'nearby one-off and asset requests are not attributed');
my $v6=rows();for(0..9){$v6->[$_]{client}=$_%2?'2001:db8::1':'2001:0db8:0:0:0:0:0:1';}
is(run($v6)->{behavior}{distributed_login_flagged_requests},30,'equivalent IPv6 spellings share a participant');
my $epoch=rows();$_->{timestamp}-=100 for @$epoch;is(run($epoch)->{behavior}{distributed_login_flagged_requests},30,'epoch-zero offset grid uses floor rather than truncation');
my $reversed=run([reverse @{rows()}]);is_deeply(ids($reversed),ids($positive),'input ordering does not change request attribution');
my $include=config();$include->{exclude}=['suspected_automation'];$include->{behavior_include}=[sha256_hex($J->encode(rows()->[0]))];
my $included=run(rows(),$include);is($included->{adjusted_requests}{excluded},29,'request-ID inclusion overrides distributed flag');
ok($included->{details}[0]{distributed_login_flagged} && $included->{details}[0]{behavior_included},'override retains evidence');
my $both=config();$both->{probing}=$C->config($J->encode({schema_version=>1,probing=>{enabled=>1,window_seconds=>60,min_requests=>10,distinct_user_agents=>4,distinct_platforms=>2,paths=>['/account/login','/admin']}}))->{probing};
my $joint=run(rows(),$both);is_deeply([@{$joint->{behavior}}{qw(probing_flagged_requests distributed_login_flagged_requests flagged_requests overlap_requests eligible_requests)}],[30,30,30,30,30],'union and overlap count each row once');
my @chain;
for my $ip(1..5){my @part=map {+{%$_,client=>"192.0.2.$ip"}} @{rows()}[0..9];
    for my $i(0..3){my $edge=$i==0?$ip-1:$ip;
        $part[$i]{user_agent}=$i<2?'Mozilla/5.0 ('.($edge%2?'Linux':'Windows').') Chrome/'.(200+$edge):
            'Mozilla/5.0 ('.($i%2?'Macintosh':'Windows').') Chrome/'.(300+$ip*10+$i);}
    push @chain,@part;
}
is(run(\@chain,config(shared_user_agents=>2))->{behavior}{distributed_login_flagged_requests},0,'iterative peer peeling removes a cascade, not just its endpoints');
my $peeled=run(\@chain,config(shared_user_agents=>2));
my @peer_diagnostics=map {@{$_->{distributed_login_diagnostics}}} @{$peeled->{details}};
@peer_diagnostics=grep {grep {$_ eq 'peer_agent_evidence'} @{$_->{reasons}}} @peer_diagnostics;
ok(@peer_diagnostics,'cascade produces retained peer-evidence diagnostics');
is_deeply([sort {$a<=>$b} map {$_->{source_shared_user_agents}} @peer_diagnostics],[(0)x scalar(@peer_diagnostics)],'removed participants report actual surviving-peer evidence, not elimination-time counts');

is_deeply(ids(run(\@chain,config(shared_user_agents=>2))),oracle(\@chain,config(shared_user_agents=>2)),'independent peer-core oracle agrees on cascade');
for my $change ({min_sources=>1},{min_source_posts=>1},{distinct_source_platforms=>1},{shared_user_agents=>0},{admin_paths=>[]},{login_paths=>['/admin']},{min_post_requests=>5},{unknown=>1}) {
    ok(!eval {config(%$change);1},'invalid distributed configuration fails closed');
}
for my $method (undef,'','P0ST',[],('A'x33)) {
    my $r=rows();$r->[0]{method}=$method;my $p=run($r);is($p->{counts}{unparsed},1,'malformed supplied method is rejected');
}
my $lower=rows();$_->{method}=lc($_->{method}) for @$lower;is(run($lower)->{behavior}{distributed_login_flagged_requests},30,'ASCII methods normalize uppercase');
my $caps=rows();$caps->[$_]{timestamp}+=100*$_ for 0..$#$caps;
my $cap_config=config();$cap_config->{limits}{groups}=20;
ok(!eval {run($caps,$cap_config);1},'window-group resource cap fails closed');

# Deliberately slow independent oracle: enumerate grid windows, compare all
# ordered event pairs for stable veto/sequence, and repeatedly rebuild peer sets.
# It never calls the production window, source, platform or peeling helpers.
sub oracle {
    my ($rows,$cfg)=@_;my $d=$cfg->{distributed_login};my (@r,%pairs,%starts,%flag);
    for my $i(0..$#$rows){my $r=$rows->[$i];my $ua=$r->{user_agent}//'';
        my $platform=$ua=~/Windows/?'windows':$ua=~/Macintosh/?'mac':$ua=~/Linux/?'linux':undef;
        next if !defined($platform) || !defined($r->{method}) || !defined($r->{status});
        my $packed=eval {inet_pton(AF_INET,$r->{client})};$packed=eval {inet_pton(AF_INET6,$r->{client})} if !defined($packed);next if !defined($packed);
        my $post=uc($r->{method}) eq 'POST' && grep {$_ eq $r->{target}} @{$d->{login_paths}};
        my $get=uc($r->{method}) eq 'GET' && grep {$_ eq $r->{target}} (@{$d->{login_paths}},@{$d->{admin_paths}});
        next if !$post && !$get;
        push @r,{%$r,i=>$i,platform=>$platform,post=>$post?1:0,source=>unpack('H*',$packed).'|'.($r->{host}//'')};
    }
    for my $a(@r){for my $b(@r){next if $a->{source} ne $b->{source} || !$a->{post} || $b->{post};
        push @{$pairs{$a->{source}}},[$a->{timestamp},$b->{timestamp}] if $a->{user_agent} eq $b->{user_agent} &&
            ($a->{timestamp}<$b->{timestamp} || ($a->{timestamp}==$b->{timestamp} && $a->{i}<$b->{i})) && $b->{timestamp}-$a->{timestamp}<=$d->{window_seconds};}}
    for my $r(@r){for my $offset(0,int($d->{window_seconds}/2)){$starts{($r->{host}//'').'|'.(floor(($r->{timestamp}-$offset)/$d->{window_seconds})*$d->{window_seconds}+$offset)}=1;}}
    for my $start(keys %starts){my($host,$time)=split /\|/,$start;my %s;
        for my $r(@r){push @{$s{$r->{source}}},$r if ($r->{host}//'') eq $host && $time<=$r->{timestamp} && $r->{timestamp}<$time+$d->{window_seconds};}
        for my $source(keys %s){delete $s{$source} if grep {$_->[0]<$time+$d->{window_seconds} && $_->[1]>=$time} @{$pairs{$source}||[]};}
        for my $source(keys %s){my @p=grep {$_->{post}} @{$s{$source}};my %u=map {$_->{user_agent}=>1}@p;my %p=map {$_->{platform}=>1}@p;my $sequence=0;
            for my $a(@p){for my $b(@{$s{$source}}){$sequence=1 if !$b->{post} && ($a->{timestamp}<$b->{timestamp} || ($a->{timestamp}==$b->{timestamp} && $a->{i}<$b->{i}));}}
            delete $s{$source} if @p<$d->{min_source_posts} || keys(%u)<$d->{distinct_source_user_agents} || keys(%p)<$d->{distinct_source_platforms} || !$sequence;
        }
        while(1){my @drop;
            for my $source(keys %s){my %own=map {$_->{user_agent}=>1}grep {$_->{post}}@{$s{$source}};my %peers;
                for my $other(keys %s){next if $source eq $other;$peers{$_->{user_agent}}=1 for grep {$_->{post}}@{$s{$other}};}
                push @drop,$source if scalar(grep {$peers{$_}}keys %own)<$d->{shared_user_agents};}
            last if !@drop;delete @s{@drop};
        }
        next if keys(%s)<$d->{min_sources};my @all=map {@$_} values %s;my @p=grep {$_->{post}}@all;
        my %u=map {$_->{user_agent}=>1}@p;my %p=map {$_->{platform}=>1}@p;
        next if @all<$d->{min_requests} || @p<$d->{min_post_requests} || keys(%u)<$d->{distinct_user_agents} || keys(%p)<$d->{distinct_platforms};
        $flag{sha256_hex($J->encode($rows->[$_->{i}]))}=1 for @all;
    }
    return [sort keys %flag];
}
for my $variant(0..23){my $r=rows();for my $i(0..$#$r){$r->[$i]{timestamp}=200+($i%10)*5+$variant;}
    $r->[0]{method}='GET' if $variant%5==0;
    $r->[4]{user_agent}=$r->[0]{user_agent} if $variant%7==0;
    $r->[13]{host}='other.test' if $variant%3==0;
    is_deeply(ids(run($r)),oracle($r,config()),'independent fixed-window/source oracle variant '.$variant);
}
my $distant_flow=rows();push @$distant_flow,{%{$distant_flow->[0]},timestamp=>10},{%{$distant_flow->[0]},timestamp=>11,method=>'GET',target=>'/admin'};
my $local=run($distant_flow);is($local->{behavior}{distributed_login_flagged_requests},30,'an unrelated early coherent pair no longer exempts all later activity');
is_deeply(ids($local),oracle($distant_flow,config()),'independent pair-overlap oracle agrees with narrower protection');
my $edge_flow=rows();push @$edge_flow,{%{$edge_flow->[0]},timestamp=>89},{%{$edge_flow->[0]},timestamp=>91,method=>'GET',target=>'/admin'};
is(run($edge_flow)->{behavior}{distributed_login_flagged_requests},0,'coherent pair straddling a grid edge protects intersecting windows');
my $office=rows();for my $ip(1..3){push @$office,{%{$office->[($ip-1)*10]},timestamp=>104,method=>'GET',target=>'/admin'};}
is(run($office)->{behavior}{distributed_login_flagged_requests},0,'coherent browser sessions protect a shared-office mixture of platforms');
my $slow=rows();$_->{timestamp}=100+($_->{timestamp}-100)*500 for @$slow;
is(run($slow)->{behavior}{distributed_login_flagged_requests},0,'ordinary short window does not silently broaden to slow campaigns');
is(run($slow,config(window_seconds=>7200))->{behavior}{distributed_login_flagged_requests},30,'explicit longer window can detect a slower campaign');
ok(!eval {config(window_seconds=>21601);1},'distributed execution-window cap remains bounded');
# Split exactly the same campaign across UTC midnight, preserving every
# primary identity and using opposite halves solely as contextual evidence.
my $midnight=rows();$_->{timestamp}=86400-5+($_->{timestamp}-100) for @$midnight;
my @early=grep {$_->{timestamp}<86400} @$midnight;my @late=grep {$_->{timestamp}>=86400} @$midnight;
my @split_ids;
for my $part ([\@early,'after',\@late],[\@late,'before',\@early]) {
    my $e=$C->new(config=>config(),format=>'jsonl',details=>1);$e->feed(join('',map {$J->encode($_)."\n"}@{$part->[0]}));
    $e->add_context($part->[1],join('',map {$J->encode($_)."\n"}@{$part->[2]}));my $r=$e->finish;
    is($r->{counts}{analyzed},15,'distributed daily primary count excludes halo');
    is($r->{behavior}{distributed_login_flagged_requests},15,'distributed daily matched count excludes halo');
    push @split_ids,@{ids($r)};
}
is_deeply([sort @split_ids],ids(run($midnight)),'segmented distributed selection equals complete unsegmented campaign');
for my $row (@{$local->{details}}){ok(@{$row->{distributed_login_diagnostics}}<=2,'retention diagnostics obey fixed-grid membership cap');}
done_testing;
