use v5.020;
use strict;
use warnings;
use Test::More;
use JSON::PP;
use Digest::SHA qw(sha256_hex);
use VStats::TrafficClassifier;
my $C='VStats::TrafficClassifier';my $J=JSON::PP->new->utf8->canonical;
my @ua=('Mozilla/5.0 (Windows) Chrome/126','Mozilla/5.0 (Windows) Chrome/125','Mozilla/5.0 (Linux) Firefox/128');
my $cfg=$C->config($J->encode({schema_version=>1,exclude=>['suspected_automation'],behavior=>{enabled=>1,window_seconds=>10,min_requests=>6,distinct_user_agents=>3,distinct_platforms=>2,distinct_paths=>3,not_found_requests=>3}}));
sub raw {return join('',map {$J->encode($_)."\n"} @{$_[0]});}
sub analyze {
    my ($primary,$before,$after,$config)=@_;my $e=$C->new(config=>$config//$cfg,format=>'jsonl',details=>1);
    $e->feed(raw($primary));$e->add_context('before',raw($before)) if defined $before;$e->add_context('after',raw($after)) if defined $after;
    return ($e->finish,$e);
}
my @all=map {+{timestamp=>86400-3+$_,client=>'192.0.2.1',host=>'example.test',target=>'/p'.($_%3),method=>'GET',status=>$_<3?404:200,user_agent=>$ua[$_%3]}} 0..5;
my @before=@all[0..2];my @primary=@all[3..5];
my ($plain)=analyze(\@primary);is($plain->{behavior}{flagged_requests},0,'isolated half-burst has insufficient evidence');
my ($after,$engine)=analyze(\@primary,\@before);
is_deeply([@{$after->{counts}}{qw(lines_total parsed analyzed)}],[3,3,3],'context never increases primary counts');
is_deeply($after->{actors},{unknown=>3,declared_crawler_or_tool=>0,verified_crawler=>0},'actor counts are primary-only');
is($after->{behavior}{flagged_requests},3,'before-midnight evidence can identify primary requests');
is($after->{behavior}{broad_flagged_requests},3,'rule count is primary-only');
is($after->{behavior}{eligible_requests},3,'eligibility count is primary-only');
is($after->{behavior}{merged_sequences},1,'contextual sequence touching primary is counted once');
is($after->{input_sha256},sha256_hex(raw(\@primary)),'primary digest excludes context bytes');
is($after->{analysis_context}{before}{sha256},sha256_hex(raw(\@before)),'context separately identity-bound');
is($after->{analysis_context}{before}{used_analyzed_records},3,'used context count explicit');
is_deeply($engine->excluded_line_indices,[1,2,3],'export references primary physical indices only');
is($after->{details}[0]{behavior_evidence}{requests},6,'witness retains complete contextual volume');
is_deeply($after->{input}{period},{from=>86400,until=>86402},'primary period stays within its UTC day');
is_deeply($after->{analysis_period},{from=>86397,until=>86402},'evidence period crosses midnight explicitly');
my ($earlier)=analyze(\@before,undef,\@primary);my ($whole)=analyze(\@all);
is($earlier->{behavior}{flagged_requests},3,'following-day evidence can identify earlier primary requests');
my @separate=sort map {$_->{request_id}} (@{$earlier->{details}},@{$after->{details}});my @joined=sort map {$_->{request_id}} @{$whole->{details}};
is_deeply(\@separate,\@joined,'both daily reports partition the complete unsegmented request identities');
is($earlier->{adjusted_requests}{excluded}+$after->{adjusted_requests}{excluded},$whole->{adjusted_requests}{excluded},'no duplicated exclusions across midnight');
my @far=map {+{%$_,timestamp=>$_->{timestamp}-1000}} @before;
my ($distant)=analyze(\@primary,\@far);is($distant->{behavior}{flagged_requests},0,'unneeded distant context supplies no detection evidence');
is($distant->{analysis_context}{before}{used_analyzed_records},0,'unused distant context is disclosed');
for my $side(qw(before after)) {
    ok(!eval {my $e=$C->new(config=>$cfg,format=>'jsonl');$e->feed(raw(\@primary));$e->add_context($side,raw(\@primary));$e->finish;1},'overlapping '.$side.' context rejected');
}
my $tiny=$J->decode($J->encode($cfg));$tiny->{limits}{input_bytes}=length(raw(\@primary))+length(raw(\@before))-1;
ok(!eval {analyze(\@primary,\@before,undef,$tiny);1},'combined byte cap includes context');
$tiny=$J->decode($J->encode($cfg));$tiny->{limits}{records}=5;
ok(!eval {analyze(\@primary,\@before,undef,$tiny);1},'combined record cap includes context');
my $e=$C->new(config=>$cfg,format=>'jsonl');$e->feed(raw(\@primary));$e->add_context('before',raw(\@before));
ok(!eval {$e->add_context('before','');1},'duplicate context side rejected');
my $included=$J->decode($J->encode($cfg));$included->{behavior_include}=[sha256_hex($J->encode($primary[0]))];
my ($restored)=analyze(\@primary,\@before,undef,$included);is($restored->{adjusted_requests}{excluded},2,'context leaves primary request-ID overrides effective');
# A provider absence attestation must cover all context actually used.
my $scanner=$C->config($J->encode({schema_version=>1,probe_families=>[{id=>'a',paths=>['/p0','/p1','/p2'],absent_from=>86400,absent_until=>86402}],scanner=>{distinct_paths=>3,distinct_families=>1,window_seconds=>10}}));
my ($unattested)=analyze(\@primary,\@before,undef,$scanner);is_deeply($unattested->{probes}{active_families},[],'context cannot use an absence attestation limited to primary period');
for my $rule(qw(probing rapid_scan)) {
    my $rule_cfg=$C->config($J->encode({schema_version=>1,exclude=>['suspected_automation'],
        $rule=>$rule eq 'probing'?{enabled=>1,window_seconds=>10,min_requests=>6,distinct_user_agents=>3,distinct_platforms=>2,paths=>['/p0','/p1','/p2']}:
            {enabled=>1,window_seconds=>10,min_requests=>6,distinct_paths=>3,not_found_requests=>3}}));
    my($r)=analyze(\@primary,\@before,undef,$rule_cfg);
    is($r->{behavior}{flagged_requests},3,$rule.' context excludes only primary requests');
    is($r->{behavior}{$rule.'_flagged_requests'},3,$rule.' rule count is primary-only');
    is($r->{behavior}{merged_sequences},1,$rule.' qualifying context interval counted once');
    is($r->{behavior}{eligible_requests},3,$rule.' eligibility is primary-only');
}
my @single=map {+{%$_,user_agent=>$ua[0]}}@all;my @scanner_before=@single[0..2];my @scanner_primary=@single[3..5];
my $full_scanner=$C->config($J->encode({schema_version=>1,probe_families=>[{id=>'a',paths=>['/p0','/p1','/p2'],absent_from=>86397,absent_until=>86402}],scanner=>{distinct_paths=>3,distinct_families=>1,window_seconds=>10}}));
my($scanned)=analyze(\@scanner_primary,\@scanner_before,undef,$full_scanner);
is($scanned->{scanner_flagged_requests},3,'absence-attested scanner flags primary records only');
is($scanned->{merged_scanner_sequences},1,'scanner sequence touching primary counted once');
is($scanned->{counts}{analyzed},3,'scanner context is not exported analysis population');

# A coherent span can begin one further rule width before a grid that
# intersects the primary day. Day partitioning must retain that veto.
{
    require POSIX;
    my @agents=('Mozilla/5.0 (Windows NT 10.0) Chrome/120.0',
        'Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0',
        'Mozilla/5.0 (Linux; Android 10) Chrome/121.0');
    my $day=1790899200;
    sub login_record {
        my ($stamp,$source,$method,$agent)=@_;
        return {timestamp=>$stamp,client=>'192.0.2.'.$source,host=>'example.test',
            method=>$method,target=>$method eq 'POST'?'/login':'/admin',status=>200,user_agent=>$agent};
    }
    for my $width (1800,1801,21600) {
        my $d=$C->config($J->encode({schema_version=>1,distributed_login=>{
            enabled=>1,window_seconds=>$width,min_requests=>6,min_sources=>2,
            min_post_requests=>4,distinct_user_agents=>2,distinct_platforms=>2,
            min_source_posts=>2,distinct_source_user_agents=>2,distinct_source_platforms=>2,
            shared_user_agents=>1,login_paths=>['/login'],admin_paths=>['/admin']}}));
        my @start=sort {$a<=>$b} map {POSIX::floor(($day+10-$_)/$width)*$width+$_} (0,int($width/2));
        my @evidence=(login_record($start[0]-$width+11,10,'POST',$agents[0]),
            login_record($start[0]+10,10,'GET',$agents[0]),
            login_record($start[1]-200,10,'POST',$agents[0]),
            login_record($start[1]-190,10,'POST',$agents[1]),
            login_record($start[1]-100,11,'POST',$agents[0]),
            login_record($start[1]-90,11,'POST',$agents[1]));
        my @part=(login_record($day+10,10,'GET',$agents[2]),login_record($day+20,11,'GET',$agents[2]));
        my ($whole)=analyze([@evidence,@part],undef,undef,$d);
        is($whole->{behavior}{distributed_login_flagged_requests},0,"$width whole input preserves intersecting coherent span");
        my ($daily)=analyze(\@part,\@evidence,undef,$d);
        is($daily->{behavior}{distributed_login_flagged_requests},0,"$width before-day evidence preserves the same veto");
        is($daily->{counts}{analyzed},2,"$width transitive context remains evidence only");
        is($daily->{input_sha256},sha256_hex(raw(\@part)),"$width primary digest does not absorb wider evidence");
        my @without_pair=@evidence[1..$#evidence];
        my ($positive)=analyze(\@part,\@without_pair,undef,$d);
        is($positive->{behavior}{distributed_login_flagged_requests},2,"$width removing coherent POST restores actual campaign detection");
    }
    my $d=$C->config($J->encode({schema_version=>1,distributed_login=>{
        enabled=>1,window_seconds=>1800,min_requests=>7,min_sources=>2,min_post_requests=>4,
        distinct_user_agents=>2,distinct_platforms=>2,min_source_posts=>2,
        distinct_source_user_agents=>2,distinct_source_platforms=>2,shared_user_agents=>1,
        login_paths=>['/login'],admin_paths=>['/admin']}}));
    my $end=$day+86400;
    my @part=(login_record($end-700,10,'POST',$agents[0]),login_record($end-690,10,'POST',$agents[1]),
        login_record($end-600,11,'POST',$agents[0]),login_record($end-590,11,'POST',$agents[1]),
        login_record($end-20,11,'GET',$agents[2]),login_record($end-10,10,'GET',$agents[2]));
    my @later=(login_record($end+800,10,'POST',$agents[0]),login_record($end+2000,10,'GET',$agents[0]));
    my ($whole)=analyze([@part,@later],undef,undef,$d);
    my ($daily)=analyze(\@part,undef,\@later,$d);
    is($whole->{behavior}{distributed_login_flagged_requests},0,'whole input protects coherent flow ending beyond the next midnight');
    is($daily->{behavior}{distributed_login_flagged_requests},0,'after-day transitive context preserves coherent-flow veto');
    is($daily->{counts}{analyzed},6,'after-day context remains outside primary counts');
}
# The contract is independent of how an input is partitioned at a UTC day.
# Cover minimum, odd, ordinary and maximum rule widths at both boundaries.
{
    require POSIX;
    my $day=1790899200;my $end=$day+86400;
    my @agents=('Mozilla/5.0 (Windows NT 10.0) Chrome/120.0',
        'Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0',
        'Mozilla/5.0 (Linux; Android 10) Chrome/121.0');
    for my $w (1,2,1799,1800,1801,21599,21600) {
        for my $edge (qw(before after)) {
            my @whole;
            if ($edge eq 'before') {
                my @starts=sort {$a<=>$b} map {POSIX::floor(($day-$_)/$w)*$w+$_} (0,int($w/2));
                my $get=$starts[1]==$day?$starts[0]:$starts[1];
                my $post=$get-$w+1;
                my $campaign_post=$w==1?$day:$day-1;
                @whole=(login_record($post,10,'POST',$agents[0]),login_record($get,10,'GET',$agents[0]));
                for my $source (10,11) {
                    push @whole,login_record($campaign_post,$source,'POST',$agents[0]),
                        login_record($campaign_post,$source,'POST',$agents[1]),
                        login_record($day,$source,'GET',$agents[2]);
                }
            } else {
                my @starts=sort {$a<=>$b} map {POSIX::floor(($end-1-$_)/$w)*$w+$_} (0,int($w/2));
                for my $source (10,11) {
                    push @whole,login_record($end-1,$source,'POST',$agents[0]),
                        login_record($end-1,$source,'POST',$agents[1]),
                        login_record($end-1,$source,'GET',$agents[2]);
                }
                my $post=$starts[1]+$w-1;
                push @whole,login_record($post,10,'POST',$agents[0]),
                    login_record($post+($w>1?$w-1:1),10,'GET',$agents[0]);
            }
            @whole=sort {$a->{timestamp}<=>$b->{timestamp}} @whole;
            my @primary=grep {$_->{timestamp}>=$day && $_->{timestamp}<$end} @whole;
            my @before=grep {$_->{timestamp}<$day} @whole;
            my @after=grep {$_->{timestamp}>=$end} @whole;
            my $d=$C->config($J->encode({schema_version=>1,distributed_login=>{
                enabled=>1,window_seconds=>$w,min_requests=>$edge eq 'after' && $w>1?7:6,
                min_sources=>2,min_post_requests=>4,distinct_user_agents=>2,distinct_platforms=>2,
                min_source_posts=>2,distinct_source_user_agents=>2,distinct_source_platforms=>2,
                shared_user_agents=>1,login_paths=>['/login'],admin_paths=>['/admin']}}));
            my ($whole_result,$whole_engine)=analyze(\@whole,undef,undef,$d);
            my ($daily,$daily_engine)=analyze(\@primary,\@before,\@after,$d);
            my @expected=sort map {sha256_hex($J->encode($whole[$_-1]))}
                grep {$whole[$_-1]{timestamp}>=$day && $whole[$_-1]{timestamp}<$end}
                    @{$whole_engine->excluded_line_indices};
            my @observed=sort map {sha256_hex($J->encode($primary[$_-1]))} @{$daily_engine->excluded_line_indices};
            is_deeply(\@observed,\@expected,"$w $edge-edge primary exclusions match whole input");
            is($daily->{counts}{analyzed},scalar(@primary),"$w $edge-edge halo does not increase the input population");
            is($daily->{behavior}{distributed_login_flagged_requests},0,"$w $edge-edge complete coherent span protects sources");
            my @without_get=grep {!($_->{client} eq '192.0.2.10' && $_->{method} eq 'GET' && $_->{user_agent} eq $agents[0])} @whole;
            my ($positive)=analyze(\@without_get,undef,undef,$d);
            cmp_ok($positive->{behavior}{distributed_login_flagged_requests},'>',0,"$w $edge-edge removing the coherent GET reveals a real campaign");
        }
    }
}
done_testing;
