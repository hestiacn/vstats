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
done_testing;
