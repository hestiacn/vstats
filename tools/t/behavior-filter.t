use v5.020;
use strict;
use warnings;
use Test::More;
use JSON::PP;
use Digest::SHA qw(sha256_hex);
use File::Temp qw(tempdir);
use Cwd qw(abs_path);
use VStats::TrafficClassifier;
my $C='VStats::TrafficClassifier';my $J=JSON::PP->new->utf8->canonical;
my $root=abs_path(__FILE__);$root =~ s{/tools/t/[^/]+\z}{};
my $dir=tempdir(CLEANUP=>1);my $serial=0;
my @ua=('Mozilla/5.0 (Windows NT 10.0) Chrome/126','Mozilla/5.0 (Windows NT 10.0) Chrome/125','Mozilla/5.0 (X11; Linux) Firefox/128');
my $cfg={schema_version=>1,exclude=>['suspected_automation'],behavior=>{enabled=>1,window_seconds=>10,min_requests=>6,distinct_user_agents=>3,distinct_platforms=>2,distinct_paths=>3,not_found_requests=>3}};
my @events=map {+{timestamp=>100+$_,client=>'192.0.2.1',target=>'/p'.($_%3).'?private=SECRET',status=>$_<3?404:200,user_agent=>$ua[$_%3]}} 0..5;
my @lines=map {$J->encode($_)} @events;
sub write_file {open my $f,'>:raw',$_[0] or die $!;print {$f} $_[1];close $f or die $!;}
sub slurp {open my $f,'<:raw',$_[0] or die $!;local $/;return <$f>//'';}
sub engine {
    my ($raw,$config)=@_;my $e=$C->new(config=>$C->config($J->encode($config)) ,format=>'jsonl',details=>1);$e->feed($raw);return ($e,$e->finish);
}
my $raw="\nmalformed\n".join('',map {$_ . "\r\n"} @lines).$J->encode({%{$events[0]},timestamp=>200});
my ($e,$r)=engine($raw,$cfg);
is_deeply($e->excluded_line_indices,[3..8],'exact physical line indices exclude no malformed or blank rows');
is($r->{adjusted_requests}{excluded},6,'explicit behavior selector union');
for my $d (grep {$_->{suspected_automation}} @{$r->{details}}) {
    my $p=$d->{behavior_evidence};ok($p && $p->{from}<=$d->{timestamp} && $p->{until}>=$d->{timestamp},'per-request proof covers its timestamp');
    ok($p->{until}-$p->{from}<=10 && $p->{requests}>=6 && $p->{distinct_user_agents}>=3 && $p->{distinct_platforms}>=2 && $p->{distinct_paths}>=3 && $p->{not_found_requests}>=3,'proof meets all configured conditions');
    is($d->{normalized_target},'/p'.(($d->{line_index}-3)%3),'published-review path strips query');
    is($d->{request_id},sha256_hex($lines[$d->{line_index}-3]),'request ID excludes CRLF terminator');
}
my $include={%$cfg,behavior_include=>[$r->{details}[0]{request_id}]};
my ($ie,$ir)=engine($raw,$include);is($ir->{behavior}{flagged_requests},6,'override does not hide evidence');
is($ir->{behavior}{inclusion_overrides},1,'override disclosed');is($ir->{adjusted_requests}{excluded},5,'override keeps selected request');
ok($ir->{details}[0]{behavior_included} && !$ir->{details}[0]{excluded},'private review shows included state');
my $other={%$include,crawler_tokens=>['Mozilla'],exclude=>['suspected_automation','declared_crawler_or_tool']};
# A valid explicit tool marker supplies independent actor exclusion, which an
# inclusion override is not allowed to suppress.
my $actor_cfg={%$include,crawler_tokens=>['LocalFetch'],exclude=>['suspected_automation','declared_crawler_or_tool']};
my @actor_lines=map {my $x={%$_,user_agent=>$_->{user_agent}.' LocalFetch/1'};$J->encode($x)} @events;
$actor_cfg->{behavior_include}=[sha256_hex($actor_lines[0])];
my (undef,$ar)=engine(join('',map {$_ . "\n"} @actor_lines),$actor_cfg);
is($ar->{adjusted_requests}{excluded},6,'behavior override cannot override actor exclusion');
for my $bad (undef,{},['X'x64],['a'x63],['A'x64],[('a'x64)x2]) {
    my $ok=eval {$C->config($J->encode({schema_version=>1,behavior_include=>$bad}));1};ok(!$ok,'invalid inclusion list rejected');
}
my $before=$C->new(config=>$C->config('{"schema_version":1}'),format=>'jsonl');
ok(!eval {$before->excluded_line_indices;1},'selection unavailable before classification finishes');

write_file("$dir/config.json",$J->encode($include));write_file("$dir/input.jsonl",$raw);
sub invoke {
    my (@args)=@_;my $n=++$serial;my $pid=fork();die if !defined $pid;
    if (!$pid) {open STDOUT,'>:raw',"$dir/out-$n" or die;open STDERR,'>:raw',"$dir/err-$n" or die;exec {$^X} $^X,"$root/tools/traffic-classify.pl",@args;die;}
    local $SIG{ALRM}=sub {kill 9,$pid};alarm 10;waitpid($pid,0);alarm 0;my $exit=$?;return ($exit,slurp("$dir/err-$n"));
}
my @args=('--config',"$dir/config.json",'--input',"$dir/input.jsonl",'--input-format','jsonl','--output',"$dir/report.json",'--filtered-log',"$dir/kept.log");
my ($exit,$err)=invoke(@args);is($exit,0,'CLI exports explicitly filtered input');is($err,'','filtered export has no diagnostics');
my $expected="\nmalformed\n".$lines[0]."\r\n".$J->encode({%{$events[0]},timestamp=>200});
is(slurp("$dir/kept.log"),$expected,'kept bytes, malformed/blank rows and unterminated final line preserved');
my $report=$J->decode(slurp("$dir/report.json"));
is($report->{filtered_log}{sha256},sha256_hex($expected),'filtered output bound by digest');
is($report->{filtered_log}{input_sha256},sha256_hex($raw),'filtered export binds original input');
is($report->{filtered_log}{input_log_bytes},length($raw),'byte ledger original');
is($report->{filtered_log}{kept_log_bytes},length($expected),'byte ledger retained');
is($report->{filtered_log}{removed_log_bytes},length($raw)-length($expected),'byte ledger removed');
is($report->{filtered_log}{input_records},9,'record ledger includes malformed and blank input');
is($report->{filtered_log}{kept_records},4,'record ledger retains unparsed rows');
is((stat("$dir/kept.log"))[2]&0777,0600,'raw filtered output stays private');
my $first=slurp("$dir/report.json");($exit,$err)=invoke(@args);is($exit,0,'unchanged export repeats');is(slurp("$dir/report.json"),$first,'export metadata deterministic');
for my $target ("$dir/input.jsonl","$dir/config.json","$dir/report.json") {
    my @bad=@args;$bad[-1]=$target;my $old=slurp($target);($exit)=invoke(@bad);isnt($exit,0,'filtered path alias refused');is(slurp($target),$old,'alias target preserved');
}
link("$dir/report.json","$dir/report-hardlink") or die;my @hard=@args;$hard[-1]="$dir/report-hardlink";($exit)=invoke(@hard);isnt($exit,0,'hardlinked outputs refused');
symlink("$dir/kept.log","$dir/filtered-link") or die;my @sym=@args;$sym[-1]="$dir/filtered-link";($exit)=invoke(@sym);isnt($exit,0,'filtered output symlink refused');
write_file("$dir/config-none.json",'{"schema_version":1}');my @none=@args;$none[1]="$dir/config-none.json";($exit,$err)=invoke(@none);isnt($exit,0,'filtered export requires explicit selection');like($err,qr/explicit exclusion selectors/,'policy error explains selection');
opendir my $dh,$dir or die;my @temporary=grep {/^\.traffic-classify-/} readdir $dh;closedir $dh;is(scalar @temporary,0,'no export scratch survives');
done_testing;
