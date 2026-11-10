use v5.020;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Cwd qw(abs_path);
use JSON::PP;
use VStats::TrafficClassifier;
my $root=abs_path(__FILE__);$root =~ s{/tools/t/[^/]+\z}{};
my $dir=tempdir(CLEANUP=>1);my $J=JSON::PP->new->utf8->canonical;
sub write_file {my ($path,$s)=@_;open my $f,'>:raw',$path or die $!;print {$f} $s;close $f or die $!;}
sub read_file {my ($path)=@_;open my $f,'<:raw',$path or die $!;local $/;my $s=<$f>;return defined($s)?$s:'';}
write_file("$dir/config.json",'{"schema_version":1}');
my $row=$J->encode({timestamp=>100,client=>'192.0.2.1',target=>'/',user_agent=>'Bytespider;'}) . "\n";
write_file("$dir/log.jsonl",$row);
my @base=('--config',"$dir/config.json",'--input',"$dir/log.jsonl",'--input-format','jsonl','--output',"$dir/report.json");
my $serial=0;my $child_cwd;
sub invoke {
    my (@args)=@_;$serial++;my $prefix="$dir/child-$serial";
    my $pid=fork();die 'fork failed' if !defined $pid;
    if (!$pid) {
        open STDOUT,'>:raw',"$prefix.out" or die;open STDERR,'>:raw',"$prefix.err" or die;
        chdir($child_cwd) or die 'chdir failed' if defined $child_cwd;
        exec {$^X} $^X,"$root/tools/traffic-classify.pl",@args;die 'exec failed';
    }
    # Operational test-hang guard, not a performance acceptance threshold.
    local $SIG{ALRM}=sub {kill 9,$pid};alarm 10;waitpid($pid,0);alarm 0;my $status=$?;return (($status&127)?128+($status&127):$status >> 8,read_file("$prefix.out"),read_file("$prefix.err"));
}
my ($exit,$out,$err)=invoke(@base);
is($exit,0,'CLI valid');is($out,'','stdout empty');is($err,'','stderr empty');
my $report=read_file("$dir/report.json");is($J->decode($report)->{actors}{declared_crawler_or_tool},1,'CLI actor');
is((stat("$dir/report.json"))[2]&0777,0600,'mode 0600');
($exit,$out,$err)=invoke(@base);is($exit,0,'repeat');is(read_file("$dir/report.json"),$report,'replay identical');
my @html=@base;push @html,'--output-format','html';($exit)=invoke(@html);is($exit,0,'static HTML');like(read_file("$dir/report.json"),qr/<!doctype html>/,'HTML rendered');
write_file("$dir/report.json",'previous');
write_file("$dir/config-bad.json",'{"schema_version":1,"password":"SECRET_SENTINEL"}');
my @badconfig=@base;$badconfig[1]="$dir/config-bad.json";$badconfig[3]="$dir/does-not-exist";
($exit,$out,$err)=invoke(@badconfig);isnt($exit,0,'validate first');like($err,qr/configuration/,'config stage');unlike($err,qr/SECRET_SENTINEL|does-not-exist/,'private errors');
is(read_file("$dir/report.json"),'previous','preserve report');
for my $bad ('null','{"schema_version":1,"limits":{"records":1.5}}','{"schema_version":1,"limits":{"records":1,"r\\u0065cords":1}}') {
    write_file("$dir/config-bad.json",$bad);($exit)=invoke(@badconfig);isnt($exit,0,'config refusal');is(read_file("$dir/report.json"),'previous','strict preserve');
}
write_file("$dir/config-limit.json",'{"schema_version":1,"limits":{"records":1}}');
write_file("$dir/two.jsonl","bad\n".$row);
my @limit=@base;$limit[1]="$dir/config-limit.json";$limit[3]="$dir/two.jsonl";
($exit,$out,$err)=invoke(@limit);isnt($exit,0,'aggregate cap fatal');like($err,qr/Record count limit/,'cap reason');is(read_file("$dir/report.json"),'previous','cap preservation');
write_file("$dir/config-small.json",'{"schema_version":1,"limits":{"line_bytes":256,"ua_bytes":64,"target_bytes":64}}');
write_file("$dir/oversize.jsonl",('x'x20000)."\r\n".$row);
my @oversize=@base;$oversize[1]="$dir/config-small.json";$oversize[3]="$dir/oversize.jsonl";
($exit)=invoke(@oversize);is($exit,0,'oversize nonfatal');
is_deeply([@{$J->decode(read_file("$dir/report.json"))->{counts}}{qw(unparsed oversized parsed)}],[1,1,1],'oversize count');
write_file("$dir/oversize.jsonl",(' 'x20000)."\n".$row);($exit)=invoke(@oversize);is($exit,0,'oversize whitespace');is($J->decode(read_file("$dir/report.json"))->{counts}{oversized},1,'oversize != blank');
write_file("$dir/report.json",'previous');
for my $alias ("$dir/log.jsonl","$dir/config.json") {
    my @args=@base;$args[7]=$alias;my $before=read_file($alias);($exit)=invoke(@args);isnt($exit,0,'path alias');is(read_file($alias),$before,'input preserved');
}
link("$dir/log.jsonl","$dir/hardlink") or die $!;
my @alias=@base;$alias[7]="$dir/hardlink";($exit)=invoke(@alias);isnt($exit,0,'inode alias');is(read_file("$dir/log.jsonl"),$row,'hardlink preserved');
symlink("$dir/log.jsonl","$dir/symlink") or die $!;$alias[7]="$dir/symlink";($exit)=invoke(@alias);isnt($exit,0,'symlink refusal');
$alias[7]=$dir;($exit)=invoke(@alias);isnt($exit,0,'directory output');
$alias[7]="$dir/missing/report";($exit)=invoke(@alias);isnt($exit,0,'missing parent');
my @inputdir=@base;$inputdir[3]=$dir;($exit)=invoke(@inputdir);isnt($exit,0,'directory input');
SKIP: {
    my $fifo="$dir/fifo";
    my $made=eval {require POSIX; defined POSIX::mkfifo($fifo,0600)};
    skip 'POSIX FIFO unavailable on this platform',2 if !$made;
    my @args=@base;$args[3]=$fifo;
    ($exit,$out,$err)=invoke(@args);
    is($exit,1,'FIFO nonblocking');like($err,qr/Input must be a regular file/,'file-type reason');
}

{
    local $ENV{GATEWAY_INTERFACE}='';($exit,$out,$err)=invoke('--help');isnt($exit,0,'CGI empty refused');like($err,qr/CGI execution is refused/,'CGI reason');
}
($exit,$out,$err)=invoke(@base,'--unknown-secret=SECRET_SENTINEL');isnt($exit,0,'unknown option');unlike($err,qr/SECRET_SENTINEL/,'private option error');
($exit)=invoke(@base,'surplus');isnt($exit,0,'extra arguments');
($exit)=invoke();isnt($exit,0,'required arguments');
write_file("$dir/meta.json",$J->encode({provider_id=>'google_common',source_url=>'https://wrong.test',retrieved_at=>'1970-01-01T00:01:40Z'}));
write_file("$dir/snapshot.json",$J->encode({creationTime=>'x',prefixes=>[{ipv4Prefix=>'192.0.2.0/24'}]}));
my @evidence=@base;$evidence[3]="$dir/no-log";push @evidence,'--snapshot',"$dir/snapshot.json",'--attestation',"$dir/meta.json";
($exit,$out,$err)=invoke(@evidence);isnt($exit,0,'bad evidence');like($err,qr/provider evidence/,'evidence first');
write_file("$dir/meta.json",$J->encode({provider_id=>'google_common',source_url=>'https://developers.google.com/static/crawling/ipranges/common-crawlers.json',retrieved_at=>'1970-01-01T00:01:40Z'}));
write_file("$dir/google.jsonl",$J->encode({timestamp=>100,client=>'192.0.2.1',target=>'/',user_agent=>'Googlebot/2'})."\n");
$evidence[3]="$dir/google.jsonl";($exit)=invoke(@evidence);is($exit,0,'evidence pair');
my $verified=$J->decode(read_file("$dir/report.json"));is($verified->{actors}{verified_crawler},1,'CLI verification');like($verified->{provider_snapshots}[0]{sha256},qr/\A[0-9a-f]{64}\z/,'evidence digest');
$alias[7]="$dir/snapshot.json";push @alias,'--snapshot',"$dir/snapshot.json",'--attestation',"$dir/meta.json";($exit)=invoke(@alias);isnt($exit,0,'evidence alias');
my @unpaired=@base;push @unpaired,'--snapshot',"$dir/snapshot.json";($exit)=invoke(@unpaired);isnt($exit,0,'unpaired evidence');
# No report temporary files survive successful or failed operations.
opendir my $dh,$dir or die;my @temp=grep {/\A\.traffic-classify-/} readdir $dh;closedir $dh;is(scalar @temp,0,'no output scratch');
($exit,$out,$err)=invoke(@base,'--config',"$dir/config.json");
is($exit,1,'duplicate option');like($err,qr/Invalid arguments/,'duplicate reason');
mkdir("$dir/cwd") or die $!;mkdir("$dir/cwd/Encode") or die $!;
write_file("$dir/cwd/Encode/ConfigLocal.pm",'BEGIN { print STDERR "CWD_OPTIONAL_MODULE\n" } 1;');
{
    local $ENV{PERL_USE_UNSAFE_INC}=1;
    $child_cwd="$dir/cwd";
    ($exit,$out,$err)=invoke('--help');is($exit,0,'cwd help succeeds');
    unlike($err,qr/CWD_OPTIONAL_MODULE/,'cwd help isolated');
    ($exit,$out,$err)=invoke(@base);is($exit,0,'cwd run succeeds');
    unlike($err,qr/CWD_OPTIONAL_MODULE/,'cwd run isolated');
    undef $child_cwd;
}
write_file("$dir/context.jsonl",$J->encode({timestamp=>99,client=>'198.51.100.1',target=>'/',user_agent=>'Mozilla/5.0'})."\n");
($exit,$out,$err)=invoke(@base,'--context-before',"$dir/context.jsonl");is($exit,0,'bounded context CLI succeeds');
my $context_report=$J->decode(read_file("$dir/report.json"));is($context_report->{counts}{analyzed},1,'CLI context excluded from primary counts');
is($context_report->{analysis_context}{before}{counts}{analyzed},1,'CLI context identity/counts separately recorded');
my $saved_context=read_file("$dir/context.jsonl");my @context_alias=@base;$context_alias[7]="$dir/context.jsonl";
($exit)=invoke(@context_alias,'--context-before',"$dir/context.jsonl");isnt($exit,0,'output alias to context refused');
is(read_file("$dir/context.jsonl"),$saved_context,'context alias refusal preserves context');
($exit)=invoke(@base,'--context-before',"$dir/log.jsonl");isnt($exit,0,'overlapping primary/context refused');
($exit)=invoke(@base,'--context-before',"$dir/context.jsonl",'--context-before',"$dir/context.jsonl");isnt($exit,0,'duplicate context argument refused');
done_testing;
