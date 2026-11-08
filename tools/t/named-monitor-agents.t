use v5.020;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use Cwd qw(abs_path);
use JSON::PP;
use VStats::TrafficClassifier;
my $root=abs_path(__FILE__);$root=~s{/tools/t/[^/]+\z}{};
require "$root/wwwroot/cgi-bin/lib/robots.pm";
our (@RobotsSearchIDOrder_list1,%RobotsHashIDLib);
for my $token ('fd-crm-enrich','RisikomonitorNotify') {
    my $ua='Mozilla/5.0 (Linux; Android 10) Mobile Chrome/130.0 (compatible; '.$token.'/1)';
    my $id=RegisteredCrawlerRobotID($ua,1);
    ok($id && $ua=~/$id/i,'explicit enabled identity is bounded and overrides device exemption');
    like($RobotsHashIDLib{$id},qr/self-declared/,'display does not imply authenticated ownership');
    is(RegisteredCrawlerRobotID($ua,0),'','disabled native signatures remain disabled');
    for my $bad ('X'.$token,$token.'ling',$token.'_Custom',$token.'-suffix') {
        my $text='Mozilla/5.0 (Android) Mobile Chrome/130.0 '.$bad.'/1';
        is(RegisteredCrawlerRobotID($text,1),'','marker collision does not override browser exemption');
        ok(!grep({$text=~/$_/i && /\Q$token\E/} @RobotsSearchIDOrder_list1),'same boundary protects desktop registry matching');
    }
    my $cfg=VStats::TrafficClassifier->config('{"schema_version":1}');
    my $e=VStats::TrafficClassifier->new(config=>$cfg,format=>'jsonl',details=>1);
    $e->feed(JSON::PP->new->encode({timestamp=>100,client=>'192.0.2.1',target=>'/',user_agent=>$ua})."\n");
    my $r=$e->finish;
    is($r->{actors}{declared_crawler_or_tool},1,'classifier labels declaration without verification');
    is($r->{actors}{verified_crawler},0,'signature does not verify operator identity');
}
for my $module (qw(JSON::XS Try::Tiny Geo::IPfree)) {
    eval "require $module; 1" or BAIL_OUT("Native regression dependencies unavailable: $module");
}
sub read_file {open my $f,'<:raw',$_[0] or die $!;local $/;return <$f>//'';}
sub write_file {open my $f,'>:raw',$_[0] or die $!;print {$f} $_[1];close $f or die $!;}
my $dir=tempdir('vstats-named-XXXXXX',TMPDIR=>1,CLEANUP=>1);my $serial=0;
my $model=read_file("$root/wwwroot/cgi-bin/awstats.model.conf");
sub native {
    my ($ua,$level)=@_;my $case="$dir/case-".++$serial;make_path("$case/config","$case/data");
    write_file("$case/access.log",'192.0.2.1 - - [02/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "'.$ua.'"'."\n");
    my $cfg=$model;$cfg=~s/^\s*LoadPlugin\s*=.*$/# No plugins in synthetic fixture/mg;
    my %settings=(LogFile=>"$case/access.log",LogFormat=>1,SiteDomain=>'example.test',HostAliases=>'example.test',
        DirData=>"$case/data",DirCgi=>'/stats',DirLang=>"$root/wwwroot/cgi-bin/lang",DNSLookup=>0,DecodeUA=>0,
        Lang=>'en',EnableLocaldatePlugin=>0,AllowToUpdateStatsFromBrowser=>0,PurgeLogFile=>0,ArchiveLogRecords=>0,
        LevelForRobotsDetection=>$level,KeepBackupOfHistoricFiles=>0);
    for my $k (sort keys %settings) {my $line="$k=\"$settings{$k}\"";$cfg.="\n$line\n" if $cfg!~s/^\Q$k\E\s*=.*$/$line/m;}
    write_file("$case/config/awstats.fixture.conf",$cfg);
    my $pid=fork();die if !defined $pid;
    if (!$pid) {
        open STDOUT,'>:raw',"$case/out" or die;open STDERR,'>:raw',"$case/err" or die;
        exec {$^X} $^X,"$root/wwwroot/cgi-bin/awstats.pl",'-config=fixture',"-configdir=$case/config",'-update';die;
    }
    waitpid($pid,0);is($?,0,'native fixture exits cleanly');is(read_file("$case/err"),'','native fixture emits no diagnostics');
    my $history=read_file("$case/data/awstats102026.fixture.txt");my ($time)=$history=~/^BEGIN_TIME[^\n]*\n(.*?)^END_TIME/ms;
    my @counts=(0,0,0,0);
    for my $line (split /\n/,$time//'') {my @q=split /\s+/,$line;next if @q<7;$counts[0]+=$q[2];$counts[1]+=$q[3];$counts[2]+=$q[5];$counts[3]+=$q[6];}
    return \@counts;
}
for my $token ('fd-crm-enrich','RisikomonitorNotify') {
    for my $prefix ('Mozilla/5.0 (compatible; ','Mozilla/5.0 (Android 10) Mobile Chrome/130.0 (compatible; ') {
        is_deeply(native($prefix.$token.'/1)',1),[0,0,1,100],'native accounting places declared agent in non-viewed traffic');
    }
    is_deeply(native('Mozilla/5.0 (compatible; '.$token.'/1)',0),[1,100,0,0],'native checkbox off retains declared agent traffic');
}
done_testing;
