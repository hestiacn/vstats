use v5.020;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use File::Copy qw(copy);
use Cwd qw(abs_path);
for my $module (qw(JSON::XS Try::Tiny Geo::IPfree)) {
    eval "require $module; 1" or plan skip_all=>"Full parser requires $module";
}
my $root=abs_path(__FILE__);$root=~s{/tools/t/[^/]+\z}{};
my $dir=tempdir('vstats-mobile-XXXXXX',TMPDIR=>1,CLEANUP=>1);my $serial=0;
sub read_file {open my $f,'<:raw',$_[0] or die $!;local $/;return <$f>//'';}
sub write_file {open my $f,'>:raw',$_[0] or die $!;print {$f} $_[1];close $f or die $!;}
my $model=read_file("$root/wwwroot/cgi-bin/awstats.model.conf");
sub parse {
    my ($ua,$level)=@_;$level//=2;my $case="$dir/case-".++$serial;make_path("$case/config","$case/data");
    write_file("$case/access.log",'192.0.2.1 - - [02/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "'.$ua.'"'."\n");
    my $cfg=$model;$cfg=~s/^\s*LoadPlugin\s*=.*$/# No plugins in synthetic fixture/mg;
    my %settings=(LogFile=>"$case/access.log",LogFormat=>1,SiteDomain=>'example.test',HostAliases=>'example.test',DirData=>"$case/data",DirCgi=>'/stats',DirLang=>"$root/wwwroot/cgi-bin/lang",DNSLookup=>0,Lang=>'en',EnableLocaldatePlugin=>0,AllowToUpdateStatsFromBrowser=>0,PurgeLogFile=>0,ArchiveLogRecords=>0,LevelForRobotsDetection=>$level,KeepBackupOfHistoricFiles=>0);
    for my $k(sort keys %settings){my $line="$k=\"$settings{$k}\"";$cfg.="\n$line\n" if $cfg!~s/^\Q$k\E\s*=.*$/$line/m;}
    write_file("$case/config/awstats.fixture.conf",$cfg);
    my $pid=fork();die if !defined $pid;
    if (!$pid){open STDOUT,'>:raw',"$case/out" or die;open STDERR,'>:raw',"$case/err" or die;exec {$^X} $^X,"$root/wwwroot/cgi-bin/awstats.pl",'-config=fixture',"-configdir=$case/config",'-update';die;}
    waitpid($pid,0);is($?,0,'native fixture exits successfully');is(read_file("$case/err"),'','native fixture has no diagnostics');
    my $history=read_file("$case/data/awstats102026.fixture.txt");my($time)=$history=~/^BEGIN_TIME[^\n]*\n(.*?)^END_TIME/ms;my($robots)=$history=~/^BEGIN_ROBOT[^\n]*\n(.*?)^END_ROBOT/ms;
    my @n=(0,0,0,0);for my $line(split /\n/,$time//''){my@q=split /\s+/,$line;next if@q<7;$n[0]+=$q[2];$n[1]+=$q[3];$n[2]+=$q[5];$n[3]+=$q[6];}
    return (\@n,$robots//'');
}
my $android='Mozilla/5.0 (Linux; Android 7.0;) AppleWebKit/537.36 Mobile Safari/537.36';
for my $case ([$android.' (compatible; PetalBot; +https://example.test/petalbot)','PetalBot'],
    ['Mozilla/5.0 (iPad) Mobile Safari/604.1 PetalBot/1','PetalBot'],
    [$android.' ClaudeBot/1','ClaudeBot/'],[$android.' GPTBot/1','GPTBot/'],
    [$android.' Applebot-Extended/1','Applebot-Extended/']) {
    my($counts,$robots)=parse($case->[0]);is_deeply($counts,[0,0,1,100],'explicit named crawler remains non-viewed despite device claims');like($robots,qr/^\Q$case->[1]\E /m,'existing registry history ID retained');
}
for my $ua ($android,'Mozilla/5.0 (iPad) Mobile Safari/604.1',$android.' XPetalBot/1',$android.' PetalBotling/1',$android.' PetalBot_Custom/1',$android.' casualcrawler/1',$android.' TTWebView/1',$android.' okhttp/4') {
    my($counts)=parse($ua);is_deeply($counts,[1,100,0,0],'ordinary mobile or unregistered/colliding marker stays viewed');
}
my($disabled)=parse($android.' PetalBot/1',0);is_deeply($disabled,[1,100,0,0],'robots-disabled configuration remains unchanged');
my($desktop,$desktop_robots)=parse('Mozilla/5.0 PetalBot/1');is_deeply($desktop,[0,0,1,100],'desktop registry matching remains unchanged');like($desktop_robots,qr/^PetalBot /m,'desktop history ID unchanged');
done_testing;
