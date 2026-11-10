use v5.020;
use strict;
use warnings;
use Test::More;
use JSON::PP;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use Cwd qw(abs_path);
for my $module (qw(JSON::XS Try::Tiny Geo::IPfree)) {
    eval "require $module;1" or plan skip_all=>"Full native parser requires $module";
}
my $root=abs_path(__FILE__);$root =~ s{/tools/t/[^/]+\z}{};
my $dir=tempdir(CLEANUP=>1);
my $J=JSON::PP->new->utf8->canonical;
sub slurp {open my $f,'<:raw',$_[0] or die $!;local $/;return <$f>//'';}
sub write_file {open my $f,'>:raw',$_[0] or die $!;print {$f} $_[1];close $f or die $!;}
my $url='https://developers.google.com/static/crawling/ipranges/common-crawlers.json';
sub bundle {
    my ($prefix)=@_;my @snapshots;
    for my $time ('2026-10-30T09:59:00Z','2026-10-30T10:10:00Z') {
        push @snapshots,{raw_json=>$J->encode({creationTime=>'fixture',prefixes=>[{ipv4Prefix=>$prefix//'192.0.2.0/24'}]}),
            attestation_json=>$J->encode({provider_id=>'google_common',source_url=>$url,retrieved_at=>$time})};
    }
    return $J->encode({schema_version=>1,snapshots=>\@snapshots});
}
my $mobile='Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
my $desktop='Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
my $browser='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36';
my $model=slurp("$root/wwwroot/cgi-bin/awstats.model.conf");my $serial=0;my $last_case;
sub run {
    my ($rows,$evidence,$level,$overrides)=@_;$overrides//={};$level//=3;my $case="$dir/case-".++$serial;$last_case=$case;make_path("$case/config","$case/data");
    my $log='';my $minute=0;
    for my $row (@$rows) {my ($ip,$path,$status,$bytes,$ua)=@$row;$log.=sprintf('%s - - [30/Oct/2026:10:%02d:00 +0000] "GET %s HTTP/1.1" %d %d "-" "%s"',$ip,$minute++,$path,$status,$bytes,$ua)."\n";}
    write_file("$case/access.log",$log);write_file("$case/evidence.json",$evidence) if defined $evidence;
    my $conf=$model;$conf =~ s/^\s*LoadPlugin\s*=.*$/# Fixture has no plugins/mg;
    my %settings=(LogFile=>"$case/access.log",LogFormat=>1,SiteDomain=>'example.test',HostAliases=>'example.test',
        DirData=>"$case/data",DirLang=>"$root/wwwroot/cgi-bin/lang",DNSLookup=>0,Lang=>'en',EnableLocaldatePlugin=>0,
        LevelForRobotsDetection=>$level,ValidHTTPCodes=>'200 206 304',KeepBackupOfHistoricFiles=>0,
        VerifiedCrawlerEvidenceFile=>defined($evidence)?"$case/evidence.json":'');
    for my $key (keys %settings) {my $value="$key=\"$settings{$key}\"";$conf.="\n$value\n" if $conf !~ s/^\Q$key\E\s*=.*$/$value/m;}
    for my $key (keys %$overrides) {
        $conf =~ s/^\Q$key\E\s*=.*\n//mg;
        $conf .= "$key=\"$overrides->{$key}\"\n" if defined $overrides->{$key};
    }
    write_file("$case/config/awstats.fixture.conf",$conf);
    my @snapshots;
    for my $pass (1,2) {
        my $pid=fork();die 'fork' if !defined $pid;
        if (!$pid) {open STDOUT,'>:raw',"$case/out" or die;open STDERR,'>:raw',"$case/err" or die;exec {$^X} $^X,"$root/wwwroot/cgi-bin/awstats.pl",'-config=fixture',"-configdir=$case/config",'-update';die 'exec';}
        waitpid($pid,0);is($?,0,'native update succeeds');is(slurp("$case/err"),'','native update has no diagnostics');
        my $text=slurp("$case/data/awstats102026.fixture.txt");my ($time)=$text =~ /^BEGIN_TIME[^\n]*\n(.*?)^END_TIME/ms;my @n=(0,0,0,0);
        for my $line (split /\n/,$time//'') {my @f=split /\s+/,$line;next if @f<7;$n[0]+=$f[2];$n[1]+=$f[3];$n[2]+=$f[5];$n[3]+=$f[6];}
        push @snapshots,\@n;
    }
    is_deeply($snapshots[0],$snapshots[1],'repeat preserves native counters');return $snapshots[1];
}
sub row {return ['192.0.2.1','/file.zip',200,100,$mobile];}
is_deeply(run([row()],undef),[1,100,0,0],'existing crawler download exemption remains with layer off');
is_deeply(run([row()],bundle()),[0,0,1,100],'confirmed crawler download moves once to non-viewed traffic');
is_deeply(run([row()],'{"schema_version":1,"snapshots":[]}'),[1,100,0,0],'missing evidence adds no exclusion');
is_deeply(run([row()],bundle('198.51.100.0/24')),[1,100,0,0],'failed verification adds no exclusion');
is_deeply(run([['192.0.2.1','/',200,100,$browser]],bundle()),[1,100,0,0],'ordinary browser on provider address stays unchanged');
is_deeply(run([['198.51.100.1','/',200,100,$desktop]],bundle()),run([['198.51.100.1','/',200,100,$desktop]],undef),'existing unverified desktop robot rules are preserved');
is_deeply(run([['192.0.2.1','/file.zip',200,100,$mobile],['192.0.2.1','/file.zip',206,50,$mobile]],bundle()),[0,0,2,150],'confirmed 200 and 206 downloads excluded before download accounting');
is_deeply(run([['192.0.2.1','/',304,0,$mobile]],bundle()),[0,0,1,0],'confirmed cached response has no invented bytes');
is_deeply(run([['192.0.2.1','/missing',404,0,$mobile]],bundle()),run([['192.0.2.1','/missing',404,0,$mobile]],undef),'existing error accounting preserved');
is_deeply(run([row()],bundle(),0),[0,0,1,100],'additional evidence is independent of disabled legacy UA detection');
{
    my $values=run([row()],'{"schema_version":1,"snapshots":[]}');my $case=$last_case;
    my $path="$case/data/awstats102026.fixture.txt";my $before=slurp($path);
    write_file("$case/evidence.json",'{broken');
    my $pid=fork();die 'fork' if !defined $pid;
    if (!$pid) {open STDOUT,'>:raw',"$case/bad-out" or die;open STDERR,'>:raw',"$case/bad-err" or die;exec {$^X} $^X,"$root/wwwroot/cgi-bin/awstats.pl",'-config=fixture',"-configdir=$case/config",'-update';die 'exec';}
    waitpid($pid,0);isnt($?,0,'invalid evidence stops update');
    is(slurp($path),$before,'invalid evidence preserves every existing history byte');
}
is_deeply(run([['192.0.2.1','/',200,100,$browser]],bundle(),3,{LogType=>undef}),[1,100,0,0],'omitted LogType uses native W before evidence validation');
{
    my $case=$last_case;my $config="$case/config/awstats.fixture.conf";my $valid=slurp($config);
    my $history="$case/data/awstats102026.fixture.txt";my $before=slurp($history);
    for my $type ('S','M','F','w') {
        write_file($config,$valid."\nLogType=\"$type\"\n");
        my $pid=fork();die 'fork' if !defined $pid;
        if (!$pid) {open STDOUT,'>:raw',"$case/refused-out" or die;open STDERR,'>:raw',"$case/refused-err" or die;exec {$^X} $^X,"$root/wwwroot/cgi-bin/awstats.pl",'-config=fixture',"-configdir=$case/config",'-update';die 'exec';}
        waitpid($pid,0);isnt($?,0,"effective type $type is refused by optional evidence");
        is(slurp($history),$before,'refusal leaves all history bytes untouched');
    }
}
done_testing;
