use v5.020;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use Cwd qw(abs_path);
for my $module (qw(JSON::XS Try::Tiny Geo::IPfree)) {
    eval "require $module; 1" or plan skip_all=>"Full parser requires $module";
}
my $root=abs_path(__FILE__);$root=~s{/tools/t/[^/]+\z}{};
my $dir=tempdir('vstats-icon-bytes-XXXXXX',TMPDIR=>1,CLEANUP=>1);
make_path("$dir/config","$dir/data");
sub read_file {open my $f,'<:raw',$_[0] or die $!;local $/;return <$f>//'';}
sub write_file {open my $f,'>:raw',$_[0] or die $!;print {$f} $_[1];close $f or die $!;}
my @rows=(['/favicon.ico',404,101],['/manifest.json',404,202],
    ['/nested/manifest.webmanifest',404,303],['/browserconfig.xml',404,404],
    ['/safari-pinned-tab.svg',404,0],['/apple-touch-icon.png',404,505],
    ['/favicon.ico',404,'-'],['/favicon.png',200,37],['/favicon.svg',304,0],['/favicon.ico',200,'-']);
my ($raw,$expected) = ('',0);
for my $i (0..$#rows) {
    my ($path,$status,$bytes)=@{$rows[$i]};$expected+=$bytes if $bytes ne '-';
    $raw.=sprintf '192.0.2.1 - - [01/Oct/2026:10:00:%02d +0000] "GET %s HTTP/1.1" %d %s "-" "Mozilla/5.0 (Windows) Chrome/130"', $i,$path,$status,$bytes;
    $raw.="\n";
}
write_file("$dir/access.log",$raw);
my $cfg=read_file("$root/wwwroot/cgi-bin/awstats.model.conf");$cfg=~s/^\s*LoadPlugin\s*=.*$/# No plugins in synthetic fixture/mg;
my %settings=(LogFile=>"$dir/access.log",LogFormat=>1,SiteDomain=>'example.test',HostAliases=>'example.test',
    DirData=>"$dir/data",DirCgi=>'/stats',DirLang=>"$root/wwwroot/cgi-bin/lang",DNSLookup=>0,
    Lang=>'en',EnableLocaldatePlugin=>0,AllowToUpdateStatsFromBrowser=>0,PurgeLogFile=>0,ArchiveLogRecords=>0,
    ValidHTTPCodes=>'200 206 304',KeepBackupOfHistoricFiles=>0);
for my $key (sort keys %settings) {my $line="$key=\"$settings{$key}\"";$cfg.="\n$line\n" if $cfg!~s/^\Q$key\E\s*=.*$/$line/m;}
write_file("$dir/config/awstats.fixture.conf",$cfg);
sub update {
    my $pid=fork();die if !defined $pid;
    if (!$pid) {
        $ENV{LC_ALL}=$ENV{LANG}='C';$ENV{TZ}='UTC';delete @ENV{qw(PERL5OPT PERLLIB)};
        chdir $dir or die $!;open STDOUT,'>:raw',"$dir/out" or die $!;open STDERR,'>:raw',"$dir/err" or die $!;
        exec {$^X} $^X,"$root/wwwroot/cgi-bin/awstats.pl",'-config=fixture',"-configdir=$dir/config",'-update';die;
    }
    waitpid($pid,0);is($?,0,'native update succeeds');is(read_file("$dir/err"),'','native update has no diagnostics');
    my $history=read_file("$dir/data/awstats102026.fixture.txt");my ($time)=$history=~/^BEGIN_TIME[^\n]*\n(.*?)^END_TIME/ms;ok(defined $time,'native TIME section exists');
    my ($viewed,$hits,$bytes)=(0,0,0);
    for my $line (split /\n/,$time//'') {my @v=split /\s+/,$line;next if @v<7;$viewed+=$v[2];$hits+=$v[5];$bytes+=$v[6];}
    return {viewed_hits=>$viewed,nonviewed_hits=>$hits,nonviewed_bytes=>$bytes};
}
my $first=update();is($first->{viewed_hits},0,'icons and manifests retain existing non-viewed classification');
is($first->{nonviewed_hits},scalar @rows,'every synthetic icon/manifest counted exactly once');
is($first->{nonviewed_bytes},$expected,'404 bodies included; missing/zero sizes remain zero');
my $repeat=update();is_deeply($repeat,$first,'repeat does not duplicate icon/manifest bytes or requests');
done_testing;
