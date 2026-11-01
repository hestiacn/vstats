use v5.020;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use Cwd qw(abs_path);
for my $module (qw(JSON::XS Try::Tiny Geo::IPfree)) {
    eval "require $module;1" or plan skip_all=>"Native history test requires $module";
}
my $root=abs_path(__FILE__);$root =~ s{/tools/t/[^/]+\z}{};
my $dir=tempdir(CLEANUP=>1);
sub slurp {open my $f,'<:raw',$_[0] or die $!;local $/;return <$f>//'';}
sub write_file {open my $f,'>:raw',$_[0] or die $!;print {$f} $_[1];close $f or die $!;}
my $model=slurp("$root/wwwroot/cgi-bin/awstats.model.conf");
for my $format ('text') {
    my $case="$dir/$format";make_path("$case/config","$case/data","$case/locks");
    my $cfg=$model;$cfg =~ s/^\s*LoadPlugin\s*=.*$/# No fixture plugins/mg;
    my %settings=(LogFile=>"$case/access.log",LogFormat=>1,SiteDomain=>'example.test',HostAliases=>'example.test',
        DirData=>"$case/data",DirLang=>"$root/wwwroot/cgi-bin/lang",DNSLookup=>0,Lang=>'en',
        BuildHistoryFormat=>$format,LevelForRobotsDetection=>0,EnableLocaldatePlugin=>0,
        LevelForOSDetection=>2,LevelForBrowsersDetection=>2,VerifiedCrawlerEvidenceFile=>'');
    for my $key (keys %settings) {my $value="$key=\"$settings{$key}\"";$cfg.="\n$value\n" if $cfg !~ s/^\Q$key\E\s*=.*$/$value/m;}
    write_file("$case/config/awstats.fixture.conf",$cfg);
    my $log='';my @agents=('Zzzzz/1.0 (zzzz zzzz)','END_UNKNOWNREFERER','END_UNKNOWNREFERERBROWSER');
    sub update {
        my ($case)=@_;my $pid=fork();die if !defined $pid;
        if (!$pid) {local $ENV{TEMP}="$case/locks";local $ENV{TMP}="$case/locks";open STDOUT,'>:raw',"$case/out" or die;open STDERR,'>:raw',"$case/err" or die;exec {$^X} $^X,"$root/wwwroot/cgi-bin/awstats.pl",'-config=fixture',"-configdir=$case/config",'-update';die;}
        waitpid($pid,0);is($?,0,'native update succeeds');is(slurp("$case/err"),'','no native diagnostics');
    }
    my @snapshots;
    for my $minute (0,1) {
        for my $i (0..$#agents) {$log.=sprintf('192.0.2.%d - - [01/Nov/2026:10:%02d:00 +0000] "GET / HTTP/1.1" 200 100 "-" "%s"',$i+1,$minute,$agents[$i])."\n";}
        write_file("$case/access.log",$log);update($case);
        my $history=slurp("$case/data/awstats112026.fixture.txt");
        my %by;
        for my $section ('UNKNOWNREFERER','UNKNOWNREFERERBROWSER') {
            # Extract rows using line boundaries for both existing native formats.
            my $inside=0;my @rows;
            for my $line (split /\n/,$history) {
                if ($line =~ /BEGIN_\Q$section\E(?:\s|>)/) {$inside=1;next;}
                last if $inside && $line =~ /END_\Q$section\E(?:\s|>|$)/ && $line !~ /[0-9]{14}/;
                push @rows,$line if $inside && $line ne '';
            }
            $by{$section}=\@rows;
            is(scalar @rows,scalar @agents,"$format $section stores one row per canonical key");
            like(join("\n",@rows),qr/Zzzzz\/1\.0%20\(zzzz%20zzzz\)/,"$section retains the spaced agent");
            like(join("\n",@rows),qr/20261101100\Q$minute\E00/,"$format $section retains latest observed date");
            unlike(join("\n",@rows),qr/20261101100000/,"$format $section has no stale duplicate") if $minute==1;
        }
        push @snapshots,\%by;
    }
    update($case);
    my $history=slurp("$case/data/awstats112026.fixture.txt");
    for my $section ('UNKNOWNREFERER','UNKNOWNREFERERBROWSER') {
        my $inside=0;my @rows;
        for my $line (split /\n/,$history) {
            if ($line =~ /BEGIN_\Q$section\E(?:\s|>)/) {$inside=1;next;}
            last if $inside && $line =~ /END_\Q$section\E(?:\s|>|$)/ && $line !~ /[0-9]{14}/;
            push @rows,$line if $inside && $line ne '';
        }
        is_deeply([sort @rows],[sort @{$snapshots[-1]{$section}}],"$format $section survives unchanged repeat");
    }
}
done_testing;
