use v5.020;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Copy qw(copy);
use File::Path qw(make_path);
use Cwd qw(abs_path);
for my $module (qw(JSON::XS Try::Tiny Geo::IPfree)) {
    eval "require $module; 1" or plan skip_all=>"Optional full parser requires $module";
}
my $root=abs_path(__FILE__);$root =~ s{/tools/t/[^/]+\z}{};
my $dir=tempdir(CLEANUP=>1);
sub slurp {open my $f,'<:raw',$_[0] or die $!;local $/;my $s=<$f>;return $s//'';}
sub write_file {open my $f,'>:raw',$_[0] or die $!;print {$f} $_[1];close $f or die $!;}
sub copy_tree {
    my ($src,$dst)=@_;make_path($dst);opendir my $dh,$src or die $!;
    for my $name (readdir $dh) {
        next if $name eq '.' || $name eq '..';
        if (-d "$src/$name") {copy_tree("$src/$name","$dst/$name");}
        else {copy("$src/$name","$dst/$name") or die $!;}
    }
    closedir $dh;
}
for my $kind (qw(candidate legacy)) {
    make_path("$dir/$kind");copy("$root/wwwroot/cgi-bin/awstats.pl","$dir/$kind/awstats.pl") or die $!;
    copy_tree("$root/wwwroot/cgi-bin/lib","$dir/$kind/lib");
    copy_tree("$root/wwwroot/cgi-bin/plugins","$dir/$kind/plugins");
}
my $old=slurp("$dir/legacy/lib/robots.pm");
$old =~ s/^sub BytespiderRobotID \{.*?^\}\n//ms or die 'helper removal fixture failed';
$old =~ s/^sub RegisteredCrawlerRobotID \{.*?^\}\n//ms or die 'registered helper removal fixture failed';
write_file("$dir/legacy/lib/robots.pm",$old);
my $model=slurp("$root/wwwroot/cgi-bin/awstats.model.conf");
my $serial=0;
sub parse {
    my ($kind,$ua,$level)=@_;$level//=2;$serial++;my $case="$dir/case-$serial";
    make_path("$case/config","$case/data");
    write_file("$case/access.log",'192.0.2.10 - - [30/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "'.$ua.'"'."\n");
    my $config=$model;
    my %values=(LogFile=>"$case/access.log",SiteDomain=>'example.test',DirData=>"$case/data",DirCgi=>"$dir/$kind",DirLang=>"$root/wwwroot/cgi-bin/lang",DNSLookup=>0,Lang=>'en',EnableLocaldatePlugin=>0,AllowBrowserUpdate=>0,LevelForRobotsDetection=>$level);
    $config =~ s/^LoadPlugin=/#LoadPlugin=/mg;
    for my $key (sort keys %values) {
        my $line="$key=\"$values{$key}\"";
        $config.="\n$line\n" if $config !~ s/^\Q$key\E=.*$/$line/m;
    }
    write_file("$case/config/awstats.fixture.conf",$config);
    my $pid=fork();die 'fork failed' if !defined $pid;
    if (!$pid) {
        open STDOUT,'>:raw',"$case/stdout" or die;open STDERR,'>:raw',"$case/stderr" or die;
        exec {$^X} $^X,"$dir/$kind/awstats.pl",'-config=fixture',"-configdir=$case/config",'-update';die 'exec failed';
    }
    waitpid($pid,0);my $exit=$? >> 8;
    is($exit,0,"$kind parser exits successfully");
    my $history="$case/data/awstats102026.fixture.txt";
    if ($exit || !-f $history) {diag substr(slurp("$case/stderr"),0,300);return [0,0,''];}
    my $raw=slurp($history);my ($time)=$raw =~ /BEGIN_TIME\s+\d+\n(.*?)END_TIME/s;my ($robots)=$raw =~ /BEGIN_ROBOT\s+\d+\n(.*?)END_ROBOT/s;
    my ($viewed,$nonviewed)=(0,0);
    for my $line (split /\n/,$time) {my @row=split /\s+/,$line;next if @row<7 || $row[0] !~ /\A[0-9]+\z/;$viewed+=$row[2];$nonviewed+=$row[5];}
    return [$viewed,$nonviewed,$robots//''];
}
my $android='Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36';
my $google='Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
my $reference=parse('candidate',$google);cmp_ok($reference->[1],'>=',1,'Googlebot nonviewed control');
my $legacy_id=parse('legacy','Bytespider/1.0')->[2];my ($id)=$legacy_id =~ /\A(\S+) /;
is($id,'Bytespider/','existing history ID measured by legacy branch');
for my $ua ($android.' (compatible; Bytespider; https://example.test/)',$android.' Bytespider/1.0','iPad Bytespider;','SmartTV Bytespider;','Mozilla/5.0 (Linux; Wear OS) Bytespider;','crawler Bytespider/1.0','Mobile_(Bytespider;_x)') {
    my $r=parse('candidate',$ua);
    is_deeply([@$r[0,1]],[@$reference[0,1]],'Byte counters match same-run Googlebot, not a frozen accounting bug');
    like($r->[2],qr/\A\Q$id\E /,'baseline ID preserved, including precedence');
}
for my $ua ($android,$android =~ s/Android 5\.0/Android 12/r,'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',$google,$android.' XBytespider/1',$android.' Bytespiderling/1') {
    my $before=parse('legacy',$ua);my $after=parse('candidate',$ua);
    is_deeply($after,$before,'ordinary/browser/crawler/collision control unchanged');
    is($after->[1],0,'ordinary mobile retains robot exemption') if $ua !~ /Googlebot/;
}
my $fallback=parse('legacy',$android.' Bytespider/1.0');is($fallback->[1],0,'custom database without helpers retains legacy mobile outcome');
my $disabled=parse('candidate',$android.' Bytespider/1.0',0);is($disabled->[1],0,'robots-disabled configuration retains exemption');
done_testing;
