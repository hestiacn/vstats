use v5.020;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use Cwd qw(abs_path);
use IO::Compress::Gzip qw(gzip $GzipError);
use IO::Uncompress::Gunzip qw(gunzip $GunzipError);
for my $module (qw(JSON::XS Try::Tiny Geo::IPfree)) {
    eval "require $module; 1" or plan skip_all=>"Native parser requires $module";
}
my $root=abs_path(__FILE__);$root=~s{/tools/t/[^/]+\z}{};
my $dir=tempdir('vstats-compressed-XXXXXX',TMPDIR=>1,CLEANUP=>1);
make_path("$dir/config","$dir/data");
sub read_file {open my $f,'<:raw',$_[0] or die $!;local $/;return <$f>//'';}
sub write_file {open my $f,'>:raw',$_[0] or die $!;print {$f} $_[1];close $f or die $!;}
my $cfg=read_file("$root/wwwroot/cgi-bin/awstats.model.conf");
$cfg=~s/^\s*LoadPlugin\s*=.*$/# No plugins in synthetic fixture/mg;
my %settings=(LogFile=>"$dir/access.log",LogFormat=>1,SiteDomain=>'example.test',HostAliases=>'example.test',DirData=>"$dir/data",DirLang=>"$root/wwwroot/cgi-bin/lang",DNSLookup=>0,Lang=>'en',EnableLocaldatePlugin=>0,KeepBackupOfHistoricFiles=>0);
for my $k(sort keys %settings){my $line="$k=\"$settings{$k}\"";$cfg.="\n$line\n" if $cfg!~s/^\Q$k\E\s*=.*$/$line/m;}
write_file("$dir/config/awstats.fixture.conf",$cfg);
my $line='192.0.2.1 - - [02/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0 (Windows) Chrome/126"'."\n";
sub update {
    my $pid=fork();die if !defined $pid;
    if (!$pid){open STDOUT,'>:raw',"$dir/out" or die;open STDERR,'>:raw',"$dir/err" or die;exec {$^X} $^X,"$root/wwwroot/cgi-bin/awstats.pl",'-config=fixture',"-configdir=$dir/config",'-update';die;}
    waitpid($pid,0);is($?,0,'compressed-history update exits successfully');is(read_file("$dir/err"),'','compressed suffix never becomes a numeric date field');
    my $base="$dir/data/awstats102026.fixture.txt";my $raw;
    if(-f $base){$raw=read_file($base);gzip \$raw=>"$base.gz" or die $GzipError;unlink $base or die;}
    else{gunzip "$base.gz"=>\$raw or die $GunzipError;}
    my($time)=$raw=~/^BEGIN_TIME[^\n]*\n(.*?)^END_TIME/ms;my($hits,$bytes)=(0,0);
    for(split /\n/,$time//''){my @q=split /\s+/;next if @q<7;$hits+=$q[2]+$q[5];$bytes+=$q[3]+$q[6];}
    return [$hits,$bytes];
}
write_file("$dir/access.log",$line);is_deeply(update(),[1,100],'seed history accounts for its request');
is_deeply(update(),[1,100],'compressed history is unchanged on an identical repeat');
write_file("$dir/access.log",$line.($line=~s/02\/Oct/03\/Oct/r));
is_deeply(update(),[2,200],'new requests append to compressed history without loss or duplication');
done_testing;
