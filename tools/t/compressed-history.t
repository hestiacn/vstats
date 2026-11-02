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
# Exercise the production atomic compressor with authoritative plaintext and
# an independently generated stale archive, including failure preservation.
my $native=read_file("$root/wwwroot/cgi-bin/awstats.pl");
my ($compressor)=$native=~/(^sub Compress_History_File \{.*?^\})/ms;
ok(defined($compressor),'production history compressor found');eval $compressor;die $@ if $@;
my $binary="new history\0\xFF\n"x31;my $plain="$dir/data/history with ' quote.txt";
write_file($plain,$binary);chmod 0640,$plain;my $old='stale history';gzip \$old=>"$plain.gz" or die $GzipError;
ok(Compress_History_File($plain),'stale gzip replaced from authoritative plaintext');
my $roundtrip='';gunzip "$plain.gz"=>\$roundtrip or die $GunzipError;
is($roundtrip,$binary,'independent decompression returns every updated binary byte');
ok(!-e $plain,'plaintext removed only after successful archive publication');
is((stat("$plain.gz"))[2]&0777,0640,'archive retains history permissions');
ok(!Compress_History_File($plain),'absent plaintext is an idempotent no-op');
write_file($plain,'keep me');unlink "$plain.gz" or die;mkdir "$plain.gz" or die;
ok(!Compress_History_File($plain),'non-file destination refuses replacement');is(read_file($plain),'keep me','failed replacement preserves plaintext');
rmdir "$plain.gz" or die;my $target="$dir/untouched";write_file($target,'untouched');symlink $target,"$plain.gz" or die;
ok(!Compress_History_File($plain),'symlink archive is rejected');is(read_file($target),'untouched','archive symlink target stays unchanged');unlink "$plain.gz" or die;
unlink $plain or die;symlink $target,$plain or die;ok(!Compress_History_File($plain),'symlink plaintext is rejected');unlink $plain or die;
my $readonly="$dir/readonly";mkdir $readonly or die;write_file("$readonly/keep.txt",'latest');gzip \$old=>"$readonly/keep.txt.gz" or die $GzipError;
my $archive_before=read_file("$readonly/keep.txt.gz");chmod 0500,$readonly;
SKIP: {skip 'permission failure requires unprivileged test user',3 if $>==0;
    ok(!Compress_History_File("$readonly/keep.txt"),'temporary-file failure preserves both inputs');
    is(read_file("$readonly/keep.txt"),'latest','failed compression preserves latest plaintext');
    is(read_file("$readonly/keep.txt.gz"),$archive_before,'failed compression preserves preceding archive');
}
chmod 0700,$readonly;
opendir my $dh,"$dir/data" or die;my @left=grep {/\.gzip-/}readdir $dh;closedir $dh;
is_deeply(\@left,[],'no incomplete archive siblings remain');
done_testing;
