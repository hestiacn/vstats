use v5.020;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use Cwd qw(abs_path);
use Digest::SHA qw(sha256_hex);

for my $module (qw(JSON::XS Try::Tiny Geo::IPfree)) {
    eval "require $module; 1" or BAIL_OUT("native parser needs $module");
}
my $root=abs_path(__FILE__);$root=~s{/tools/t/[^/]+\z}{};
my $dir=tempdir('vstats-paneologist-XXXXXX',TMPDIR=>1,CLEANUP=>1);
make_path("$dir/config","$dir/data");
sub read_file {open my $f,'<:raw',$_[0] or die $!;local $/;return <$f>//'';}
sub write_file {open my $f,'>:raw',$_[0] or die $!;print {$f} $_[1];close $f or die $!;}
my $source=read_file("$root/wwwroot/cgi-bin/awstats.pl");

# Exercise the real DNS loader with a literal pipe-suffixed file. The open
# wrapper refuses unsafe forms before execution, including against a regression.
my ($loader)=$source=~/(sub Read_DNS_Cache \{.*?^\})/ms;ok(defined $loader,'real DNS loader located');
my $dns_package=q{
 package DNSFixture;
 use subs qw(open);
 our ($DirData,$Debug,%PluginsLoaded,@opens);
 sub error {die $_[0];}
 sub debug {}
 sub open (*;$@) {
   push @opens,[@_];die "unsafe DNS open" unless @_==3 && $_[1] eq '<';
   my $name=$_[0];$name="DNSFixture::$name" unless $name=~/::/;
   no strict 'refs';return CORE::open(*{$name},$_[1],$_[2]);
 }
};
eval $dns_package.$loader.';1;' or BAIL_OUT($@);
{
 no warnings 'once';$DNSFixture::DirData=$dir;
 write_file("$dir/cache|","192.0.2.1 fixture.example\n");my %cache;
 is(DNSFixture::Read_DNS_Cache(\%cache,'cache|','',0),0,'DNS loader reads pipe-suffixed filename literally');
 is($cache{'192.0.2.1'},'fixture.example','real DNS cache data retained');
 is(scalar @DNSFixture::opens,1,'one safe cache open');
 is($DNSFixture::opens[0][1],'<','cache is explicitly read-only');
}
my $cfg=read_file("$root/wwwroot/cgi-bin/awstats.model.conf");
$cfg=~s/^\s*LoadPlugin\s*=.*$/# no plugins in the default synthetic fixture/mg;
my %settings=(LogFile=>"$dir/access.log",LogFormat=>1,SiteDomain=>'fixture.test',HostAliases=>'fixture.test',
 DirData=>"$dir/data",DirCgi=>'/stats',DirIcons=>'/assets/icon',DirLang=>"$root/wwwroot/cgi-bin/lang",DNSLookup=>0,
 Lang=>'en',EnableLocaldatePlugin=>0,AllowToUpdateStatsFromBrowser=>0,PurgeLogFile=>0,ArchiveLogRecords=>0,
 KeepBackupOfHistoricFiles=>0);
for my $key (sort keys %settings) {my $line="$key=\"$settings{$key}\"";$cfg.="\n$line\n" if $cfg!~s/^\Q$key\E\s*=.*$/$line/m;}
write_file("$dir/config/awstats.fixture.conf",$cfg);
my $serial=0;
sub invoke {
 my ($extra,@args)=@_;my $tag=++$serial;my $pid=fork();die $! unless defined $pid;
 if (!$pid) {
  $ENV{LC_ALL}=$ENV{LANG}='C';$ENV{TZ}='UTC';delete @ENV{qw(PERL5OPT PERLLIB GATEWAY_INTERFACE REQUEST_METHOD QUERY_STRING)};
  @ENV{keys %$extra}=values %$extra if $extra;
  chdir $dir or die $!;open STDOUT,'>:raw',"$dir/out-$tag" or die $!;open STDERR,'>:raw',"$dir/err-$tag" or die $!;
  exec {$^X} $^X,"$root/wwwroot/cgi-bin/awstats.pl","-configdir=$dir/config",@args;die $!;
 }
 waitpid($pid,0);return ($?>>8,read_file("$dir/out-$tag"),read_file("$dir/err-$tag"));
}
my ($rc,$out,$err)=invoke({},'-config=missing');
isnt($rc,0,'missing CLI configuration exits unsuccessfully');
is($out,'','normal CLI diagnostic does not contaminate stdout');
like($err,qr/config/i,'normal CLI diagnostic goes to stderr');
($rc,$out,$err)=invoke({},'-config=missing','-output');
isnt($rc,0,'HTML-generation failure remains unsuccessful');
like($out,qr/<html\b/i,'requested HTML failure stays in report output');
is($err,'','HTML diagnostic does not leak to stderr');
($rc,$out,$err)=invoke({GATEWAY_INTERFACE=>'CGI/1.1',REQUEST_METHOD=>'GET',QUERY_STRING=>'config=missing&output'},'-config=missing');
isnt($rc,0,'CGI error remains unsuccessful');
like($out,qr/Content-Type:/i,'CGI response retains its HTTP header');
like($out,qr/<html\b/i,'CGI response retains error HTML');
is($err,'','CGI error response remains on stdout');

write_file("$dir/access.log",("invalid synthetic log record\n" x 101));
($rc,$out,$err)=invoke({},'-config=fixture','-update');
isnt($rc,0,'malformed-log update fails');
like($err,qr/LogFormat|LogSeparator/,'format diagnostic goes to stderr');
unlike($out,qr/did not find|LogFormat parameter|LogSeparator/i,'format diagnostic is absent from stdout');

my $rows='';my @paths=('/','/next','/other','/asset.css','/image.png','/missing');
for my $i (0..$#paths) {
 $rows.=sprintf '192.0.2.%d - - [01/Oct/2026:10:00:%02d +0000] "GET %s HTTP/1.1" %d %d "-" "FixtureBrowser/1"',1+($i%2),$i,$paths[$i],($i==5?404:200),100+$i;
 $rows.="\n";
}
write_file("$dir/access.log",$rows);
($rc,$out,$err)=invoke({},'-config=fixture','-update');
is($rc,0,'synthetic native update succeeds');is($err,'','valid native update has no errors');
my @histories=glob "$dir/data/awstats*.fixture.txt";ok(@histories,'native history exists');
my %before=map {$_=>sha256_hex(read_file($_))} @histories;
($rc,$out,$err)=invoke({},'-config=fixture','-output','-month=10','-year=2026','-staticlinks');
is($rc,0,'default native report succeeds');
my $baseline_warnings=$err;
like($err,qr/\A(?:Use of uninitialized value \$_domener_[uv] in addition \(\+\) at [^\n]+ line \d+\.\n)*\z/,'baseline contains only the unchanged upstream country-counter warnings');
unlike($out,qr/<svg role="img" aria-label=/,'plugin is disabled by default');
write_file("$dir/config/awstats.fixture.conf",$cfg."\nLoadPlugin=\"graphsvg\"\n");
($rc,$out,$err)=invoke({},'-config=fixture','-output','-month=10','-year=2026','-staticlinks');
is($rc,0,'native renderer loads optional SVG plugin');is($err,$baseline_warnings,'optional SVG introduces no additional report diagnostics');
my @svg=$out=~/(<svg role="img" aria-label=.*?<\/svg>)/sg;
cmp_ok(scalar @svg,'>=',4,'native monthly/day/week/hour hooks render SVG');
unlike(join('',@svg),qr/<(?:script|image|foreignObject)\b|\b(?:href|src)\s*=/i,'rendered charts have no external or executable content');
my %after=map {$_=>sha256_hex(read_file($_))} @histories;
is_deeply(\%after,\%before,'chart rendering does not modify native histories');
write_file("$dir/config/awstats.fixture.conf",$cfg."\nLoadPlugin=\"graphsvg\"\nBuildReportFormat=\"xhtml\"\n");
($rc,$out,$err)=invoke({},'-config=fixture','-output','-month=10','-year=2026','-staticlinks');
is($rc,0,'SVG plugin works with native XHTML mode');is($err,$baseline_warnings,'XHTML introduces no additional report diagnostics');
like($out,qr/<svg role="img"/,'XHTML output includes inline SVG');
done_testing;
