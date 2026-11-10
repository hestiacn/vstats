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
    eval "require $module; 1" or plan skip_all => "Full parser requires $module";
}
my $root = abs_path(__FILE__);
$root =~ s{/tools/t/[^/]+\z}{};
my $dir = tempdir('vstats-accounting-XXXXXX', TMPDIR => 1, CLEANUP => 1);
my $program = "$root/wwwroot/cgi-bin/awstats.pl";
my @topics = qw(main alldomains allhosts allrobots browserdetail downloads
    errors400 errors403 errors404 keyphrases keywords lasthosts lastrobots
    osdetail refererpages refererse session unknownbrowser unknownip unknownos
    urldetail urlentry urlexit);
my $browser = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
my $google = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

sub slurp {
    open my $f, '<:raw', $_[0] or die "$!: $_[0]";
    local $/;
    return <$f> // '';
}
sub write_file {
    open my $f, '>:raw', $_[0] or die "$!: $_[0]";
    print {$f} $_[1];
    close $f or die $!;
}
my $model = slurp("$root/wwwroot/cgi-bin/awstats.model.conf");
sub fixture {
    my ($name, $rows) = @_;
    my $case = "$dir/$name";
    make_path("$case/config", "$case/data");
    my $log = '';
    for my $i (0 .. $#$rows) {
        my ($ip, $url, $status, $bytes, $agent, $month) = @{$rows->[$i]};
        $month //= 'Oct';
        $log .= sprintf '%s - - [01/%s/2026:10:%02d:00 +0000] "GET %s HTTP/1.1" %d %d "-" "%s"',
            $ip, $month, $i, $url, $status, $bytes, $agent;
        $log .= "\n";
    }
    write_file("$case/access.log", $log);
    my $config = $model;
    $config =~ s/^\s*LoadPlugin\s*=.*$/# No plugins in synthetic fixtures/mg;
    my %settings = (
        LogFile => "$case/access.log", LogFormat => 1,
        SiteDomain => 'example.test', HostAliases => 'example.test',
        DirData => "$case/data", DirCgi => '/stats', DirIcons => '/icons',
        DirLang => "$root/wwwroot/cgi-bin/lang", DNSLookup => 0, Lang => 'en',
        EnableLocaldatePlugin => 0, AllowToUpdateStatsFromBrowser => 0,
        PurgeLogFile => 0, ArchiveLogRecords => 0,
        ValidHTTPCodes => '200 206 304', KeepBackupOfHistoricFiles => 0,
    );
    for my $key (sort keys %settings) {
        my $line = "$key=\"$settings{$key}\"";
        $config .= "\n$line\n" if $config !~ s/^\Q$key\E\s*=.*$/$line/m;
    }
    write_file("$case/config/awstats.fixture.conf", $config);
    return $case;
}
sub invoke {
    my ($case, @args) = @_;
    my $pid = fork();
    die 'fork failed' if !defined $pid;
    if (!$pid) {
        $ENV{LC_ALL} = $ENV{LANG} = 'C';
        $ENV{TZ} = 'UTC';
        delete @ENV{qw(PERL5OPT PERLLIB)};
        chdir $case or die $!;
        open STDOUT, '>:raw', "$case/stdout" or die $!;
        open STDERR, '>:raw', "$case/stderr" or die $!;
        exec {$^X} $^X, $program, '-config=fixture', "-configdir=$case/config", @args;
        die 'exec failed';
    }
    waitpid($pid, 0);
    my $status = $?;
    is($status, 0, "@args exits successfully");
    my $err = slurp("$case/stderr");
    ok($err eq '', "@args has no diagnostics");
    diag substr($err, 0, 500) if length $err;
    return slurp("$case/stdout");
}
sub history {
    my ($case, $month) = @_;
    $month //= '10';
    my $path = "$case/data/awstats${month}2026.fixture.txt";
    return slurp($path) if -f $path;
    my $text = '';
    gunzip "$path.gz" => \$text or die "History: $GunzipError";
    return $text;
}
sub totals {
    my ($text) = @_;
    my ($general) = $text =~ /^BEGIN_GENERAL[^\n]*\n(.*?)^END_GENERAL/ms;
    my %general = map { my @v = split /\s+/, $_; @v > 1 ? ($v[0] => $v[1]) : () }
        split /\n/, $general // '';
    my ($time) = $text =~ /^BEGIN_TIME[^\n]*\n(.*?)^END_TIME/ms;
    my %n = (hits => 0, bytes => 0, nonviewed_hits => 0, nonviewed_bytes => 0,
        unique => 0 + ($general{TotalUnique} // 0), visits => 0 + ($general{TotalVisits} // 0));
    for my $line (split /\n/, $time // '') {
        my @v = split /\s+/, $line;
        next if @v < 7;
        $n{hits} += $v[2]; $n{bytes} += $v[3];
        $n{nonviewed_hits} += $v[5]; $n{nonviewed_bytes} += $v[6];
    }
    return \%n;
}
sub sections {
    my ($text) = @_;
    my %sections;
    while ($text =~ /^BEGIN_(\w+)[^\n]*\n(.*?)^END_\1\b/mgs) {
        my ($name, $body) = ($1, $2);
        next if $name eq 'MAP';
        # LastUpdate records this invocation, including how many records were old.
        my @rows = grep { length && !($name eq 'GENERAL' && /^LastUpdate\s/) }
            split /\n/, $body;
        $sections{$name} = [sort @rows];
    }
    return \%sections;
}
sub render {
    my ($case, $month) = @_;
    $month //= '10';
    my $main;
    for my $topic (@topics) {
        my $html = invoke($case, "-month=$month", '-year=2026', '-staticlinks',
            $topic eq 'main' ? '-output' : "-output=$topic");
        like($html, qr/<html\b/i, "$topic contains HTML");
        $main = $html if $topic eq 'main';
    }
    return $main;
}

# Expectations follow directly from the synthetic requests and byte sizes.
my @cases = (
    ['zero-byte-page', [['192.0.2.1','/zero.html',200,0,$browser]],
        {hits=>1,bytes=>0,unique=>1,visits=>1,nonviewed_hits=>0}],
    ['mixed-types', [['192.0.2.1','/zero.html',200,0,$browser],['192.0.2.1','/style.css',200,100,$browser]],
        {hits=>2,bytes=>100,unique=>1,visits=>1,nonviewed_hits=>0}],
    ['browser-pages', [['192.0.2.1','/one.html',200,100,$browser],['192.0.2.2','/two.html',200,200,$browser],['192.0.2.3','/missing.html',404,0,$browser]],
        {hits=>2,bytes=>300,unique=>2,visits=>2,nonviewed_hits=>1}],
    ['download-range', [['192.0.2.1','/sample.zip',200,1000,$browser],['192.0.2.1','/sample.zip',206,100,$browser]],
        {hits=>2,bytes=>1100,unique=>0,visits=>0,nonviewed_hits=>0}],
    ['cached-response', [['192.0.2.1','/one.html',200,100,$browser],['192.0.2.1','/one.html',304,0,$browser]],
        {hits=>2,bytes=>100,unique=>1,visits=>1,nonviewed_hits=>0}],
    ['known-bot', [['192.0.2.1','/one.html',200,100,$google]],
        {hits=>0,bytes=>0,unique=>0,visits=>0,nonviewed_hits=>1}],
    ['unknown-agent', [['192.0.2.1','/one.html',200,100,'-']],
        {hits=>0,bytes=>0,unique=>0,visits=>0,nonviewed_hits=>1}],
    ['tiff-image', [['192.0.2.1','/one.html',200,100,$browser],['192.0.2.1','/photo.tiff',200,200,$browser]],
        {hits=>2,bytes=>300,unique=>1,visits=>1,nonviewed_hits=>0}],
);
my $robot_case;
for my $spec (@cases) {
    my ($name, $rows, $expected) = @$spec;
    subtest $name => sub {
        my $case = fixture($name, $rows);
        $robot_case = $case if $name eq 'known-bot';
        invoke($case, '-update');
        my $before = history($case);
        my $n = totals($before);
        is_deeply({map {$_ => $n->{$_}} keys %$expected}, $expected, 'exact fixture accounting');
        my ($day) = $before =~ /^BEGIN_DAY[^\n]*\n(.*?)^END_DAY/ms;
        my ($day_hits, $day_bytes) = (0, 0);
        for my $line (split /\n/, $day // '') {
            next if $line !~ /\S/;
            my @v = split /\s+/, $line;
            $day_hits += $v[2]; $day_bytes += $v[3];
        }
        is_deeply([$day_hits, $day_bytes], [@$expected{qw(hits bytes)}], 'daily hits and bytes agree');
        invoke($case, '-update');
        is_deeply(sections(history($case)), sections($before), 'repeat update preserves every history section');
        my $html = render($case);
        if ($name eq 'tiff-image') {
            like($html, qr{/icons/mime/tiff\.svg}, 'TIFF report requests its MIME asset');
            ok(-f "$root/wwwroot/icon/mime/tiff.svg", 'requested TIFF asset is packaged');
        }
    };
}

subtest 'robot signatures with spaces' => sub {
    my $path = "$robot_case/data/awstats102026.fixture.txt";
    my $original = slurp($path);
    my ($body) = $original =~ /^BEGIN_ROBOT[^\n]*\n(.*?)^END_ROBOT/ms;
    my ($id, $numbers) = ($body // '') =~ /^(\S+)\s+(\d+\s+\d+\s+\d+(?:\s+\d+)?)[ \t]*$/m;
    ok(defined($id) && length($id) > 2, 'fixture produced a robot row') or return;
    my $spaced = $id;
    substr($spaced, 1, 1) = ' ';
    # Equal-length replacements keep all persisted MAP offsets valid.
    for my $omit_robots_txt (0, 1) {
        my $row = "$spaced $numbers";
        $row =~ s/ 0\z/  / if $omit_robots_txt;
        my $text = $original;
        $text =~ s/^(\Q$id\E[ \t]+\Q$numbers\E)[ \t]*$/$row/m or die 'robot fixture substitution failed';
        is(length($text), length($original), 'history byte offsets remain valid');
        write_file($path, $text);
        my $before = totals($text);
        for (1 .. 2) {
            invoke($robot_case, '-update');
            my $after = history($robot_case);
            like($after, qr/^\Q$spaced\E \Q$numbers\E[ \t]*$/m, 'full robot key and counters survive history round trip');
            is_deeply(totals($after), $before, 'robot history keeps traffic totals');
        }
        my $html = invoke($robot_case, '-month=10', '-year=2026', '-output=allrobots', '-staticlinks');
        like($html, qr/<html\b/i, 'space-containing robot report renders');
    }
};

subtest 'errors-only and compressed history' => sub {
    my $case = fixture('errors-only', [
        ['192.0.2.1','/broken',500,0,'-','Jul'],
        ['192.0.2.1','/missing',404,0,'-'],
        ['192.0.2.1','/anonymous',200,0,'-'],
    ]);
    invoke($case, '-update');
    my $july = "$case/data/awstats072026.fixture.txt";
    if (-f $july) {
        gzip $july => "$july.gz" or die $GzipError;
        unlink $july or die $!;
    }
    ok(-f "$july.gz", 'previous month uses gzip history');
    my %before;
    for my $month ('07', '10') {
        my $text = history($case, $month);
        is_deeply(totals($text), {hits=>0,bytes=>0,unique=>0,visits=>0,
            nonviewed_hits=>($month eq '07' ? 1 : 2),nonviewed_bytes=>0}, 'exact errors-only totals');
        $before{$month} = sections($text);
    }
    invoke($case, '-update');
    for my $month ('07', '10') {
        is_deeply(sections(history($case, $month)), $before{$month}, 'compressed/empty history survives repeat');
        render($case, $month);
    }
};
done_testing;
