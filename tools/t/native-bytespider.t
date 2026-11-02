use v5.020;
use strict;
use warnings;
use Test::More;
use Cwd qw(abs_path);
my $root = abs_path(__FILE__); $root =~ s{/tools/t/[^/]+\z}{};
our ($Debug, @RobotsSearchIDOrder_list1, @RobotsSearchIDOrder_list2, @RobotsSearchIDOrder_listgen, %RobotsHashIDLib);
$Debug = 0;
require "$root/wwwroot/cgi-bin/lib/robots.pm";
require "$root/wwwroot/cgi-bin/lib/browsers.pm";
my $android = 'Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36';
my @positive = ('Bytespider', 'bytespider/1.0', 'Bytespider;', '(Bytespider)', "Bytespider\t1", $android.' (compatible; Bytespider; https://example.test/)', 'iPad Bytespider;', 'SmartTV Bytespider;', 'Mozilla/5.0 (Linux; Wear OS) Bytespider;', 'crawler Bytespider/1.0', 'Mobile_(Bytespider;_https://example.test/)');
my @negative = ('', 'XBytespider/1', 'Bytespiderling', 'Bytespider.foo', 'Bytespider_x', "Byte\x{17f}pider/1", "Bytespider\x{a0}rest", $android, $android.' XBytespider/1');
for my $ua (@positive) { is(BytespiderRobotID($ua),'Bytespider/','bounded marker recognized'); }
for my $ua (@negative) { is(BytespiderRobotID($ua),'','collision/browser remains unrecognized'); }
is(BytespiderRobotID(undef),'','missing UA');
is(scalar(grep {$_ eq 'Bytespider/'} @RobotsSearchIDOrder_list1),1,'legacy list entry retained');
like($RobotsHashIDLib{'Bytespider/'},qr/Bytespider/,'legacy display entry retained');
is(get_device_type($android),'mobile','old Android stays mobile');
my ($broad) = grep {$android =~ /$_/i} (@RobotsSearchIDOrder_list1,@RobotsSearchIDOrder_list2,@RobotsSearchIDOrder_listgen);
like($broad,qr/Android/,'control would match broad robot heuristic if exemption were lost');
for my $rule (@RobotsSearchIDOrder_list1,@RobotsSearchIDOrder_list2,@RobotsSearchIDOrder_listgen) {
    next if $rule =~ /[\[\]().*+?{}^\$\\|]/ || $rule eq 'Bytespider/';
    is(BytespiderRobotID($android.' (compatible; '.$rule.'1.0;)'),'','other literal marker does not gain a bypass');
}
is(get_device_type($android.' (compatible; Bytespider; https://example.test/)'),'mobile','mobile wrapper is exercised');
is(get_device_type('iPad Bytespider;'),'tablet','tablet wrapper is exercised');
is(get_device_type('SmartTV Bytespider;'),'tv','TV wrapper is exercised');
is(get_device_type('Mozilla/5.0 (Linux; Wear OS) Bytespider;'),'wearable','wearable wrapper is exercised');
done_testing;
