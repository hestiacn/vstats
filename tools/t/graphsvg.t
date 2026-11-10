use v5.020;
use strict;
use warnings;
use utf8;
use Test::More;
use Cwd qw(abs_path);
use Encode qw(decode);

my $root=abs_path(__FILE__);$root=~s{/tools/t/[^/]+\z}{};
our ($color_weekend,$color_h)=('eeeeee','123abc');
my @debug;
sub Check_Plugin_Version {return 0;}
sub Format_Number {return $_[0];}
sub Format_Bytes {return $_[0].' Bytes';}
sub debug {push @debug,$_[0];}
sub _t {return $_[0];}
sub _esc {return 'existing escape helper';}
sub Graph_Pie {return 'existing graph helper';}
require "$root/wwwroot/cgi-bin/plugins/graphsvg.pm";
is(Init_graphsvg(''),'Init ShowGraph','standard native plugin hooks');
is(_esc(),'existing escape helper','does not replace unrelated helper');
is(Graph_Pie(),'existing graph helper','does not replace another graph helper');

sub render {
    my ($type,$labels,$values,$colors,$title,$width)=@_;
    my $out='';open my $capture,'>',\$out or die $!;binmode $capture,':encoding(UTF-8)';
    {local *STDOUT=$capture;
     &ShowGraph_graphsvg($title//'Fixture & <chart>',$type,$width//'PHB',
       $labels,['Hits','Bandwidth'],$colors||['123abc','abc'],[],[5,1024],[],$values);}
    close $capture;return decode('UTF-8',$out);
}
sub xml_ok {
    my ($svg,$name)=@_;
    open my $pipe,'|-','/usr/bin/python3','-c',
      'import sys,xml.etree.ElementTree as E;r=E.fromstring(sys.stdin.buffer.read());assert r.tag=="{http://www.w3.org/2000/svg}svg";assert r.attrib["role"]=="img";assert r.find("{http://www.w3.org/2000/svg}title") is not None;assert not any(k.lower().startswith("on") for e in r.iter() for k in e.attrib);assert not any(e.tag.split("}")[-1] in ("script","image","foreignObject") for e in r.iter())' or die $!;
    binmode $pipe,':encoding(UTF-8)';print {$pipe} $svg;
    ok(close($pipe),$name.' is accessible, well-formed SVG');
}
for my $type (qw(month daysofmonth daysofweek hours)) {
    my $svg=render($type,["Jan\n2026:","Feb!"],[2,512,3,512]);
    xml_ok($svg,$type);
    like($svg,qr/1024 Bytes/,$type.' retains bandwidth unit');
    unlike($svg,qr/(?:NaN|Infinity|\bInf\b)/,$type.' has finite geometry');
}
for my $type (qw(cluster filetypes httpstatus browsers downloads pages oss hosts)) {
    my $svg=render($type,['First','Second'],[60,20]);
    xml_ok($svg,$type);
    like($svg,qr/Share of displayed entries/,$type.' declares subset denominator');
    like($svg,qr/75\.0%/,$type.' shares use displayed values');
}
my $single=render('browsers',['Zero','Only positive','Zero again'],[0,8,0]);
like($single,qr/<circle\b/,'one positive slice renders a full circle even with zero entries');
unlike($single,qr/<path\b/,'one positive slice avoids a zero-length full-circle arc');
xml_ok($single,'single positive slice');
is(render('browsers',['Empty'],[0]),'','all-zero data produces no chart');
is(render('month',[],[]),'','empty time series produces no chart');
my $hostile=q{<script>alert(1)</script> & " onload="bad};
my $escaped=render('browsers',[$hostile,'普通访问'],[2,1],['" onload="bad'],$hostile);
unlike($escaped,qr/<script/,'labels cannot introduce executable elements');
like($escaped,qr/&lt;script&gt;/,'hostile label remains escaped text');
like($escaped,qr/普通访问/,'Unicode labels survive');
xml_ok($escaped,'hostile/Unicode labels');
my $scientific=render('hours',['Hour'],['2e0','1.024e3']);
like($scientific,qr/1024 Bytes/,'finite scientific values are retained');
my $invalid=render('hours',['Hour'],['NaN','1e9999']);
unlike($invalid,qr/(?:NaN|Infinity|\bInf\b)/,'nonfinite data cannot enter SVG coordinates');
xml_ok($invalid,'nonfinite inputs');
my $tiny=render('hours',['Hour'],[1,2],undef,undef,1);
unlike($tiny,qr/width="-/,'tiny width never produces negative bar widths');
xml_ok($tiny,'tiny dimensions');
my @countries=map {'Country '.$_} 1..20;my @values=reverse 1..20;
my $rank=render('countries_map',\@countries,\@values);
xml_ok($rank,'country ranking');
is(scalar(()=$rank=~/<rect[^>]*><title>/g),15,'ranking retains the native plugin top-15 display bound');
like($rank,qr/Country 1/,'highest country is retained');
unlike($rank,qr/>Country 20</,'lowest omitted country is outside top 15');
for my $svg ($escaped,$scientific,$rank) {
    unlike($svg,qr/<(?:script|image|foreignObject)\b|\b(?:href|src)\s*=/i,'chart has no external resources or executable elements');
}
done_testing;
