use v5.020;
use strict;
use warnings;
use Test::More;
use Cwd qw(abs_path);
use VStats::TrafficClassifier;
my $root=abs_path(__FILE__);$root =~ s{/tools/t/[^/]+\z}{};
sub slurp {open my $f,'<:raw',$_[0] or die;local $/;return scalar <$f>;}
my $C='VStats::TrafficClassifier';my $default=$C->defaults;
is_deeply($C->config(slurp("$root/tools/traffic-classification.example.json")),$default,'example expands to canonical defaults');
my $guide=slurp("$root/docs/traffic-classification.md");
for my $key (sort keys %{$default->{limits}}) {
    like($guide,qr/\| `\Q$key\E` \| \Q$default->{limits}{$key}\E \|/,'guide resource default agrees with module');
}
for my $key (sort keys %{$default->{scanner}}) {
    like($guide,qr/`\Q$key\E: \Q$default->{scanner}{$key}\E`/,'guide scanner default agrees with module');
}
for my $key (sort keys %{$default->{behavior}}) {
    like($guide,qr/`\Q$key\E: \Q$default->{behavior}{$key}\E`/,'guide behavior default agrees with module');
}
for my $key (sort keys %{$default->{probing}}) {
    next if ref $default->{probing}{$key};
    like($guide,qr/`\Q$key\E: \Q$default->{probing}{$key}\E`/,'guide probing default agrees with module');
}
like($guide,qr/`paths: \[\]`/,'guide probing endpoint default agrees with module');
like($guide,qr/`max_gap_seconds: \Q$default->{verification}{max_gap_seconds}\E`/,'guide evidence gap default agrees');
for my $token (@{$default->{crawler_tokens}}) {like($guide,qr/`\Q$token\E`/,'guide default token present');}
my $registry=$C->provider_registry;
is_deeply([map {$_->{parser_id}} @$registry],['google_prefixes_v1'],'one reviewed parser registry');
for my $url (@{$registry->[0]{source_urls}}) {like($guide,qr/\Q$url\E/,'guide registry URL exact');}
my $cli=slurp("$root/tools/traffic-classify.pl");
like($cli,qr/->fixed_limits/,'CLI shares module resource constants');
unlike($cli,qr/(?:1048576|2097152|16384|32768)/,'no CLI cap replicas');
my $module=slurp("$root/tools/lib/VStats/TrafficClassifier.pm");
unlike($module,qr/\b(?:open|sysopen|readline|system|exec|connect|gethostbyaddr|gethostbyname)\s*\(/,'library has no file/network/process I/O');
my $fixed=$C->fixed_limits;
is($fixed->{tokens},128,'reviewed token cap');is($fixed->{snapshots},32,'reviewed snapshot cap');
is($fixed->{distributed_max_window},21600,'distributed execution guard is explicit');
like($guide,qr/`21600` seconds/,'guide documents longer-window execution guard');
like($guide,qr/context_binding_version: 2/,'guide documents halo-bound IP evidence context');
like($guide,qr/--context-before FILE/,'guide documents context CLI');
is($C->analysis_window($default),60,'default analysis horizon comes from the library');
done_testing;
