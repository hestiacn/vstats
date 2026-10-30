#!/usr/bin/env perl
use v5.020;
use strict;
use warnings;
BEGIN {
    @INC=grep {$_ ne '.'} @INC;
    require Cwd; require File::Spec;
    my ($vol,$dir)=File::Spec->splitpath(Cwd::abs_path(__FILE__));
    unshift @INC,File::Spec->catpath($vol,File::Spec->catdir($dir,'lib'),'');
}
use VStats::TrafficClassifier;
use Getopt::Long qw(GetOptions Configure);
use File::Temp qw(tempfile);
use File::Spec;
use Cwd qw(abs_path);

my $stage='arguments';
my $caps=VStats::TrafficClassifier->fixed_limits;
sub fail { die "$_[0]\n"; }
sub regular_read {
    my ($path)=@_;
    fail('Input must be a regular file') if !-f $path;
    open my $fh,'<:raw',$path or fail('Cannot open input file');
    fail('Input must be a regular file') if !-f $fh;
    return $fh;
}
sub read_small {
    my ($path,$cap)=@_; my $fh=regular_read($path); my $raw='';
    while (1) {
        my $n=read($fh,my $chunk,8192); fail('Input read failed') if !defined $n; last if !$n;
        fail('File byte limit exceeded') if length($raw)+$n>$cap;
        $raw.=$chunk;
    }
    close($fh) or fail('Input close failed'); return $raw;
}
sub output_target {
    my ($path,$inputs)=@_;
    fail('Output must not be a symlink or nonregular file') if -l $path || (-e $path && !-f $path);
    my ($vol,$dir,$file)=File::Spec->splitpath(File::Spec->rel2abs($path));
    fail('Output filename is required') if !length $file;
    my $parent=abs_path(File::Spec->catpath($vol,$dir,''));
    fail('Output directory must already exist') if !defined($parent) || !-d $parent;
    my $target=File::Spec->catfile($parent,$file); my @out=stat($target);
    for my $input (@$inputs) {
        my $resolved=abs_path($input); my @in=stat($input);
        fail('Output aliases an input file') if defined($resolved) && ($resolved eq $target || (@out && @in && $out[0]==$in[0] && $out[1]==$in[1]));
    }
    return ($target,$parent);
}
sub main {
    fail('CGI execution is refused') if exists $ENV{GATEWAY_INTERFACE};
    Configure(qw(no_auto_abbrev no_ignore_case no_getopt_compat require_order));
    my ($config,$input,$format,$output,$render,$details,$help,@snapshots,@attestations);
    $render='json';
    my ($parsed,%seen);
    my $once=sub {my ($name,$ref)=@_;return sub {fail('Invalid arguments') if $seen{$name}++;$$ref=$_[1];}};
    { local $SIG{__WARN__}=sub {};
    $parsed=GetOptions('config=s'=>$once->('config',\$config),'input=s'=>$once->('input',\$input),'input-format=s'=>$once->('input-format',\$format),
        'output=s'=>$once->('output',\$output),'output-format=s'=>$once->('output-format',\$render),'details'=>$once->('details',\$details),
        'snapshot=s@'=>\@snapshots,'attestation=s@'=>\@attestations,'help'=>$once->('help',\$help));
    }
    fail('Invalid arguments') if !$parsed;
    if ($help && !@ARGV) {
        print "Usage: perl tools/traffic-classify.pl --config FILE --input FILE --input-format common|combined|jsonl --output FILE [--output-format json|html] [--details] [--snapshot RAW --attestation META]...\n";
        return;
    }
    fail('Explicit config, input, format and output are required') if @ARGV || !defined($config) || !defined($input) || !defined($format) || !defined($output);
    fail('Unsupported input or output format') if $format !~ /\A(?:common|combined|jsonl)\z/ || $render !~ /\A(?:json|html)\z/;
    fail('Snapshot and attestation counts must match, maximum32') if @snapshots!=@attestations || @snapshots>$caps->{snapshots};
    $stage='configuration';
    my $cfg=VStats::TrafficClassifier->config(read_small($config,$caps->{config_bytes}));
    $stage='provider evidence'; my @evidence;
    for my $i (0..$#snapshots) {
        push @evidence,VStats::TrafficClassifier->snapshot(read_small($snapshots[$i],$caps->{snapshot_bytes}),read_small($attestations[$i],$caps->{attestation_bytes}));
    }
    # All config/evidence validation precedes opening the access log.
    my $engine=VStats::TrafficClassifier->new(config=>$cfg,format=>$format,snapshots=>\@evidence,details=>$details);
    my @inputs=($config,$input,@snapshots,@attestations);
    $stage='output path'; my ($target,$parent)=output_target($output,\@inputs);
    $stage='input'; my $fh=regular_read($input);
    while (1) { my $n=read($fh,my $chunk,8192); fail('Log read failed') if !defined $n; last if !$n; $engine->feed($chunk); }
    close($fh) or fail('Log close failed');
    my $report=$engine->finish;
    $stage='render'; my $bytes=$render eq 'json' ? VStats::TrafficClassifier::canonical_json($report):VStats::TrafficClassifier::html_report($report);
    $stage='output';
    # Trusted parent directory required; recheck aliases immediately before write.
    output_target($output,\@inputs);
    my ($out,$temp)=tempfile('.traffic-classify-XXXXXXXX',DIR=>$parent,UNLINK=>0);
    my $ok=eval {
        binmode($out,':raw') or fail('Cannot set output mode');
        chmod(0600,$temp)==1 or fail('Cannot set private output permissions');
        print {$out} $bytes or fail('Cannot write report');
        close($out) or fail('Cannot close report');
        output_target($output,\@inputs);
        rename($temp,$target) or fail('Cannot publish report');
        1;
    };
    if (!$ok) { my $error=$@; close($out) if defined(fileno($out)); unlink $temp; die $error; }
}
my $ok=eval { main(); 1 };
if (!$ok) {
    # JSON decoders and OS errors may contain data/paths; never echo them.
    my $reason=$@;
    $reason='Invalid data or operation failed' if $reason !~ /\A[A-Za-z][A-Za-z0-9 ,:()\/.-]*\n\z/;
    $reason =~ s/\n\z//;
    print STDERR "traffic-classify: $stage: $reason\n";
    exit 1;
}
exit 0;
