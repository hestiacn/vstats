package VStats::TrafficClassifier;
use v5.020;
use strict;
use warnings;
use JSON::PP ();
use Digest::SHA ();
use Socket qw(AF_INET AF_INET6 inet_pton);
use Time::Local qw(timegm);
use Encode qw(decode encode FB_CROAK LEAVE_SRC);

# GPL version 2 or later, like the parent project. No file or network I/O here.
our $VERSION = '1.0';
my $ALGORITHM = 'vstats-traffic-v1';
my $word=qr/[^ \t]+/;
my $MAX_EPOCH = 4102444800;
my $PROVIDER = {provider_id=>'google_common',ua_tokens=>['Googlebot'],
    source_urls=>['https://developers.google.com/static/crawling/ipranges/common-crawlers.json'],parser_id=>'google_prefixes_v1'};
my $FIXED = {config_bytes=>1048576,snapshot_bytes=>2097152,attestation_bytes=>16384,
    tokens=>128,token_bytes=>64,families=>64,paths=>2048,references=>2048,
    snapshots=>32,prefixes=>32768,json_depth=>32,max_window=>3600,max_gap=>604800,family_id_bytes=>32};
my $JSON = JSON::PP->new->canonical->allow_nonref;
my $DEFAULT = {
    schema_version => 1, hosts => [],
    crawler_tokens => [qw(Googlebot Bytespider bingbot AhrefsBot ClaudeBot GPTBot curl Wget python-requests)],
    probe_families => [], site_references => [], exclude => [],
    scanner => {distinct_paths => 3, distinct_families => 2, window_seconds => 60},
    verification => {max_gap_seconds => 86400},
    limits => {input_bytes => 67108864, line_bytes => 16384, records => 100000,
               groups => 100000, ua_bytes => 4096, target_bytes => 8192},
};

sub defaults { return $JSON->decode($JSON->encode($DEFAULT)); }
sub fixed_limits { return $JSON->decode($JSON->encode($FIXED)); }
sub provider_registry { return $JSON->decode($JSON->encode([$PROVIDER])); }
sub canonical_json { return JSON::PP->new->utf8->canonical->pretty->encode($_[0]); }
sub _bad { die "$_[0]\n"; }
sub _bytes { return length(encode('UTF-8', $_[0])); }
sub _str {
    my ($v) = @_;
    _bad('Expected JSON string') if !defined($v) || ref($v) || $JSON->encode($v) !~ /\A"/;
    return $v;
}
sub _uint {
    my ($v,$max,$min) = @_; $min //= 0;
    _bad('Expected bounded nonnegative JSON integer') if !defined($v) || ref($v)
        || $JSON->encode($v) !~ /\A(?:0|[1-9][0-9]*)\z/ || $v < $min || $v > $max;
    return $v;
}
sub _keys {
    my ($v,@allowed) = @_;
    _bad('Expected JSON object') if ref($v) ne 'HASH';
    my %allowed = map {$_=>1} @allowed;
    _bad('Unknown JSON field') if grep {!$allowed{$_}} keys %$v;
}
sub _array { _bad('Expected bounded JSON array') if ref($_[0]) ne 'ARRAY' || @{$_[0]} > $_[1]; }

# JSON::PP supplies string/Unicode and grammar decoding. This bounded lexical
# preflight additionally rejects duplicate decoded keys and noninteger lexemes.
sub strict_json {
    my ($raw) = @_;
    my $text = decode('UTF-8',$raw,FB_CROAK|LEAVE_SRC);
    my $value = JSON::PP->new->max_depth($FIXED->{json_depth})->decode($text);
    my @stack;
    pos($text) = 0;
    while ((pos($text) // 0) < length($text)) {
        next if $text =~ /\G[\x20\x09\x0A\x0D]+/gc;
        if ($text =~ /\G"/gc) {
            my $begin=pos($text)-1;
            while (1) {
                _bad('Unsupported JSON token') if $text !~ /\G[^"\\]*(["\\])/gc;
                last if $1 eq '"';
                pos($text)=pos($text)+1;
            }
            my $lexeme=substr($text,$begin,pos($text)-$begin);
            if ($text =~ /\G(?=[\x20\x09\x0A\x0D]*:)/gc) {
                my $key = $JSON->decode($lexeme);
                _bad('Duplicate JSON key') if !@stack || !defined($stack[-1]) || $stack[-1]{$key}++;
            }
            next;
        }
        if ($text =~ /\G(-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/gc) {
            _bad('Integer JSON lexeme required') if $1 !~ /\A(?:0|[1-9][0-9]{0,9})\z/;
            next;
        }
        if ($text =~ /\G([{}\[\]:,])/gc) {
            my $p=$1;
            push @stack,{} if $p eq '{';
            push @stack,undef if $p eq '[';
            pop @stack if $p eq '}' || $p eq ']';
            next;
        }
        next if $text =~ /\G(?:true|false|null)/gc;
        _bad('Unsupported JSON token');
    }
    return $value;
}

sub literal_ip {
    my ($s)=@_; return if !defined($s) || ref($s) || $s =~ /[^0-9A-Fa-f:.]/;
    for my $af (AF_INET,AF_INET6) {
        my $packed = eval { inet_pton($af,$s) };
        return ($af,$packed) if defined $packed;
    }
    return;
}
sub _host {
    my ($s)=@_; _str($s);
    _bad('Invalid host') if $s =~ /[^A-Za-z0-9.-]/;
    $s =~ tr/A-Z/a-z/; $s =~ s/\.\z//;
    _bad('Invalid host') if !length($s) || length($s)>253 || literal_ip($s);
    for my $label (split /\./,$s,-1) {
        _bad('Invalid host') if length($label)>63 || $label !~ /\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z/;
    }
    return $s;
}
sub normalize_target {
    my ($s)=@_; return if !defined($s) || ref($s);
    $s =~ s/[?#].*\z//s;
    return if $s !~ m{\A/(?!/)} || $s =~ /[^\x20-\x7E]/ || $s =~ /\\/
        || $s =~ /%(?![0-9A-Fa-f]{2})/ || $s =~ /%(?:2[fF]|5[cC])/;
    $s =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
    return if $s =~ /[^\x20-\x7E]|[%?#\\]/ || $s =~ m{//} || $s =~ m{(?:\A|/)\.{1,2}(?:/|\z)};
    return $s;
}
sub marker_matches {
    my ($ua,$token)=@_; return 0 if !defined($ua);
    return $ua =~ /(?:^|[^A-Za-z0-9])\Q$token\E(?=[\x09-\x0D\x20\/;)]|\z)/iaa ? 1:0;
}
sub _period {
    my ($o,$from,$until)=@_;
    _uint($o->{$from},$MAX_EPOCH); _uint($o->{$until},$MAX_EPOCH);
    _bad('Reversed evidence period') if $o->{$from}>$o->{$until};
}
sub config {
    my ($class,$raw)=@_;
    _bad('Config byte limit exceeded') if length($raw)>$FIXED->{config_bytes};
    my $c = strict_json($raw); _keys($c,keys %$DEFAULT);
    _uint($c->{schema_version},1,1);
    my $d=defaults();
    for my $key (keys %$d) {
        if (!exists $c->{$key}) { $c->{$key}=$d->{$key}; next; }
        if ($key eq 'scanner' || $key eq 'verification' || $key eq 'limits') {
            _keys($c->{$key},keys %{$d->{$key}});
            for my $k (keys %{$d->{$key}}) { $c->{$key}{$k}=$d->{$key}{$k} if !exists $c->{$key}{$k}; }
        }
    }
    _bad('Expected hosts array') if ref($c->{hosts}) ne 'ARRAY'; my %hosts;
    for (@{$c->{hosts}}) { $_=_host($_); _bad('Duplicate host') if $hosts{$_}++; }
    _array($c->{crawler_tokens},$FIXED->{tokens}); my %tokens;
    my %refused=map {lc($_)=>1} qw(Mozilla Chrome Safari Firefox Android AppleWebKit Mobile Version Linux Windows Macintosh Edg Edge OPR Opera);
    for my $token (@{$c->{crawler_tokens}}) {
        _str($token);
        _bad('Invalid crawler token') if length($token)>$FIXED->{token_bytes} || $token !~ /\A[A-Za-z0-9][A-Za-z0-9._-]*\z/;
        _bad('Duplicate or generic browser token') if $tokens{lc($token)}++ || $refused{lc($token)};
    }
    my $s=$c->{scanner}; _uint($s->{distinct_paths},$FIXED->{paths},1); _uint($s->{distinct_families},$s->{distinct_paths},1); _uint($s->{window_seconds},$FIXED->{max_window},1);
    _uint($c->{verification}{max_gap_seconds},$FIXED->{max_gap});
    for my $k (keys %{$d->{limits}}) { _uint($c->{limits}{$k},$d->{limits}{$k},1); }
    _bad('Field cap exceeds line cap') if $c->{limits}{ua_bytes}>$c->{limits}{line_bytes} || $c->{limits}{target_bytes}>$c->{limits}{line_bytes};
    _array($c->{exclude},3); my %exclude;
    for (@{$c->{exclude}}) { _str($_); _bad('Invalid exclusion selector') if !/\A(?:declared_crawler_or_tool|verified_crawler|scanner_flagged)\z/ || $exclude{$_}++; }
    _array($c->{probe_families},$FIXED->{families}); my (%ids,%paths); my $n=0;
    for my $f (@{$c->{probe_families}}) {
        _keys($f,qw(id paths absent_from absent_until)); _str($f->{id});
        _bad('Invalid or duplicate family ID') if $f->{id} !~ /\A[a-z][a-z0-9_-]*\z/ || length($f->{id})>$FIXED->{family_id_bytes} || $ids{$f->{id}}++;
        _period($f,'absent_from','absent_until'); _array($f->{paths},$FIXED->{paths}); _bad('Empty probe family') if !@{$f->{paths}};
        for my $p (@{$f->{paths}}) {
            _str($p); my $normal=normalize_target($p);
            _bad('Invalid or duplicate probe path') if !defined($normal) || $normal ne $p || $paths{$p}++ || ++$n>$FIXED->{paths};
        }
    }
    _array($c->{site_references},$FIXED->{references}); my %refs;
    for my $ref (@{$c->{site_references}}) {
        _keys($ref,qw(path from until)); _str($ref->{path}); _period($ref,'from','until');
        my $p=normalize_target($ref->{path});
        _bad('Invalid or duplicate site reference') if !defined($p) || $p ne $ref->{path} || $refs{$p}++;
    }
    return $c;
}

sub _epoch {
    my ($year,$month,$day,$hour,$minute,$second,$offset)=@_;
    _bad('Invalid timestamp') if $year<1969 || $year>2100 || $month<1 || $month>12 || $hour>23 || $minute>59 || $second>59;
    my $t=timegm($second,$minute,$hour,$day,$month-1,$year);
    my @g=gmtime($t);
    _bad('Invalid calendar date') if $g[3]!=$day || $g[4]!=$month-1 || $g[5]+1900!=$year;
    $t -= $offset;
    _bad('Timestamp outside supported range') if $t<0 || $t>$MAX_EPOCH;
    return $t;
}
sub _rfc3339 {
    my ($s)=@_; _str($s);
    _bad('Expected UTC RFC3339 timestamp') if $s !~ /\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z\z/;
    return _epoch($1,$2,$3,$4,$5,$6,0);
}
sub cidr_index {
    my ($prefixes)=@_; my %index;
    for my $cidr (@$prefixes) {
        _str($cidr);
        _bad('Invalid CIDR') if $cidr !~ /\A([^\/]+)\/(0|[1-9][0-9]*)\z/;
        my ($ip,$n)=($1,$2); my ($af,$packed)=literal_ip($ip);
        _bad('Invalid CIDR address or length') if !defined($af) || $n>8*length($packed);
        my $bits=unpack('B*',$packed);
        _bad('Noncanonical CIDR network bits') if substr($bits,$n) =~ /1/;
        $index{$af}{$n}{substr($bits,0,$n)}=1;
    }
    return \%index;
}
sub cidr_contains {
    my ($index,$ip)=@_; my ($af,$packed)=literal_ip($ip); return 0 if !defined($af);
    my $bits=unpack('B*',$packed);
    for my $n (keys %{$index->{$af} || {}}) { return 1 if $index->{$af}{$n}{substr($bits,0,$n)}; }
    return 0;
}
sub snapshot {
    my ($class,$raw,$meta_raw)=@_;
    _bad('Snapshot byte limit exceeded') if length($raw)>$FIXED->{snapshot_bytes} || length($meta_raw)>$FIXED->{attestation_bytes};
    my $meta=strict_json($meta_raw); _keys($meta,qw(provider_id source_url retrieved_at));
    _str($meta->{provider_id}); _str($meta->{source_url});
    _bad('Unregistered provider source') if $meta->{provider_id} ne $PROVIDER->{provider_id} || !grep {$_ eq $meta->{source_url}} @{$PROVIDER->{source_urls}};
    my $t=_rfc3339($meta->{retrieved_at}); my $data=strict_json($raw);
    _keys($data,qw(creationTime prefixes)); _str($data->{creationTime}); _array($data->{prefixes},$FIXED->{prefixes});
    _bad('Empty provider prefix set') if !@{$data->{prefixes}};
    my @prefixes;
    for my $p (@{$data->{prefixes}}) {
        _keys($p,qw(ipv4Prefix ipv6Prefix));
        _bad('Ambiguous provider prefix') if keys(%$p)!=1;
        my ($key)=keys %$p; _str($p->{$key}); my ($af)=literal_ip((split /\//,$p->{$key},2)[0]);
        _bad('Provider prefix family mismatch') if !defined($af) || $af != ($key eq 'ipv4Prefix' ? AF_INET:AF_INET6);
        push @prefixes,$p->{$key};
    }
    return {provider_id=>$PROVIDER->{provider_id},timestamp=>$t,prefix_count=>scalar(@prefixes),index=>cidr_index(\@prefixes),
        provenance=>{%$meta,sha256=>Digest::SHA::sha256_hex($raw),creationTime=>$data->{creationTime},authenticity=>'operator-attested'}};
}
sub _verification {
    my ($self,$r)=@_; return 'unavailable' if !literal_ip($r->{client});
    my $s=$self->{snapshots}; my ($lo,$hi)=(0,scalar(@$s));
    while ($lo<$hi) { my $m=int(($lo+$hi)/2); if ($s->[$m]{timestamp}<$r->{timestamp}) {$lo=$m+1} else {$hi=$m} }
    my $b=$lo<@$s ? $s->[$lo]:undef;
    my $a=defined($b) && $b->{timestamp}==$r->{timestamp} ? $b:($lo ? $s->[$lo-1]:undef);
    return 'unavailable' if !$a || !$b || $b->{timestamp}-$a->{timestamp}>$self->{config}{verification}{max_gap_seconds};
    return cidr_contains($a->{index},$r->{client}) && cidr_contains($b->{index},$r->{client}) ? 'verified':'failed';
}

# Decode Apache's ap_escape_logitem octets once, then validate UTF-8 again.
sub _apache_string {
    my ($s)=@_;
    my %escape=('"'=>'"','\\'=>'\\',b=>"\b",n=>"\n",r=>"\r",t=>"\t",v=>"\x0B");
    $s =~ s{\\(x[0-9A-Fa-f]{2}|["\\bnrtv])}{substr($1,0,1) eq 'x' ? pack('C',hex(substr($1,1))) : $escape{$1}}eg;
    # Unknown backslashes were excluded by the quoted-field grammar.
    return decode('UTF-8',$s,FB_CROAK|LEAVE_SRC);
}
sub _parse_line {
    my ($self,$raw)=@_; my $text=decode('UTF-8',$raw,FB_CROAK|LEAVE_SRC); my $r;
    if ($self->{format} eq 'jsonl') {
        $r=strict_json($raw); _keys($r,qw(timestamp client target user_agent host));
        _uint($r->{timestamp},$MAX_EPOCH); _str($r->{client}); _str($r->{target});
        _bad('Empty client') if !length($r->{client});
        _str($r->{user_agent}) if defined $r->{user_agent};
        $r->{user_agent}=undef if defined($r->{user_agent}) && $r->{user_agent} eq '';
        $r->{host}=_host($r->{host}) if defined $r->{host};
    } else {
        my $q=qr/(?:[^"\\]|\\(?:x[0-9A-Fa-f]{2}|["\\bnrtv]))*/;
        my $tail=$self->{format} eq 'combined' ? qr/[ \t]+"($q)"[ \t]+"($q)"/ : qr//;
        _bad('Unsupported Apache line') if $raw !~ /\A($word)[ \t]+$word[ \t]+$word[ \t]+\[([^\]]+)\][ \t]+"($q)"[ \t]+[1-5][0-9]{2}[ \t]+(?:-|[0-9]+)$tail\z/;
        my ($client,$date,$request,$referer,$ua)=($1,$2,$3,$4,$5);
        $client=decode('UTF-8',$client,FB_CROAK|LEAVE_SRC); $request=_apache_string($request);
        _bad('Unsupported HTTP request') if $request !~ /\A[A-Za-z]+[ \t]+($word)[ \t]+HTTP\/[0-9]+\.[0-9]+\z/;
        my $target=$1;
        _bad('Unsupported Apache timestamp') if $date !~ /\A([0-9]{2})\/([A-Z][a-z]{2})\/([0-9]{4}):([0-9]{2}):([0-9]{2}):([0-9]{2}) ([+-])([0-9]{2})([0-9]{2})\z/;
        my ($day,$month,$year,$hour,$min,$sec,$sign,$oh,$om)=($1,$2,$3,$4,$5,$6,$7,$8,$9);
        my %month; @month{qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec)}=(1..12);
        _bad('Unsupported timestamp offset') if !$month{$month} || $oh>23 || $om>59;
        my $offset=($oh*3600+$om*60)*($sign eq '+'?1:-1);
        my $t=_epoch($year,$month{$month},$day,$hour,$min,$sec,$offset);
        _apache_string($referer) if defined $referer;
        $ua=_apache_string($ua) if defined $ua;
        $ua=undef if defined($ua) && ($ua eq '' || $ua eq '-');
        $r={timestamp=>$t,client=>$client,target=>$target,user_agent=>$ua,host=>undef};
    }
    _bad('OVERSIZED_FIELD') if _bytes($r->{target})>$self->{config}{limits}{target_bytes}
        || (defined($r->{user_agent}) && _bytes($r->{user_agent})>$self->{config}{limits}{ua_bytes});
    return $r;
}
sub new {
    my ($class,%args)=@_; my $config=$args{config};
    _bad('Unsupported input format') if ($args{format}//'') !~ /\A(?:jsonl|common|combined)\z/;
    my @s=sort {$a->{timestamp}<=>$b->{timestamp}} @{$args{snapshots}||[]};
    _bad('Too many snapshots') if @s>$FIXED->{snapshots};
    my (%times,$prefixes);
    for (@s) { _bad('Duplicate snapshot time') if $times{$_->{provider_id}.':'.$_->{timestamp}}++; $prefixes += $_->{prefix_count}; }
    _bad('Prefix count limit exceeded') if ($prefixes//0)>$FIXED->{prefixes};
    return bless {config=>$config,format=>$args{format},snapshots=>\@s,details=>$args{details}?1:0,
        digest=>Digest::SHA->new(256),input_bytes=>0,line=>'',line_present=>0,oversized=>0,records=>[],groups_seen=>{},
        hosts=>{map {$_=>1} @{$config->{hosts}}},
        counts=>{lines_total=>0,blank=>0,unparsed=>0,oversized=>0,parsed=>0,host_missing=>0,out_of_scope=>0,analyzed=>0},nonblank=>0},$class;
}
sub feed {
    my ($self,$chunk)=@_; _bad('Input after finish') if $self->{finished};
    $self->{input_bytes}+=length($chunk);
    _bad('Input byte limit exceeded') if $self->{input_bytes}>$self->{config}{limits}{input_bytes};
    $self->{digest}->add($chunk);
    my $pos=0;
    while ($pos<length($chunk)) {
        my $end=index($chunk,"\n",$pos); my $last=$end<0?length($chunk):$end;
        my $part=substr($chunk,$pos,$last-$pos); $self->{line_present}=1;
        if (!$self->{oversized}) {
            my $cap=$self->{config}{limits}{line_bytes};
            if (length($self->{line})+length($part)>$cap+1) { $self->{oversized}=1; $self->{line}=''; }
            else {
                $self->{line}.=$part;
                if (length($self->{line})>$cap && substr($self->{line},-1) ne "\r") { $self->{oversized}=1; $self->{line}=''; }
            }
        }
        $self->_line(1) if $end>=0;
        $pos=$end<0?length($chunk):$end+1;
    }
}
sub _line {
    my ($self,$terminated)=@_; my $c=$self->{counts}; $c->{lines_total}++;
    my $raw=$self->{line}; $raw =~ s/\r\z// if $terminated;
    my $oversized=$self->{oversized} || length($raw)>$self->{config}{limits}{line_bytes};
    $self->{line}=''; $self->{oversized}=0; $self->{line_present}=0;
    if (!$oversized && $raw =~ /\A[\x09-\x0D\x20]*\z/) { $c->{blank}++; return; }
    _bad('Record count limit exceeded') if ++$self->{nonblank}>$self->{config}{limits}{records};
    if ($oversized) { $c->{unparsed}++; $c->{oversized}++; return; }
    my $r=eval {$self->_parse_line($raw)}; my $err=$@;
    if (!$r) { $c->{unparsed}++; $c->{oversized}++ if $err eq "OVERSIZED_FIELD\n"; return; }
    $r->{line_index}=$c->{lines_total}; $c->{parsed}++;
    $self->{min}=$r->{timestamp} if !defined($self->{min}) || $r->{timestamp}<$self->{min};
    $self->{max}=$r->{timestamp} if !defined($self->{max}) || $r->{timestamp}>$self->{max};
    if (defined($r->{user_agent}) && literal_ip($r->{client})) {
        $self->{groups_seen}{$r->{client}."\0".$r->{user_agent}}=1;
        _bad('Group count limit exceeded') if keys(%{$self->{groups_seen}})>$self->{config}{limits}{groups};
    }
    my $hosts=$self->{hosts};
    if (%$hosts && !defined $r->{host}) { $c->{host_missing}++; return; }
    if (%$hosts && !$hosts->{$r->{host}}) { $c->{out_of_scope}++; return; }
    $c->{analyzed}++; push @{$self->{records}},$r;
}
sub _scan {
    my ($self,$groups)=@_; my $cfg=$self->{config}{scanner}; my $sequences=0;
    for my $key (sort keys %$groups) {
        my @p=sort {$a->{timestamp}<=>$b->{timestamp} || $a->{line_index}<=>$b->{line_index}} @{$groups->{$key}};
        my (%paths,%families,@diff); my ($left,$last_end)=(0,undef);
        for my $right (0..$#p) {
            $paths{$p[$right]{normal}}++; $families{$p[$right]{family}}++;
            while ($p[$right]{timestamp}-$p[$left]{timestamp}>$cfg->{window_seconds}) {
                delete $paths{$p[$left]{normal}} if --$paths{$p[$left]{normal}}==0;
                delete $families{$p[$left]{family}} if --$families{$p[$left]{family}}==0;
                $left++;
            }
            if (keys(%paths)>=$cfg->{distinct_paths} && keys(%families)>=$cfg->{distinct_families}) {
                $diff[$left]++; $diff[$right+1]--;
                $sequences++ if !defined($last_end) || $p[$left]{timestamp}>$last_end;
                $last_end=$p[$right]{timestamp};
            }
        }
        my $coverage=0;
        for my $i (0..$#p) { $coverage+=$diff[$i]//0; $p[$i]{scanner_flagged}=1 if $coverage>0; }
    }
    return $sequences;
}
sub finish {
    my ($self)=@_; _bad('Already finished') if $self->{finished};
    $self->_line(0) if $self->{line_present}; $self->{finished}=1;
    _bad('No parsed records') if !$self->{counts}{parsed};
    _bad('No in-scope records') if !$self->{counts}{analyzed};
    my $cfg=$self->{config}; my (%paths,@active,@inactive,%exempt);
    for my $r (@{$cfg->{site_references}}) { $exempt{$r->{path}}=1 if $r->{from}<=$self->{max} && $r->{until}>=$self->{min}; }
    for my $f (@{$cfg->{probe_families}}) {
        if ($f->{absent_from}<=$self->{min} && $f->{absent_until}>=$self->{max}) {
            push @active,$f->{id}; for (@{$f->{paths}}) {$paths{$_}=$f->{id} if !$exempt{$_}};
        } else { push @inactive,{id=>$f->{id},reason=>'absence attestation does not cover entire parsed input period'}; }
    }
    my %actors=map {$_=>0} qw(unknown declared_crawler_or_tool verified_crawler);
    my %verification=map {$_=>0} qw(verified failed unavailable not_applicable);
    my (%groups,$insufficient,$unsupported); $insufficient=$unsupported=0;
    for my $r (@{$self->{records}}) {
        my $claimed=grep {marker_matches($r->{user_agent},$_)} @{$PROVIDER->{ua_tokens}};
        my $outcome=$claimed ? $self->_verification($r):'not_applicable';
        my $declared=$claimed;
        for my $token (@{$cfg->{crawler_tokens}}) { $declared=1 if marker_matches($r->{user_agent},$token); }
        $r->{actor}=$outcome eq 'verified' ? 'verified_crawler':$declared ? 'declared_crawler_or_tool':'unknown';
        $r->{verification_outcome}=$outcome; $r->{scanner_flagged}=0;
        $actors{$r->{actor}}++; $verification{$outcome}++;
        my $normal=normalize_target($r->{target}); $unsupported++ if !defined $normal;
        if (!defined($r->{user_agent}) || !literal_ip($r->{client})) { $insufficient++; next; }
        if (defined($normal) && exists($paths{$normal})) {
            $r->{normal}=$normal; $r->{family}=$paths{$normal};
            push @{$groups{$r->{client}."\0".$r->{user_agent}}},$r;
        }
    }
    my $sequences=$self->_scan(\%groups); my ($flagged,$excluded)=(0,0); my %exclude=map {$_=>1} @{$cfg->{exclude}};
    for my $r (@{$self->{records}}) {
        $flagged++ if $r->{scanner_flagged};
        $excluded++ if $exclude{$r->{actor}} || ($exclude{scanner_flagged} && $r->{scanner_flagged});
    }
    my $nondefault=grep {$cfg->{scanner}{$_}!=$DEFAULT->{scanner}{$_}} keys %{$cfg->{scanner}};
    my $report={schema_version=>1,algorithm_id=>$ALGORITHM,
        config_sha256=>Digest::SHA::sha256_hex($ALGORITHM."\n".JSON::PP->new->utf8->canonical->encode($cfg)),
        input_sha256=>$self->{digest}->hexdigest,input=>{format=>$self->{format},bytes=>$self->{input_bytes},period=>{from=>$self->{min},until=>$self->{max}},
            host_policy=>@{$cfg->{hosts}}?'configured hosts enforced; missing host excluded':'all parsed hosts; aliases inseparable for hostless records',hosts=>$cfg->{hosts}},
        effective=>{scanner=>$cfg->{scanner},scanner_nondefault=>$nondefault?JSON::PP::true:JSON::PP::false,verification=>$cfg->{verification},limits=>$cfg->{limits},
            status=>'Thresholds, continuity gaps and resource caps are heuristic assumptions; detection accuracy is unmeasured',crawler_tokens=>$cfg->{crawler_tokens}},
        counts=>{%{$self->{counts}}},actors=>\%actors,verification_outcomes=>\%verification,scanner_flagged_requests=>$flagged,merged_scanner_sequences=>$sequences,
        scanner_insufficient_fields=>$insufficient,unsupported_targets=>$unsupported,
        probes=>{active_families=>\@active,inactive_families=>\@inactive,exempt_paths=>[sort keys %exempt]},
        provider_snapshots=>[map {$_->{provenance}} @{$self->{snapshots}}],
        limitations=>[
            'Actor labels are separate from scanner flags; unknown is neither verified human nor bot. Counts are requests, not visitors or AWStats visits.',
            'Verified means verified against operator-attested published-range snapshots, not cryptographic source authentication. Bracketing assumes range continuity and does not prove uninterrupted ownership.',
            'Historical requests without covering archived evidence remain unavailable. IPv4-mapped IPv6 is not converted to IPv4; literal-IP acceptance follows platform inet_pton.',
            'Scanner flags describe qualifying probe requests, not intent or people. Shared IPs/UA and duplicate or overlapping input can affect results. Supply one nonoverlapping stable site snapshot.',
            'Local tokens, component absence and site-reference periods are operator attestations; no status-code or weak browser signal supplies identity or absence.',
            'No live DNS, network queries, incremental history or blocking. Exclusions affect only the configured comparison. Caller controls retention and any manual publication.',
        ]};
    if (%exclude) { $report->{adjusted_requests}={label=>'requests in this input excluding '.join(', ',sort keys %exclude),original=>$self->{counts}{analyzed},excluded=>$excluded,remaining=>$self->{counts}{analyzed}-$excluded}; }
    if ($self->{details}) {
        $report->{details_warning}='Contains raw request data; keep private and apply your retention policy.';
        $report->{details}=[map {my $r=$_; +{(map {$_=>$r->{$_}} qw(line_index timestamp client user_agent target host actor verification_outcome)),scanner_flagged=>$r->{scanner_flagged}?JSON::PP::true:JSON::PP::false}} @{$self->{records}}];
    }
    return $report;
}
sub _html_escape { my ($s)=@_; $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; $s =~ s/"/&quot;/g; $s =~ s/'/&#39;/g; return $s; }
sub html_report {
    my ($report)=@_;
    my $text=decode('UTF-8',canonical_json($report),FB_CROAK);
    $report=$JSON->decode($text);
    my $html='<!doctype html><html lang="en"><meta charset="utf-8"><title>Traffic classification</title><body><h1>Traffic classification</h1><p>Observed requests; unknown does not mean human. Scanner flags are behavior evidence, separate from actor identity.</p><table><caption>Requests in this input</caption>';
    for my $actor (qw(verified_crawler declared_crawler_or_tool unknown)) { $html.='<tr><th>'._html_escape($actor).'</th><td>'.$report->{actors}{$actor}.'</td></tr>'; }
    $html.='</table><p>Scanner-flagged requests: '.$report->{scanner_flagged_requests}.'. Merged qualifying sequences: '.$report->{merged_scanner_sequences}.'.</p>';
    if ($report->{adjusted_requests}) { my $a=$report->{adjusted_requests}; $html.='<p>'._html_escape($a->{label}).': '.$a->{remaining}.' (original '.$a->{original}.', excluded '.$a->{excluded}.').</p>'; }
    $html.='<p>Heuristic thresholds; precision and recall are unknown. This tool changes no AWStats history or access rules.</p><details><summary>Evidence, effective rules and report data</summary><pre>'._html_escape($text).'</pre></details></body></html>';
    return encode('UTF-8',$html);
}
1;
