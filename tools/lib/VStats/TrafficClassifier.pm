package VStats::TrafficClassifier;
use v5.020;
use strict;
use warnings;
use JSON::PP ();
use Digest::SHA ();
use Socket qw(AF_INET AF_INET6 inet_pton);
use Time::Local qw(timegm);
use POSIX qw(floor);
use Encode qw(decode encode FB_CROAK LEAVE_SRC);

# GPL version 2 or later, like the parent project. No file or network I/O here.
our $VERSION = '1.7';
my $ALGORITHM = 'vstats-traffic-v8';
my $word=qr/[^ \t]+/;
my $MAX_EPOCH = 4102444800;
my $PROVIDER = {provider_id=>'google_common',ua_tokens=>['Googlebot'],
    source_urls=>['https://developers.google.com/static/crawling/ipranges/common-crawlers.json'],parser_id=>'google_prefixes_v1'};
my $FIXED = {config_bytes=>1048576,snapshot_bytes=>2097152,attestation_bytes=>16384,evidence_bundle_bytes=>67108864,
    tokens=>128,token_bytes=>64,families=>64,paths=>2048,references=>2048,
    snapshots=>32,prefixes=>32768,json_depth=>32,max_window=>3600,distributed_max_window=>21600,max_gap=>604800,family_id_bytes=>32};
my $JSON = JSON::PP->new->canonical->allow_nonref;
my $DEFAULT = {
    schema_version => 1, hosts => [],
    crawler_tokens => [qw(Googlebot Bytespider bingbot AhrefsBot ClaudeBot GPTBot curl Wget python-requests)],
    probe_families => [], site_references => [], exclude => [], behavior_include => [],
    scanner => {distinct_paths => 3, distinct_families => 2, window_seconds => 60},
    behavior => {enabled => 0, window_seconds => 60, min_requests => 60,
                distinct_user_agents => 4, distinct_platforms => 2,
                distinct_paths => 10, not_found_requests => 10},
    probing => {enabled => 0, window_seconds => 60, min_requests => 30,
                distinct_user_agents => 4, distinct_platforms => 2, paths => []},
    rapid_scan => {enabled => 0, window_seconds => 60, min_requests => 30,
                   distinct_paths => 20, not_found_requests => 10},
    distributed_login => {enabled => 0, window_seconds => 1800, min_requests => 30,
        min_sources => 3, min_post_requests => 10, distinct_user_agents => 8, distinct_platforms => 2,
        min_source_posts => 2, distinct_source_user_agents => 2, distinct_source_platforms => 2,
        shared_user_agents => 1, login_paths => [], admin_paths => []},
    verification => {max_gap_seconds => 86400},
    limits => {input_bytes => 67108864, line_bytes => 16384, records => 100000,
               groups => 100000, ua_bytes => 4096, target_bytes => 8192},
};

sub defaults { return $JSON->decode($JSON->encode($DEFAULT)); }
sub analysis_window {
    my ($class,$config)=@_;my $window=$config->{scanner}{window_seconds};
    for my $rule (qw(behavior probing rapid_scan distributed_login)) {
        $window=$config->{$rule}{window_seconds} if $config->{$rule}{enabled} && $config->{$rule}{window_seconds}>$window;
    }
    return $window;
}
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
        if ($key eq 'scanner' || $key eq 'behavior' || $key eq 'probing' || $key eq 'rapid_scan' || $key eq 'distributed_login' || $key eq 'verification' || $key eq 'limits') {
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
    my $b=$c->{behavior}; _uint($b->{enabled},1); _uint($b->{window_seconds},$FIXED->{max_window},1);
    _uint($b->{min_requests},$d->{limits}{records},2);
    _uint($b->{distinct_user_agents},$b->{min_requests},2);
    _uint($b->{distinct_platforms},5,2);
    _bad('Behavior platforms exceed user agents') if $b->{distinct_platforms}>$b->{distinct_user_agents};
    _uint($b->{distinct_paths},$FIXED->{paths},2); _uint($b->{not_found_requests},$b->{min_requests},2);
    _bad('Behavior paths exceed requests') if $b->{distinct_paths}>$b->{min_requests};
    my $p=$c->{probing}; _uint($p->{enabled},1); _uint($p->{window_seconds},$FIXED->{max_window},1);
    _uint($p->{min_requests},$d->{limits}{records},2);
    _uint($p->{distinct_user_agents},$p->{min_requests},2);
    _uint($p->{distinct_platforms},5,2);
    _bad('Probing platforms exceed user agents') if $p->{distinct_platforms}>$p->{distinct_user_agents};
    _array($p->{paths},$FIXED->{paths}); my %probe_paths;
    for my $path (@{$p->{paths}}) {
        _str($path); my $normal=normalize_target($path);
        _bad('Invalid or duplicate probing path') if !defined($normal) || $normal ne $path || $probe_paths{$path}++;
    }
    _bad('Enabled probing requires configured paths') if $p->{enabled} && !@{$p->{paths}};
    my $rapid=$c->{rapid_scan}; _uint($rapid->{enabled},1); _uint($rapid->{window_seconds},$FIXED->{max_window},1);
    _uint($rapid->{min_requests},$d->{limits}{records},2);
    _uint($rapid->{distinct_paths},$FIXED->{paths},2);
    _uint($rapid->{not_found_requests},$rapid->{min_requests},2);
    _bad('Rapid scan paths exceed requests') if $rapid->{distinct_paths}>$rapid->{min_requests};
    my $dl=$c->{distributed_login}; _uint($dl->{enabled},1); _uint($dl->{window_seconds},$FIXED->{distributed_max_window},1);
    for my $key (qw(min_requests min_post_requests distinct_user_agents min_source_posts distinct_source_user_agents)) {
        _uint($dl->{$key},$d->{limits}{records},2);
    }
    _uint($dl->{min_sources},$d->{limits}{groups},2);
    _uint($dl->{distinct_platforms},5,2); _uint($dl->{distinct_source_platforms},5,2);
    _uint($dl->{shared_user_agents},$dl->{distinct_source_user_agents},1);
    _bad('Inconsistent distributed-login thresholds') if
        $dl->{min_post_requests}<$dl->{min_sources}*$dl->{min_source_posts} ||
        $dl->{min_requests}<$dl->{min_post_requests}+$dl->{min_sources} ||
        $dl->{distinct_user_agents}>$dl->{min_post_requests} ||
        $dl->{distinct_platforms}>$dl->{distinct_user_agents} ||
        $dl->{distinct_source_user_agents}>$dl->{min_source_posts} ||
        $dl->{distinct_source_platforms}>$dl->{distinct_source_user_agents};
    my %login_paths;
    for my $key (qw(login_paths admin_paths)) {
        _array($dl->{$key},$FIXED->{paths});
        for my $path (@{$dl->{$key}}) {
            _str($path);my $normal=normalize_target($path);
            _bad('Invalid, duplicate or overlapping distributed-login path') if
                !defined($normal) || $normal ne $path || $login_paths{$path}++;
        }
        _bad('Enabled distributed-login detection requires login and admin paths') if $dl->{enabled} && !@{$dl->{$key}};
    }
    _uint($c->{verification}{max_gap_seconds},$FIXED->{max_gap});
    for my $k (keys %{$d->{limits}}) { _uint($c->{limits}{$k},$d->{limits}{$k},1); }
    _bad('Field cap exceeds line cap') if $c->{limits}{ua_bytes}>$c->{limits}{line_bytes} || $c->{limits}{target_bytes}>$c->{limits}{line_bytes};
    for my $path (@{$p->{paths}}) {
        _bad('Probing path exceeds target field cap') if _bytes($path)>$c->{limits}{target_bytes};
    }
    for my $path (@{$dl->{login_paths}},@{$dl->{admin_paths}}) {
        _bad('Distributed-login path exceeds target field cap') if _bytes($path)>$c->{limits}{target_bytes};
    }
    _array($c->{exclude},4); my %exclude;
    for (@{$c->{exclude}}) { _str($_); _bad('Invalid exclusion selector') if !/\A(?:declared_crawler_or_tool|verified_crawler|scanner_flagged|suspected_automation)\z/ || $exclude{$_}++; }
    _array($c->{behavior_include},$FIXED->{references}); my %include;
    for (@{$c->{behavior_include}}) { _str($_); _bad('Invalid or duplicate behavior inclusion ID') if !/\A[0-9a-f]{64}\z/ || $include{$_}++; }
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

# Streaming consumers use the same identity rules without accumulating a log or
# applying scanner/exclusion heuristics. Evidence remains operator-attested.
sub evidence_verifier {
    my ($class,$raw,%args)=@_;
    _bad('Evidence bundle byte limit exceeded') if length($raw)>$FIXED->{evidence_bundle_bytes};
    my $bundle=strict_json($raw); _keys($bundle,qw(schema_version snapshots));
    _uint($bundle->{schema_version},1,1); _array($bundle->{snapshots},$FIXED->{snapshots});
    my @snapshots;
    for my $entry (@{$bundle->{snapshots}}) {
        _keys($entry,qw(raw_json attestation_json));
        _str($entry->{raw_json}); _str($entry->{attestation_json});
        push @snapshots,$class->snapshot(encode('UTF-8',$entry->{raw_json}),encode('UTF-8',$entry->{attestation_json}));
    }
    return $class->new(config=>$class->config('{"schema_version":1}'),
        format=>$args{format}//'combined',snapshots=>\@snapshots);
}

sub _actor_labels {
    my ($self,$r)=@_;
    my $claimed=grep {marker_matches($r->{user_agent},$_)} @{$PROVIDER->{ua_tokens}};
    my $outcome=$claimed ? $self->_verification($r):'not_applicable';
    my $declared=$claimed;
    for my $token (@{$self->{config}{crawler_tokens}}) {
        $declared=1 if marker_matches($r->{user_agent},$token);
    }
    return {actor=>$outcome eq 'verified' ? 'verified_crawler':$declared ? 'declared_crawler_or_tool':'unknown',
        verification_outcome=>$outcome};
}

sub classify_line {
    my ($self,$raw)=@_;
    return {actor=>'unknown',verification_outcome=>'unavailable'} if !defined($raw) || ref($raw);
    $raw =~ s/\n\z//; $raw =~ s/\r\z//;
    my $r=eval {
        _bad('OVERSIZED_FIELD') if length($raw)>$self->{config}{limits}{line_bytes};
        $self->_parse_line($raw);
    };
    return {actor=>'unknown',verification_outcome=>'unavailable'} if !$r;
    return $self->_actor_labels($r);
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
        $r=strict_json($raw); _keys($r,qw(timestamp client target user_agent host status method));
        _uint($r->{timestamp},$MAX_EPOCH); _str($r->{client}); _str($r->{target});
        _bad('Empty client') if !length($r->{client});
        _str($r->{user_agent}) if defined $r->{user_agent};
        $r->{user_agent}=undef if defined($r->{user_agent}) && $r->{user_agent} eq '';
        $r->{host}=_host($r->{host}) if defined $r->{host};
        _uint($r->{status},599,100) if exists $r->{status};
    } else {
        my $q=qr/(?:[^"\\]|\\(?:x[0-9A-Fa-f]{2}|["\\bnrtv]))*/;
        my $tail=$self->{format} eq 'combined' ? qr/[ \t]+"($q)"[ \t]+"($q)"/ : qr//;
        _bad('Unsupported Apache line') if $raw !~ /\A($word)[ \t]+$word[ \t]+$word[ \t]+\[([^\]]+)\][ \t]+"($q)"[ \t]+([1-5][0-9]{2})[ \t]+(?:-|[0-9]+)$tail\z/;
        my ($client,$date,$request,$status,$referer,$ua)=($1,$2,$3,$4,$5,$6);
        $client=decode('UTF-8',$client,FB_CROAK|LEAVE_SRC); $request=_apache_string($request);
        _bad('Unsupported HTTP request') if $request !~ /\A([A-Za-z]+)[ \t]+($word)[ \t]+HTTP\/[0-9]+\.[0-9]+\z/;
        my ($method,$target)=(uc($1),$2);
        _bad('Unsupported Apache timestamp') if $date !~ /\A([0-9]{2})\/([A-Z][a-z]{2})\/([0-9]{4}):([0-9]{2}):([0-9]{2}):([0-9]{2}) ([+-])([0-9]{2})([0-9]{2})\z/;
        my ($day,$month,$year,$hour,$min,$sec,$sign,$oh,$om)=($1,$2,$3,$4,$5,$6,$7,$8,$9);
        my %month; @month{qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec)}=(1..12);
        _bad('Unsupported timestamp offset') if !$month{$month} || $oh>23 || $om>59;
        my $offset=($oh*3600+$om*60)*($sign eq '+'?1:-1);
        my $t=_epoch($year,$month{$month},$day,$hour,$min,$sec,$offset);
        _apache_string($referer) if defined $referer;
        $ua=_apache_string($ua) if defined $ua;
        $ua=undef if defined($ua) && ($ua eq '' || $ua eq '-');
        $r={timestamp=>$t,client=>$client,target=>$target,user_agent=>$ua,host=>undef,status=>0+$status,method=>$method};
    }
    if (exists $r->{method}) {
        _str($r->{method}); _bad('Invalid HTTP method') if $r->{method} !~ /\A[A-Za-z]{1,32}\z/;
        $r->{method}=uc($r->{method});
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
        contexts=>{},context_bytes=>0,context_nonblank=>0,digest=>Digest::SHA->new(256),input_bytes=>0,line=>'',line_present=>0,oversized=>0,records=>[],groups_seen=>{},
        hosts=>{map {$_=>1} @{$config->{hosts}}},
        counts=>{lines_total=>0,blank=>0,unparsed=>0,oversized=>0,parsed=>0,host_missing=>0,out_of_scope=>0,analyzed=>0},nonblank=>0},$class;
}
sub feed {
    my ($self,$chunk)=@_; _bad('Input after finish') if $self->{finished};
    $self->{input_bytes}+=length($chunk);
    _bad('Input byte limit exceeded') if $self->{input_bytes}+$self->{context_bytes}>$self->{config}{limits}{input_bytes};
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
# Context is evidence only. It has its own identities and can never change the
# primary digest, physical line numbering, output records or exported input.
sub add_context {
    my ($self,$side,$raw)=@_;
    _bad('Invalid or duplicate context side') if !defined($side) || $side !~ /\A(?:before|after)\z/ || exists($self->{contexts}{$side});
    _bad('Context after finish') if $self->{finished};
    _bad('Invalid context bytes') if !defined($raw) || ref($raw);
    _bad('Combined input byte limit exceeded') if $self->{input_bytes}+$self->{context_bytes}+length($raw)>$self->{config}{limits}{input_bytes};
    my $parser=ref($self)->new(config=>$self->{config},format=>$self->{format});
    $parser->feed($raw);$parser->_line(0) if $parser->{line_present};
    _bad('Combined record count limit exceeded') if $self->{nonblank}+$self->{context_nonblank}+$parser->{nonblank}>$self->{config}{limits}{records};
    for my $key (keys %{$parser->{groups_seen}}) {$self->{groups_seen}{$key}=1;}
    _bad('Combined group count limit exceeded') if keys(%{$self->{groups_seen}})>$self->{config}{limits}{groups};
    $_->{_context}=1 for @{$parser->{records}};
    $self->{contexts}{$side}={records=>$parser->{records},meta=>{sha256=>$parser->{digest}->hexdigest,bytes=>length($raw),counts=>$parser->{counts},period=>{from=>$parser->{min},until=>$parser->{max}}}};
    $self->{context_bytes}+=length($raw);$self->{context_nonblank}+=$parser->{nonblank};
}
sub _primary_prefix {
    my ($rows)=@_;my @prefix=(0);
    push @prefix,$prefix[-1]+($_->{_context}?0:1) for @$rows;
    return \@prefix;
}
sub _line {
    my ($self,$terminated)=@_; my $c=$self->{counts}; $c->{lines_total}++;
    my $raw=$self->{line}; $raw =~ s/\r\z// if $terminated;
    my $oversized=$self->{oversized} || length($raw)>$self->{config}{limits}{line_bytes};
    $self->{line}=''; $self->{oversized}=0; $self->{line_present}=0;
    if (!$oversized && $raw =~ /\A[\x09-\x0D\x20]*\z/) { $c->{blank}++; return; }
    _bad('Record count limit exceeded') if ++$self->{nonblank}+$self->{context_nonblank}>$self->{config}{limits}{records};
    if ($oversized) { $c->{unparsed}++; $c->{oversized}++; return; }
    my $r=eval {$self->_parse_line($raw)}; my $err=$@;
    if (!$r) { $c->{unparsed}++; $c->{oversized}++ if $err eq "OVERSIZED_FIELD\n"; return; }
    $r->{line_index}=$c->{lines_total}; $r->{request_id}=Digest::SHA::sha256_hex($raw); $c->{parsed}++;
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
        my @p=sort {$a->{timestamp}<=>$b->{timestamp} || $a->{_order}<=>$b->{_order}} @{$groups->{$key}}; my $primary=_primary_prefix(\@p);
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
                if ($primary->[$right+1]>$primary->[$left]) {
                    $sequences++ if !defined($last_end) || $p[$left]{timestamp}>$last_end;
                    $last_end=$p[$right]{timestamp};
                }
            }
        }
        my $coverage=0;
        for my $i (0..$#p) { $coverage+=$diff[$i]//0; $p[$i]{scanner_flagged}=1 if $coverage>0; }
    }
    return $sequences;
}

# Browser claims are heuristic features, never proof of device, person or bot
# identity. In particular, a shared proxy may legitimately carry diverse UAs.
sub _browser_platform {
    my ($ua)=@_; return if !defined($ua) || $ua !~ /(?:^|[^A-Za-z0-9])(?:Chrome|CriOS|Firefox|FxiOS|Safari|Edg|OPR|Opera)\//iaa;
    return 'ios' if $ua =~ /(?:^|[^A-Za-z0-9])(?:iPhone|iPad|iPod)(?=[^A-Za-z0-9]|\z)/iaa;
    return 'android' if $ua =~ /(?:^|[^A-Za-z0-9])Android(?=[^A-Za-z0-9]|\z)/iaa;
    return 'windows' if $ua =~ /(?:^|[^A-Za-z0-9])Windows(?=[^A-Za-z0-9]|\z)/iaa;
    return 'mac' if $ua =~ /(?:^|[^A-Za-z0-9])Macintosh(?=[^A-Za-z0-9]|\z)/iaa;
    return 'linux' if $ua =~ /(?:^|[^A-Za-z0-9])Linux(?=[^A-Za-z0-9]|\z)/iaa;
    return;
}
sub _behavior {
    my ($self)=@_; my $cfg=$self->{config}{behavior};
    my $result={enabled=>$cfg->{enabled}?JSON::PP::true:JSON::PP::false,
        rule_id=>'burst_browser_rotation_path_probing_v1',flagged_requests=>0,
        eligible_requests=>0,insufficient_fields=>0,merged_sequences=>0,flagged_source_groups=>0,
        actors=>{map {$_=>0} qw(unknown declared_crawler_or_tool verified_crawler)}};
    $_->{suspected_automation}=0 for @{$self->{records}};
    return $result if !$cfg->{enabled};
    my %groups;
    for my $r (@{$self->{records}}) {
        my $platform=_browser_platform($r->{user_agent});
        my ($af,$packed)=literal_ip($r->{client});
        if (!defined($af) || !defined($r->{normal}) || !defined($r->{status}) || !defined($platform)) {
            $r->{_broad_insufficient}=1; $result->{insufficient_fields}++ if !$r->{_context}; next;
        }
        $r->{_broad_eligible}=1;
        $r->{behavior_platform}=$platform; $result->{eligible_requests}++ if !$r->{_context};
        # UA is deliberately absent from the key: variation is tested within a
        # source/host, never pooled across hosts or attributed to every source hit.
        push @{$groups{$af.':'.unpack('H*',$packed)."\0".($r->{host}//'')}},$r;
        _bad('Behavior group count limit exceeded') if keys(%groups)>$self->{config}{limits}{groups};
    }
    for my $key (sort keys %groups) {
        my @p=sort {$a->{timestamp}<=>$b->{timestamp} || $a->{_order}<=>$b->{_order}} @{$groups{$key}}; my $primary=_primary_prefix(\@p);
        my (%paths,%uas,%platforms,@diff); my ($left,$not_found,$last_end,$assigned_end)=(0,0,undef,-1);
        for my $right (0..$#p) {
            my $r=$p[$right]; $paths{$r->{normal}}++; $uas{$r->{user_agent}}++; $platforms{$r->{behavior_platform}}++;
            $not_found++ if $r->{status}==404;
            while ($r->{timestamp}-$p[$left]{timestamp}>$cfg->{window_seconds}) {
                my $old=$p[$left++];
                delete $paths{$old->{normal}} if --$paths{$old->{normal}}==0;
                delete $uas{$old->{user_agent}} if --$uas{$old->{user_agent}}==0;
                delete $platforms{$old->{behavior_platform}} if --$platforms{$old->{behavior_platform}}==0;
                $not_found-- if $old->{status}==404;
            }
            if ($right-$left+1>=$cfg->{min_requests} && keys(%uas)>=$cfg->{distinct_user_agents}
                    && keys(%platforms)>=$cfg->{distinct_platforms} && keys(%paths)>=$cfg->{distinct_paths}
                    && $not_found>=$cfg->{not_found_requests}) {
                $diff[$left]++; $diff[$right+1]--;
                my $proof={from=>$p[$left]{timestamp},until=>$r->{timestamp},requests=>$right-$left+1,
                    distinct_user_agents=>scalar(keys %uas),distinct_platforms=>scalar(keys %platforms),
                    distinct_paths=>scalar(keys %paths),not_found_requests=>$not_found};
                # Left/right endpoints only advance. Assign the first witnessing
                # interval once per request, retaining linear total work.
                my $start=$left>$assigned_end+1?$left:$assigned_end+1;
                $p[$_]{behavior_evidence}=$proof for $start..$right;
                $assigned_end=$right;
                if ($primary->[$right+1]>$primary->[$left]) {
                    $result->{merged_sequences}++ if !defined($last_end) || $p[$left]{timestamp}>$last_end;
                    $last_end=$r->{timestamp};
                }
            }
        }
        my ($coverage,$flagged)=(0,0);
        for my $i (0..$#p) {
            $coverage+=$diff[$i]//0; next if $coverage<=0;
            $p[$i]{suspected_automation}=1; next if $p[$i]{_context}; $result->{flagged_requests}++; $result->{actors}{$p[$i]{actor}}++; $flagged=1;
        }
        $result->{flagged_source_groups}++ if $flagged;
    }
    return $result;
}

# Positive endpoint configuration is deliberately separate from the existing
# absence-attested scanner families. These routes may exist and return 200.
# Only configured-endpoint requests contribute to or receive this flag.
sub _probing {
    my ($self)=@_; my $cfg=$self->{config}{probing};
    my $result={enabled=>$cfg->{enabled}?JSON::PP::true:JSON::PP::false,
        rule_id=>'configured_endpoint_rotation_v1',flagged_requests=>0,
        eligible_requests=>0,insufficient_fields=>0,other_path_requests=>0,
        merged_sequences=>0,flagged_source_groups=>0,
        actors=>{map {$_=>0} qw(unknown declared_crawler_or_tool verified_crawler)}};
    $_->{probing_flagged}=0 for @{$self->{records}};
    return $result if !$cfg->{enabled};
    my %paths=map {$_=>1} @{$cfg->{paths}}; my %groups;
    for my $r (@{$self->{records}}) {
        my $platform=_browser_platform($r->{user_agent});
        my ($af,$packed)=literal_ip($r->{client});
        if (!defined($af) || !defined($r->{normal}) || !defined($r->{status}) || !defined($platform)) {
            $r->{_probing_insufficient}=1; $result->{insufficient_fields}++ if !$r->{_context}; next;
        }
        if (!$paths{$r->{normal}}) { $result->{other_path_requests}++ if !$r->{_context}; next; }
        $r->{_probing_eligible}=1; $r->{behavior_platform}=$platform;
        $result->{eligible_requests}++ if !$r->{_context};
        push @{$groups{$af.':'.unpack('H*',$packed)."\0".($r->{host}//'')}},$r;
        _bad('Probing group count limit exceeded') if keys(%groups)>$self->{config}{limits}{groups};
    }
    for my $key (sort keys %groups) {
        my @p=sort {$a->{timestamp}<=>$b->{timestamp} || $a->{_order}<=>$b->{_order}} @{$groups{$key}}; my $primary=_primary_prefix(\@p);
        my (%paths,%uas,%platforms,@diff); my ($left,$not_found,$last_end,$assigned_end)=(0,0,undef,-1);
        for my $right (0..$#p) {
            my $r=$p[$right]; $paths{$r->{normal}}++; $uas{$r->{user_agent}}++;
            $platforms{$r->{behavior_platform}}++; $not_found++ if $r->{status}==404;
            while ($r->{timestamp}-$p[$left]{timestamp}>$cfg->{window_seconds}) {
                my $old=$p[$left++];
                delete $paths{$old->{normal}} if --$paths{$old->{normal}}==0;
                delete $uas{$old->{user_agent}} if --$uas{$old->{user_agent}}==0;
                delete $platforms{$old->{behavior_platform}} if --$platforms{$old->{behavior_platform}}==0;
                $not_found-- if $old->{status}==404;
            }
            if ($right-$left+1>=$cfg->{min_requests} && keys(%uas)>=$cfg->{distinct_user_agents}
                    && keys(%platforms)>=$cfg->{distinct_platforms}) {
                $diff[$left]++; $diff[$right+1]--;
                my $proof={from=>$p[$left]{timestamp},until=>$r->{timestamp},requests=>$right-$left+1,
                    distinct_user_agents=>scalar(keys %uas),distinct_platforms=>scalar(keys %platforms),
                    distinct_paths=>scalar(keys %paths),not_found_requests=>$not_found};
                my $start=$left>$assigned_end+1?$left:$assigned_end+1;
                $p[$_]{probing_evidence}=$proof for $start..$right;
                $assigned_end=$right;
                if ($primary->[$right+1]>$primary->[$left]) {
                    $result->{merged_sequences}++ if !defined($last_end) || $p[$left]{timestamp}>$last_end;
                    $last_end=$r->{timestamp};
                }
            }
        }
        my ($coverage,$flagged)=(0,0);
        for my $i (0..$#p) {
            $coverage+=$diff[$i]//0; next if $coverage<=0;
            $p[$i]{probing_flagged}=1; next if $p[$i]{_context}; $result->{flagged_requests}++;
            $result->{actors}{$p[$i]{actor}}++; $flagged=1;
        }
        $result->{flagged_source_groups}++ if $flagged;
    }
    return $result;
}
# Content-path bursts are independent of browser identity. Static asset suffixes
# neither contribute to a witness nor receive this request-level flag. A later
# caller may separately apply the explicit whole-IP policy.
sub _rapid_scan {
    my ($self)=@_; my $cfg=$self->{config}{rapid_scan};
    my $result={enabled=>$cfg->{enabled}?JSON::PP::true:JSON::PP::false,
        rule_id=>'rapid_content_path_probing_v1',flagged_requests=>0,
        eligible_requests=>0,insufficient_fields=>0,asset_requests=>0,
        merged_sequences=>0,flagged_source_groups=>0,
        actors=>{map {$_=>0} qw(unknown declared_crawler_or_tool verified_crawler)}};
    $_->{rapid_scan_flagged}=0 for @{$self->{records}};
    return $result if !$cfg->{enabled};
    my %groups;
    for my $r (@{$self->{records}}) {
        my ($af,$packed)=literal_ip($r->{client});
        if (!defined($af) || !defined($r->{normal}) || !defined($r->{status})) {
            $r->{_rapid_insufficient}=1; $result->{insufficient_fields}++ if !$r->{_context}; next;
        }
        if ($r->{normal} =~ /\.(?:css|js|mjs|cjs|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|tiff?|woff2?|ttf|otf|eot|mp3|mp4|webm|ogg|wav|pdf|zip|gz|br|rar|7z|tar)\z/iaa) {
            $result->{asset_requests}++ if !$r->{_context}; next;
        }
        $r->{_rapid_eligible}=1; $result->{eligible_requests}++ if !$r->{_context};
        my $platform=_browser_platform($r->{user_agent});
        $r->{behavior_platform}=$platform if defined $platform;
        push @{$groups{$af.':'.unpack('H*',$packed)."\0".($r->{host}//'')}},$r;
        _bad('Rapid scan group count limit exceeded') if keys(%groups)>$self->{config}{limits}{groups};
    }
    for my $key (sort keys %groups) {
        my @p=sort {$a->{timestamp}<=>$b->{timestamp} || $a->{_order}<=>$b->{_order}} @{$groups{$key}}; my $primary=_primary_prefix(\@p);
        my (%paths,%uas,%platforms,@diff); my ($left,$not_found,$last_end,$assigned_end)=(0,0,undef,-1);
        for my $right (0..$#p) {
            my $r=$p[$right]; $paths{$r->{normal}}++;
            $uas{$r->{user_agent}}++ if defined $r->{user_agent};
            $platforms{$r->{behavior_platform}}++ if defined $r->{behavior_platform};
            $not_found++ if $r->{status}==404;
            while ($r->{timestamp}-$p[$left]{timestamp}>$cfg->{window_seconds}) {
                my $old=$p[$left++];
                delete $paths{$old->{normal}} if --$paths{$old->{normal}}==0;
                delete $uas{$old->{user_agent}} if defined($old->{user_agent}) && --$uas{$old->{user_agent}}==0;
                delete $platforms{$old->{behavior_platform}} if defined($old->{behavior_platform}) && --$platforms{$old->{behavior_platform}}==0;
                $not_found-- if $old->{status}==404;
            }
            if ($right-$left+1>=$cfg->{min_requests} && keys(%paths)>=$cfg->{distinct_paths}
                    && $not_found>=$cfg->{not_found_requests}) {
                $diff[$left]++; $diff[$right+1]--;
                my $proof={from=>$p[$left]{timestamp},until=>$r->{timestamp},requests=>$right-$left+1,
                    distinct_user_agents=>scalar(keys %uas),distinct_platforms=>scalar(keys %platforms),
                    distinct_paths=>scalar(keys %paths),not_found_requests=>$not_found};
                my $start=$left>$assigned_end+1?$left:$assigned_end+1;
                $p[$_]{rapid_scan_evidence}=$proof for $start..$right;
                $assigned_end=$right;
                if ($primary->[$right+1]>$primary->[$left]) {
                    $result->{merged_sequences}++ if !defined($last_end) || $p[$left]{timestamp}>$last_end;
                    $last_end=$r->{timestamp};
                }
            }
        }
        my ($coverage,$flagged)=(0,0);
        for my $i (0..$#p) {
            $coverage+=$diff[$i]//0; next if $coverage<=0;
            $p[$i]{rapid_scan_flagged}=1; next if $p[$i]{_context}; $result->{flagged_requests}++;
            $result->{actors}{$p[$i]{actor}}++; $flagged=1;
        }
        $result->{flagged_source_groups}++ if $flagged;
    }
    return $result;
}

# Coherent same-UA spans protect intersecting candidate windows. Context rows
# can supply evidence but cannot contribute to primary request/report counts.
sub _login_diagnostic {
    my ($rows,$from,$until,$reasons,$metrics)=@_;
    for my $r (@$rows) {
        next if $r->{_context};
        _bad('Distributed-login diagnostic membership cap exceeded') if @{$r->{distributed_login_diagnostics}}>=2;
        push @{$r->{distributed_login_diagnostics}},{from=>$from,until=>$until,reasons=>$reasons,%{$metrics||{}}};
    }
}
sub _coherent_window {
    my ($intervals,$from,$until)=@_;my ($low,$high)=(0,scalar(@$intervals));
    while ($low<$high) {my $middle=int(($low+$high)/2);if ($intervals->[$middle][1]<$from) {$low=$middle+1;}else{$high=$middle;}}
    return $low<@$intervals && $intervals->[$low][0]<$until;
}
sub _distributed_login {
    my ($self)=@_;my $cfg=$self->{config}{distributed_login};
    my $out={enabled=>$cfg->{enabled}?JSON::PP::true:JSON::PP::false,
        rule_id=>'distributed_login_rotation_v2',flagged_requests=>0,eligible_requests=>0,
        insufficient_fields=>0,other_route_requests=>0,stable_flow_source_groups=>0,
        protected_source_windows=>0,qualified_windows=>0,merged_sequences=>0,flagged_source_groups=>0,
        actors=>{map {$_=>0} qw(unknown declared_crawler_or_tool verified_crawler)}};
    for my $r (@{$self->{records}}) {$r->{distributed_login_flagged}=0;$r->{distributed_login_diagnostics}=[];}
    if (!$cfg->{enabled}) {
        for my $r (@{$self->{records}}) {_login_diagnostic([$r],$r->{timestamp},$r->{timestamp},['disabled'],{});}
        return $out;
    }
    my %login=map {$_=>1} @{$cfg->{login_paths}};my %admin=map {$_=>1} @{$cfg->{admin_paths}};
    my (%sources,%buckets,%coherent,%flagged,%intervals);my $width=$cfg->{window_seconds};my $source_windows=0;
    for my $r (@{$self->{records}}) {
        my $platform=_browser_platform($r->{user_agent});
        if (!defined($r->{source_key}) || !defined($r->{normal}) || !defined($r->{status}) ||
                !defined($r->{method}) || !defined($platform)) {
            $r->{_distributed_insufficient}=1;$out->{insufficient_fields}++ if !$r->{_context};_login_diagnostic([$r],$r->{timestamp},$r->{timestamp},['insufficient_fields'],{});next;
        }
        my $is_post=$login{$r->{normal}} && $r->{method} eq 'POST';
        my $is_get=($login{$r->{normal}} || $admin{$r->{normal}}) && $r->{method} eq 'GET';
        if (!$is_post && !$is_get) {$out->{other_route_requests}++ if !$r->{_context};_login_diagnostic([$r],$r->{timestamp},$r->{timestamp},['other_route'],{});next;}
        $r->{_distributed_eligible}=1;$r->{_login_post}=$is_post?1:0;
        $r->{behavior_platform}=$platform;$out->{eligible_requests}++ if !$r->{_context};
        my $source=$r->{source_key}."\0".($r->{host}//'');
        push @{$sources{$source}},$r;
        _bad('Distributed-login source group cap exceeded') if keys(%sources)>$self->{config}{limits}{groups};
    }
    for my $source (sort keys %sources) {
        my @rows=sort {$a->{timestamp}<=>$b->{timestamp} || $a->{_order}<=>$b->{_order}} @{$sources{$source}};
        my (%posts,%head,@pairs);
        for my $r (@rows) {
            my $ua=$r->{user_agent};
            if ($r->{_login_post}) {push @{$posts{$ua}},$r->{timestamp};next;}
            next if !exists $posts{$ua};
            $head{$ua}//=0;
            $head{$ua}++ while $head{$ua}<@{$posts{$ua}} && $r->{timestamp}-$posts{$ua}[$head{$ua}]>$width;
            push @pairs,[$posts{$ua}[$head{$ua}],$r->{timestamp}] if $head{$ua}<@{$posts{$ua}};
        }
        my @merged;
        for my $pair (sort {$a->[0]<=>$b->[0] || $a->[1]<=>$b->[1]} @pairs) {
            if (@merged && $pair->[0]<=$merged[-1][1]) {$merged[-1][1]=$pair->[1] if $pair->[1]>$merged[-1][1];}
            else {push @merged,[@$pair];}
        }
        $coherent{$source}=\@merged;
        $out->{stable_flow_source_groups}++ if @merged && grep {!$_->{_context}} @rows;
        for my $r (@rows) {
            my %seen;
            for my $offset (0,int($width/2)) {
                my $start=floor(($r->{timestamp}-$offset)/$width)*$width+$offset;
                next if $seen{$start}++;
                my $key=($r->{host}//'')."\0".$start;
                if (!exists $buckets{$key}{$source}) {
                    _bad('Distributed-login source-window cap exceeded') if ++$source_windows>$self->{config}{limits}{groups};
                }
                push @{$buckets{$key}{$source}},$r;
                _bad('Distributed-login window group cap exceeded') if keys(%buckets)>$self->{config}{limits}{groups};
            }
        }
    }
    for my $key (sort keys %buckets) {
        my (%active,%post_uas,%source_proof,%source_metrics,%owners,%degree,%shared);
        my (undef,$window_start)=split /\0/,$key,2;my $window_end=$window_start+$width;
        for my $source (sort keys %{$buckets{$key}}) {
            my @rows=@{$buckets{$key}{$source}};my (@posts,%uas,%platforms,$first_post,$follow);
            for my $r (@rows) {
                if ($r->{_login_post}) {
                    push @posts,$r;$uas{$r->{user_agent}}=1;$platforms{$r->{behavior_platform}}=1;
                    $first_post//=$r;
                } elsif ($first_post && !$follow) {$follow=$r;}
            }
            my $metrics={source_requests=>scalar(@rows),source_post_requests=>scalar(@posts),
                source_distinct_user_agents=>scalar(keys %uas),source_distinct_platforms=>scalar(keys %platforms)};
            if (_coherent_window($coherent{$source},$window_start,$window_end)) {
                _login_diagnostic(\@rows,0+$window_start,$window_end-1,['coherent_flow_window'],$metrics);
                $out->{protected_source_windows}++ if grep {!$_->{_context}} @rows;next;
            }
            my @reasons;
            push @reasons,'source_post_count' if @posts<$cfg->{min_source_posts};
            push @reasons,'source_agent_diversity' if keys(%uas)<$cfg->{distinct_source_user_agents};
            push @reasons,'source_platform_diversity' if keys(%platforms)<$cfg->{distinct_source_platforms};
            push @reasons,'source_followup_missing' if !$follow;
            if (@reasons) {_login_diagnostic(\@rows,0+$window_start,$window_end-1,\@reasons,$metrics);next;}
            $source_metrics{$source}=$metrics;
            $active{$source}=1;$post_uas{$source}=\%uas;
            $source_proof{$source}={source_requests=>scalar(@rows),source_post_requests=>scalar(@posts),
                source_distinct_user_agents=>scalar(keys %uas),source_distinct_platforms=>scalar(keys %platforms),
                sequence_post_request_id=>$first_post->{request_id},sequence_post_timestamp=>$first_post->{timestamp},
                sequence_follow_request_id=>$follow->{request_id},sequence_follow_timestamp=>$follow->{timestamp}};
            for my $ua (keys %uas) {push @{$owners{$ua}},$source;$degree{$ua}++;}
        }
        # Peeling is linear in IP-UA edges. A singleton cannot use a removed
        # participant to supply its required peer-shared POST-UA evidence.
        my @queue;
        for my $source (sort keys %active) {
            $shared{$source}=grep {$degree{$_}>=2} keys %{$post_uas{$source}};
            push @queue,$source if $shared{$source}<$cfg->{shared_user_agents};
        }
        for (my $i=0;$i<@queue;$i++) {
            my $source=$queue[$i];next if !delete $active{$source};
            for my $ua (keys %{$post_uas{$source}}) {
                next if --$degree{$ua}!=1;
                my ($peer)=grep {$active{$_}} @{$owners{$ua}};
                if (defined($peer) && --$shared{$peer}<$cfg->{shared_user_agents}) {push @queue,$peer;}
            }
        }
        for my $source (sort keys %source_metrics) {
            next if $active{$source};
            _login_diagnostic($buckets{$key}{$source},0+$window_start,$window_end-1,['peer_agent_evidence'],
                {%{$source_metrics{$source}},source_shared_user_agents=>scalar(grep {$degree{$_}>0} keys %{$post_uas{$source}})});
        }
        my (@pool,%uas,%platforms,%paths);my ($posts,$errors)=(0,0);
        for my $source (sort keys %active) {
            for my $r (@{$buckets{$key}{$source}}) {
                push @pool,$r;$paths{$r->{normal}}=1;$errors++ if $r->{status}==404;
                if ($r->{_login_post}) {$posts++;$uas{$r->{user_agent}}=1;$platforms{$r->{behavior_platform}}=1;}
            }
        }
        my @reasons;
        push @reasons,'campaign_sources' if keys(%active)<$cfg->{min_sources};
        push @reasons,'campaign_requests' if @pool<$cfg->{min_requests};
        push @reasons,'campaign_posts' if $posts<$cfg->{min_post_requests};
        push @reasons,'campaign_agent_diversity' if keys(%uas)<$cfg->{distinct_user_agents};
        push @reasons,'campaign_platform_diversity' if keys(%platforms)<$cfg->{distinct_platforms};
        if (@reasons) {
            for my $source (sort keys %active) {
                _login_diagnostic($buckets{$key}{$source},0+$window_start,$window_end-1,\@reasons,
                    {%{$source_metrics{$source}},source_shared_user_agents=>$shared{$source},
                    requests=>scalar(@pool),post_requests=>$posts,distinct_sources=>scalar(keys %active),
                    distinct_user_agents=>scalar(keys %uas),distinct_platforms=>scalar(keys %platforms)});
            }
            next;
        }
        @pool=sort {$a->{timestamp}<=>$b->{timestamp} || $a->{_order}<=>$b->{_order}} @pool;
        my $proof={from=>$pool[0]{timestamp},until=>$pool[-1]{timestamp},requests=>scalar(@pool),
            post_requests=>$posts,distinct_sources=>scalar(keys %active),distinct_user_agents=>scalar(keys %uas),
            distinct_platforms=>scalar(keys %platforms),distinct_paths=>scalar(keys %paths),not_found_requests=>$errors,
            campaign_id=>Digest::SHA::sha256_hex(join("\n",'distributed_login_rotation_v2',$key,map {$_->{request_id}} @pool))};
        if (grep {!$_->{_context}} @pool) {
            $out->{qualified_windows}++;
            push @{$intervals{$pool[0]{host}//''}},[$proof->{from},$proof->{until}];
        }
        for my $source (sort keys %active) {
            my $witness={%$proof,%{$source_proof{$source}},source_shared_user_agents=>$shared{$source}};
            _login_diagnostic($buckets{$key}{$source},0+$window_start,$window_end-1,['qualified'],$witness);
            for my $r (@{$buckets{$key}{$source}}) {
                next if $r->{distributed_login_flagged};
                $r->{distributed_login_flagged}=1;$r->{distributed_login_evidence}=$witness;
                next if $r->{_context};$out->{flagged_requests}++;$out->{actors}{$r->{actor}}++;$flagged{$source}=1;
            }
        }
    }
    for my $host (keys %intervals) {
        my $end;
        for my $interval (sort {$a->[0]<=>$b->[0] || $a->[1]<=>$b->[1]} @{$intervals{$host}}) {
            $out->{merged_sequences}++ if !defined($end) || $interval->[0]>$end;
            $end=$interval->[1] if !defined($end) || $interval->[1]>$end;
        }
    }
    $out->{flagged_source_groups}=scalar(keys %flagged);return $out;
}

sub finish {
    my ($self)=@_; _bad('Already finished') if $self->{finished};
    $self->_line(0) if $self->{line_present}; $self->{finished}=1;
    _bad('No parsed records') if !$self->{counts}{parsed};
    _bad('No in-scope records') if !$self->{counts}{analyzed};
    my $primary_records=$self->{records};my @combined;
    for my $side (qw(before after)) {
        for my $r (@{$self->{contexts}{$side}{records}||[]}) {
            _bad('Context overlaps primary input period') if $side eq 'before' ? $r->{timestamp}>=$self->{min} : $r->{timestamp}<=$self->{max};
        }
    }
    my $context_window=ref($self)->analysis_window($self->{config});
    my @before=grep {$_->{timestamp}>=$self->{min}-$context_window} @{$self->{contexts}{before}{records}||[]};
    my @after=grep {$_->{timestamp}<=$self->{max}+$context_window} @{$self->{contexts}{after}{records}||[]};
    $self->{contexts}{before}{meta}{used_analyzed_records}=scalar(@before) if exists($self->{contexts}{before}{meta});
    $self->{contexts}{after}{meta}{used_analyzed_records}=scalar(@after) if exists($self->{contexts}{after}{meta});
    @combined=(@before,@$primary_records,@after);
    my ($analysis_min,$analysis_max)=($self->{min},$self->{max});
    for my $i (0..$#combined) {
        $combined[$i]{_order}=$i;
        $analysis_min=$combined[$i]{timestamp} if $combined[$i]{timestamp}<$analysis_min;
        $analysis_max=$combined[$i]{timestamp} if $combined[$i]{timestamp}>$analysis_max;
    }
    local $self->{records}=\@combined;
    my $cfg=$self->{config}; my (%paths,@active,@inactive,%exempt);
    for my $r (@{$cfg->{site_references}}) { $exempt{$r->{path}}=1 if $r->{from}<=$analysis_max && $r->{until}>=$analysis_min; }
    for my $f (@{$cfg->{probe_families}}) {
        if ($f->{absent_from}<=$analysis_min && $f->{absent_until}>=$analysis_max) {
            push @active,$f->{id}; for (@{$f->{paths}}) {$paths{$_}=$f->{id} if !$exempt{$_}};
        } else { push @inactive,{id=>$f->{id},reason=>'absence attestation does not cover entire used evidence period'}; }
    }
    my %actors=map {$_=>0} qw(unknown declared_crawler_or_tool verified_crawler);
    my %verification=map {$_=>0} qw(verified failed unavailable not_applicable);
    my (%groups,$insufficient,$unsupported); $insufficient=$unsupported=0;
    for my $r (@{$self->{records}}) {
        my $labels=$self->_actor_labels($r);
        $r->{actor}=$labels->{actor};
        $r->{verification_outcome}=$labels->{verification_outcome}; $r->{scanner_flagged}=0;
        $actors{$r->{actor}}++ if !$r->{_context}; $verification{$r->{verification_outcome}}++ if !$r->{_context};
        my $normal=normalize_target($r->{target}); $unsupported++ if !defined($normal) && !$r->{_context};
        $r->{normal}=$normal if defined $normal;
        my @utc=gmtime($r->{timestamp});
        $r->{source_month}=sprintf('%04d-%02d',$utc[5]+1900,$utc[4]+1);
        my ($source_af,$source_packed)=literal_ip($r->{client});
        if (defined $source_af) {
            $r->{source_key}=(length($source_packed)==4?'4:':'6:').unpack('H*',$source_packed);
            $r->{source_month_key}=$r->{source_month}.'|'.$r->{source_key};
        }
        if (!defined($r->{user_agent}) || !literal_ip($r->{client})) { $insufficient++ if !$r->{_context}; next; }
        if (defined($normal) && exists($paths{$normal})) {
            $r->{normal}=$normal; $r->{family}=$paths{$normal};
            push @{$groups{$r->{client}."\0".$r->{user_agent}}},$r;
        }
    }
    my $sequences=$self->_scan(\%groups);
    my $broad=$self->_behavior; my $probing=$self->_probing; my $rapid=$self->_rapid_scan; my $distributed=$self->_distributed_login;
    $self->{records}=$primary_records;
    my $behavior={enabled=>($broad->{enabled} || $probing->{enabled} || $rapid->{enabled} || $distributed->{enabled})?JSON::PP::true:JSON::PP::false,
        rule_id=>'behavior_union_v3',broad_rule=>$broad,probing_rule=>$probing,rapid_scan_rule=>$rapid,distributed_login_rule=>$distributed,
        broad_flagged_requests=>$broad->{flagged_requests},probing_flagged_requests=>$probing->{flagged_requests},
        rapid_scan_flagged_requests=>$rapid->{flagged_requests},distributed_login_flagged_requests=>$distributed->{flagged_requests},
        overlap_requests=>0,flagged_requests=>0,eligible_requests=>0,insufficient_fields=>0,
        merged_sequences=>$broad->{merged_sequences}+$probing->{merged_sequences}+$rapid->{merged_sequences}+$distributed->{merged_sequences},flagged_source_groups=>0,
        actors=>{map {$_=>0} qw(unknown declared_crawler_or_tool verified_crawler)}};
    my %behavior_groups;
    for my $r (@{$self->{records}}) {
        $r->{broad_probing_flagged}=$r->{suspected_automation};
        $behavior->{overlap_requests}++ if $r->{broad_probing_flagged}+$r->{probing_flagged}+$r->{rapid_scan_flagged}+$r->{distributed_login_flagged}>=2;
        $r->{suspected_automation}=1 if $r->{probing_flagged} || $r->{rapid_scan_flagged} || $r->{distributed_login_flagged};
        $behavior->{eligible_requests}++ if $r->{_broad_eligible} || $r->{_probing_eligible} || $r->{_rapid_eligible} || $r->{_distributed_eligible};
        $behavior->{insufficient_fields}++ if $r->{_broad_insufficient} || $r->{_probing_insufficient} || $r->{_rapid_insufficient} || $r->{_distributed_insufficient};
        next if !$r->{suspected_automation};
        $behavior->{flagged_requests}++; $behavior->{actors}{$r->{actor}}++;
        my ($af,$packed)=literal_ip($r->{client});
        $behavior_groups{$af.':'.unpack('H*',$packed)."\0".($r->{host}//'')}=1;
    }
    $behavior->{flagged_source_groups}=scalar(keys %behavior_groups);
    my ($flagged,$excluded,$included)=(0,0,0); my %exclude=map {$_=>1} @{$cfg->{exclude}};
    my %include=map {$_=>1} @{$cfg->{behavior_include}};
    for my $r (@{$self->{records}}) {
        $flagged++ if $r->{scanner_flagged};
        $r->{behavior_included}=$r->{suspected_automation} && $include{$r->{request_id}} ? 1:0;
        $included++ if $r->{behavior_included};
        $r->{excluded}=($exclude{$r->{actor}} || ($exclude{scanner_flagged} && $r->{scanner_flagged})
            || ($exclude{suspected_automation} && $r->{suspected_automation} && !$r->{behavior_included}))?1:0;
        $excluded++ if $r->{excluded};
    }
    $behavior->{inclusion_overrides}=$included;
    my $nondefault=grep {$cfg->{scanner}{$_}!=$DEFAULT->{scanner}{$_}} keys %{$cfg->{scanner}};
    my $report={schema_version=>1,algorithm_id=>$ALGORITHM,
        config_sha256=>Digest::SHA::sha256_hex($ALGORITHM."\n".JSON::PP->new->utf8->canonical->encode($cfg)),
        analysis_context=>{map {$_=>$self->{contexts}{$_}{meta}} grep {exists($self->{contexts}{$_}{meta})} qw(before after)},analysis_period=>{from=>$analysis_min,until=>$analysis_max},
        input_sha256=>$self->{digest}->hexdigest,input=>{format=>$self->{format},bytes=>$self->{input_bytes},period=>{from=>$self->{min},until=>$self->{max}},
            host_policy=>@{$cfg->{hosts}}?'configured hosts enforced; missing host excluded':'all parsed hosts; aliases inseparable for hostless records',hosts=>$cfg->{hosts}},
        effective=>{scanner=>$cfg->{scanner},scanner_nondefault=>$nondefault?JSON::PP::true:JSON::PP::false,behavior=>$cfg->{behavior},probing=>$cfg->{probing},rapid_scan=>$cfg->{rapid_scan},distributed_login=>$cfg->{distributed_login},behavior_include=>$cfg->{behavior_include},verification=>$cfg->{verification},limits=>$cfg->{limits},
            status=>'Thresholds, continuity gaps and resource caps are heuristic assumptions; detection accuracy is unmeasured',crawler_tokens=>$cfg->{crawler_tokens}},
        counts=>{%{$self->{counts}}},actors=>\%actors,verification_outcomes=>\%verification,scanner_flagged_requests=>$flagged,merged_scanner_sequences=>$sequences,
        scanner_insufficient_fields=>$insufficient,unsupported_targets=>$unsupported,behavior=>$behavior,
        probes=>{active_families=>\@active,inactive_families=>\@inactive,exempt_paths=>[sort keys %exempt]},
        provider_snapshots=>[map {$_->{provenance}} @{$self->{snapshots}}],
        limitations=>[
            'Actor labels are separate from scanner flags; unknown is neither verified human nor bot. Counts are requests, not visitors or AWStats visits.',
            'Verified means verified against operator-attested published-range snapshots, not cryptographic source authentication. Bracketing assumes range continuity and does not prove uninterrupted ownership.',
            'Historical requests without covering archived evidence remain unavailable. IPv4-mapped IPv6 is not converted to IPv4; literal-IP acceptance follows platform inet_pton.',
            'Scanner flags describe qualifying probe requests, not intent or people. Shared IPs/UA and duplicate or overlapping input can affect results. Supply one nonoverlapping stable site snapshot.',
            'Suspected automation is the union of optional broad path/404 probing, configured endpoint probing, rapid content-path/404 probing and distributed login probing, not verified crawler identity. Broad and endpoint rules require browser/platform diversity; rapid scanning requires neither browser identity nor rotation and excludes static asset suffixes. Each requires its own coincident conditions in a source/host window. Endpoint probing uses configured paths without an absence or failed-response requirement. Overlaps count once; sequence counts sum across rules. Request-ID inclusions override only behavioral exclusion. Shared proxies, authorized tests and insufficient boundary context can affect results; accuracy is unmeasured.',
            'Distributed login probing pools only repeatedly participating sources within configured login/admin paths and two fixed UTC grids. Each source needs POST-UA/platform rotation, POST-follow-up order and peer-shared exact POST UAs; coherent same-UA POST/follow-up spans veto intersecting source/host windows, rather than unrelated later activity. Pool counts are separate from source contributions. This is heuristic campaign evidence, not authentication, login success, intent or ownership; shared offices can cause false positives and stable-emulating bots, sparse sources and partition/grid boundaries can evade detection.',
            'Optional disjoint before/after context supplies evidence only. Primary hashes, physical indices, counts and filtered exports exclude context rows. Caller must freeze nonoverlapping contexts and bind their hashes when caching; contextual witness counts can exceed primary-day request counts.',
            'Local tokens, component absence and site-reference periods are operator attestations; no status-code or weak browser signal supplies identity or absence.',
            'No live DNS, network queries, incremental history or blocking. The report exposes the configured comparison; the CLI can explicitly export matching filtered input for a separate native replay. Caller controls retention and publication.',
        ]};
    if (%exclude) { $report->{adjusted_requests}={label=>'requests in this input excluding '.join(', ',sort keys %exclude),original=>$self->{counts}{analyzed},excluded=>$excluded,remaining=>$self->{counts}{analyzed}-$excluded}; }
    if ($self->{details}) {
        $report->{details_warning}='Contains raw request data; keep private and apply your retention policy.';
        $report->{details}=[map {my $r=$_; +{(map {$_=>$r->{$_}} qw(line_index timestamp client user_agent target host actor verification_outcome status request_id method behavior_evidence probing_evidence rapid_scan_evidence distributed_login_evidence distributed_login_diagnostics behavior_platform source_key source_month source_month_key)),normalized_target=>$r->{normal},scanner_flagged=>$r->{scanner_flagged}?JSON::PP::true:JSON::PP::false,suspected_automation=>$r->{suspected_automation}?JSON::PP::true:JSON::PP::false,broad_probing_flagged=>$r->{broad_probing_flagged}?JSON::PP::true:JSON::PP::false,probing_flagged=>$r->{probing_flagged}?JSON::PP::true:JSON::PP::false,rapid_scan_flagged=>$r->{rapid_scan_flagged}?JSON::PP::true:JSON::PP::false,distributed_login_flagged=>$r->{distributed_login_flagged}?JSON::PP::true:JSON::PP::false,excluded=>$r->{excluded}?JSON::PP::true:JSON::PP::false,behavior_included=>$r->{behavior_included}?JSON::PP::true:JSON::PP::false}} @{$self->{records}}];
    }
    return $report;
}
sub excluded_line_indices {
    my ($self)=@_; _bad('Classification must finish first') if !$self->{finished};
    return [map {$_->{line_index}} grep {$_->{excluded}} @{$self->{records}}];
}
sub _html_escape { my ($s)=@_; $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; $s =~ s/"/&quot;/g; $s =~ s/'/&#39;/g; return $s; }
sub html_report {
    my ($report)=@_;
    my $text=decode('UTF-8',canonical_json($report),FB_CROAK);
    $report=$JSON->decode($text);
    my $html='<!doctype html><html lang="en"><meta charset="utf-8"><title>Traffic classification</title><body><h1>Traffic classification</h1><p>Observed requests; unknown does not mean human. Scanner flags are behavior evidence, separate from actor identity.</p><table><caption>Requests in this input</caption>';
    for my $actor (qw(verified_crawler declared_crawler_or_tool unknown)) { $html.='<tr><th>'._html_escape($actor).'</th><td>'.$report->{actors}{$actor}.'</td></tr>'; }
    $html.='</table><p>Scanner-flagged requests: '.$report->{scanner_flagged_requests}.'. Merged qualifying sequences: '.$report->{merged_scanner_sequences}.'.</p>';
    if (my $b=$report->{behavior}) {
        $html.='<h2>Suspected automation</h2>';
        if ($b->{enabled}) {
            $html.='<p>Requests flagged by any enabled behavioral rule: '.$b->{flagged_requests}.'. Merged qualifying sequences (sum across rules): '.$b->{merged_sequences}.'.</p><p>Broad path probing: '.($b->{broad_flagged_requests}//$b->{flagged_requests}).'; configured endpoint probing: '.($b->{probing_flagged_requests}//0).'; rapid content-path probing: '.($b->{rapid_scan_flagged_requests}//0).'; distributed login probing: '.($b->{distributed_login_flagged_requests}//0).'; overlap (two or more rules): '.($b->{overlap_requests}//0).'.</p><p>Of these requests, '.$b->{actors}{unknown}.' have unknown actor identity. Behavioral flags overlap actor labels and do not prove crawler identity. Exclusions require an explicit selection; inclusion overrides: '.($b->{inclusion_overrides}//0).'.</p>';
        } else { $html.='<p>Behavioral detection is disabled for this report.</p>'; }
    }
    if ($report->{adjusted_requests}) { my $a=$report->{adjusted_requests}; $html.='<p>'._html_escape($a->{label}).': '.$a->{remaining}.' (original '.$a->{original}.', excluded '.$a->{excluded}.').</p>'; }
    $html.='<p>Heuristic thresholds; precision and recall are unknown. This tool changes no AWStats history or access rules.</p><details><summary>Evidence, effective rules and report data</summary><pre>'._html_escape($text).'</pre></details></body></html>';
    return encode('UTF-8',$html);
}
1;
