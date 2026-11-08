package VStats::OperatorEvidence;
use v5.020;
use strict;
use warnings;
use Socket qw(AF_INET AF_INET6 inet_pton inet_ntop);
use Digest::SHA qw(sha256_hex);

# Offline, operator-attested DNS observations. No network or filesystem I/O.
my $SOURCE='https://www.internet-census.org/home.html';
my $DOMAIN='internet-census.org';
sub canonical_ip {
    my ($value)=@_;return if !defined($value) || ref($value) || $value=~/[^0-9a-fA-F:.]/;
    if ($value=~/\A[0-9.]+\z/) {
        return if $value!~/\A(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}\z/;
    }
    for my $family (AF_INET,AF_INET6) {
        my $packed=eval {inet_pton($family,$value)};next if !defined($packed);
        if ($family==AF_INET6 && substr($packed,0,12) eq ("\0"x10)."\xff\xff") {
            $packed=substr($packed,12);return (AF_INET,$packed,inet_ntop(AF_INET,$packed));
        }
        return ($family,$packed,inet_ntop($family,$packed));
    }
    return;
}
sub _name {
    my ($s)=@_;return if !defined($s) || ref($s) || $s=~/[^A-Za-z0-9.-]/;
    $s=lc($s);$s=~s/\.\z//;return if !length($s) || length($s)>253;
    for (split /\./,$s,-1) {return if length($_)>63 || !/\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z/;}
    return $s;
}
sub _uint {return defined($_[0]) && !ref($_[0]) && $_[0]=~/\A(?:0|[1-9][0-9]*)\z/ && $_[0]<=($_[1]//4102444800);}
sub _keys {
    my ($v,@allowed)=@_;die "Invalid operator evidence\n" if ref($v) ne 'HASH';
    my %allowed=map {$_=>1} @allowed;die "Invalid operator evidence\n" if grep {!$allowed{$_}} keys %$v;
}
sub _reverse {
    my ($family,$packed)=@_;
    return join('.',reverse unpack('C*',$packed)).'.in-addr.arpa' if $family==AF_INET;
    return join('.',reverse split //,unpack('H*',$packed)).'.ip6.arpa';
}
sub _chain {
    my ($q,$start,$type,$wanted)=@_;
    return if ref($q) ne 'HASH' || ($q->{status}//'') ne 'NOERROR' || ($q->{truncated}//1)!=0
        || ($q->{qtype}//'') ne $type || (_name($q->{qname})//'') ne $start || ref($q->{answers}) ne 'ARRAY' || @{$q->{answers}}>128;
    my (%seen,@used);my $owner=$start;
    for my $hop (0..8) {
        return if $seen{$owner}++;
        my @records=grep {ref($_) eq 'HASH' && (_name($_->{owner})//'') eq $owner} @{$q->{answers}};
        return if grep {!_uint($_->{ttl},2147483647)} @records;
        my @links=grep {($_->{type}//'') eq 'CNAME'} @records;
        if (@links) {
            return if @links!=1 || $hop==8 || grep {($_->{type}//'') eq $type} @records;
            my $next=_name($links[0]{data});return if !defined($next);
            push @used,$links[0];$owner=$next;next;
        }
        for my $rr (@records) {
            next if ($rr->{type}//'') ne $type;
            my $match;
            if ($type eq 'PTR') {$match=_name($rr->{data});}
            else {my ($af,$packed)=canonical_ip($rr->{data});$match=defined($af) && $packed eq $wanted && (($type eq 'A')==($af==AF_INET))?1:undef;}
            next if !defined($match);return (\@used,$rr,$match) if $type ne 'PTR';
        }
        return (\@used,[grep {($_->{type}//'') eq 'PTR' && defined(_name($_->{data}))} @records]) if $type eq 'PTR';
        return;
    }
    return;
}
sub new {
    my ($class,$raw)=@_;die "Operator evidence exceeds byte limit\n" if length($raw)>16777216;
    my $v=VStats::TrafficClassifier::strict_json($raw);
    _keys($v,qw(schema_version provider_id source_url source_document_fetched_at resolver selection observations));
    die "Invalid operator evidence\n" if ($v->{schema_version}//0)!=1 || ($v->{provider_id}//'') ne 'internet_census'
        || ($v->{source_url}//'') ne $SOURCE || !_uint($v->{source_document_fetched_at}) || ref($v->{observations}) ne 'ARRAY' || @{$v->{observations}}>4096;
    _keys($v->{resolver},qw(address nonrewriting));
    my ($resolver)=canonical_ip($v->{resolver}{address});
    die "Invalid operator resolver\n" if !defined($resolver) || !defined($v->{resolver}{nonrewriting}) || ref($v->{resolver}{nonrewriting}) || $v->{resolver}{nonrewriting}!~/\A[01]\z/;
    die "Invalid operator selection\n" if !defined($v->{selection}) || ref($v->{selection}) || length($v->{selection})>2048;
    my %sources;
    for my $obs (@{$v->{observations}}) {
        _keys($obs,qw(client completed_at queries));
        my ($family,$packed,$client)=canonical_ip($obs->{client});
        next if !defined($family) || !_uint($obs->{completed_at}) || ref($obs->{queries}) ne 'ARRAY' || @{$obs->{queries}}>32;
        my $slot={lookup_at=>0+$obs->{completed_at},valid=>0};push @{$sources{$client}},$slot;
        next if !$v->{resolver}{nonrewriting};
        my $ptrname=_reverse($family,$packed);my @ptr=grep {($_->{qtype}//'') eq 'PTR' && (_name($_->{qname})//'') eq $ptrname} @{$obs->{queries}};
        next if @ptr!=1;my ($prefix,$records)=_chain($ptr[0],$ptrname,'PTR');next if !defined($records) || ref($records) ne 'ARRAY' || @$records>16;
        for my $rr (@$records) {
            my $name=_name($rr->{data});next if $name ne $DOMAIN && $name!~/\.\Q$DOMAIN\E\z/;
            my $type=$family==AF_INET?'A':'AAAA';
            my @forward=grep {($_->{qtype}//'') eq $type && (_name($_->{qname})//'') eq $name} @{$obs->{queries}};
            next if @forward!=1;my ($chain,$last)=_chain($forward[0],$name,$type,$packed);next if !defined($last);
            my @ttls=map {$_->{ttl}} (@$prefix,$rr,@$chain,$last);my ($ttl)=sort {$a<=>$b} @ttls;next if !$ttl;
            %$slot=(valid=>1,provider_id=>'internet_census',procedure=>'forward-confirmed reverse DNS',
                source_url=>$SOURCE,lookup_at=>0+$obs->{completed_at},expires_at=>$obs->{completed_at}+$ttl,
                hostname=>$name,evidence_class=>'operator_associated',evidence_sha256=>sha256_hex($raw));last;
        }
    }
    for (values %sources) {@$_=sort {$a->{lookup_at}<=>$b->{lookup_at}} @$_;}
    return bless {sources=>\%sources,sha256=>sha256_hex($raw)},$class;
}
sub association {
    my ($self,$r)=@_;return if ($r->{client_source}//'')!~/\A(?:socket_peer|trusted_proxy)\z/;
    my (undef,undef,$client)=canonical_ip($r->{client});return if !defined($client);
    my @proof=@{$self->{sources}{$client}||[]};my ($historical,$last);
    for my $proof (@proof) {
        $last=$proof if $proof->{lookup_at}<$r->{timestamp};
        $historical//=$proof if $proof->{valid} && $r->{timestamp}<=$proof->{lookup_at};
    }
    if ($last && $last->{valid} && $r->{timestamp}<$last->{expires_at}) {return {%$last,state=>'dated_association'};}
    return if $last && !$last->{valid};
    return $historical ? {%$historical,state=>'historical_candidate',evidence_class=>'historical_candidate'}:undef;
}
1;
