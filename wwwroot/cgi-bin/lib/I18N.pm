#!/usr/bin/perl
package I18N;
use strict;
use warnings;
our $VERSION = '1.0';
#------------------------------------------------------------------------------
# Global Variables
#------------------------------------------------------------------------------
our @Message                   = ();
our %translate_map             = ();
our %LangBrowserToLangAwstats  = ();
our $DirLang                   = '';
our $DIR                       = '';
our $Debug                     = 0;
our $PageCode                  = 'utf-8';
our $PageDir                   = 0;
our $LogType                   = '';

#------------------------------------------------------------------------------
# Basic Output Functions
#------------------------------------------------------------------------------
sub error {
    print STDERR "Error: $_[0].\n";
}

sub warning {
    print STDERR "Warning: $_[0].\n";
}

sub debug {
    my $level = $_[1] || 1;
    if ( $Debug >= $level ) {
        print localtime(time) . " - DEBUG $level - $_[0]\n";
    }
}

#------------------------------------------------------------------------------
# Translate message
#------------------------------------------------------------------------------
sub _t {
    my $msgid = shift;
    if ( $msgid =~ /^\d+$/ && defined $Message[$msgid] ) {
        return $Message[$msgid];
    }
    if ( defined $translate_map{$msgid} ) {
        return $translate_map{$msgid};
    }
    return $msgid;
}

sub store_translation {
    my ( $msgid, $msgstr ) = @_;
    $translate_map{$msgid} = $msgstr;
    if ( $msgid eq 'PageCode' ) {
        $PageCode = $msgstr;
    }
    elsif ( $msgid eq 'PageDir' ) {
        $PageDir = $msgstr;
    }
}

#------------------------------------------------------------------------------
# Terminal Language Detection
#------------------------------------------------------------------------------
sub detect_terminal_language {
    my $lang = $ENV{'LANG'} || $ENV{'LANGUAGE'} || $ENV{'LC_ALL'} || $ENV{'LC_MESSAGES'} || '';
    return undef if !$lang;
    $lang =~ s/\..*$//;
    $lang =~ s/_/-/g;
    $lang = lc($lang);
    my @supported = qw(
        am ar az be bg bn br bs ca cs cy da de el
        en-ca en-gb en-us es et eu fa fi fr ga gl gu
        he hi hr hu hy id is it ja ka kk km kn ko
        lo lt lv mk ml mn mr ms my nb ne nl nn or
        pa pl ps pt pt-br ro ru si sk sl sq sr sr-latn
        sv sw ta te th tl tr ug uk ur uz vi zh-cn zh-tw
    );
    foreach (@supported) {
        if ( $_ eq $lang ) {
            return $lang;
        }
    }
    my $primary = ( split /-/, $lang )[0];
    foreach (@supported) {
        if ( $_ eq $primary ) {
            return $primary;
        }
    }
    return undef;
}

#------------------------------------------------------------------------------
# Read language file
#------------------------------------------------------------------------------
sub Read_Language_Data {
    my $lang = shift || 'en-us';

    if ( $lang eq 'auto' && $ENV{'HTTP_ACCEPT_LANGUAGE'} ) {
        my @accept = split /,/, $ENV{'HTTP_ACCEPT_LANGUAGE'};
        foreach my $lang_pref (@accept) {
            $lang_pref =~ s/;.*//;
            $lang_pref =~ s/^\s+|\s+$//g;
            $lang_pref = lc($lang_pref);
            $lang_pref =~ s/_/-/g;
            if ( $LangBrowserToLangAwstats{$lang_pref} ) {
                $lang = $LangBrowserToLangAwstats{$lang_pref};
                last;
            }
            my $short = substr( $lang_pref, 0, 2 );
            if ( $LangBrowserToLangAwstats{$short} ) {
                $lang = $LangBrowserToLangAwstats{$short};
                last;
            }
        }
        if ( $lang eq 'auto' && $accept[0] ) {
            my $first = $accept[0];
            $first =~ s/;.*//;
            $first =~ s/^\s+|\s+$//g;
            $first = lc($first);
            $first =~ s/_/-/g;
            my $short = substr( $first, 0, 2 );
            if ( $LangBrowserToLangAwstats{$short} ) {
                $lang = $LangBrowserToLangAwstats{$short};
            }
        }
    }

    my @PossibleLangDir;
    if ($^O eq 'MSWin32') {
        @PossibleLangDir = ( "$DirLang", "$DIR/lang", "C:/AWStats/share/lang" );
    } else {
        @PossibleLangDir = ( "$DirLang", "$DIR/lang", "/usr/share/awstats/lang", "/usr/local/share/awstats/lang" );
    }
    my $FileLang = '';

    foreach my $dir (@PossibleLangDir) {
        my $searchdir = $dir;
        if ( $searchdir =~ /\|/ ) {
            error("DirLang parameter can't contains character |");
            next;
        }
        if ( $searchdir && !( $searchdir =~ /\/$/ ) && !( $searchdir =~ /\\$/ ) ) {
            $searchdir .= "/";
        }
        my $pofile = "${searchdir}awstats-$lang.po";
        if ( -f $pofile ) {
            $FileLang = $pofile;
            last;
        }
        my $lang_underscore = $lang;
        $lang_underscore =~ s/-/_/g;
        if ( $lang_underscore ne $lang ) {
            $pofile = "${searchdir}awstats-${lang_underscore}.po";
            if ( -f $pofile ) {
                $FileLang = $pofile;
                last;
            }
        }
    }

    if ( !$FileLang ) {
        foreach my $dir (@PossibleLangDir) {
            my $searchdir = $dir;
            if ( $searchdir && !( $searchdir =~ /\/$/ ) && !( $searchdir =~ /\\$/ ) ) {
                $searchdir .= "/";
            }
            my $pofile = "${searchdir}awstats-en-us.po";
            if ( -f $pofile ) {
                $FileLang = $pofile;
                last;
            }
        }
    }

    if ($Debug) {
        debug("Call to Read_Language_Data [FileLang=\"$FileLang\"]");
    }

    if ($FileLang) {
        parse_po_file($FileLang);
    }
    else {
        warning( sprintf(
            _t("Warning: Can't find language files for \"%s\". English will be used."),
            $lang
        ) );
    }

    $PageCode = 'utf-8';
    my @rtl_langs = qw(ar he fa ur ug);
    if ( grep { $_ eq $lang } @rtl_langs ) {
        $PageDir = 1;
    } else {
        $PageDir = 0;
    }

    if ( $LogType eq 'M' ) {
        $translate_map{"First"} = _t("First");
        $translate_map{"Last"}  = _t("Last");
        $translate_map{"Mails"} = _t("Mails");
        $translate_map{"Size"}  = _t("Size");
    }
}

#------------------------------------------------------------------------------
# Parsing .po
#------------------------------------------------------------------------------
sub parse_po_file {
    my ($pofile) = @_;
    my $fh;
    if ( !open( $fh, "<:encoding(UTF-8)", $pofile ) ) {
        warning("Warning: Cannot open .po file: $pofile");
        return;
    }
    my $msgid     = '';
    my $msgstr    = '';
    my $in_msgid  = 0;
    my $in_msgstr = 0;
    my $unescape = sub {
        my $text = shift;
        $text =~ s/\\\\/\\/g;
        $text =~ s/\\n/\n/g;
        $text =~ s/\\\"/\"/g;
        $text =~ s/\\t/\t/g;
        return $text;
    };
    my $submit_translation = sub {
        if ( $msgid ne '' && $msgstr ne '' ) {
            store_translation( $unescape->($msgid), $unescape->($msgstr) );
        }
    };

    while (<$fh>) {
        chomp;
        s/\r//;
        next if /^\s*#/;
        next if /^\s*$/;

        if (/^msgid\s+"(.*)"/) {
            $submit_translation->();
            $msgid     = $1;
            $msgstr    = '';
            $in_msgid  = 1;
            $in_msgstr = 0;
        }
        elsif (/^msgstr\s+"(.*)"/) {
            $msgstr    = $1;
            $in_msgid  = 0;
            $in_msgstr = 1;
        }
        elsif (/^"(.*)"/) {
            if ($in_msgid) {
                $msgid .= $1;
            }
            elsif ($in_msgstr) {
                $msgstr .= $1;
            }
        }
    }
    $submit_translation->();
    close($fh);
}
#------------------------------------------------------------------------------
# Function:     Append one run record to log file, keep last $keep records
# Parameters:   $content  - string of the whole run record
#               $logfile  - log file path
#               $keep     - keep last N records (default 7)
# Return:       None
# Note:         No encoding on read/write, store exactly what was printed
#------------------------------------------------------------------------------
sub log_run {
    my ($content, $logfile, $keep) = @_;
    $keep ||= 7;
    return if !$logfile;

    my @records = ();
    if ( -f $logfile ) {
        if ( open( my $fh, '<', $logfile ) ) {
            binmode($fh);
            local $/;
            my $data = <$fh>;
            close($fh);
            @records = split( /^(?=#={30})/m, $data );
            @records = grep { /\S/ } @records;
        }
    }

    push @records, $content;
    if ( @records > $keep ) {
        @records = @records[ -$keep .. -1 ];
    }

    if ( open( my $fh, '>', $logfile ) ) {
        binmode($fh);
        foreach my $r (@records) {
            print $fh $r;
            print $fh "\n" if $r !~ /\n$/;
        }
        close($fh);
    }
}

#------------------------------------------------------------------------------
# Function:     Format timestamp with translated day of week
# Parameters:   $time (optional, default: now)
# Return:       e.g. "2026-09-11 12:32:26 周五"
#------------------------------------------------------------------------------
sub format_time {
    my $t = shift || time;
    my ($sec, $min, $hour, $mday, $mon, $year, $wday) = localtime($t);
    $year += 1900;
    $mon  += 1;
    my @dow = (
        $translate_map{"DayOfWeek_0"} // "Sun",
        $translate_map{"DayOfWeek_1"} // "Mon",
        $translate_map{"DayOfWeek_2"} // "Tue",
        $translate_map{"DayOfWeek_3"} // "Wed",
        $translate_map{"DayOfWeek_4"} // "Thu",
        $translate_map{"DayOfWeek_5"} // "Fri",
        $translate_map{"DayOfWeek_6"} // "Sat",
    );
    my $fmt = $translate_map{"dateformat_long"} // "yyyy-mm-dd HH:MM:SS";
    my $result = $fmt;
    $result =~ s/yyyy/sprintf("%04d", $year)/e;
    $result =~ s/mm/sprintf("%02d", $mon)/e;
    $result =~ s/dd/sprintf("%02d", $mday)/e;
    $result =~ s/HH/sprintf("%02d", $hour)/e;
    $result =~ s/MM/sprintf("%02d", $min)/e;
    $result =~ s/SS/sprintf("%02d", $sec)/e;
    return "$result $dow[$wday]";
}

1;