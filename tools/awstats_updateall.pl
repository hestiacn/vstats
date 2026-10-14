#!/usr/bin/perl
#------------------------------------------------------------------------------
# Launch update process for all config files found in a particular directory.
# See COPYING.TXT file about AWStats GNU General Public License.
#------------------------------------------------------------------------------
use strict;
use warnings;
use Encode qw(is_utf8 encode_utf8);
use FindBin qw($RealBin);
if ($^O eq 'MSWin32') {
	use lib ( "$RealBin/lib", "C:/AWStats/share/lib", "C:/AWStats/cgi-bin/lib" );
} else {
	use lib ( "$RealBin/lib", "/usr/share/awstats/lib", "/usr/local/share/awstats/lib" );
}
use IO::Select;
require I18N;
*main::_t = \&I18N::_t;
*main::detect_terminal_language = \&I18N::detect_terminal_language;
*main::Read_Language_Data       = \&I18N::Read_Language_Data;
*main::log_run                  = \&I18N::log_run;
*main::format_time              = \&I18N::format_time;
my @PluginsToLoad = ();
my @conftoexclude;
my $Lang = '';

#------------------------------------------------------------------------------
# Defines
#------------------------------------------------------------------------------
my $REVISION='20260510';
my $VERSION="8.1 (release $REVISION)";
# Default value of DIRCONFIG
my $DIRCONFIG;
my $Awstats;
my @possible_paths;

if ($^O eq 'MSWin32') {
	$DIRCONFIG = "C:/laragon/etc/awstats";
	$Awstats   = "C:/AWStats/cgi-bin/awstats.pl";
	@possible_paths = (
		"C:/AWStats/cgi-bin/awstats.pl",
		"C:/AWStats/wwwroot/cgi-bin/awstats.pl",
		"awstats.pl",
		"./awstats.pl",
	);
} else {
	$DIRCONFIG = "/etc/awstats";
	if (!-d $DIRCONFIG) {
		$DIRCONFIG = "/usr/local/etc/awstats";
	}
	$Awstats = "awstats.pl";
	@possible_paths = (
		"awstats.pl",
		"./awstats.pl",
		"/usr/lib/cgi-bin/awstats.pl",
		"/usr/local/www/cgi-bin/awstats.pl",
		"/usr/local/awstats/wwwroot/cgi-bin/awstats.pl",
		"/usr/share/awstats/wwwroot/cgi-bin/awstats.pl",
	);
}

my $Debug=0;

my $AwstatsDir='';
my $AwstatsProg='';
my $LastLine='';
my $SingleDomain = '';
my $LOGDIR;
my $LOGFILE;
my $LOGKEEP = 7;
if ($^O eq 'MSWin32') {
	$LOGDIR  = "C:/AWStats/logs";
	$LOGFILE = "$LOGDIR/awstats-update.log";
} else {
	$LOGDIR  = "/var/log/awstats";
	$LOGFILE = "$LOGDIR/awstats-update.log";
}
my %bash_paths = (
	'linux'    => '/bin/bash',
	'darwin'   => '/bin/bash',
	'freebsd'  => '/usr/local/bin/bash',
	'openbsd'  => '/usr/local/bin/bash',
	'netbsd'   => '/usr/pkg/bin/bash',
	'solaris'  => '/usr/bin/bash',
	'aix'      => '/usr/bin/bash',
	'hpux'     => '/usr/bin/bash',
);

my $bash_path = $bash_paths{$^O} || '/bin/bash';
#------------------------------------------------------------------------------
# Function:		Write error message and exit
# Parameters:	$message
# Input:		None
# Output:		None
# Return:		None
#------------------------------------------------------------------------------
sub error {
	print STDERR "Error: $_[0].\n";
	exit 1;
}

#------------------------------------------------------------------------------
# Function:     Write debug message and exit
# Parameters:   $string $level
# Input:        %HTMLOutput  $Debug=required level  $DEBUGFORCED=required level forced
# Output:		None
# Return:		None
#------------------------------------------------------------------------------
sub debug {
	my $level = $_[1] || 1;
	if ($Debug >= $level) {
		my $debugstring = $_[0];
		if ($ENV{"GATEWAY_INTERFACE"}) { $debugstring =~ s/^ /&nbsp&nbsp /; $debugstring .= "<br />"; }
		print localtime(time)." - DEBUG $level - $debugstring\n";
	}
}

#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------
my $LOG_BUFFER = "";
my $log_add = sub {
	my $msg = shift;
	if ( is_utf8($msg) ) {
		$msg = encode_utf8($msg);
	}
	$LOG_BUFFER .= $msg . "\n";
};
$log_add->("=" x 30 . _t("Your log file") . "=" x 30);
$log_add->("");
# Change default value if options are used
my $helpfound=0;my $nowfound=0;
my %confexcluded=();
for (0..@ARGV-1) {
	if ($ARGV[$_] =~ /^-*h/i)     		  	 { $helpfound=1; last; }
	if ($ARGV[$_] =~ /^-*awstatsprog=(.*)/i) { $Awstats="$1"; next; }
	if ($ARGV[$_] =~ /^-*configdir=(.*)/i)   { $DIRCONFIG="$1"; next; }
	if ($ARGV[$_] =~ /^-*config=(.*)/i)      { $SingleDomain="$1"; next; }
	if ($ARGV[$_] =~ /^-*excludeconf=(.*)/i) { @conftoexclude = split(/,/, $1);
	foreach (@conftoexclude) { $confexcluded{"$_"}=1; } next; }
	if ($ARGV[$_] =~ /^-*debug=(\d+)/i)  	 { $Debug=$1; next; }
	if ($ARGV[$_] =~ /^-*lastline=(\d+)/i)   { $LastLine=$1; next; }
	if ($ARGV[$_] =~ /^-*lang=([a-z-]+)/i)   { $Lang=$1; next; }
	if ($ARGV[$_] =~ /^now/i)     		  	 { $nowfound=1; next; }
}
my $term_lang = I18N::detect_terminal_language();
my $use_lang  = $Lang || $term_lang || 'en-us';
I18N::Read_Language_Data($use_lang);

# Show usage help
my $DIR; my $PROG; my $Extension;
($DIR=$0) =~ s/([^\/\\]*)$//; ($PROG=$1) =~ s/\.([^\.]*)$//; $Extension=$1;
if (!$nowfound || $helpfound || !@ARGV) {
	my $term_lang = detect_terminal_language();
	$Lang = $term_lang || 'en-us';
	binmode(STDOUT, ':utf8');
	Read_Language_Data($Lang);
	my $title        = sprintf( _t("AWStats Batch Updater %s"), $VERSION );
	my $copyright1   = _t("Copyright (c) Laurent Destailleur");
	my $copyright2   = _t("Licensed under GNU General Public License");
	my $description  = _t("DESCRIPTION");
	my $desc1        = _t("awstats_updateall automatically updates all AWStats config files found");
	my $desc2        = sprintf( _t("in a specified directory (default: %s)."), $DIRCONFIG );
	my $desc3        = _t("This is useful for setting up scheduled cron jobs.");
	my $desc4        = _t("Output terminal display text and log records in your specified language");
	my $m_log        = _t("Log file: %s");
	my $usage        = _t("USAGE");
	my $options      = _t("OPTIONS");
	my $examples     = _t("EXAMPLES");
	my $quickstart   = _t("QUICK START");
	my $periodic     = _t("PERIODIC TASK");
	my $content      = _t("Content:");
	my $example      = _t("Example:");

	print "===========================================================================\n";
	print "  $title\n";
	print "  $copyright1\n";
	print "  $copyright2\n";
	print "===========================================================================\n";
	print "\n";
	print "  $description\n";
	print "  ------------------------------------------------------------------------\n";
	print "  $desc1\n";
	print "  $desc2\n";
	print "  $desc3\n";
	print "\n";
	print "  $usage\n";
	print "  ------------------------------------------------------------------------\n";
	print sprintf( "  %s.%s now [OPTIONS]\n", $PROG, $Extension );
	print "\n";
	print "  $options\n";
	print "  ------------------------------------------------------------------------\n";
	print "  " . _t("-awstatsprog=PATH    Path to awstats.pl (auto-detected if omitted)") . "\n";
	print "  " . _t("-config=DOMAIN       Update only the specified domain") . "\n";
	print "  " . _t("-configdir=DIR       Directory containing config files (default: /etc/awstats)") . "\n";
	print "  " . _t("-excludeconf=CONF    Exclude configs by name (comma-separated)") . "\n";
	print "  " . _t("-lang=LL             Language for output (en-ca, en-gb, en-us, zh-cn, zh-tw, de, fr, etc.)") . "\n";
	print "  " . _t("-debug=N             Enable debug output (higher N = more verbose)") . "\n";
	print "  " . _t("-lastline=TIMESTAMP  Set LastLine value for all updates") . "\n";
	print "  " . _t("-h, -help            Show this help message") . "\n";
	print "\n";
	print "  $examples\n";
	print "  ------------------------------------------------------------------------\n";
	print "  # " . _t("Update all sites") . "\n";
	print "  awstats-update now\n";
	print "\n";
	print "  # " . _t("Generate data file comments in your preferred language") . "\n";
	print "  $example awstats-update now -lang=ja\n";
	print "\n";
	print "  # " . _t("Update only one specific site") . "\n";
	print "  awstats-update now -config=example.com\n";
	print "\n";
	print "  # " . _t("Update all sites with a custom AWStats path (e.g., when using virtual hosts or a custom awstats.pl location)") . "\n";
	print "  awstats-update now -awstatsprog=/usr/local/bin/awstats.pl\n";
	print "\n";
	print "  # " . _t("Update all sites except awstats.example.com.conf") . "\n";
	print "  awstats-update now -excludeconf=example.com\n";
	print "\n";
	print "  # " . _t("Use custom config directory") . "\n";
	print "  awstats-update now -configdir=/etc/awstats\n";
	print "\n";
	print "  $quickstart\n";
	print "  ------------------------------------------------------------------------\n";
	print "  " . _t("The 'awstats-update' wrapper is already installed.") . "\n";
	print "  " . _t("Simply run:") . "\n";
	print "\n";
	print "    awstats-update now                       # " . _t("Update all sites") . "\n";
	print "\n";
	print "    awstats-update now -lang=LL\n";
	print "      #  $desc4  " . _t("Update all sites") . "\n";
	print "\n";
	print "    awstats-update now -config=example.com   # " . _t("Update single site") . "\n";
	print "\n";
	print "    awstats-update now -config=example.com -lang=LL\n";
	print "      # $desc4\n";
	print "      # " . sprintf( $m_log, $LOGFILE ) . "\n";
	print "\n";
	print "    awstats-update -h                        # " . _t("Show help") . "\n";
	print "\n";
	print "  " . _t("No need to type the full path to awstats_updateall.pl.") . "\n";
	print "\n";
	if (!-x "/usr/local/bin/awstats-update") {
		print "  " . _t("WRAPPER COMMAND (Optional)") . "\n";
		print "  ------------------------------------------------------------------------\n";
		print "  " . sprintf(_t("To run %s without specifying the full path."), "$PROG.$Extension") . "\n";
		print "  " . sprintf(_t("Create a wrapper script in %s:"), "/usr/local/bin") . "\n";
		print "  " . _t("Copy and run the following wrapper command in your terminal:") . "\n";
		print "\n";
		print "sudo tee /usr/local/bin/awstats-update << 'EOF'\n";
		print "#!$bash_path\n";
		print "# /usr/local/bin/awstats-update - " . sprintf(_t("Wrapper for %s"), "awstats_updateall.pl") . "\n";
		print "exec " . ($^O =~ /freebsd/i ? "/usr/local/share" : "/usr/share") . "/awstats/tools/awstats_updateall.pl \"\$@\"\n";
		print "EOF\n";
		print "\n";
		print "  ------------------------------------------------------------------------\n";
		print "  " . _t("Then make it executable:") . "\n";
		print "\n";
		print "    sudo chmod +x /usr/local/bin/awstats-update\n";
		print "\n";
		print "  " . _t("You can now run the update using the following command:") . "\n";
		print "\n";
		print "    awstats-update now\n";
		print "\n";
	}
	print "  $periodic\n";
	print "  ------------------------------------------------------------------------\n";
	if ($^O =~ /freebsd/i) {
		print "  " . _t("Daily update script:") . " /usr/local/etc/periodic/daily/awstats-update\n";
		print "\n";
		print "  $content\n";
		system("cat /usr/local/etc/periodic/daily/awstats-update 2>/dev/null || echo '  (not found)'");
		print "\n";
	} else {
		print "  " . _t("Cron job:") . " /etc/cron.d/awstats-update\n";
		print "\n";
		print "  $content\n";
		system("cat /etc/cron.d/awstats-update 2>/dev/null || echo '  (not found)'");
		print "\n";
	}
	print "===========================================================================\n";
	exit 0;
}

debug("Scan directory $DIRCONFIG");

# Scan directory $DIRCONFIG
opendir(DIR, $DIRCONFIG) || do {
	$log_add->("ERROR: Can't scan directory $DIRCONFIG");
	log_run($LOG_BUFFER, $LOGFILE, $LOGKEEP);
	error("Can't scan directory $DIRCONFIG");
};
my @filesindir = grep { /^awstats\.(.*)conf$/ } sort readdir(DIR);
closedir(DIR);

debug("List of files found :".join(",",@filesindir));

# Build file list
my @files=();
if ($SingleDomain) {
	my $target_file = "awstats.$SingleDomain.conf";
	if (grep { $_ eq $target_file } @filesindir) {
		push @files, $target_file;
		my $msg1 = sprintf( _t("Updating specified site: %s"), $SingleDomain ) . "\n";
		utf8::encode($msg1);
		print $msg1;
	} else {
		my $msg_err = sprintf( _t("Directory '%s' does not contain a config file for domain '%s'"), $DIRCONFIG, $target_file );
		utf8::encode($msg_err);
		$log_add->($msg_err);
		log_run($LOG_BUFFER, $LOGFILE, $LOGKEEP);
		error($msg_err);
	}
} else {
	foreach my $file (@filesindir) {
		if ($confexcluded{$file}) { next; }
		if ($file =~ /^awstats\.(.*)conf$/) {
			my $conf=$1; next if !$conf; $conf =~ s/\.$//;
			if ($conf eq 'model') { next; }
			if ($conf eq 'default') { next; }
			if ($confexcluded{$conf}) { next; }
		}
		push @files, $file;
	}
}
debug("List of files qualified :".join(",",@files));

# Run update process for each config file found
if (@files) {
	# Check if AWSTATS prog is found
	my $AwstatsFound = 0;
	if ($Awstats && $Awstats ne 'awstats.pl' && -s $Awstats) {
		$AwstatsFound = 1;
	} else {
		foreach my $path (@possible_paths) {
			if (-s $path) {
				$Awstats = $path;
				$AwstatsFound = 1;
				last;
			}
		}
	}

	if (! $AwstatsFound) {
		$log_add->("ERROR: Can't find AWStats program ('$Awstats')");
		log_run($LOG_BUFFER, $LOGFILE, $LOGKEEP);
		error("Can't find AWStats program ('$Awstats').\nUse -awstatsprog option to solve this");
		exit 1;
	}
	# Define AwstatsDir and AwstatsProg
	($AwstatsDir=$Awstats) =~ s/([^\/\\]+)$//; $AwstatsProg=$1;
	$AwstatsDir||='.'; $AwstatsDir =~ s/([^\/\\])[\\\/]+$/$1/;
	debug("AwstatsDir=$AwstatsDir");
	debug("AwstatsProg=$AwstatsProg");

	foreach (@files) {
		if ($_ =~ /^awstats\.(.*)conf$/) {
			my $domain = $1||"default"; $domain =~ s/\.$//;
			if ($SingleDomain && $domain ne $SingleDomain) {
				next;
			}
			my $command="\"$AwstatsDir/$AwstatsProg\" -update -config=$domain";
			$command.=" -configdir=\"$DIRCONFIG\"";
			if ($LastLine) 
			{
				$command.=" -lastline=$LastLine";
			}
			if ($Lang) {
				$command.=" -lang=$Lang";
			}
			# Run command line
			my $msg2 = sprintf( _t("Updating the site %s. Update command: '%s'"), $domain, $command ) . "\n";
			utf8::encode($msg2);
			print $msg2;
			$| = 1;
			my $msg3 = "  " . _t("Updating data, please wait");
			utf8::encode($msg3);
			my $use_ansi = 1;
			if ($^O eq 'MSWin32') {
				$use_ansi = ($ENV{WT_SESSION} || $ENV{ConEmuANSI} || $ENV{ANSICON}) ? 1 : 0;
			}

			my $start    = time;
			my $expected = 200;
			my $pid      = open(my $fh, '-|', "$command 2>&1");
			my $sel      = IO::Select->new($fh);
			my $output   = '';
			my $last_pct = -1;
			my $last_now = -1;
			while (1) {
				if ($sel->can_read(0.5)) {
					my $line = <$fh>;
					if (defined $line) {
						$output .= $line;
					} else {
						last;
					}
				}
				my $now = time - $start;
				my $pct = int($now / $expected * 100);
				$pct = 99 if $pct > 99;

				if ($pct != $last_pct || $now != $last_now) {
					my $bar_len = 20;
					my $filled  = int($bar_len * $pct / 100);
					my $bar     = '=' x $filled . '>' . ' ' x ($bar_len - $filled - 1);
					if ($use_ansi) {
						print "\033[2K\r$msg3 [$bar] $pct%  (${now}s)";
					} else {
						print "\r$msg3 [$bar] $pct%  (${now}s)";
					}
					$last_pct = $pct;
					$last_now = $now;
				}
			}
			close($fh);
			my $elapsed = time - $start;
			my $bar_len = 20;
			my $bar     = '=' x $bar_len;
			if ($use_ansi) {
				print "\033[2K\r$msg3 [$bar] 100%  (${elapsed}s)\n";
			} else {
				print "\r$msg3 [$bar] 100%  (${elapsed}s)\n";
			}
			my $msg4 = sprintf( _t("done (%s seconds)"), $elapsed ) . "\n";
			utf8::encode($msg4);
			print $msg4;
			print "$output\n";
			$log_add->("$output");
		}
	}
} else {
	my $msg5 = sprintf( _t("No AWStats config file for any site found in %s"), $DIRCONFIG ) . "\n";
	utf8::encode($msg5);
	print $msg5;
	$log_add->($msg5);
}

$log_add->("");
$log_add->("=" x 17 . " " . _t("Last visit") . ": " . format_time() . " " . "=" x 17);
if ( !-d $LOGDIR ) {
	mkdir $LOGDIR, 0755;
}
log_run($LOG_BUFFER, $LOGFILE, $LOGKEEP);

0;