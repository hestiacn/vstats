# 📋 AWStats Release Changelog

*Based on official documentation, SourceForge records, and historical author materials*

⚠️ **AWStats 8.0 will be the last version maintained by the original author (Laurent Destailleur). Subsequent versions are maintained by the community.**

## 🚀 8.x Series (2024-latest)

### 8.1 - 2026-03-10
- 📱 HTML5 standard with responsive design support
- 🌙 New dark/light theme toggle feature
- 🧭 New navigation menu allowing site deployers to view official documentation in their native language
- 📖 New documentation viewer (iframe) - click menu links to view documentation within the page, with close button support
- ♻️ Refactored English hard-coded documentation, users can read docs according to language preference, translated using [deepseek](https://www.deepseek.com) based on official documentation. Report translation errors to [hestiacn@tuta.io](mailto:hestiacn@tuta.io)
- 🚀 Language files migrated from GBK-encoded .txt format to modern UTF-8 .po format, based on gettext standard for easier maintenance and translation
- 🛡️ Default security headers added: X-Content-Type-Options, X-Frame-Options, Referrer-Policy
- 🌐 Auto-enable geoipfree plugin if no GeoIP plugins are loaded
- ⬆️ Minimum Perl version requirement raised from 5.007 to 5.020
- 🔧 Enabled use warnings and use utf8, unified UTF-8 encoding output
- 🎨 CSS variables for theme colors with one-click switching
- 📊 Modernized table styling: rounded corners, hover effects
- 😊 Icons全面 replaced with emoji
- ⚡ Optimized DNS caching mechanism, reducing duplicate resolution
- 🔄 Improved try/catch exception handling to avoid JSON parsing crashes
- 📡 Enhanced IPv6 and CloudFlare real IP header support
- 📚 Help information updated, added examples for generating Chinese reports
- 📋 New version changelog page awstats_changelog.html with categorized version display
- 🐛 Fixed compilation errors from undeclared variables $lang and $dir_attr
- 🔨 Corrected Try::Tiny syntax errors ensuring proper try/catch parsing
- 📐 Independently controlled first column width for IP and robot lists to prevent layout distortion
- 🚪 Documentation viewer no longer occupies blank area by default, appears after link click with close button
- 🌏 Fixed language loading logic, correctly falls back to English in auto mode
- 📅 Copyright year auto-updates based on current year
- 🧹 Removed obsolete PrintCLIHelp, unified with print_help

### 8.0 - 2025-08-26
- 👋 *This is the last version maintained by the original developer (Laurent Destailleur)*
- 🔄 Improved CSS stylesheets
- 📋 Updated robots.pm database
- 🌍 Fixed #248
- 📖 Migrated Traditional Chinese translation to UTF-8 encoding
- 🌳 Sorting tree: check key existence regardless of value
- 📋 Added JSON log format support
- 🔧 Fixed NotPageList default settings
- 📋 Added request time reporting
- 📋 Fixed broken links in documentation
- 🗑️ Removed native Android and native iOS/OSX browser User Agents from robots.pm
- 🔧 Fixed GPTBot recognition error in robots.pm
- 🔧 Fixed encoding issues in Ukrainian translation

---

## 📦 7.x Series (2011-2023)

### 7.9 - 2023-01-17
- 🪟 Added Windows 11 and Android 13 OS detection
- 🇭🇺 Updated Hungarian translation and migrated to UTF-8
- 🛡️ Fixed cross-site scripting vulnerability (CVE-2020-35176)
- 🔧 Replaced hardcoded text with $Message variables (month, day, hour)
- 📱 Added Android 11/12, macOS 11/12 detection
- 🇩🇪 Updated German translation
- 🔄 Improved newline replacement logic, supporting both HTML and XHTML
- 🤖 Added new robots and mobile browsers, fixed errors in robots.pm
- 📂 Look for configuration only in dedicated awstats directory
- 📧 Handle SRS email addresses
- 🔒 Fixed #195/CVE-2020-35176
- 🌍 Fixed geoip2_country plugin issues
- 🖥️ Added HaikuOS and Safari-based WebPositive browser support
- 🔨 Added missing td tags
- 🇹🇯 Added Tajik language support

### 7.8 - 2020-04-30
- 🗄️ Added DatabaseBreak mode selection: month, day, hour
- 📋 Updated HTTP status codes
- 📁 Added more file types
- 📖 Updated README.md
- 🌍 Fixed geoip2 formatting issues
- 🔍 Fixed incorrect entries in search_engines.pm
- 🪟 Fixed geoip2 plugin on Windows
- 🤖 Updated robots.pm with new bots: PiplBot, um-IC/um-LN, arcemedia, bit.ly, bidswitchbot, bnf.fr_bot, contxbot, flamingo, getintent, laserlikebot, mappy, mojeek, serendeputy, trendiction, yak, zoominfobot
- 🔨 Fixed #104
- 📝 Improved Markdown readability
- 📅 Updated copyright year
- 🔒 Switched to https links
- 🔗 Fixed Perl download links
- ⏱️ Added %time6 tag for certain IIS log formats
- 📊 Fixed geoip2 table formatting errors
- 🍏 Added macOS DMG and PKG file support
- 🖥️ Fixed browser detection for HTTP 206 status codes
- 💻 Added macOS 10.13/10.14 support, improved icon compression
- 📈 Using top 5 as chart baseline
- 🧹 Cleaned up geoip2 and geoip2 city modules: proper DNS name conversion, public IP only queries, HTML escaped output, code improvements
- 🗜️ Lossless PNG compression (~33%)
- 🤖 Added robot: The Knowledge AI
- 🔄 Fixed RobotsSearchIDOrder_listx record count inconsistency
- ⚡ Optimized OptimizeArray function
- ⏰ Added UptimeRobot
- ⚙️ Fixed syntax errors in configuration files
- 📏 Ignored search phrases exceeding 80 characters
- 🔧 Fixed 404 details page not updating
- 🔤 Decoded RFC 3986 unreserved characters
- 🔨 Fixed #80
- ⚠️ Disabled nested include warnings for Perl > 5.6
- 🌐 Updated domains.pm
- 🔍 Fixed two invalid entries in search_engines.pm
- 💾 TB unit formatting
- ➗ Fixed division by zero error
- 🔨 Fixed #79
- 🛠️ Improved error handling in awstats_buildstaticpages.pl
- 🔨 Fixed #90
- 🚫 Excluded private IP addresses (GeoIP2::Reader unsupported)
- 🧹 Clear only saved section data
- 🏙️ Improved city plugin functionality
- 📊 Fixed ShowHost section issues
- 🌍 Initial GeoIP2 City query implementation
- 🇮🇱 Updated Hebrew language file
- 🔍 Improved Yahoo detection
- 📱 Added device pixel ratio to awstats_misc_tracker.js
- 🤖 Added 37 new robots based on 7.7 robots.pm
- 🔄 Moved oBot entry to avoid misidentification
- 🏁 Missing Sint Maarten flag
- 🌍 Fixed #76 - incorrect country names
- 📝 Fixed UTF BOM files
- 🛡️ Fixed vulnerabilities reported by cPanel security team
- 🧪 Added more tests

### 7.7 - 2018-01-07
- 🛡️ Security fix: CVE-2017-1000501
- 🔒 Security fix: Missing parameter sanitization
- 🔧 Fixed LogFormat=4 for URLs containing spaces
- 🪟 Fixed window.opener vulnerability for external referrer links
- 📝 Added methodurlprot log format definition
- 🔄 Added dynamic DNS lookup
- 🌐 Fixed Edge support

### 7.6 - 2016-12-07
- 🛡️ Security fix: DirLang parameter doesn't allow |
- 🔒 Security fix: Stricter AWSTATS_ENABLE_CONFIG_DIR usage rules
- 🤖 Updated robots database
- 💻 Fixed OS database
- 📚 Updated/fixed documentation
- 🏁 Added missing el country flag
- 📁 Partial support for pure-ftpd statistics format
- 🍏 Added macOS Sierra support
- 🔤 Added web fonts to default NotPageList, support for GPX and JSON files

### 7.5 - 2016-04-29
- 🐪 Perl 5.22 compatibility
- 🌐 Edge browser version detection support
- 🤖 Updated robots database
- 🔤 Added eot/woff/woff2 to mime.pm as fonts
- 🖼️ Added .svgz to image list
- 🚫 Excluded groups.google from search engines
- ⏱️ Added %time5 tag for ISO time format with timezone
- 🔄 Added DynamicDNSLookup option for DNS lookup at output time instead of during log analysis
- 📊 Increased MaxRowsInHTMLOutput default value

### 7.4 - 2015-11-11
- 🌍 Added geoip6 plugin supporting IPv4 and IPv6
- ☁️ Amazon AWS log file support (using %time5 tag)
- 🔧 Fixed permission issues in certain .pl scripts
- 🔨 Fixed #205: GetResolvedIP_ipv6 not removing trailing dot
- ⚠️ Fixed #496: Tool scripts should output warnings and errors to STDERR
- 🔗 Fixed #919: Referrers not being tracked
- 📝 Fixed #921: geoip_generator.pl help text error
- 🐛 Fixed #909: awstats_buildstaticpages.pl excessive debug output
- 💥 Fixed #680: Invalid data passed to Time::Local causing global destruction
- 🛡️ Fixed CVE-2006-2237

### 7.3 - 2015-11-11
- 📌 Added command line option -version
- 🌍 Improved error management in geoip modules
- 🗄️ Updated domains, robots, and search engines databases
- 📱 #877: AWStats supports Windows 8 and iOS
- 🪟 Detects IE11 and Windows 8.1
- 🔗 Fixed static linking error when using builddate option
- 🌐 Restored Opera browser version detection
- 🏙️ #838: GeoIP Cities page not working
- 🖼️ Added missing icons
- 🔒 #881: Avoid http/https mixed warnings in graphgooglechartapi module
- 🔧 #918: Use $MinHit{'Host'} instead of $MinHit{'Login'} in HTMLShowLogins
- 📦 Migrated version system to SourceForge Git

### 7.2 - 2013-07-09
- ⚖️ License upgraded to GPL v3+
- 📚 Documentation updated
- ☁️ modCloudFlareIIS support
- 🖥️ Fixed layout issue for Webmin 1.53
- 🔗 Updated broken links to maxmind

### 7.1.1 - 2013-03-08
- 🪟 Added Windows 8 detection
- ⏱️ Support for ISO date time with %time5
- 🐪 Fixed Perl 5.14 issues

### 7.1 - 2012-12-20
- 🌍 Updated translations
- 🌐 Updated browser list
- 🔧 Added nginx configuration example
- 📦 Added some Debian package patches
- 📛 Documentation domain renamed to awstats.org
- 🔑 awredir.pl can be used without md5 key parameter
- 📊 awstats_buildstaticpages.pl supports databasebreak option
- 🔗 Added rel=nofollow links
- 🧩 Added AddLinkToExternalCGIWrapper option
- 🛡️ Fixed security issue in awredir.pl
- 🇬🇧 Fixed uk case issue in googlechart api
- 🐪 Fixed compatibility with latest Perl versions

### 7.0 - 2011-01-08
- 🪟 Windows 7 detection
- 🔢 Number formatting according to language
- 📁 More MIME types
- 🌍 Added geoip_asn_maxmind plugin
- 🗺️ GeoIP Maxmind city plugin supports overlay files
- 📊 Added graphgooglechartapi using online Google Chart API for graphs
- 🗺️ Country map display capability
- 🧹 Code cleanup and optimization
- 🚫 Added parameter to ignore missing log files
- 🤖 Updated robots database
- 📥 Added download tracking feature
- 🧩 WrapperScript parameter supports wrappers with arguments
- 🏢 AWStats usage in Dolibarr ERP/CRM plugin
- 🖥️ Fixed Webmin module compatibility with newer versions
- 🛡️ Security fix (LoadPlugin directory traversal)
- 🔒 Security fix (Restricted config directory access)

---

## ⚙️ 6.x Series (2004-2009)

### 6.95 - 2009-10-28
- 🛡️ Fixed awredir.pl security issue, added security key by default
- 🧹 Enhanced parameter sanitization
- 📋 Added configuration filename in data file header
- 🌐 Added version details for Chrome, Opera, Safari, Konqueror browsers
- 📱 Added AdobeAir detection
- 🤖 Major updates to browser, robot, and search engine databases (including Bing)
- 🔍 Significantly improved robot detection
- 🇫🇷 Added Breton language
- 🖥️ Improved Safari version detection
- 🗺️ Added subpages for geoip maxmind modules
- 🇵🇱 Fixed typos in Polish language file
- ⚠️ Fixed warnings in geoipfree
- 🔧 Fixed robot detection issues

### 6.9 - 2008-12-28
- 📧 maillogconvert.pl supports DSN, avoids duplicate counting
- 📊 logresolvemerge.pl supports FreeRADIUS logs
- 🛑 Added stoponfirsteof option
- 🔄 Added host_proxy tag support
- ⭐ Renamed to "Add to favourites"
- 🤖 Updated robot and search engine databases (added Chrome, improved Vista, WII detection, etc.)
- 🌍 Updated language files
- 🗺️ Fixed maxmind city, org, and isp plugins
- 🛡️ Fixed multiple security issues
- 🖼️ Added missing icons
- 🐪 *Requires Perl 5.007 or higher*

### 6.8 - 2008-07-20
- 👥 Added OnlyUsers option
- 📡 RPC request tracking support
- 📝 HTMLHeadSection supports newlines
- 🤖 Added MetaRobot option
- 🔍 Significantly improved robot detection
- 🪟 Improved Windows OS detection
- ➕ Added HOSTINLOG condition in extra sections
- 📄 Fixed XML output issues
- 🐛 Fixed bugs in awstats_configure.pl script

### 6.7 - 2007-07-07
- 📅 Full -day option support, building different reports for each day
- 🏷️ Added virtualenamequot tag
- 🚫 Added NotPageList option
- 🌐 Added .jobs and .mobi domains
- 🐛 Fixed minor bugs in awstats_configure.pl
- 🌍 Updated language files
- 🌐 Updated browser database

### 6.6 - 2006-12-24
- 🐪 All geoip plugins support PurePerl version
- ➕ vhost support in extra sections
- 🌐 AllowAccessFromWebToFollowingIPAddresses parameter supports IPv6
- 🗂️ Added svn series to browser detection
- 🌍 IE7 support
- 🔇 Removed some Perl warnings
- 🛡️ Fixed XSS attack vulnerabilities
- 🌏 Updated language files
- 🌐 Updated browser database

### 6.5 - 2005-12-24
- ⚡ 30x speed improvement when merging large log files with logresolvemerge.pl
- 🐧 Added Linux and BSD distribution detection
- 🚫 Added SkipReferrersBlackList option to exclude spam referrers
- 📰 Added RSS feed aggregators/readers to robot database
- 🗄️ Added databasebreak option
- 🗺️ geoip_cities plugin reports region when data available
- 📱 LevelForBrowsersDetection accepts allphones value
- 🔄 LogFormat=2 can dynamically detect log format changes
- 📋 Added SectionsToBeSaved option
- 🌐 Added Epiphany browser detection
- 🔗 awredir supports ftp, https, and other protocols
- 📧 Fixed Gmail click counting issues
- 🔨 Fixed multiple bugs and XSS issues
- 🛡️ Fixed XSS issues

### 6.4 - 2005-02-25
- 📊 Added ShowSummary option
- 🌍 Added column in host report when GeoIP plugin enabled
- 🔄 LogFormat=2 auto-detects log format changes
- 🔓 Fixed security vulnerability (log file content reading possible)
- 🛡️ Fixed potential DoS attack vulnerability
- 🎥 Fixed media server analysis errors
- 🪟 Fixed configdir option issues on Windows servers
- 🏁 Added missing Basque flag icon

### 6.3 - 2005-02-25
- 🌍 Added geoip_isp_maxmind and geoip_org_maxmind plugins
- 🦊 Display Firefox version details
- 🔍 Support for detecting search engines storing keywords in URLs
- 🔓 Removed two security vulnerabilities
- 🗺️ Fixed geoip_city_maxmind plugin issues
- 📁 Fixed file type table display
- 🌐 Fixed corrupted translation entries
- 📄 Fixed XML parsing errors

### 6.2 - 2004-11-06
- ⚙️ Added -excludeconf option to awstats_updateall.pl
- ➕ Allow plugins to add entries in menu
- 🔄 Allow plugins to compile data during update process
- 🗺️ Added geoip_region_maxmind and geoip_city_maxmind plugins
- 📧 maillogconvert.pl supports postfix 2.1
- ⚡ Minor speed improvement
- 🚫 Statistics for browsers with JavaScript disabled
- 🏷️ Support for %extraX tags in log format
- 📁 PUT method support when analyzing FTP logs
- 🔨 Fixed multiple bugs

### 6.1 - 2004-05-15
- 📄 BuildHistoryFormat supports XML format
- ⏱️ Added %time4 tag for Unix timestamp support
- 🦊 Added Firefox to browser database
- 🔗 Added IncludeInternalLinksInOriginSection parameter
- 📑 PDF detection supports PDF 6
- 📧 maillogconvert.pl auto-adjusts year
- 💡 Added tooltips for mail reports
- ❌ Added failed mail count in summary
- 🔤 AllowAccessFromWebToFollowingAuthenticatedUsers no longer case sensitive
- 🌐 Added Camino browser detection
- 🔨 Fixed multiple bugs

### 6.0 - 2004-01-25
- ⚡ 10-20% speed improvement
- 🐛 Added worm reports
- 📄 XML output support
- 🔤 Added decodeUTFkeys plugin
- ⚙️ Added configure.pl script
- 🔄 Code rewrite for better understanding and maintenance
- 🔍 New search engine database supporting multiple match IDs
- ➕ Support for UA and HOST fields in ExtraSection
- 🔁 Support for right-to-left languages
- 📊 Added file type percentage column
- 🔨 Fixed multiple bugs

---

## 🔧 5.x Series (2002-2003)

### 5.9 - 2003-09-22
- 🖥️ Webmin module updated to 1.1
- 📅 Added AllowFullYearView parameter
- 🌍 Year entries display localized text in combo box
- 📧 maillogconvert.pl supports some exchange formats
- ⚙️ awstats_buildstaticpages.pl -noloadplugin option accepts comma-separated list
- 📨 Error logging support for qmail logs
- 🔨 Fixed multiple bugs

### 5.8 - 2003-09-16
- 🔧 Fixed mod_deflate compressed reports
- 📊 Fixed column count error for "others" row in host chart
- 🔍 Fixed parsing issues with uabracket and refererquot
- 🖥️ Added Webmin module
- ➕ Enhanced Extra functionality with ExtraSectionFirstColumnFormatX parameters
- 🏷️ Added %lognamequot tag
- 👥 Added OnlyUserAgents parameter
- 🛠️ Added awredir.pl tool
- 📊 Added cluster reports

### 5.7 - 2003-08-23
- 📝 Added rawlog plugin
- 🔍 Added dynamic exclusion filters in full list report pages
- 📧 Added maillogconvert.pl for mail log analysis
- ➕ Added -addfilenum option to logresolvemerge.pl
- ⏱️ Added -updatefor option to limit rows per update
- 🎥 Darwin streaming server support
- 🔥 Added Firebird browser detection
- 📄 awstats_buildstaticpages.pl can build PDF files
- ⚙️ Improved plugin loading failure handling
- 🏷️ Added LogType parameter

### 5.6 - 2003-06-28
- 🗜️ mod_deflate compressed report support
- 🌐 Improved browser detection
- 🔣 Regex values support for list parameters
- 🎨 StyleSheet parameter fully effective
- 🤖 Added meta tag robots noindex,nofollow
- 📊 Added misc charts reporting browser support for Java, Flash, Real, QuickTime, WMA, PDF
- ⚡ Improved update process, faster
- 🦊 Improved display on Netscape/Mozilla browsers

### 5.5 - 2003-05-25
- 📱 Added screen size reports
- 💻 OS grouping by family with detailed version charts
- 🔍 Improved 404 error management
- 🌍 Added geoipfree plugin
- 👤 Added userinfo plugin
- 📅 Month parameter accepts -month=D format
- ⚡ Optimized code size and HTML output
- 🌐 Added ipv6 plugin
- 📊 Split month summary and month days charts into two independent charts
- 🔗 Added -staticlinksext option
- 📧 QMail support

### 5.4 - 2003-02-23
- 🌍 Lang parameter accepts auto value
- 🎥 Partial realmedia server support
- 🛠️ Added urlaliasbuilder.pl tool
- 🔗 ExtraSection first column supports URLs
- #️⃣ Added URLWithAnchor parameter
- 💡 Tooltip functionality exported as plugin
- ⏱️ Added average time and percentage in visit duration report
- 📦 logresolvemerge.pl can read .gz or .bz2 files
- 📁 Added icons and MIME labels for file type report
- ➕ Added multiple data array parameters
- 🪟 Whois info displayed in centered popup window
- 🎨 Improved browser report appearance

### 5.3 - 2003-01-02
- 📤 Added awstats_exportlib.pl tool
- 🌍 Added full list view for domain/country reports
- 📧 Added full list and last view for mail senders/receivers charts
- ⚡ Added memory cache for GeoIP plugin
- 🔤 Added AuthenticatedUsersNotCaseSensitive parameter
- 🚀 Speed improvement when using ExtraSection
- 🔄 Updated robot, OS, browser, search engine databases
- 🖥️ Added X11 as unknown Unix OS, added Atari OS

### 5.2 - 2002-12-03
- 🔗 Added urlalias plugin
- 🌍 Added geoip plugin
- 📧 postfix mail log support
- 📊 Added total and average rows at bottom of date data arrays
- 🔍 Added dynamic filters in host and referrer pages
- 🚫 Removed Bytes text when value is 0
- 📦 Reduced home page size
- 👥 Added OnlyHosts parameter
- ⚠️ Added ErrorMessages parameter
- 🐛 Added DebugMessages parameter
- 🔣 Added URLQuerySeparators parameter
- 🔒 Added UseHTTPSLinkForUrl parameter
- 🇦🇱 Added Albanian language
- 🇧🇬 Added Bulgarian language
- 🏴󠁧󠁢󠁷󠁬󠁳󠁿 Added Welsh language
- 🇸🇨 Added Seychelles flag

### 5.1 - 2002-10-26
- 📁 Improved FTP log file support
- 📧 Improved mail log file support
- 🎥 Streaming media log analysis (Windows Media Server)
- 📅 Added month and year selection boxes in CGI mode
- 📊 Month and day data values displayed directly below home page charts
- 🔧 ShowxxxStats parameters accept codes to determine displayed columns
- 🚫 Added SkipUserAgents parameter
- 🔤 Added URLNotCaseSensitive parameter
- 🔗 Added URLWithQueryWithoutFollowingParameters parameter
- 🔄 Added URLReferrerWithquery parameter
- 🏷️ Added multiple date tags
- 🛡️ Fixed analysis halt when log files contain binary characters

### 5.0 - 2002-10-06
- 🔄 Complete rewrite of update process and history file read/write code
- 🔄 Compatible with previous versions (3.x or 4.x)
- ⚡ Old history files can be migrated with -migrate command for speed improvement
- 🔧 Fixed errors when using different offset tags
- 🔐 CreateDataDirIfNotExists directory permissions changed from 0666 to 0766
- 🌐 Track detailed browser major/minor versions
- 🤖 Added bandwidth reports for robots and errors
- 📦 DNS cache file support for DNS lookups
- 🧩 Added plugin support and multiple working plugins
- 🖼️ Frame report usage (UseFramesWhenCGI parameter)
- 📉 Reduced global variable count
- 📄 DefaultFile parameter accepts multiple values
- 🤖 Added all robots and last robots full list reports
- 👤 Added all logins and last logins full list reports
- 🚪 Added URL entry and exit full list reports
- 🛡️ Added AllowAccessFromWebToFollowingIPAddresses parameter
- 🔣 Added LogSeparator parameter
- 🔒 Added EnableLockForUpdate parameter
- 🔤 Added DecodeUA parameter
- 🏷️ Added %WY tag

---

## 📊 4.x Series (2002)

### 4.1 - 2002-07-09
- ⌨️ -logfile option usable anywhere in command line, supports spaces in filenames
- 🧠 Fixed memory leak in logresolvemerge.pl
- 📉 Reduced discarded records for non-fully sorted log files
- 🏷️ Added %virtualname tag for sharing same log file across multiple virtual servers
- 🔧 Pipe support in LogFile parameter
- 🔗 Added full list of referrer search engines and referrer pages
- 🔍 Simultaneous keyword and keyphrase reporting
- 🚪 Exit page reporting
- ⏱️ Visit duration reporting
- 📁 Added -dir option to awstats_buildstaticpages.pl

### 4.0 - 2002-04-21
- ⚠️ *Warning: Incompatible with old history files*
- ⚡ Speed improvement, reduced memory usage for large sites
- 🌐 Unresolved IPs now handled like resolved ones
- 🖼️ Added icons in browser charts
- 📋 Custom log formats also support tab delimiters
- 🔒 New security/privacy management methods and parameters
- 🤖 Crawler browsers marked in browser charts
- 📊 Added average file size in page/URL report charts
- ⚙️ Dynamic environment variables usable in configuration files
- 📝 Full keyphrase list viewing
- 🧩 Added WrapperScript parameter
- 📁 Added CreateDirDataIfNotExists parameter
- ✅ Added ValidHTTPCodes parameter
- 📏 Added MaxRowsInHTMLOutput parameter
- 🔗 Added ShowLinksToWhoIs parameter
- 🔗 Added LinksToWhoIs parameter
- 🎨 Added StyleSheet parameter
- 🔗 Added -staticlinks option
- 🛠️ Added common2combined.pl tool
- 🛠️ Added awstats_buildstaticpages.pl tool

---

## 🎨 3.x Series (2001)

### 3.2 - 2001-12-29
- ⚡ 19% speed improvement
- 🔧 Fixed history file corruption issues
- 🛡️ Security fix: Cannot update via URL when AllowToUpdateStatsFromBrowser is off
- 🏷️ Added various tags for dynamic log filenames
- 🚫 Added NotPageList parameter
- 💾 Added KeepBackupOfHistoricFiles option
- 📊 Visit counts visible in day statistics
- 📅 Added day of week statistics
- 📁 Added file type statistics
- 🚪 Added entry page statistics
- 🗜️ Added web compression statistics (mod_gzip)
- 👤 Added authenticated user/login statistics
- 📋 Added parameter to select displayed reports on home page
- 🔗 Added URLWithQuery option
- 🏁 ShowFlagLinks accepts all required flags list
- 🖥️ Standard ISA server log format support
- 🛠️ Added logresolvemerge tool
- 📝 Added HTMLHeadSection parameter
- 🔢 Added NbOfLinesForCorruptedLog parameter

### 3.1 - 2001-09
- ⚡ Significantly improved update speed
- ⚡ Significantly improved statistics viewing speed
- 🧠 Reduced memory usage
- 📂 AWStats searches configuration files in multiple directories
- 📄 NCSA common log file analysis
- 🕒 Last visit lists
- 📊 Full URL score lists
- 📅 Date format selectable by country
- 🌍 Added DirLang parameter
- ⏱️ Added Expires parameter
- 🔗 Added LogoLink parameter
- 🎨 Added color_weekend option
- ⚙️ Added -update and -output options
- 🔍 Added -showsteps option
- 🔧 Fixed OS detection
- 📱 Added WAP browsers to database

### 3.0 - 2001-07-22
- 🎨 New look and feel
- 📅 Added daily page, hit, and byte reports
- 🔄 AWStats can use its own conversion array for reverse DNS lookups
- 🚫 Added SkipDNSLookupFor option
- 📁 Added OnlyFiles option
- 📋 Custom log format support
- ⚡ Default: no update while viewing stats in browser, added immediate update button
- 💡 Tooltips now work in Netscape 6, Opera, etc.
- 🌐 Updated browser database, added audio browsers
- 💻 Updated OS database
- 🤖 Updated robot database
- 🌍 Support for new domains
- 🏁 Added missing flag icons
- 🔧 Rewrote UnescapeURL function
- 📊 Auto-scaling bytes
- 🎨 Fixed style issues
- 🌐 Added new languages

---

## 🔄 2.x Series (2001)

### 2.24 - 2001-03-09
- ⏱️ Dynamic year/month/day/hour inclusion in LogFile parameter
- ⌨️ Month, year, and language selection from command line
- 🔒 https requests correctly reported
- ⚙️ Parameter initialization to avoid mod_perl caching issues
- 🛡️ Fixed parameter checking to avoid XSS attacks
- 🏁 Added multiple country flags
- 🔍 New keyword detection algorithm
- 📝 Added option to report keywords as individual words or full search strings
- 🇬🇷 Added Greek language
- 🇨🇿 Added Czech language
- 🇵🇹 Added Portuguese translation
- ⚡ Faster configuration file parsing
- 🪟 Distinguish between Windows NT and Windows 2000
- 🌐 Added OmniWeb and iCab browsers

### 2.23 - 2001-02-10
- ⚙️ Configuration file usage
- 📁 Old log file processing capability
- 📅 Monthly statistics now working correctly
- 📅 Old years viewable from AWStats report page
- 📂 Working directory selection
- 🗑️ Added PurgeLogFile option
- 📝 awstats.pl can be renamed to awstats.plx and still work
- 🔗 Command-line generated statistics pages have correct links
- 📅 Added links for full year view selection
- 📊 Domain and page reports sorted by pages
- 🔄 Auto-disable completed DNS lookups
- ➕ Custom HTML code can be added at end of awstats
- 🇮🇹 Added Italian language
- 🇩🇪 Added German language
- 🇵🇱 Added Polish language

### 2.1 - 2001-01-01
- 🔄 AWStats treats myserver and www.myserver as identical
- 🔧 Fixed excessively high unique visitor counter
- 📦 Added ArchiveLog parameter
- ❓ Distinguish between unknown browsers and unknown OS
- 🤖 Robot statistics separated from visitors
- 🔍 Improved keyword detection algorithm
- 🕒 Added last connection time per host
- 📋 Added URL list for HTTP 404 errors
- 📊 Added page, hit, and KB statistics
- 🎨 Added colors and links
- 🪟 IIS support
- ⚡ Cleaner, faster code
- 🖼️ Images in .png format
- 🌐 4 languages

---

## 🌟 1.x Series (2000)

### 1.0 - 2000-05-02
- 🎉 First public release on SourceForge (version 1.0)
- 📄 Apache log format support
- 📊 Basic statistics: visits, pages, files

---

## 📜 Early Development Stage (1995-1999)

### 1999 - Pre-open source
- 🚀 Standardized architecture, introduced lang/ dictionary system (initially established GBK/ISO encoding specifications) to adapt to different server environments, final transformation from personal tool to standardized product
- 🔍 Enhanced recognition: Significantly expanded crawler recognition library
- 🎯 Mode fixation: Improved CGI script runtime mode
- 👥 Community testing: Conducted tests among peers, completed code cleanup and documentation based on feedback

### 1998 - Feature Deepening
- ⚙️ High-frequency internal private iterations
- 🔄 Established "incremental update" architecture, introduced intermediate database files to ensure statistics don't consume server real-time resources under big data
- 💻 Added OS, browser type, and HTTP status code recognition capabilities
- 🔌 Leveraged Perl cross-platform capabilities, tested Unix/Linux and Windows environment compatibility

### 1997 - Project Inception
- 🌟 Official documentation recognized starting point, transformation from scattered scripts to analysis engine
- 📊 Established static report generation mode, first output analysis results as HTML pages with graphical interface
- 🔍 Began building search engine and robot recognition rule libraries
- 📈 Benefited from Common Log Format standardization, scripts began to have generalization foundation

### 1995-1996 - Concept Germination
- 💡 Responded to access.log analysis needs after Apache HTTP Server became popular
- 🧪 No formal project name yet, experimental code snippets by author Laurent Destailleur
- 🐪 Written based on Perl 5, using complex hash structures for basic regex matching, used for total hits and simple file type filtering
- 📊 Only used for internal traffic monitoring on author's personal website (cdr)