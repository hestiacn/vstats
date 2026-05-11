# AWStats 8.1 - Advanced Website Statistics Tool (Community Edition)

<p align="center">
  <img src="docs/images/screenshot.png" alt="AWStats Dashboard Preview" width="800">
</p>

<p align="center">
  <a href="https://www.gnu.org/licenses/gpl-3.0.html#license-text"><img src="https://img.shields.io/badge/License-GPL%20v3-blue.svg" alt="License"></a>
  <a href="https://www.perl.org/"><img src="https://img.shields.io/badge/Perl-5.20%2B-brightgreen.svg" alt="Perl Version"></a>
  <br><br>
  <a href="https://github.com/hestiacn/vstats/releases/latest"><img src="https://img.shields.io/github/v/release/hestiacn/vstats?style=for-the-badge&logo=github&label=Latest%20Release&color=blue" alt="Latest Release"></a>
  <br><br>
  <a href="docs/CHANGELOG.md"><img src="https://img.shields.io/badge/📝_Changelog-English_Version-0891b2?style=for-the-badge&logo=markdown&logoColor=white" alt="Changelog"></a>
</p>

> **🎉 This is the first major community release of vstats!** A comprehensive modernization of the legendary `AWStats` (1997-2025). We've dusted it off and made it shine, ready to face the challenges of the next 25 years!

The original `AWStats`, after 25 years of maintenance, was archived in November 2025. This project is a comprehensive refactoring and enhancement of the original, continuously maintained by the [hestiacn](https://github.com/hestiacn/vstats) community.

| Language | Readme |
|:---:|:---:|
| 🇰🇷 한국어 | [README.ko.md](README.ko.md) |
| 🇬🇧 English | [README.md](README.md) |
| 🇨🇳 简体中文 | [README.zh-CN.md](README.zh_CN.md) |
| 🇹🇼 繁體中文 | [README.zh-TW.md](README-zh_TW.md) |
| 🇫🇷 Français | [README.fr.md](README.fr.md) |
| 🇷🇺 Русский | [README.ru.md](README.ru.md) |
| 🇸🇦 العربية | [README.ar.md](README.ar.md) |
| 🇯🇵 日本語 | [README.ja.md](README.ja.md) |
| 🇳🇱 Nederlands | [README.nl.md](README.nl.md) |
---

## 🚀 Release Highlights

### 1. Native UTF-8 Support (Say Goodbye to Encoding Issues)

Say goodbye to troublesome encoding problems! All internal logic and output now fully support UTF-8 encoding. Chinese, Japanese, Arabic, and other special characters are now displayed perfectly.

### 2. Global "Soulful" Localization (73 Languages)

- Switched the entire translation system from numeric indices to semantic keys (`_t('key')`)
- Added/updated 73 languages (including Cypriot, Brazilian Portuguese, etc.)
- Added unique humorous "hilarious" descriptions for 24-hour statistics - a little surprise for system administrators working at 4 AM! ☕️

### 3. Modern User Interface & Responsive Design

- **Dark/Light Mode**: One-click toggle between light and dark themes
- **Pure CSS Charts**: Old PNG images replaced with modern CSS charts featuring `border-radius`
- **Emoji Integration**: Visual data representation using Emoji for a modern visual experience

### 4. Performance & Code Optimization

- Major cleanup of Perl code to improve performance in modern CGI environments
- Improved detection of modern browsers and bots (updated for 2026)

### 5. Multi-Calendar Support with 13-Month 🗓️

Supports **13 calendar systems** including Japanese era, Buddhist calendar, Republic of China calendar, Sexagenary cycle, Islamic calendar, Persian calendar, etc. (including Ethiopian and Hebrew calendars with **13 months**), automatically matching the site language.

> 📌 **Ethiopian calendar**: First 12 months have 30 days each, the 13th month has 6 days in leap years and 5 days in common years.
> 📌 **Hebrew calendar**: 7 leap years in a 19-year cycle, adding Adar I (30 days) in leap years, forming 13 months.

### 6. Custom Branding Display 🏷️

> **For Hosting Providers and Enterprise Users**

Now supports displaying custom brand information at the top of `AWStats` pages, including **Logo** and **Brand Name**.

**Features**:
- 📍 Brand area automatically displays when `/stats/logo.svg` exists
- 🔗 Supports custom brand link (Logo click redirect)
- 🏷️ Supports any brand name (English recommended for multi-language compatibility), automatically concatenated as **`BrandName + " Server Management Panel"`**

**Use Case Examples**:
| Type | Examples |
|:---:|:---:|
| 🐧 Linux Distributions | `RHEL`, `Debian`, `Ubuntu`, `CentOS`, `Arch Linux`, `Fedora`, `Rocky Linux` |
| 🖥️ Operating Systems | `macOS`, `Windows`, `FreeBSD` |
| ☁️ Cloud Providers | `Aliyun`, `Tencent`, `AWS`, `Azure`, `Google Cloud` |

**Configuration Example**:
```perl
# Add to AWStats configuration file
BrandLink="https://example.com"      # Logo click redirect URL
BrandPlatform="Ubuntu"               # Brand name (displays "Ubuntu Server Management Panel")
StatsUrl="/vstats"                   # AWStats deployment directory
```

> **Note**: Brand area only displays when `logo.svg` exists. If `BrandLink` is not configured, defaults to `https://hestiacp.com`.

---

## 📦 Download & Installation

Get the latest version from the links below:

| System/Format | Download Link |
|:---:|:---:|
| **Debian/Ubuntu** | [![Download .deb](https://img.shields.io/badge/Download-.deb-2ea44f?logo=debian&logoColor=white)](https://github.com/hestiacn/vstats/releases/latest/download/awstats_8.1-1_all.deb) |
| **RHEL/CentOS/Fedora** | [![Download .rpm](https://img.shields.io/badge/Download-.rpm-2ea44f?logo=fedora&logoColor=white)](https://github.com/hestiacn/vstats/releases/latest/download/awstats-8.1-1.noarch.rpm) |
| **Source (tar.gz)** | [![Download .tar.gz](https://img.shields.io/badge/Download-.tar.gz-2ea44f?logo=sourceforge&logoColor=white)](https://github.com/hestiacn/vstats/releases/latest/download/awstats-8.1.tar.gz) |
| **Source (zip)** | [![Download .zip](https://img.shields.io/badge/Download-.zip-2ea44f?logo=sourceforge&logoColor=white)](https://github.com/hestiacn/vstats/releases/latest/download/awstats-8.1.zip) |
| **Windows** | [![Download Windows](https://img.shields.io/badge/Download-Windows-2ea44f?logo=windows&logoColor=white)](https://github.com/hestiacn/vstats/releases/latest/download/awstats-8.1.exe) |

> **Windows Note**: The Windows version only packages an EXE installer; directory structures and paths have not been tested. If you encounter issues, please submit an Issue or Pull Request!

---

## 📊 Comparison with Original

| Feature | Original AWStats | Refactored Version |
|:---:|:---:|:---:|
| Encoding | GBK / Local encoding | **Full UTF-8 Support** |
| Translation | Numeric indices `$Message[169]` | **Semantic keys `_t('key')`** |
| Interface | Fixed style | **Dark/Light theme + Responsive** |
| Country Flags | PNG images | **Emoji** |
| Charts | PNG images | **Pure CSS Charts** |
| Calendar Support | Gregorian only | **13 Calendar Systems** |
| Maintenance Status | Archived | **Actively Maintained** |

---

## ✨ Complete Feature List

| Category | Features |
|:---:|:---:|
| 🌐 Multi-language CGI Access | `73` language interfaces, automatic browser detection. Let global visitors view reports in their native language! [View Detailed Language Support List](docs/CHANGELOG.md#-language-support) |
| 🗓️ Multi-Calendar Support | Japanese Era, Buddhist Calendar, Republic of China Calendar, Sexagenary Cycle, Islamic Calendar, Persian Calendar, etc. **13 calendar systems** (including Ethiopian 13-month calendar), automatically matches site language |
| 📊 Traffic Statistics | Unique visitors, visit counts, visit duration, authenticated user tracking |
| 🌍 Geolocation | `DB-IP` free database, country/region/city level mapping, IPv4/IPv6 support |
| 💻 Client Information | Browser, operating system, screen resolution, device type (desktop/mobile) |
| 🤖 Bot Detection | `500+` search engine bots, AI/ML bots (ClaudeBot, GPTBot, etc.) |
| 📁 File Statistics | File types, downloads (resume support), compression (mod_gzip/mod_deflate) |
| ⚠️ Error Analysis | `HTTP` errors (404, etc.), error sources, worm attack detection with localized status codes |
| 🎨 Modern Interface | Responsive design, dark/light theme, pure CSS charts, Emoji flag icons |

---

## 📋 System Requirements

### Basic Requirements
- ✅ Access to server log files to analyze (Web/FTP/Email)
- ✅ Perl 5.20 or higher (5.32+ recommended)
- ✅ Command line and/or CGI environment

### Supported Operating Systems
- 🐧 Linux/Unix (Ubuntu, Debian, CentOS, RHEL, etc.)
- 🪟 Windows (Windows 10/11, Windows Server)
- 🍎 macOS
- 🔵 FreeBSD, OpenBSD

### Supported Servers
- 🌐 Web: Apache, Nginx, IIS, Caddy, Lighttpd
- 📁 FTP: ProFTPd, vsFTPd, Pure-FTPd
- 📧 Mail: Postfix, Sendmail, QMail, Exim
- 🎥 Streaming: RealMedia, Windows Media Server

---

## 🔄 Upgrade Conversion (For upgrading from old versions only)

If upgrading from an old version (7.0-7.9), first run `/usr/share/awstats/tools/awstats_convert-en.pl` to convert historical data files (*.txt) from (7.0-7.9 → 8.1). The program will automatically detect all AWStats data files (*.txt) in `/home/*/web/*/stats/` directories and perform batch conversion. It will automatically backup original files before conversion. If your sites are not in the `home` directory, adjust the path structure `/home/username/web/yourdomain/stats/` accordingly. After conversion, proceed with data update operations, otherwise updates will fail due to format incompatibility.

> **Note**: If your site version is below 7.0, adjust the regex pattern `s/AWSTATS DATA FILE 7\.[0-9]{1,2}/AWSTATS DATA FILE 8.1/` in the script according to your actual version number.

> **💡 Tip**: Backup files are saved in `/backup/awstats_converter/backup_timestamp/`.

```bash
# Dry run (view which files will be converted)
perl /usr/share/awstats/tools/awstats_convert-en.pl --dryrun

# Actual conversion
perl /usr/share/awstats/tools/awstats_convert-en.pl

# Force reconvert all files
perl /usr/share/awstats/tools/awstats_convert-en.pl --force

# Quiet mode
perl /usr/share/awstats/tools/awstats_convert-en.pl --quiet

# help
perl /usr/share/awstats/tools/awstats_convert-en.pl --help
```

---

## 🚀 Quick Start

### 1. Installation

#### For HestiaCP Users (Recommended)

HestiaCP already includes AWStats, just update by installing the deb package.

Supports official [Debian](https://github.com/hestiacp/hestiacp) and community [RHEL](https://github.com/bayrepo/hestiacp-rpm) versions.

**Files you may need to adjust**:
- Template file: `/usr/local/hestia/data/templates/web/awstats/awstats.tpl`
- Domain configuration: `/etc/awstats/` directory
- Update script: `/usr/local/hestia/bin/v-update-web-domain-stat`
- Reference script template: [v-update-web-domain-stat](/make/test/awstats/conf/v-update-web-domain-stat)
- Reference config template: [awstats.tpl](/make/test/awstats/conf/awstats.tpl)

#### Download and Install

```bash
# When installing with HestiaCP, if prompted about configuration file updates, choose N (keep original config)
wget -P /tmp/ https://github.com/hestiacn/vstats/releases/latest/download/awstats_8.1-1_all.deb && apt install -y /tmp/awstats_8.1-1_all.deb
```

### Debian/Ubuntu

```bash
wget -P /tmp/ https://github.com/hestiacn/vstats/releases/latest/download/awstats_8.1-1_all.deb && apt install -y /tmp/awstats_8.1-1_all.deb
```

### RHEL/CentOS/Fedora

```bash
wget https://github.com/hestiacn/vstats/releases/latest/download/awstats-8.1-1.noarch.rpm
dnf localinstall -y awstats-8.1-1.noarch.rpm
```

### Basic Configuration

Edit `/etc/awstats/awstats.yourdomain.conf`:

```perl
LogFile="/var/log/apache2/domains/yourdomain.log"  # Log file path
LogFormat=1                                         # Use combined log format
SiteDomain="yourdomain.com"                         # Website domain
HostAliases="localhost 127.0.0.1"                   # Host aliases
```

### Update Statistics

```bash
awstats.pl -config=yourdomain -update
```

### View Reports

- **HestiaCP Environment**: Visit `https://yourdomain.com/vstats/` - bookmark this directory if needed. Access automatically loads CGI mode!
- **Generate Static Report**: `awstats.pl -config=yourdomain -output > report.html`

---

## 📖 Command Line Help

### View Help in Your Native Language

```bash
# Chinese (Traditional)
dnf install -y glibc-langpack-zh
localectl set-locale LANG=zh_TW.UTF-8
# For RHEL/CentOS/Fedora:
source /etc/locale.conf
# For Debian/Ubuntu:
source /etc/default/locale
awstats -h

# English (US)
dnf install -y glibc-langpack-en
localectl set-locale LANG=en_US.UTF-8
# For RHEL/CentOS/Fedora:
source /etc/locale.conf
# For Debian/Ubuntu:
source /etc/default/locale
awstats -h

# Japanese
dnf install -y glibc-langpack-ja
localectl set-locale LANG=ja_JP.UTF-8
# For RHEL/CentOS/Fedora:
source /etc/locale.conf
# For Debian/Ubuntu:
source /etc/default/locale
awstats -h

# Chinese (Simplified)
dnf install -y glibc-langpack-zh
localectl set-locale LANG=zh_CN.UTF-8
# For RHEL/CentOS/Fedora:
source /etc/locale.conf
# For Debian/Ubuntu:
source /etc/default/locale
awstats -h

# English (UK)
dnf install -y glibc-langpack-en 
localectl set-locale LANG=en_GB.UTF-8
# For RHEL/CentOS/Fedora:
source /etc/locale.conf
# For Debian/Ubuntu:
source /etc/default/locale
awstats -h

# Portuguese (Brazil)
dnf install -y glibc-langpack-pt
localectl set-locale LANG=pt_BR.UTF-8
# For RHEL/CentOS/Fedora:
source /etc/locale.conf
# For Debian/Ubuntu:
source /etc/default/locale
awstats -h
```

### Common Commands

| Command | Description |
|:---:|:---:|
| `awstats.pl -config=xxx -update` | Update statistics |
| `awstats.pl -config=xxx -output > report.html` | Generate static report |
| `awstats.pl -config=xxx -update -debug=2` | Debug mode (requires `DebugMessages=1` in config file, default is 0) |
| `awstats -h` | Show help |
| `awstats -v` | Show version |

---

## 📚 Documentation

| Document | Link |
|:---:|:---:|
| Changelog (Chinese) | [docs/CHANGELOG-zh_CN.md](docs/CHANGELOG-zh_CN.md) |
| Changelog (English) | [docs/CHANGELOG.md](docs/CHANGELOG.md) |
| Installation Guide | [docs/awstats_setup.html](docs/awstats_setup.html) |
| Configuration Guide | [docs/awstats_config.html](docs/awstats_config.html) |
| FAQ | [docs/awstats_faq.html](docs/awstats_faq.html) |

---

## 🤝 Contributing & Feedback

- **Project Repository**: [GitHub - hestiacn/vstats](https://github.com/hestiacn/vstats)
- **Issue Tracker**: [GitHub Issues](https://github.com/hestiacn/vstats/issues)

---

## 💖 Acknowledgements

Special thanks to all translators and testers who helped us correctly translate Welsh and Arabic with their six plural forms. You are true internet heroes!

---

## 📄 License

`AWStats` is open-source software released under the [GNU General Public License v3](https://www.gnu.org/licenses/gpl-3.0.html#license-text).

---

## 👨‍💻 About the Author & Maintenance

**Original Author**: Laurent Destailleur (1997-2025)
- Project founder, announced end of updates in November 2025
- [Dolibarr ERP CRM](https://www.dolibarr.org) project lead

**Community Maintainer**: [hestiacn](https://github.com/hestiacn/vstats)
- Version 8.1 modernization refactoring
- Ongoing maintenance and updates

---

## 🔗 Related Links

- Original Project Website: [https://www.awstats.org](https://www.awstats.org)
- Original Project GitHub Repository: [eldy/AWStats](https://github.com/eldy/AWStats)
- DB-IP Database: [https://db-ip.com](https://db-ip.com)

---

## © 1997-2026 AWStats Team | Community Edition - Continuously Maintained
