#!/usr/bin/perl
#----------------------------------------------------------------------------
# \file         make/makepack-awstats.pl
# \brief        Package builder (tgz, zip, pkg, rpm, deb, exe) with Git automation
# \author       (c)2004-2026 Laurent Destailleur  <eldy@users.sourceforge.net>
#----------------------------------------------------------------------------

use strict;
use warnings;
use v5.20;
$| = 1;
use Cwd;
use experimental qw(declared_refs);
use File::Path qw(remove_tree make_path);
use File::Copy;
use File::Basename;
use Getopt::Long;
use POSIX qw(strftime);
use Digest::SHA qw(sha256_hex);
use Cwd qw(abs_path);
use File::Spec;
use File::Find;

# 检测运行环境
my $IS_GITHUB_ACTIONS = $ENV{GITHUB_ACTIONS} ? 1 : 0;
my $IS_WINDOWS = ($^O =~ /win32/i) ? 1 : 0;

print "运行环境: " . ($IS_GITHUB_ACTIONS ? "GitHub Actions" : "本地") . "\n";
print "操作系统: " . ($IS_WINDOWS ? "Windows" : "Unix-like") . "\n";

# 项目配置
my $PROJECT = "awstats";
my $RPMSUBVERSION = "1";
my $PKGSUBVERSION = "1";
my $WBMVERSION = "2.0";
my @TARGETS = ("TGZ", "ZIP", "PKG", "RPM", "DEB");
my $GITHUB_REPO = "hestiacn/vstats";

# 工具依赖
my %REQUIREMENTS = (
    "TGZ" => "tar",
    "ZIP" => "7z",
    "PKG" => "pkg",
    "RPM" => "rpmbuild",
    "DEB" => "dpkg-buildpackage",
    "EXE" => "makensis"
);

# 版本信息
my ($MAJOR, $MINOR, $BUILD);
my ($REVISION, $VERSION) = ('', '');

# 路径配置
my ($DIR, $PROG, $SOURCE, $DESTI, $TEMP, $BUILDROOT, $RPMDIR);
my $OS = '';
my $PROGPATH = '';

# 检测操作系统
sub detect_os {
    if ($^O eq "freebsd") { return 'freebsd'; }
    elsif ($^O =~ /linux/i || (-d "/etc" && -d "/var" && $^O !~ /cygwin/i)) { 
        return 'linux'; 
    }
    elsif (-d "/etc" && -d "/Users") { 
        return 'macosx'; 
    }
    elsif ($^O =~ /cygwin/i || $^O =~ /win32/i) { 
        return 'windows'; 
    }
    else {
        die "Unsupported OS: $^O";
    }
}

# 获取 Git 版本信息
sub get_git_version {
    my $source_dir = shift;
    my $olddir = getcwd();
    chdir($source_dir);
    
    my $tag = `git describe --tags --abbrev=0 2>/dev/null`;
    chomp($tag);
    my $commit = `git rev-parse --short HEAD 2>/dev/null`;
    chomp($commit);
    my $date = `git log -1 --format=%cd --date=short 2>/dev/null`;
    chomp($date);
    
    chdir($olddir);
    return ($tag, $commit, $date);
}

# 生成发布说明
sub generate_release_notes {
    my ($source_dir, $old_tag, $new_tag) = @_;
    
    my $olddir = getcwd();
    chdir($source_dir);
    
    my $log = `git log $old_tag..$new_tag --pretty=format:"* %s (%h)"`;
    chdir($olddir);
    
    my $date = strftime("%Y-%m-%d", localtime);
    
    return <<"NOTES";
## AWStats $MAJOR.$MINOR ($date)

### What's Changed
$log

### Downloads
- [Source Code (tar.gz)](https://github.com/$GITHUB_REPO/releases/download/v$MAJOR.$MINOR/$PROJECT-$MAJOR.$MINOR.tar.gz)
- [Source Code (zip)](https://github.com/$GITHUB_REPO/releases/download/v$MAJOR.$MINOR/$PROJECT-$MAJOR.$MINOR.zip)
- [RPM Package](https://github.com/$GITHUB_REPO/releases/download/v$MAJOR.$MINOR/$PROJECT-$MAJOR.$MINOR-$RPMSUBVERSION.noarch.rpm)
- [DEB Package](https://github.com/$GITHUB_REPO/releases/download/v$MAJOR.$MINOR/${PROJECT}_$MAJOR.$MINOR-${RPMSUBVERSION}_all.deb)
- [FreeBSD Package](https://github.com/$GITHUB_REPO/releases/download/v$MAJOR.$MINOR/$PROJECT-$MAJOR.$MINOR-$PKGSUBVERSION.pkg)

### Installation
See [INSTALL.md](https://github.com/$GITHUB_REPO/blob/main/docs/INSTALL.md) for details.

### Full Changelog
https://github.com/$GITHUB_REPO/compare/$old_tag...$new_tag
NOTES
}

# 使用 gh CLI 发布
sub publish_with_gh_cli {
    my ($version, $notes, @files) = @_;
    
    if (system("gh --version > /dev/null 2>&1") != 0) {
        print "⚠ GitHub CLI (gh) not installed\n";
        print "Install from: https://cli.github.com/\n";
        return 0;
    }
    
    if (system("gh auth status > /dev/null 2>&1") != 0) {
        print "⚠ Not logged into GitHub\n";
        print "Run: gh auth login\n";
        return 0;
    }
    
    my $user = `gh api user -q .login`;
    chomp $user;
    print "✓ Logged in as: $user\n";
    
    my $tag = "v$version";
    if (system("git rev-parse $tag > /dev/null 2>&1") != 0) {
        print "Creating tag $tag...\n";
        system("git tag -a $tag -m 'Release $version'");
        system("git push origin $tag");
    }
    
    my $notes_file = "$TEMP/release_notes_$$.md";
    open my $fh, '>', $notes_file or die "Cannot create $notes_file: $!";
    print $fh $notes;
    close $fh;
    
    print "Creating GitHub release $tag...\n";
    my $cmd = "gh release create $tag --title 'AWStats $version' --notes-file '$notes_file'";
    foreach my $file (@files) {
        if (-f $file) {
            $cmd .= " '$file'";
        }
    }
    system($cmd);
    
    unlink $notes_file;
    print "✓ Published to GitHub: https://github.com/$GITHUB_REPO/releases/tag/$tag\n";
    return 1;
}

# 生成 SHA256 校验和
sub generate_checksums {
    my @files = @_;
    
    my $checksum_file = "$DESTI/SHA256SUMS.txt";
    open my $fh, '>', $checksum_file or die "Cannot create $checksum_file: $!";
    
    foreach my $file (@files) {
        if (-f $file) {
            open my $in, '<', $file or next;
            binmode $in;
            my $ctx = Digest::SHA->new(256);
            $ctx->addfile($in);
            close $in;
            
            my $hash = $ctx->hexdigest;
            my $basename = basename($file);
            print $fh "$hash  $basename\n";
        }
    }
    
    close $fh;
    print "✓ Checksums generated: $checksum_file\n";
    return $checksum_file;
}

# 初始化
sub init {
    ($DIR = $0) =~ s/([^\/\\]+)$//;
    ($PROG = $1) =~ s/\.([^\.]*)$//;
    $DIR ||= '.';
    $DIR =~ s/([^\/\\])[\\\/]+$/$1/;
    
    # 获取脚本的绝对路径
    my $script_dir = abs_path($DIR);
    print "脚本目录: $script_dir\n";
    
    # 项目根目录（脚本在 make 目录下）
    my $project_root;
    if ($IS_WINDOWS) {
        # Windows 路径处理
        $project_root = File::Spec->catdir($script_dir, '..');
        $project_root = abs_path($project_root);
    } else {
        $project_root = "$script_dir/..";
    }
    
    print "项目根目录: $project_root\n";
    
    # 查找 awstats.pl 的可能位置
    my @possible_paths = (
        File::Spec->catfile($project_root, 'wwwroot', 'cgi-bin', 'awstats.pl'),
        File::Spec->catfile($project_root, 'awstats', 'wwwroot', 'cgi-bin', 'awstats.pl'),
        File::Spec->catfile($script_dir, '..', 'wwwroot', 'cgi-bin', 'awstats.pl'),
        File::Spec->catfile($script_dir, '..', '..', 'awstats', 'wwwroot', 'cgi-bin', 'awstats.pl'),
    );
    
    $SOURCE = '';
    foreach my $test_path (@possible_paths) {
        print "检查: $test_path\n";
        if (-f $test_path) {
            print "找到 awstats.pl: $test_path\n";
            # 获取源码目录（向上三级到项目根）
            $SOURCE = File::Spec->catdir($test_path, '..', '..', '..');
            $SOURCE = abs_path($SOURCE);
            last;
        }
    }
    
    unless ($SOURCE) {
        # 默认使用项目根目录
        $SOURCE = $project_root;
        print "使用默认源码目录: $SOURCE\n";
        
        # 检查文件是否存在
        my $test_file = File::Spec->catfile($SOURCE, 'wwwroot', 'cgi-bin', 'awstats.pl');
        unless (-f $test_file) {
            die "Cannot find awstats.pl. Please ensure file exists at: $test_file";
        }
    }
    
    $DESTI = File::Spec->catdir($SOURCE, 'make');
    
    # 检测操作系统
    $OS = detect_os();
    
    # 设置临时目录（Windows 特殊处理）
    if ($OS eq 'windows') {
        $TEMP = $ENV{TEMP} || $ENV{TMP} || 'C:\temp';
        $PROGPATH = $ENV{ProgramFiles} || 'C:\Program Files';
        
        # 处理 HOME 环境变量（Windows 可能没有）
        unless ($ENV{HOME}) {
            $ENV{HOME} = $ENV{USERPROFILE} || 'C:\Users\runneradmin';
        }
    } elsif ($OS eq 'linux' || $OS eq 'macosx' || $OS eq 'freebsd') {
        $TEMP = $ENV{TEMP} || $ENV{TMP} || '/tmp';
    }
    
    die "No temporary directory found" unless ($TEMP && -d $TEMP);
    
    $BUILDROOT = File::Spec->catdir($TEMP, "${PROJECT}-buildroot");
    
    # 设置 RPM 目录（Windows 忽略）
    unless ($OS eq 'windows') {
        if (-d "/usr/src/redhat") { $RPMDIR = "/usr/src/redhat"; }
        elsif (-d "/usr/src/RPM") { $RPMDIR = "/usr/src/RPM"; }
        elsif (-d "/home/ldestailleur/rpmbuild") { $RPMDIR = "/home/ldestailleur/rpmbuild"; }
        elsif ($ENV{HOME}) { $RPMDIR = "$ENV{HOME}/rpmbuild"; }
    }
    
    # 从 awstats.pl 读取版本
    my $version_file = File::Spec->catfile($SOURCE, 'wwwroot', 'cgi-bin', 'awstats.pl');
    print "读取版本文件: $version_file\n";
    
    if (open my $fh, '<', $version_file) {
        while (<$fh>) {
            if (/VERSION\s*=\s*"([\d\.a-z\-]+)/) {
                my $fullver = $1;
                ($MAJOR, $MINOR, $BUILD) = split(/\./, $fullver, 3);
                last;
            }
        }
        close $fh;
    } else {
        die "Cannot open version file: $version_file";
    }
    
    die "Cannot detect version from $version_file" unless $MAJOR;
    
    print "=" x 60, "\n";
    print "AWStats Packager\n";
    print "=" x 60, "\n";
    print "Version: $MAJOR.$MINOR\n";
    print "Source: $SOURCE\n";
    print "Output: $DESTI\n";
    print "OS: $OS\n";
    print "=" x 60, "\n\n";
}

# 准备构建目录
sub prepare_buildroot {
    my $skip_copy = shift || 0;
    
    if ($skip_copy) {
        print "Skipping buildroot preparation (using source directly for TGZ/ZIP)\n";
        $BUILDROOT = $SOURCE;
        return;
    }
    
    print "Preparing build directory for PKG/RPM/DEB/EXE...\n";
    
    remove_tree($BUILDROOT) if -d $BUILDROOT;
    make_path($BUILDROOT);
    
    my $target_dir = "$BUILDROOT/$PROJECT-$MAJOR.$MINOR";
    make_path($target_dir);
    
    # 复制所有需要的顶层目录（保持原有结构）
    my @top_dirs = qw(docs tools wwwroot);
    foreach my $item (@top_dirs) {
        my $src = File::Spec->catfile($SOURCE, $item);
        if (-e $src) {
            print "Copying $item/ ...\n";
            system("cp -pr '$src' '$target_dir/'");
        } else {
            print "Warning: $src not found\n";
        }
    }
    
    # 复制 README 文件
    foreach my $readme (qw(README.md README-zh_CN.md README-zh_TW.md)) {
        my $src = File::Spec->catfile($SOURCE, $readme);
        if (-f $src) {
            print "Copying $readme...\n";
            copy($src, "$target_dir/$readme") or warn "Failed to copy $readme: $!";
        }
    }
    
    # 复制配置文件（它们应该在 wwwroot/cgi-bin/ 下）
    my @config_files = qw(awstats.conf awstats.model.conf);
    foreach my $conf (@config_files) {
        my $src = File::Spec->catfile($SOURCE, 'wwwroot', 'cgi-bin', $conf);
        my $dst = "$target_dir/wwwroot/cgi-bin/$conf";
        if (-f $src) {
            print "Copying $conf...\n";
            copy($src, $dst) or warn "Failed to copy $conf: $!";
        } else {
            print "Warning: $conf not found at $src\n";
        }
    }
    
    # 清理不需要的文件
    cleanup_buildroot($BUILDROOT, "$MAJOR.$MINOR");

    print "Build directory ready: $target_dir\n\n";
}

# 完整清理函数
sub cleanup_buildroot {
    my ($build_dir, $version) = @_;
    
    my $target_dir = "$build_dir/$PROJECT-$version";
    print "Cleaning files in $target_dir...\n";
    
    # 删除版本控制文件和备份
    my @patterns = (
        '.git', '.svn', 'CVS',
        '.github', '.settings',
        '*.bak', '*~', '*.old',
        '.cvsignore', '.gitignore',
        '.project', '.gitattributes',
        'Thumbs.db', '.DS_Store'
    );
    
    foreach my $pattern (@patterns) {
        system("find '$target_dir' -name '$pattern' -exec rm -rf {} \\; 2>/dev/null");
    }
    
    # 删除特定文件
    my @specific_files = (
        "$target_dir/git2cvs.sh",
        "$target_dir/wwwroot/cgi-bin/.cvsignore",
        "$target_dir/wwwroot/classes/src/.cvsignore",
        "$target_dir/docs/images/.cvsignore",
        "$target_dir/tools/webmin/.cvsignore",
        "$target_dir/tools/webmin/awstats/images/.cvsignore",
    );
    
    foreach my $file (@specific_files) {
        unlink $file if -f $file;
    }
    
    # 删除不需要的目录
    my @remove_dirs = (
        "$target_dir/make",
        "$target_dir/test",
    );
    
    foreach my $dir (@remove_dirs) {
        system("rm -rf '$dir' 2>/dev/null");
    }
    
    print "Cleanup completed\n";
}

# 检查依赖工具
sub check_requirements {
    my $target = shift;
    my $req = $REQUIREMENTS{$target};
    
    print "Checking requirement for $target: $req... ";
    
    if ($OS eq 'windows') {
        $req .= ".exe" if $req !~ /\.exe$/;
        my $found = 0;
        foreach my $path (split(/;/, $ENV{PATH})) {
            if (-f "$path\\$req") {
                $found = 1;
                last;
            }
        }
        if ($found) {
            print "OK (found in PATH)\n";
            return 1;
        } else {
            print "FAILED (not found in PATH)\n";
            return 0;
        }
    } else {
        my $ret = system("$req --version > /dev/null 2>&1");
        if ($ret == 0) {
            print "OK\n";
            return 1;
        } else {
            print "FAILED\n";
            return 0;
        }
    }
}

# 构建 TGZ 包
sub build_tgz {
    my $version = "$MAJOR.$MINOR";
    my $filename = "$PROJECT-$version";
    my $output_file = "$DESTI/$filename.tar.gz";
    
    print "\nBuilding TGZ package: $filename\n";
    
    my $nested_dir = "$SOURCE/$filename";
    if (-d $nested_dir) {
        print "Removing nested directory: $nested_dir\n";
        system("rm -rf '$nested_dir'");
    }
    
    chdir($SOURCE);
    
    my $cmd = "tar --exclude='.git' --exclude='.github' --exclude='.settings' "
            . "--exclude='make' --exclude='test' --exclude='*.bak' --exclude='*~' "
            . "--exclude='*.old' --exclude='.gitignore' --exclude='.gitattributes' "
            . "--exclude='.project' --exclude='.cvsignore' --exclude='git2cvs.sh' "
            . "-czf '$output_file' --transform='s/^/$filename\\//' . 2>&1";
    
    print "Running: $cmd\n";
    system($cmd);
    
    if (-f $output_file && -s $output_file > 0) {
        print "✅ TGZ package created\n";
        return $output_file;
    }
    return undef;
}

# 构建 ZIP 包
sub build_zip {
    my $version = "$MAJOR.$MINOR";
    my $filename = "$PROJECT-$version";
    my $output_file = "$DESTI/$filename.zip";
    
    print "\nBuilding ZIP package: $filename\n";
    
    my $which_7z = `which 7z 2>&1`;
    if ($which_7z =~ /not found/i) {
        print "⚠️ 7z command not found, skipping ZIP build\n";
        return undef;
    }
    
    my $nested_dir = "$SOURCE/$filename";
    if (-d $nested_dir) {
        print "Removing nested directory: $nested_dir\n";
        system("rm -rf '$nested_dir'");
    }
    
    chdir($SOURCE);
    
    my $cmd = "7z a -r -tzip -mx9 '$output_file' "
            . "-xr!.git -xr!.github -xr!.settings "
            . "-xr!make -xr!test "
            . "-xr!*.bak -xr!*~ -xr!*.old "
            . "-xr!.gitignore -xr!.gitattributes "
            . "-xr!.project -xr!.cvsignore -xr!git2cvs.sh "
            . ". 2>&1";
    
    print "Running: $cmd\n";
    system($cmd);
    
    if (-f $output_file) {
        print "✅ ZIP package created\n";
        return $output_file;
    }
    return undef;
}

# 构建 RPM 包
sub build_rpm {
    my $version = "$MAJOR.$MINOR";
    my $filename = "$PROJECT-$version";
    my $output = "$DESTI/$PROJECT-$version-$RPMSUBVERSION.noarch.rpm";

    print "\nBuilding RPM package: $filename\n";
    print "  Current directory: " . Cwd::getcwd() . "\n";
    print "  BUILDROOT: $BUILDROOT\n";
    print "  RPMDIR: $RPMDIR\n";

    make_path("$RPMDIR/SOURCES");
    
    # 创建源码包
    my $tgz_file = "$RPMDIR/SOURCES/$PROJECT-$version.tgz";
    unlink $tgz_file;

    my $exclude_file = "$SOURCE/make/tgz/tar.exclude";
    my $exclude_opt = -f $exclude_file ? "--exclude-from='$exclude_file'" : "";
    my $cmd = "tar $exclude_opt --directory='$BUILDROOT' -czvf '$tgz_file' $filename";

    print "  Creating source tarball: $cmd\n";
    system($cmd) == 0 or die "Failed to create source tarball";

    if (-f $tgz_file) {
        my $size = -s $tgz_file;
        print "  ✅ Source tarball created: $tgz_file (" . int($size/1024) . " KB)\n";
    } else {
        die "❌ Source tarball not created";
    }

    my $changelog_date = `date "+%a %b %d %Y"`;
    chomp $changelog_date;
    print "  Changelog date: $changelog_date\n";

    # ===== 写 conf 文件到临时目录 =====
    my $conf_dir = "$TEMP/rpm-conf";
    make_path($conf_dir);

    # httpd conf
    open my $fh_httpd, '>', "$conf_dir/awstats.httpd.conf" or die "Cannot write httpd conf: $!";
    print $fh_httpd 'Alias /awstatsclasses "/usr/share/awstats/classes/"', "\n";
    print $fh_httpd 'Alias /awstatscss "/usr/share/awstats/css/"', "\n";
    print $fh_httpd 'Alias /awstatsicons "/usr/share/awstats/icon/"', "\n";
    print $fh_httpd 'Alias /awstatsdocs "/usr/share/doc/awstats/"', "\n";
    print $fh_httpd 'ScriptAlias /awstats/ "/usr/lib/cgi-bin/"', "\n";
    print $fh_httpd '', "\n";
    print $fh_httpd '<Directory "/usr/share/awstats">', "\n";
    print $fh_httpd '    Options None', "\n";
    print $fh_httpd '    AllowOverride None', "\n";
    print $fh_httpd '    Require all granted', "\n";
    print $fh_httpd '</Directory>', "\n";
    print $fh_httpd '', "\n";
    print $fh_httpd '<IfModule mod_env.c>', "\n";
    print $fh_httpd '    SetEnv PERL5LIB /usr/share/awstats/lib:/usr/share/awstats/plugins', "\n";
    print $fh_httpd '</IfModule>', "\n";
    close $fh_httpd;

    # logrotate conf
    open my $fh_logrotate, '>', "$conf_dir/awstats.logrotate" or die "Cannot write logrotate conf: $!";
    print $fh_logrotate '/var/log/awstats/*.log {', "\n";
    print $fh_logrotate '    weekly', "\n";
    print $fh_logrotate '    missingok', "\n";
    print $fh_logrotate '    rotate 52', "\n";
    print $fh_logrotate '    compress', "\n";
    print $fh_logrotate '    delaycompress', "\n";
    print $fh_logrotate '    notifempty', "\n";
    print $fh_logrotate '    create 644 root root', "\n";
    print $fh_logrotate '    sharedscripts', "\n";
    print $fh_logrotate '    postrotate', "\n";
    print $fh_logrotate '        /usr/share/awstats/tools/awstats_updateall.pl now > /dev/null 2>&1 || true', "\n";
    print $fh_logrotate '    endscript', "\n";
    print $fh_logrotate '}', "\n";
    close $fh_logrotate;

    # cron conf
    open my $fh_cron, '>', "$conf_dir/awstats.cron" or die "Cannot write cron conf: $!";
    print $fh_cron '# AWStats cron job', "\n";
    print $fh_cron '# Run AWStats update daily at 1:00 AM', "\n";
    print $fh_cron '0 1 * * * root [ -x /usr/share/awstats/tools/awstats_updateall.pl ] && /usr/share/awstats/tools/awstats_updateall.pl now > /dev/null 2>&1', "\n";
    close $fh_cron;

    # awstats wrapper
    open my $fh_wrapper, '>', "$conf_dir/awstats.wrapper" or die "Cannot write awstats wrapper: $!";
    print $fh_wrapper '#!/bin/bash', "\n";
    print $fh_wrapper 'perl /usr/lib/cgi-bin/awstats.pl "$@"', "\n";
    close $fh_wrapper;

    # awstats-update wrapper
    open my $fh_upd_wrapper, '>', "$conf_dir/awstats-update.wrapper" or die "Cannot write awstats-update wrapper: $!";
    print $fh_upd_wrapper '#!/bin/bash', "\n";
    print $fh_upd_wrapper 'perl /usr/share/awstats/tools/awstats_updateall.pl "$@"', "\n";
    close $fh_upd_wrapper;

    # dbip-update script
    open my $fh_dbip, '>', "$conf_dir/awstats-dbip-update" or die "Cannot write dbip script: $!";
    print $fh_dbip '#!/bin/bash', "\n";
    print $fh_dbip '# ------------------------------------------------------------------------------', "\n";
    print $fh_dbip '# Generated by AWStats, do not edit manually', "\n";
    print $fh_dbip '# 由 AWStats 自动生成，请勿手动编辑', "\n";
    print $fh_dbip '# To disable automatic updates, rename this file so you can re-enable it later if needed.', "\n";
    print $fh_dbip '# 若需禁用自动更新，请将此文件重命名！以便后续启用此功能！', "\n";
    print $fh_dbip '# ------------------------------------------------------------------------------', "\n";
    print $fh_dbip 'YEAR_MONTH=$(date +%Y-%m)', "\n";
    print $fh_dbip 'DBIP_DIR="/usr/share/perl5/Geo"', "\n";
    print $fh_dbip 'DBIP_DEST="$DBIP_DIR/dbip-city.mmdb"', "\n";
    print $fh_dbip 'DBIP_TEMP_GZ="$DBIP_DIR/dbip-city.mmdb.tmp.gz"', "\n";
    print $fh_dbip 'DBIP_TEMP="$DBIP_DIR/dbip-city.mmdb.tmp"', "\n";
    print $fh_dbip 'LOG_FILE="/var/log/dbip-update.log"', "\n";
    print $fh_dbip '', "\n";
    print $fh_dbip 'if [ -f "$LOG_FILE" ] && [ $(wc -l < "$LOG_FILE") -gt 30 ]; then', "\n";
    print $fh_dbip '    tail -n 30 "$LOG_FILE" > "$LOG_FILE.tmp"', "\n";
    print $fh_dbip '    mv "$LOG_FILE.tmp" "$LOG_FILE"', "\n";
    print $fh_dbip 'fi', "\n";
    print $fh_dbip '', "\n";
    print $fh_dbip 'mkdir -p "$DBIP_DIR"', "\n";
    print $fh_dbip 'cd "$DBIP_DIR"', "\n";
    print $fh_dbip '', "\n";
    print $fh_dbip 'if ! command -v wget > /dev/null 2>&1; then', "\n";
    print $fh_dbip '    echo "$(date): wget not installed, skipping update" >> "$LOG_FILE"', "\n";
    print $fh_dbip '    exit 1', "\n";
    print $fh_dbip 'fi', "\n";
    print $fh_dbip '', "\n";
    print $fh_dbip 'echo "$(date): Downloading DB-IP database for ${YEAR_MONTH}..." >> "$LOG_FILE"', "\n";
    print $fh_dbip 'wget -q -O "$DBIP_TEMP_GZ" "https://download.db-ip.com/free/dbip-city-lite-${YEAR_MONTH}.mmdb.gz" 2>/dev/null', "\n";
    print $fh_dbip 'if [ ! -s "$DBIP_TEMP_GZ" ]; then', "\n";
    print $fh_dbip '    LAST_MONTH=$(date -d "1 month ago" +%Y-%m 2>/dev/null)', "\n";
    print $fh_dbip '    if [ -n "$LAST_MONTH" ]; then', "\n";
    print $fh_dbip '        echo "$(date): Current month ${YEAR_MONTH} not available, trying ${LAST_MONTH}" >> "$LOG_FILE"', "\n";
    print $fh_dbip '        wget -q -O "$DBIP_TEMP_GZ" "https://download.db-ip.com/free/dbip-city-lite-${LAST_MONTH}.mmdb.gz" 2>/dev/null', "\n";
    print $fh_dbip '        if [ -s "$DBIP_TEMP_GZ" ]; then', "\n";
    print $fh_dbip '            echo "$(date): Downloaded ${LAST_MONTH} instead" >> "$LOG_FILE"', "\n";
    print $fh_dbip '        fi', "\n";
    print $fh_dbip '    fi', "\n";
    print $fh_dbip 'fi', "\n";
    print $fh_dbip 'if [ -s "$DBIP_TEMP_GZ" ]; then', "\n";
    print $fh_dbip '    gunzip -f "$DBIP_TEMP_GZ"', "\n";
    print $fh_dbip '    if [ -f "$DBIP_TEMP" ]; then', "\n";
    print $fh_dbip '        mv "$DBIP_TEMP" "$DBIP_DEST"', "\n";
    print $fh_dbip '        chmod 644 "$DBIP_DEST"', "\n";
    print $fh_dbip '        echo "$(date): Successfully updated to ${YEAR_MONTH}" >> "$LOG_FILE"', "\n";
    print $fh_dbip '        echo "✓ DB-IP database updated to ${YEAR_MONTH}"', "\n";
    print $fh_dbip '    else', "\n";
    print $fh_dbip '        echo "$(date): Gunzip failed" >> "$LOG_FILE"', "\n";
    print $fh_dbip '        echo "⚠ DB-IP database decompression failed"', "\n";
    print $fh_dbip '    fi', "\n";
    print $fh_dbip 'else', "\n";
    print $fh_dbip '    rm -f "$DBIP_TEMP_GZ"', "\n";
    print $fh_dbip '    echo "$(date): Download failed for ${YEAR_MONTH}" >> "$LOG_FILE"', "\n";
    print $fh_dbip '    echo "⚠ DB-IP database update failed"', "\n";
    print $fh_dbip 'fi', "\n";
    close $fh_dbip;

    open my $fh_dbip_cron, '>', "$conf_dir/awstats-dbip-update.cron" or die "Cannot write dbip cron: $!";
    print $fh_dbip_cron '# Update DB-IP database monthly on the 3rd at 3:00 AM', "\n";
    print $fh_dbip_cron '0 3 3 * * root /usr/local/bin/awstats-dbip-update > /dev/null 2>&1', "\n";
    close $fh_dbip_cron;

    # post script
    open my $fh_post, '>', "$conf_dir/awstats.post" or die "Cannot write post script: $!";
    print $fh_post '#!/bin/sh', "\n";
    print $fh_post 'set -e', "\n";
    print $fh_post 'case "$1" in', "\n";
    print $fh_post '    1|2)', "\n";
    print $fh_post '        echo " AWStats %{version} - DB-IP Database Setup"', "\n";
    print $fh_post '        mkdir -p /usr/share/perl5/Geo', "\n";
    print $fh_post '        mkdir -p /var/lib/awstats', "\n";
    print $fh_post '        mkdir -p /var/log/awstats', "\n";
    print $fh_post '        chmod 755 /var/lib/awstats', "\n";
    print $fh_post '        chmod 755 /var/log/awstats', "\n";
    print $fh_post '        if [ -f /usr/lib/cgi-bin/awstats.pl ]; then chmod 755 /usr/lib/cgi-bin/awstats.pl; fi', "\n";
    print $fh_post '        if [ -f /usr/lib/cgi-bin/awredir.pl ]; then chmod 755 /usr/lib/cgi-bin/awredir.pl; fi', "\n";
    print $fh_post '        DBIP_DEST="/usr/share/perl5/Geo/dbip-city.mmdb"', "\n";
    print $fh_post '        if [ ! -f "$DBIP_DEST" ]; then', "\n";
    print $fh_post '            if command -v wget > /dev/null 2>&1; then', "\n";
    print $fh_post '                YEAR=$(date +%Y); MONTH=$(date +%m)', "\n";
    print $fh_post '                DBIP_URL="https://download.db-ip.com/free/dbip-city-lite-${YEAR}-${MONTH}.mmdb.gz"', "\n";
    print $fh_post '                DBIP_TEMP_GZ="/usr/share/perl5/Geo/dbip-city-temp.mmdb.gz"', "\n";
    print $fh_post '                if wget -q -O "$DBIP_TEMP_GZ" "$DBIP_URL" 2>/dev/null; then', "\n";
    print $fh_post '                    DOWNLOAD_SUCCESS=1', "\n";
    print $fh_post '                else', "\n";
    print $fh_post '                    LAST_YEAR=$(date -d "1 month ago" +%Y 2>/dev/null)', "\n";
    print $fh_post '                    LAST_MONTH=$(date -d "1 month ago" +%m 2>/dev/null)', "\n";
    print $fh_post '                    if [ -n "$LAST_YEAR" ] && [ -n "$LAST_MONTH" ]; then', "\n";
    print $fh_post '                        DBIP_URL="https://download.db-ip.com/free/dbip-city-lite-${LAST_YEAR}-${LAST_MONTH}.mmdb.gz"', "\n";
    print $fh_post '                        if wget -q -O "$DBIP_TEMP_GZ" "$DBIP_URL" 2>/dev/null; then', "\n";
    print $fh_post '                            DOWNLOAD_SUCCESS=1', "\n";
    print $fh_post '                        fi', "\n";
    print $fh_post '                    fi', "\n";
    print $fh_post '                fi', "\n";
    print $fh_post '                if [ "$DOWNLOAD_SUCCESS" = "1" ] && [ -s "$DBIP_TEMP_GZ" ]; then', "\n";
    print $fh_post '                    if gunzip -f "$DBIP_TEMP_GZ"; then', "\n";
    print $fh_post '                        mv /usr/share/perl5/Geo/dbip-city-temp.mmdb "$DBIP_DEST"', "\n";
    print $fh_post '                        chmod 644 "$DBIP_DEST"', "\n";
    print $fh_post '                    fi', "\n";
    print $fh_post '                    rm -f "$DBIP_TEMP_GZ"', "\n";
    print $fh_post '                fi', "\n";
    print $fh_post '            fi', "\n";
    print $fh_post '        fi', "\n";
    print $fh_post '        if [ -f /etc/cron.d/awstats-dbip-update ]; then chmod 644 /etc/cron.d/awstats-dbip-update; fi', "\n";
    print $fh_post '        if [ -f /usr/local/bin/awstats-dbip-update ]; then chmod 755 /usr/local/bin/awstats-dbip-update; fi', "\n";
    print $fh_post '        if [ -f /usr/lib/cgi-bin/awredir.pl ]; then', "\n";
    print $fh_post '            if command -v openssl >/dev/null 2>&1; then', "\n";
    print $fh_post '                KEY=$(openssl rand -hex 16 2>/dev/null)', "\n";
    print $fh_post '                sed -i "s/YOURKEYFORMD5/$KEY/" /usr/lib/cgi-bin/awredir.pl', "\n";
    print $fh_post '            fi', "\n";
    print $fh_post '        fi', "\n";
    print $fh_post '        if [ -x /usr/sbin/a2enmod ]; then', "\n";
    print $fh_post '            a2enmod cgi > /dev/null 2>&1 || true', "\n";
    print $fh_post '            if command -v systemctl >/dev/null 2>&1; then systemctl try-reload-or-restart httpd >/dev/null 2>&1 || true; fi', "\n";
    print $fh_post '        fi', "\n";
    print $fh_post '        ;;', "\n";
    print $fh_post 'esac', "\n";
    print $fh_post 'echo ""', "\n";
    print $fh_post 'echo " AWStats %{version} installation complete"', "\n";
    print $fh_post 'echo " Main directory: /usr/share/awstats"', "\n";
    print $fh_post 'echo " Configuration: /etc/awstats"', "\n";
    print $fh_post 'echo " CGI scripts: /usr/lib/cgi-bin"', "\n";
    print $fh_post 'echo " CLI wrapper: /usr/local/bin/awstats"', "\n";
    print $fh_post 'echo " DB-IP database: /usr/share/perl5/Geo/dbip-city.mmdb"', "\n";
    print $fh_post 'echo " Data directory: /var/lib/awstats"', "\n";
    print $fh_post 'echo " Log directory: /var/log/awstats"', "\n";
    print $fh_post 'echo " No control panel? Try HestiaCP - https://hestiadocs.brepo.ru"', "\n";
    print $fh_post 'echo ""', "\n";
    close $fh_post;

    # postun script
    open my $fh_postun, '>', "$conf_dir/awstats.postun" or die "Cannot write postun script: $!";
    print $fh_postun '#!/bin/sh', "\n";
    print $fh_postun 'if [ "$1" = "0" ]; then', "\n";
    print $fh_postun '    rm -f /usr/share/perl5/Geo/dbip-city.mmdb 2>/dev/null || true', "\n";
    print $fh_postun '    rm -f /usr/share/perl5/Geo/dbip-city.mmdb.bak 2>/dev/null || true', "\n";
    print $fh_postun 'fi', "\n";
    close $fh_postun;

    my $post_content   = do { local $/; open my $f, '<', "$conf_dir/awstats.post"   or die "Cannot read awstats.post: $!";   <$f> };
    my $postun_content = do { local $/; open my $f, '<', "$conf_dir/awstats.postun" or die "Cannot read awstats.postun: $!"; <$f> };
    print "  ✅ Conf files written to: $conf_dir\n";

    my $spec_file = "$TEMP/$PROJECT.spec";
    open my $spec_out, '>', $spec_file or die "Cannot create spec: $!";

    my $ver = "$MAJOR.$MINOR";
    my $rel = $RPMSUBVERSION;

    # spec 头部
    print $spec_out '%define name ', $PROJECT, "\n";
    print $spec_out '%define version ', $ver, "\n";
    print $spec_out '%define release ', $rel, "\n";
    print $spec_out '', "\n";
    print $spec_out 'Name: %{name}', "\n";
    print $spec_out 'Version: %{version}', "\n";
    print $spec_out 'Release: %{release}', "\n";
    print $spec_out 'Source0: %{name}-%{version}.tgz', "\n";
    print $spec_out 'Summary: AWStats Community Edition - powerful and featureful web server logfile analyzer', "\n";
    print $spec_out 'URL: https://github.com/hestiacn/vstats', "\n";
    print $spec_out 'License: GPL', "\n";
    print $spec_out 'Packager: hestiacn <hestiacn@users.noreply.github.com>', "\n";
    print $spec_out 'Vendor: hestiacn', "\n";
    print $spec_out 'BuildArchitectures: noarch', "\n";
    print $spec_out 'Group: Applications/Internet', "\n";
    print $spec_out '', "\n";
    print $spec_out 'Requires: perl >= 1:5.020', "\n";
    print $spec_out 'Requires: perl(JSON::XS)', "\n";
    print $spec_out 'Requires: perl(Try::Tiny)', "\n";
    print $spec_out 'Requires: wget', "\n";
    print $spec_out 'Recommends: cron, httpd, ca-certificates', "\n";
    print $spec_out 'AutoReqProv: yes', "\n";
    print $spec_out '', "\n";

    # %description
    print $spec_out '%description', "\n";
    print $spec_out 'AWStats Community Edition (Advanced Web Statistics) is a free powerful and featureful', "\n";
    print $spec_out 'tool that generates advanced web (but also ftp or mail) server', "\n";
    print $spec_out 'statistics, graphically.', "\n";
    print $spec_out '', "\n";
    print $spec_out 'This log analyzer works as a CGI or from command line and shows you', "\n";
    print $spec_out 'all possible information your log contains, in few graphical web', "\n";
    print $spec_out 'pages like visits, unique visitors, authenticated users, pages,', "\n";
    print $spec_out 'domains/countries, OS busiest times, robot visits, type of files,', "\n";
    print $spec_out 'search engines,keywords and keyphrases used, visits duration,', "\n";
    print $spec_out 'cluster balancing, HTTP errors and also screen size, web browser', "\n";
    print $spec_out 'java,flash,etc support and more...', "\n";
    print $spec_out 'Statistics can be updated from a browser or your scheduler.', "\n";
    print $spec_out 'AWStats uses a partial information file to be able to process large', "\n";
    print $spec_out 'log files, often and quickly.', "\n";
    print $spec_out '', "\n";
    print $spec_out 'It can analyze log files from IIS (W3C log format), Apache log files', "\n";
    print $spec_out '(NCSA combined/XLF/ELF log format or common/CLF log format), WebStar', "\n";
    print $spec_out 'and most of all web, proxy, wap, streaming servers (and ftp servers', "\n";
    print $spec_out 'or mail logs).', "\n";
    print $spec_out 'The program also supports virtual servers, plugins and a lot of', "\n";
    print $spec_out 'features.', "\n";
    print $spec_out '', "\n";

    # %description -l pl
    print $spec_out '%description -l pl', "\n";
    print $spec_out 'AWStats Community Edition (Advanced Web Statistics - zaawansowane statystyki WWW) to', "\n";
    print $spec_out 'potężne i bogate w możliwości narzędzie generujące zaawansowane', "\n";
    print $spec_out 'graficzne statystyki serwera WWW. Ten analizator logów serwera', "\n";
    print $spec_out 'działa z linii poleceń lub jako CGI i pokazuje wszystkie informacje', "\n";
    print $spec_out 'zawarte w logu w postaci graficznych stron WWW. Może analizować logi', "\n";
    print $spec_out 'wielu serwerów WWW/WAP/proxy, takich jak Apache, IIS, Weblogic,', "\n";
    print $spec_out 'Webstar, Squid... ale także serwerów pocztowych lub ftp.', "\n";
    print $spec_out '', "\n";
    print $spec_out 'Ten program może mierzyć odwiedziny, odwiedzających, uwierzytelnionych', "\n";
    print $spec_out 'użytkowników, strony, domeny/kraje, najbardziej zajęte godziny,', "\n";
    print $spec_out 'odwiedziny robotów, rodzaje plików, używane wyszukiwarki i słowa', "\n";
    print $spec_out 'kluczowe, czasy trwania odwiedzin, błędy HTTP... a nawet więcej.', "\n";
    print $spec_out 'Statystyki mogą być uaktualniane z przeglądarki lub schedulera.', "\n";
    print $spec_out 'Program obsługuje także serwery wirtualne, wtyczki i wiele innych', "\n";
    print $spec_out 'rzeczy.', "\n";
    print $spec_out '', "\n";

    # %description -l fr
    print $spec_out '%description -l fr', "\n";
    print $spec_out 'AWStats Community Edition (Advanced Web Statistics) est un outil pour générer des ', "\n";
    print $spec_out 'statistiques avancées d\'un serveur web (mais aussi ftp ou mail)', "\n";
    print $spec_out 'de manière graphique.', "\n";
    print $spec_out '', "\n";
    print $spec_out 'Cet analyseur de log fonctionne en CGI ou en ligne de commande', "\n";
    print $spec_out 'et synthétise toutes les informations que vos logs contiennent en', "\n";
    print $spec_out 'quelques pages comme les visites, visiteurs uniques, logins,', "\n";
    print $spec_out 'pages vues, domaines/pays, heures de pointes, visites des robots, ', "\n";
    print $spec_out 'type de fichiers, moteurs de recherche, mots et phrases clés,', "\n";
    print $spec_out 'durée des visites, répartition clusters, erreurs HTTP mais aussi', "\n";
    print $spec_out 'support java,flash,etc des navigateurs, résolution d\'écran,', "\n";
    print $spec_out 'estimation des ajouts aux favoris, etc...', "\n";
    print $spec_out '', "\n";
    print $spec_out 'Les statistiques peuvent etre mise à jour par un navigateur ou un', "\n";
    print $spec_out 'séquenceur.', "\n";
    print $spec_out 'AWStats génère un fichier d\'informations consolidés pour pouvoir', "\n";
    print $spec_out 'traiter de large sites souvent et rapidement.', "\n";
    print $spec_out '', "\n";
    print $spec_out 'Il peut analyser des logs IIS (W3C log format), fichier log Apache', "\n";
    print $spec_out '(format NCSA combined/XLF/ELF ou format common/CLF), WebStar et la', "\n";
    print $spec_out 'plupart des logs de serveur web, proxy, wap, streaming serveurs', "\n";
    print $spec_out '(et aussi serveurs ftp et de mails).', "\n";
    print $spec_out 'Ce programme supporte de plus les serveurs virtuels, des plugins', "\n";
    print $spec_out 'et de nombreuses fonctionnalités.', "\n";
    print $spec_out '', "\n";

    # %prep
    print $spec_out '%prep', "\n";
    print $spec_out '%setup -q -n %{name}-%{version}', "\n";
    print $spec_out '', "\n";

    # %build
    print $spec_out '%build', "\n";
    print $spec_out '# Nothing to build', "\n";
    print $spec_out '', "\n";

    # %install
    print $spec_out '%install', "\n";
    print $spec_out 'rm -rf $RPM_BUILD_ROOT', "\n";
    print $spec_out '', "\n";
    print $spec_out 'install -D -m 644 %{_confdir}/awstats.httpd.conf       $RPM_BUILD_ROOT/etc/httpd/conf.d/awstats.conf', "\n";
    print $spec_out 'install -D -m 644 %{_confdir}/awstats.logrotate        $RPM_BUILD_ROOT/etc/logrotate.d/awstats', "\n";
    print $spec_out 'install -D -m 644 %{_confdir}/awstats.cron             $RPM_BUILD_ROOT/etc/cron.d/awstats-update', "\n";
    print $spec_out 'install -D -m 755 %{_confdir}/awstats-dbip-update       $RPM_BUILD_ROOT/usr/local/bin/awstats-dbip-update', "\n";
    print $spec_out 'install -D -m 644 %{_confdir}/awstats-dbip-update.cron  $RPM_BUILD_ROOT/etc/cron.d/awstats-dbip-update', "\n";
    print $spec_out 'install -D -m 755 %{_confdir}/awstats.wrapper          $RPM_BUILD_ROOT/usr/local/bin/awstats', "\n";
    print $spec_out 'install -D -m 755 %{_confdir}/awstats-update.wrapper   $RPM_BUILD_ROOT/usr/local/bin/awstats-update', "\n";
    print $spec_out '', "\n";
    print $spec_out 'mkdir -p $RPM_BUILD_ROOT/usr/share/awstats/icon', "\n";
    print $spec_out 'mkdir -p $RPM_BUILD_ROOT/usr/share/awstats/css', "\n";
    print $spec_out 'mkdir -p $RPM_BUILD_ROOT/usr/share/awstats/js', "\n";
    print $spec_out 'mkdir -p $RPM_BUILD_ROOT/usr/share/awstats/classes', "\n";
    print $spec_out 'mkdir -p $RPM_BUILD_ROOT/usr/share/awstats/tools', "\n";
    print $spec_out 'mkdir -p $RPM_BUILD_ROOT/usr/lib/cgi-bin', "\n";
    print $spec_out 'mkdir -p $RPM_BUILD_ROOT/etc/awstats', "\n";
    print $spec_out 'mkdir -p $RPM_BUILD_ROOT/var/lib/awstats', "\n";
    print $spec_out 'mkdir -p $RPM_BUILD_ROOT/var/log/awstats', "\n";
    print $spec_out 'mkdir -p $RPM_BUILD_ROOT/usr/share/perl5/Geo', "\n";
    print $spec_out 'mkdir -p $RPM_BUILD_ROOT/usr/share/doc/awstats', "\n";
    print $spec_out '', "\n";
    print $spec_out 'if [ -d "%{_builddir}/%{name}-%{version}/tools/webmin/awstats" ]; then', "\n";
    print $spec_out '    mkdir -p $RPM_BUILD_ROOT/usr/share/awstats/tools/webmin', "\n";
    print $spec_out '    cd %{_builddir}/%{name}-%{version}/tools/webmin', "\n";
    print $spec_out '    tar -czf awstats-2.0.wbm awstats/', "\n";
    print $spec_out '    cp awstats-2.0.wbm $RPM_BUILD_ROOT/usr/share/awstats/tools/webmin/', "\n";
    print $spec_out '    cd %{_builddir}/%{name}-%{version}', "\n";
    print $spec_out 'fi', "\n";
    print $spec_out '', "\n";
    print $spec_out 'MAXMIND_SRC="%{_builddir}/%{name}-%{version}/wwwroot/cgi-bin/lib/MaxMind"', "\n";
    print $spec_out 'if [ -d "$MAXMIND_SRC" ]; then', "\n";
    print $spec_out '    mkdir -p $RPM_BUILD_ROOT/usr/share/perl5/vendor_perl', "\n";
    print $spec_out '    cp -pr "$MAXMIND_SRC" $RPM_BUILD_ROOT/usr/share/perl5/vendor_perl/', "\n";
    print $spec_out 'else', "\n";
    print $spec_out '    echo "ERROR: MaxMind not found at $MAXMIND_SRC"', "\n";
    print $spec_out '    exit 1', "\n";
    print $spec_out 'fi', "\n";
    print $spec_out '', "\n";
    print $spec_out 'cp -pr %{_builddir}/%{name}-%{version}/docs/* $RPM_BUILD_ROOT/usr/share/doc/awstats/ 2>/dev/null || true', "\n";
    print $spec_out 'cp -pr %{_builddir}/%{name}-%{version}/wwwroot/* $RPM_BUILD_ROOT/usr/share/awstats/ 2>/dev/null || true', "\n";
    print $spec_out 'mv $RPM_BUILD_ROOT/usr/share/awstats/cgi-bin/*.pl     $RPM_BUILD_ROOT/usr/lib/cgi-bin/ 2>/dev/null || true', "\n";
    print $spec_out 'mv $RPM_BUILD_ROOT/usr/share/awstats/cgi-bin/lang     $RPM_BUILD_ROOT/usr/share/awstats/ 2>/dev/null || true', "\n";
    print $spec_out 'mv $RPM_BUILD_ROOT/usr/share/awstats/cgi-bin/lib      $RPM_BUILD_ROOT/usr/share/awstats/ 2>/dev/null || true', "\n";
    print $spec_out 'mv $RPM_BUILD_ROOT/usr/share/awstats/cgi-bin/plugins  $RPM_BUILD_ROOT/usr/share/awstats/ 2>/dev/null || true', "\n";
    print $spec_out 'rm -rf $RPM_BUILD_ROOT/usr/share/awstats/cgi-bin 2>/dev/null || true', "\n";
    print $spec_out 'cp -pr %{_builddir}/%{name}-%{version}/tools $RPM_BUILD_ROOT/usr/share/awstats/ 2>/dev/null || true', "\n";
    print $spec_out 'cp -pr %{_builddir}/%{name}-%{version}/README.md $RPM_BUILD_ROOT/usr/share/awstats/ 2>/dev/null || true', "\n";
    print $spec_out '', "\n";
    print $spec_out 'cp -pr %{_builddir}/%{name}-%{version}/wwwroot/cgi-bin/awstats.conf $RPM_BUILD_ROOT/etc/awstats/awstats.conf.local', "\n";
    print $spec_out 'cp -pr %{_builddir}/%{name}-%{version}/wwwroot/cgi-bin/awstats.model.conf $RPM_BUILD_ROOT/etc/awstats/awstats.model.conf', "\n";
    print $spec_out '', "\n";
    print $spec_out 'if [ -f %{_builddir}/%{name}-%{version}/wwwroot/cgi-bin/lib/IPfree.pm ]; then', "\n";
    print $spec_out '    cp -pr %{_builddir}/%{name}-%{version}/wwwroot/cgi-bin/lib/IPfree.pm $RPM_BUILD_ROOT/usr/share/perl5/Geo/IPfree.pm', "\n";
    print $spec_out '    chmod 644 $RPM_BUILD_ROOT/usr/share/perl5/Geo/IPfree.pm', "\n";
    print $spec_out 'fi', "\n";
    print $spec_out 'if [ -f %{_builddir}/%{name}-%{version}/wwwroot/cgi-bin/lib/IPfree.pod ]; then', "\n";
    print $spec_out '    cp -pr %{_builddir}/%{name}-%{version}/wwwroot/cgi-bin/lib/IPfree.pod $RPM_BUILD_ROOT/usr/share/perl5/Geo/IPfree.pod', "\n";
    print $spec_out '    chmod 644 $RPM_BUILD_ROOT/usr/share/perl5/Geo/IPfree.pod', "\n";
    print $spec_out 'fi', "\n";
    print $spec_out '', "\n";
    print $spec_out 'chmod 644 $RPM_BUILD_ROOT/etc/cron.d/awstats-dbip-update', "\n";
    print $spec_out '', "\n";

    # %clean
    print $spec_out '%clean', "\n";
    print $spec_out 'rm -rf $RPM_BUILD_ROOT', "\n";
    print $spec_out '', "\n";

    # %files
    print $spec_out '%files', "\n";
    print $spec_out '%defattr(-,root,root)', "\n";
    print $spec_out '%config(noreplace) /etc/awstats/awstats.model.conf', "\n";
    print $spec_out '%config(noreplace) /etc/awstats/awstats.conf.local', "\n";
    print $spec_out '%config(noreplace) /etc/httpd/conf.d/awstats.conf', "\n";
    print $spec_out '%config(noreplace) /etc/cron.d/awstats-update', "\n";
    print $spec_out '%config(noreplace) /etc/logrotate.d/awstats', "\n";
    print $spec_out '%config(noreplace) /etc/cron.d/awstats-dbip-update', "\n";
    print $spec_out '/usr/share/doc/awstats/', "\n";
    print $spec_out '/usr/share/awstats/', "\n";
    print $spec_out '/usr/lib/cgi-bin/', "\n";
    print $spec_out '/usr/local/bin/awstats', "\n";
    print $spec_out '/usr/local/bin/awstats-update', "\n";
    print $spec_out '/usr/local/bin/awstats-dbip-update', "\n";
    print $spec_out '/var/lib/awstats', "\n";
    print $spec_out '/var/log/awstats', "\n";
    print $spec_out '/usr/share/perl5/Geo/', "\n";
    print $spec_out '/usr/share/perl5/vendor_perl/MaxMind/', "\n";
    print $spec_out '', "\n";

    # %post / %postun
    print $spec_out '%post -p /bin/sh', "\n";
    print $spec_out $post_content, "\n";
    print $spec_out '', "\n";
    print $spec_out '%postun -p /bin/sh', "\n";
    print $spec_out $postun_content, "\n";
    print $spec_out '', "\n";

    # %changelog
    print $spec_out '%changelog', "\n";
    print $spec_out '* ', $changelog_date, ' Laurent Destailleur <eldy@users.sourceforge.net> %{version}-%{release}', "\n";
    print $spec_out '- Add DB-IP database support with monthly updates', "\n";
    print $spec_out '- Add city-level geolocation support', "\n";
    print $spec_out '- Add mobile device detection', "\n";
    print $spec_out '- Add download statistics with resume support', "\n";

    close $spec_out;
    print "  ✅ Spec generated: $spec_file\n";

    $cmd = "rpmbuild --define '_confdir $conf_dir' --clean -ba '$spec_file' 2>&1 | tee /tmp/rpmbuild.log";
    print "  Running: $cmd\n";
    my $result = system($cmd);

    if ($result != 0) {
        my $exit_code = $result >> 8;
        warn "RPM build failed with code $exit_code";
        print "  RPM build output:\n";
        system("tail -100 /tmp/rpmbuild.log");
        return undef;
    }

    # 查找生成的 RPM
    my $rpm_file = "$RPMDIR/RPMS/noarch/$PROJECT-$version-$RPMSUBVERSION.noarch.rpm";
    if (-f $rpm_file) {
        my $size = -s $rpm_file;
        print "  ✅ RPM package created: $rpm_file (" . int($size/1024) . " KB)\n";
        move($rpm_file, $output) or warn "Failed to move RPM file";
        return $output;
    } else {
        print "  ❌ RPM package not found at: $rpm_file\n";
        system("ls -la $RPMDIR/RPMS/noarch/ 2>/dev/null || echo 'directory not found'");
        return undef;
    }
}

# 构建 DEB 包
sub build_deb {
    my $version = "$MAJOR.$MINOR";
    my $filename = "$PROJECT-$version";
    my $output = "$DESTI/${PROJECT}_$version-${RPMSUBVERSION}_all.deb";
    
    print "\n🔨 Building DEB package: $filename\n";
    print "=" x 60, "\n";
    
    # 步骤1: 检查依赖工具
    print "📋 Step 1: Checking build dependencies...\n";
    my $dpkg_check = system("dpkg-buildpackage --version > /dev/null 2>&1");
    if ($dpkg_check != 0) {
        print "  ❌ dpkg-buildpackage not found. Please install dpkg-dev\n";
        print "  💡 Run: sudo apt-get install dpkg-dev debhelper\n";
        return undef;
    }
    print "  ✅ dpkg-buildpackage found\n";
    
    my $dh_check = system("which dh > /dev/null 2>&1");
    if ($dh_check != 0) {
        print "  ❌ debhelper not found. Please install debhelper\n";
        print "  💡 Run: sudo apt-get install debhelper\n";
        return undef;
    }
    print "  ✅ debhelper found\n";
    
    # 步骤2: 创建构建目录
    print "\n📋 Step 2: Creating build directories...\n";
    my $deb_buildroot = "$BUILDROOT/deb-build";
    my $deb_packageroot = "$deb_buildroot/$filename";
    
    remove_tree($deb_buildroot);
    make_path($deb_packageroot);
    print "  ✅ Build root: $deb_buildroot\n";
    print "  ✅ Package root: $deb_packageroot\n";
    
    # 步骤3: 复制源码
    print "\n📋 Step 3: Copying source files...\n";
    my $src_dir = "$BUILDROOT/$filename";
    if (! -d $src_dir) {
        print "  ❌ Source directory not found: $src_dir\n";
        return undef;
    }
    
    my $copy_cmd = "cp -pr '$src_dir'/* '$deb_packageroot/' 2>&1";
    my $copy_result = `$copy_cmd`;
    if ($? != 0) {
        print "  ❌ Failed to copy source: $copy_result\n";
        return undef;
    }
    print "  ✅ Source files copied\n";
    
    # 步骤4: 解析模板生成 debian 目录
    print "\n📋 Step 4: Generating debian packaging files from template...\n";
    my $spec_template = "$SOURCE/make/deb/awstats.spec";
    if (! -f $spec_template) {
        print "  ❌ DEB spec template not found: $spec_template\n";
        print "  Looking in: " . Cwd::getcwd() . "/make/deb/awstats.spec\n";
        return undef;
    }
    print "  ✅ Using template: $spec_template\n";
    
    # 解析模板并生成文件
    my $gen_result = parse_deb_template($spec_template, $deb_packageroot, $version, $RPMSUBVERSION);
    unless ($gen_result) {
        print "  ❌ Failed to generate debian files\n";
        return undef;
    }
    print "  ✅ Debian files generated\n";
    
    # 步骤5: 验证所有必需文件
    print "\n📋 Step 5: Verifying required files...\n";
    my @required = qw(control changelog compat copyright rules);
    my @optional = qw(postinst prerm preinst install watch);
    my $all_ok = 1;
    
    foreach my $file (@required) {
        if (-f "$deb_packageroot/debian/$file") {
            print "  ✅ $file\n";
        } else {
            print "  ❌ $file MISSING\n";
            $all_ok = 0;
        }
    }
    
    foreach my $file (@optional) {
        if (-f "$deb_packageroot/debian/$file") {
            print "  ✅ $file (optional)\n";
        }
    }
    
    unless ($all_ok) {
        print "  ❌ Required files missing, aborting\n";
        return undef;
    }
    
    # 步骤6: 构建 DEB 包
    print "\n📋 Step 6: Building DEB package...\n";
    print "  Running: dpkg-buildpackage -us -uc -b\n";
    
    chdir($deb_packageroot) or die "Cannot chdir to $deb_packageroot: $!";
    
    my $build_output = `dpkg-buildpackage -us -uc -b 2>&1`;
    my $build_status = $?;
    
    if ($build_status != 0) {
        print "  ❌ Build failed with status: $build_status\n";
        print "  Build output:\n";
        print "-" x 40, "\n";
        print $build_output;
        print "-" x 40, "\n";
        return undef;
    }
    print "  ✅ Build completed successfully\n";
    
    # 步骤7: 查找并移动 .deb 文件
    print "\n📋 Step 7: Locating generated .deb file...\n";
    opendir my $dh, $deb_buildroot or do {
        print "  ❌ Cannot open directory: $deb_buildroot\n";
        return undef;
    };
    
    my $found = 0;
    while (my $file = readdir $dh) {
        if ($file =~ /\.deb$/) {
            my $src = "$deb_buildroot/$file";
            my $size = -s $src;
            print "  ✅ Found: $src (" . int($size/1024) . " KB)\n";
            print "  Moving to: $output\n";
            move($src, $output) or warn "  ❌ Failed to move: $!";
            $found = 1;
            last;
        }
    }
    closedir $dh;
    
    unless ($found) {
        print "  ❌ No .deb file found in $deb_buildroot\n";
        print "  Directory contents:\n";
        system("ls -la $deb_buildroot");
        return undef;
    }
    
    # 步骤8: 验证输出文件
    if (-f $output) {
        my $size = -s $output;
        print "\n✅ DEB package created successfully\n";
        print "📦 $output (" . int($size/1024) . " KB)\n";
        return $output;
    } else {
        print "  ❌ Output file not found: $output\n";
        return undef;
    }
}

# 解析 DEB 模板文件
sub parse_deb_template {
    my ($template_file, $target_root, $version, $release) = @_;
    
    print "  Parsing template: $template_file\n";
    
    open my $fh, '<', $template_file or die "Cannot open template: $template_file";
    my $content = do { local $/; <$fh> };
    close $fh;
    $content =~ s/\r\n/\n/g;
    $content =~ s/\r/\n/g;
    # 替换变量
    my $maintainer = "Laurent Destailleur <eldy\@users.sourceforge.net>";
    my $date = strftime("%a, %d %b %Y %H:%M:%S %z", localtime);
    my $project = $PROJECT || "awstats";
    
    $content =~ s/__VERSION__/$version/g;
    $content =~ s/__RELEASE__/$release/g;
    $content =~ s/__MAINTAINER__/$maintainer/g;
    $content =~ s/__DATE__/$date/g;
    $content =~ s/__PROJECT__/$project/g;
    
    # 解析 [FILE:filename] 块
    my $debian_dir = "$target_root/debian";
    make_path($debian_dir);
    
    my $file_count = 0;
    while ($content =~ /\[FILE:([^\]]+)\]\n(.*?)\n\[FILE:\1\]/gs) {
        my ($filename, $file_content) = ($1, $2);
        my $filepath = "$debian_dir/$filename";
        
        # 确保父目录存在
        my $dir = dirname($filepath);
        make_path($dir) unless -d $dir;
        
        open my $out, '>', $filepath or die "Cannot create $filepath: $!";
        print $out $file_content;
        close $out;
        
        # 设置可执行权限
        if ($filename =~ /^(postinst|prerm|preinst|rules)$/) {
            chmod 0755, $filepath;
            print "    Generated: $filename (executable)\n";
        } else {
            print "    Generated: $filename\n";
        }
        $file_count++;
    }
    
    print "  Generated $file_count files in $debian_dir\n";
    return $file_count > 0;
}

# 构建 FreeBSD PKG 包
sub build_pkg {
    my $version = "$MAJOR.$MINOR";
    my $filename = "$PROJECT-$version";
    my $output = "$DESTI/$PROJECT-$version-$PKGSUBVERSION.pkg";
    
    print "\n🔨 Building FreeBSD package: $filename\n";
    print "=" x 60, "\n";
    
    # --------------------------------------------------------------------------
    # 步骤1: 检查是否在 FreeBSD 系统
    # --------------------------------------------------------------------------
    if ($OS ne 'freebsd') {
        print "  ⚠️ Not running on FreeBSD, skipping pkg build\n";
        print "  💡 FreeBSD packages must be built on FreeBSD system\n";
        return undef;
    }
    print "  ✅ Running on FreeBSD\n";
    
    # --------------------------------------------------------------------------
    # 步骤2: 创建 staging 目录
    # --------------------------------------------------------------------------
    print "\n📋 Step 2: Creating staging directory...\n";
    my $pkg_root = "$BUILDROOT/pkg-stage";
    remove_tree($pkg_root) if -d $pkg_root;
    make_path($pkg_root);
    
    my $src_dir = "$BUILDROOT/$filename";
    if (!-d $src_dir) {
        print "  ❌ Source directory not found: $src_dir\n";
        return undef;
    }
    
    # --------------------------------------------------------------------------
    # 步骤3: 安装文件到 staging 目录 (Step 3: Installing files to staging directory)
    # --------------------------------------------------------------------------
    print "\n📋 Step 3: Installing files to staging directory...\n";

    # 创建干净的 FreeBSD FHS 标准物理目录树
    make_path("$pkg_root/usr/local/www/cgi-bin");
    make_path("$pkg_root/usr/local/share/awstats/classes");
    make_path("$pkg_root/usr/local/share/awstats/css");
    make_path("$pkg_root/usr/local/share/awstats/icon");
    make_path("$pkg_root/usr/local/share/awstats/js");
    make_path("$pkg_root/usr/local/share/awstats/lang");
    make_path("$pkg_root/usr/local/share/awstats/lib");
    make_path("$pkg_root/usr/local/share/awstats/plugins");
    make_path("$pkg_root/usr/local/share/awstats/tools");
    make_path("$pkg_root/usr/local/share/doc/awstats");
    make_path("$pkg_root/usr/local/etc/awstats");
    make_path("$pkg_root/usr/local/bin");
    make_path("$pkg_root/usr/local/etc/periodic/daily");
    make_path("$pkg_root/usr/local/etc/cron.d");
    make_path("$pkg_root/usr/local/lib/perl5/site_perl/Geo");

    # 复制 CGI 脚本到 www/cgi-bin（只复制 .pl 和可执行文件）
    print "  Copying CGI scripts...\n";
    system("cp -pr $src_dir/wwwroot/cgi-bin/awstats.pl $pkg_root/usr/local/www/cgi-bin/");
    system("cp -pr $src_dir/wwwroot/cgi-bin/awredir.pl $pkg_root/usr/local/www/cgi-bin/");
    system("cp -pr $src_dir/wwwroot/cgi-bin/awdownloadcsv.pl $pkg_root/usr/local/www/cgi-bin/");
    system("cp -pr $src_dir/wwwroot/cgi-bin/awstats-update $pkg_root/usr/local/www/cgi-bin/");
    die "Failed to copy CGI scripts" if $? != 0;

    # 复制静态资源到 share/awstats
    print "  Copying classes...\n";
    system("cp -pr $src_dir/wwwroot/classes/. $pkg_root/usr/local/share/awstats/classes/");
    die "Failed to copy classes" if $? != 0;

    print "  Copying css...\n";
    system("cp -pr $src_dir/wwwroot/css/. $pkg_root/usr/local/share/awstats/css/");
    die "Failed to copy css" if $? != 0;

    print "  Copying icon...\n";
    system("cp -pr $src_dir/wwwroot/icon/. $pkg_root/usr/local/share/awstats/icon/");
    die "Failed to copy icon" if $? != 0;

    print "  Copying js...\n";
    system("cp -pr $src_dir/wwwroot/js/. $pkg_root/usr/local/share/awstats/js/");
    die "Failed to copy js" if $? != 0;

    # 复制库文件到 share/awstats
    print "  Copying lang...\n";
    system("cp -pr $src_dir/wwwroot/cgi-bin/lang/. $pkg_root/usr/local/share/awstats/lang/");
    die "Failed to copy lang" if $? != 0;

    print "  Copying lib...\n";
    system("cp -pr $src_dir/wwwroot/cgi-bin/lib/. $pkg_root/usr/local/share/awstats/lib/");
    die "Failed to copy lib" if $? != 0;

    system("cp -pr $src_dir/wwwroot/cgi-bin/lib/IPfree.pm $pkg_root/usr/local/lib/perl5/site_perl/Geo/");
    system("cp -pr $src_dir/wwwroot/cgi-bin/lib/IPfree.pod $pkg_root/usr/local/lib/perl5/site_perl/Geo/");
    print "  Copying IPfree to Geo directory...\n";

    print "  Copying plugins...\n";
    system("cp -pr $src_dir/wwwroot/cgi-bin/plugins/. $pkg_root/usr/local/share/awstats/plugins/");
    die "Failed to copy plugins" if $? != 0;

    # 复制工具脚本
    print "  Copying tools...\n";
    system("cp -pr $src_dir/tools/. $pkg_root/usr/local/share/awstats/tools/");
    die "Failed to copy tools" if $? != 0;

    print "  Copying docs...\n";
    system("cp -pr $src_dir/docs/. $pkg_root/usr/local/share/doc/awstats/");
    die "Failed to copy docs" if $? != 0;

    # 复制说明文档
    foreach my $readme (qw(README.md README-*.md)) {
        if (-f "$src_dir/$readme") {
            copy("$src_dir/$readme", "$pkg_root/usr/local/share/doc/awstats/");
        }
    }

    # 初始默认配置文件对齐
    copy("$src_dir/wwwroot/cgi-bin/awstats.model.conf", "$pkg_root/usr/local/etc/awstats/awstats.model.conf");
    copy("$src_dir/wwwroot/cgi-bin/awstats.conf", "$pkg_root/usr/local/etc/awstats/awstats.conf.local");

    # CLI 命令层面的可执行包装脚本
    open my $wf, '>', "$pkg_root/usr/local/bin/awstats";
    print $wf "#!/bin/sh\n";
    print $wf "exec /usr/local/bin/perl /usr/local/www/cgi-bin/awstats.pl \"\$@\"\n";
    close $wf;
    chmod 0755, "$pkg_root/usr/local/bin/awstats";

    # awstats-update 包装脚本
    open my $uf, '>', "$pkg_root/usr/local/bin/awstats-update";
    print $uf "#!/bin/sh\n";
    print $uf "# /usr/local/bin/awstats-update - Wrapper for awstats_updateall.pl\n";
    print $uf "exec /usr/local/share/awstats/tools/awstats_updateall.pl \"\$@\"\n";
    close $uf;
    chmod 0755, "$pkg_root/usr/local/bin/awstats-update";

    # periodic 每日自动定时执行计划
    open my $pf, '>', "$pkg_root/usr/local/etc/periodic/daily/awstats-update";
    print $pf "#!/bin/sh\n";
    print $pf "# AWStats daily update\n";
    print $pf "/usr/local/bin/perl /usr/local/share/awstats/tools/awstats_updateall.pl now 2>/dev/null\n";
    close $pf;
    chmod 0755, "$pkg_root/usr/local/etc/periodic/daily/awstats-update";
    print "Files installed\n";
    system("ln -sf /usr/local/bin/perl /usr/bin/perl");

    # --------------------------------------------------------------------------
    # 创建每月自动执行的 DB-IP 城市级地理数据库更新脚本
    # --------------------------------------------------------------------------
    print "\nCreating DB-IP update script...\n";
    open my $dbip_fh, '>', "$pkg_root/usr/local/bin/awstats-dbip-update";
    print $dbip_fh <<'EOF';
#!/bin/sh
# ------------------------------------------------------------------------------
# Generated by AWStats, do not edit manually
# 由 AWStats 自动生成，请勿手动编辑
# To disable automatic updates, rename this file so you can re-enable it later if needed.
# 若需禁用自动更新，请将此文件重命名！以便后续启用此功能！
# ------------------------------------------------------------------------------
YEAR_MONTH=$(date +%Y-%m)
DBIP_DIR="/usr/local/lib/perl5/site_perl/Geo"
DBIP_DEST="$DBIP_DIR/dbip-city.mmdb"
DBIP_TEMP="$DBIP_DIR/dbip-city.mmdb.tmp"
LOG_FILE="/var/log/dbip-update.log"

if [ -f "$LOG_FILE" ] && [ $(cat "$LOG_FILE" | wc -l) -gt 30 ]; then
    tail -n 30 "$LOG_FILE" > "$LOG_FILE.tmp"
    mv "$LOG_FILE.tmp" "$LOG_FILE"
fi

mkdir -p "$DBIP_DIR"
cd "$DBIP_DIR"

if ! command -v fetch > /dev/null 2>&1; then
    echo "$(date): fetch not installed, skipping update" >> "$LOG_FILE"
    exit 1
fi

fetch -o "$DBIP_TEMP.gz" "https://download.db-ip.com/free/dbip-city-lite-${YEAR_MONTH}.mmdb.gz" 2>/dev/null
if [ ! -s "$DBIP_TEMP.gz" ]; then
    LAST_MONTH=$(date -v-1m +%Y-%m 2>/dev/null || date -d "1 month ago" +%Y-%m 2>/dev/null)
    if [ -n "$LAST_MONTH" ]; then
        echo "$(date): Current month ${YEAR_MONTH} not available, trying ${LAST_MONTH}" >> "$LOG_FILE"
        fetch -o "$DBIP_TEMP.gz" "https://download.db-ip.com/free/dbip-city-lite-${LAST_MONTH}.mmdb.gz" 2>/dev/null
        if [ -s "$DBIP_TEMP.gz" ]; then
            echo "$(date): Downloaded ${LAST_MONTH} instead" >> "$LOG_FILE"
        fi
    fi
fi
if [ -s "$DBIP_TEMP.gz" ]; then
    gunzip -f "$DBIP_TEMP.gz"
fi

if [ -s "$DBIP_TEMP" ]; then
    mv "$DBIP_TEMP" "$DBIP_DEST"
    chmod 644 "$DBIP_DEST"
    echo "$(date): Updated to ${YEAR_MONTH}" >> "$LOG_FILE"
else
    rm -f "$DBIP_TEMP" "$DBIP_TEMP.gz"
    echo "$(date): Update failed for ${YEAR_MONTH}" >> "$LOG_FILE"
fi
EOF
    close $dbip_fh;
    chmod 0755, "$pkg_root/usr/local/bin/awstats-dbip-update";

    open my $dbip_cron_fh, '>', "$pkg_root/etc/cron.d/awstats-dbip-update";
    print $dbip_cron_fh <<'EOF';
# Update DB-IP database monthly on the 3rd at 3:00 AM
0 3 3 * * root /usr/local/bin/awstats-dbip-update > /dev/null 2>&1
EOF
    close $dbip_cron_fh;
    chmod 0644, "$pkg_root/etc/cron.d/awstats-dbip-update";

    print "  Created cron entry at /etc/cron.d/awstats-dbip-update\n";
    print "  Verifying files...\n";
    my $file_count = 0;
    use File::Find;
    find(sub { 
        return if $_ eq '.' || $_ eq '..';
        $file_count++ if -f $File::Find::name && $File::Find::name !~ /\/\+/;
    }, $pkg_root);
    print "  Total files in staging (excluding metadata): $file_count\n";
        
    # --------------------------------------------------------------------------
    # 步骤4: 初始化并生成核心清单 +MANIFEST
    # --------------------------------------------------------------------------
    print "\n📋 Step 4: Generating package manifest...\n";
    
    my $meta_stage = "/tmp/awstats-buildroot/meta-stage";
    system("rm -rf '$meta_stage' && mkdir -p '$meta_stage'") == 0 or die "Cannot initialize meta-stage dir: $!";
    
    my $manifest_file = "$meta_stage/+MANIFEST";
    open my $mf, '>', $manifest_file or die "Cannot create $manifest_file: $!";

    use POSIX qw(strftime);
    my $build_timestamp = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime);
    my $build_date      = strftime("%Y-%m-%d %H:%M:%S", localtime);

    my $pkg_version = $version;
    if ($PKGSUBVERSION && $PKGSUBVERSION > 0) {
        $pkg_version .= "_$PKGSUBVERSION";
    }

    my $arch = `uname -m`; chomp $arch;
    my $os_version = `freebsd-version | cut -d. -f1`; chomp $os_version;
    my $freebsd_version = "$os_version:$arch";

    print $mf "name: $PROJECT\n";
    print $mf "version: $pkg_version\n";
    print $mf "origin: www/$PROJECT\n";
    print $mf "comment: Advanced Web Statistics Community Edition\n";
    print $mf "maintainer: hestiacn\@tuta.io\n";
    print $mf "www: https://awstats.org\n";
    print $mf "prefix: /usr/local\n";
    print $mf "licenses: [GPLv3]\n";
    print $mf "categories: [www]\n";
    print $mf "arch: $freebsd_version\n" if $freebsd_version;
    
    print $mf "options: {\n";
    print $mf "    JSON: on,\n";
    print $mf "    GEOIPFREE: on,\n";
    print $mf "    IPV6: on,\n";
    print $mf "    UTF8: on\n";
    print $mf "}\n";
    
    print $mf "annotations: {\n";
    print $mf "    build_timestamp: \"$build_timestamp\",\n";
    print $mf "    build_date: \"$build_date\",\n";
    print $mf "    built_by: \"hestia-automation-builder-v1\",\n";
    print $mf "    cpe: \"cpe:2.3:a:hestiacn:awstats:$pkg_version:::::freebsd15:x64:1\"\n";
    print $mf "}\n";
    
    print $mf "deps: {\n";
    print $mf "    perl5: { origin: \"lang/perl5\" },\n";
    print $mf "    p5-JSON-XS: { origin: \"converters/p5-JSON-XS\" },\n";
    print $mf "    p5-Try-Tiny: { origin: \"lang/p5-Try-Tiny\" },\n";
    print $mf "    p5-MaxMind-DB-Common: { origin: \"net/p5-MaxMind-DB-Common\" },\n";
    print $mf "    p5-MaxMind-DB-Reader: { origin: \"net/p5-MaxMind-DB-Reader\" },\n";
    print $mf "    p5-MaxMind-DB-Reader-XS: { origin: \"net/p5-MaxMind-DB-Reader-XS\" },\n";
    print $mf "    wget: { origin: \"ftp/wget\" }\n";
    print $mf "}\n";
    print $mf "\n";
    print $mf "desc: <<EOD\n";
    print $mf "AWStats is short for Advanced Web Statistics. It's a free tool that
    generates advanced web (but also ftp or mail) server statistics,
    graphically.\n";
    print $mf "\n";
    print $mf "This log analyzer works as a CGI or from command line and shows you
    all possible information that your logs contain, in a few graphical
    web pages. It uses a partial information file to be able to process
    large log files, often and quickly.\n";
    print $mf "\n";
    print $mf "It can analyze log files from IIS (W3C log format), Apache log files
    (NCSA combined/XLF/ELF log format or common/CLF log format), WebStar
    and most of all web, proxy, WAP, and streaming servers (and FTP
    servers or mail logs).\n";
    print $mf "EOD\n";
    close $mf;

    print "  Manifest version: $pkg_version\n";
    print "  Architecture: $freebsd_version\n" if $freebsd_version;
    print "  ✅ Created +MANIFEST inside metadata directory\n";

    # --------------------------------------------------------------------------
    # 步骤5: 生成安装包依赖文件列表清单 +PLIST
    # --------------------------------------------------------------------------
    print "\n📋 Step 5: Generating PLIST...\n";
    my $plist_file = "$meta_stage/+PLIST";
    open my $pfh, '>', $plist_file or die "Cannot create $plist_file: $!";

    my @files = ();
    find(sub {
        return if $_ eq '.' || $_ eq '..';
        my $fullpath = $File::Find::name;
        my $relpath = $fullpath;
        $relpath =~ s/^\Q$pkg_root\E//;
        $relpath =~ s|^/||;
        $relpath =~ s|^usr/local/||;
        
        if (-f $fullpath && $fullpath !~ /\/\+/ && $fullpath !~ /\.meta/) {
            push @files, $relpath;
        }
    }, $pkg_root);

    foreach my $file (sort @files) {
        print $pfh "$file\n";
    }
    close $pfh;
    print "  ✅ Created +PLIST (" . scalar(@files) . " files)\n";
    
    # --------------------------------------------------------------------------
    # 创建符合 FreeBSD 包管理器标准的安装后脚本 +POST_INSTALL
    # --------------------------------------------------------------------------
    print "\n📋 Creating POST_INSTALL script...\n";
    my $postinstall_file = "$meta_stage/+POST_INSTALL";
    open my $pi, '>', $postinstall_file or die "Cannot create $postinstall_file: $!";
    print $pi <<'EOF';
#!/bin/sh
mkdir -p /usr/local/lib/perl5/site_perl/Geo

DBIP_DIR="/usr/local/lib/perl5/site_perl/Geo"
DBIP_DEST="$DBIP_DIR/dbip-city.mmdb"

if [ ! -f "$DBIP_DEST" ]; then
    echo "Downloading GeoIP database..."
    
    YEAR=$(date +%Y)
    MONTH=$(date +%m)
    DBIP_URL="https://download.db-ip.com/free/dbip-city-lite-${YEAR}-${MONTH}.mmdb.gz"
    DBIP_TEMP_GZ="$DBIP_DIR/dbip-city-temp.mmdb.gz"
    DBIP_TEMP="$DBIP_DIR/dbip-city-temp.mmdb"
    
    if command -v fetch > /dev/null 2>&1; then
        fetch -o "$DBIP_TEMP_GZ" "$DBIP_URL" 2>/dev/null
        if [ ! -s "$DBIP_TEMP_GZ" ]; then
            LAST_YEAR=$(date -v-1m +%Y 2>/dev/null || date -d "1 month ago" +%Y 2>/dev/null)
            LAST_MONTH=$(date -v-1m +%m 2>/dev/null || date -d "1 month ago" +%m 2>/dev/null)
            DBIP_URL="https://download.db-ip.com/free/dbip-city-lite-${LAST_YEAR}-${LAST_MONTH}.mmdb.gz"
            echo "Current month not available, trying ${LAST_YEAR}-${LAST_MONTH}..."
            fetch -o "$DBIP_TEMP_GZ" "$DBIP_URL" 2>/dev/null
        fi
        
        if [ -s "$DBIP_TEMP_GZ" ]; then
            gunzip -f "$DBIP_TEMP_GZ" && \
            mv "$DBIP_TEMP" "$DBIP_DEST" && \
            chmod 644 "$DBIP_DEST" && \
            echo "✓ GeoIP database downloaded successfully"
        else
            rm -f "$DBIP_TEMP_GZ"
            echo "⚠️ Failed to download GeoIP database"
        fi
    else
        echo "⚠️ fetch not installed, skipping GeoIP database download"
    fi
fi

# 生成 awredir.pl 的随机密钥
if [ -f /usr/local/www/cgi-bin/awredir.pl ]; then
    echo "Generating random key for awredir.pl..."
    if command -v openssl > /dev/null 2>&1; then
        KEY=$(openssl rand -hex 16 2>/dev/null)
    else
        KEY=$(perl -e 'print int(rand(2**32))' 2>/dev/null)
    fi
    
    if [ -n "$KEY" ]; then
        sed -i '' "s/YOURKEYFORMD5/$KEY/" /usr/local/www/cgi-bin/awredir.pl
        echo "✓ Random key generated for awredir.pl"
    fi
fi

echo ""
echo "=========================================="
echo " AWStats 8.1-1 UTF-8 installation complete"
echo "=========================================="
echo " Main directory:     /usr/local/share/awstats"
echo " CGI scripts:        /usr/local/www/cgi-bin/"
echo " Configuration:      /usr/local/etc/awstats/"
echo " Tools:              /usr/local/share/awstats/tools/"
echo " Documentation:      /usr/local/share/doc/awstats/"
echo "=========================================="
echo " Configuration steps:"
echo " 1. cp /usr/local/etc/awstats/awstats.model.conf \\"
echo "    /usr/local/etc/awstats/awstats.yourdomain.conf"
echo " 2. Edit the configuration file, set LogFile, SiteDomain, etc."
echo " 3. Update statistics: /usr/local/bin/awstats -config=yourdomain -update"
echo " 4. Access: http://yourdomain/cgi-bin/awstats.pl?config=yourdomain"
echo "=========================================="
echo " Scheduled tasks:"
echo "   Daily update:   /usr/local/etc/periodic/daily/awstats"
echo "   Monthly DB update: /usr/local/etc/cron.d/awstats-dbip-update"
echo "   (Added to /var/cron/tabs/: 0 5 3 * * root ...)"
echo "=========================================="
EOF
    close $pi;
    chmod 0755, $postinstall_file;
    print "  ✅ Created +POST_INSTALL inside metadata directory\n";

    # --------------------------------------------------------------------------
    # 步骤6: 调用 FreeBSD 包编译器创建成品安装包
    # --------------------------------------------------------------------------
    print "\n📋 Step 6: Creating package...\n";
    chdir($BUILDROOT);
    
    my $cmd = "pkg create -m '$meta_stage' -r '$pkg_root' -p '$meta_stage/+PLIST' -o '$DESTI' 2>&1";
    print "  Running: $cmd\n";
    my $result = system($cmd);

    if ($result != 0) {
        print "  ❌ Package creation failed\n";
        return undef;
    }

    my $dh;
    my @pkgs;

    opendir($dh, $DESTI);
    @pkgs = grep { /\.pkg$/ && -f "$DESTI/$_" } readdir($dh);
    closedir($dh);

    my @sorted = sort { -s "$DESTI/$b" <=> -s "$DESTI/$a" } @pkgs;
    my $found = $sorted[0];

    use File::Basename qw(basename);
    use File::Copy qw(move);

    if ($found) {
        my $pkg_file = "$DESTI/$found";
        print "  Found package: $found (" . (-s $pkg_file) . " bytes)\n";
        
        my $target_base = basename($output);
        if ($found ne $target_base) {
            unlink($output) if -f $output;
            move($pkg_file, $output);
            print "  ✅ Renamed to: $target_base\n";
        }
    }

    # --------------------------------------------------------------------------
    # 步骤7: 查找并严密验证最终生成的二进制包 (确保通过 GitHub Actions 流程断检)
    # --------------------------------------------------------------------------
    print "\n📋 Step 7: Locating and verifying generated package...\n";
    print "  DESTI = $DESTI\n";
    print "  Checking directory contents:\n";
    system("ls -la $DESTI");
    print "\n";

    opendir($dh, $DESTI);
    @pkgs = grep { /\.pkg$/ && -f "$DESTI/$_" } readdir($dh);
    closedir($dh);

    print "  Found packages: " . join(", ", @pkgs) . "\n";

    if (@pkgs) {
        my $final_pkg = $pkgs[0];
        my $size = -s "$DESTI/$final_pkg";
        print "  ✅ Package created: $final_pkg (" . int($size/1024) . " KB)\n";
        
        my $target_base = basename($output);
        if ($final_pkg ne $target_base) {
            move("$DESTI/$final_pkg", $output);
            print "  ✅ Renamed to: $target_base\n";
        }
        
        # 终极物理落盘安全阻断检查
        if (-f $output) {
            print "  ✅ Verified: $output successfully generated and verified!\n";
            return $output;
        } else {
            print "  ❌ Warning: $output does not exist after final move\n";
        }
    }
    
    return undef;
}

# 构建 EXE 包
sub build_exe {
    my $version = "$MAJOR.$MINOR";
    my $filename = "$PROJECT-$version";
    my $output_file = "$DESTI/$filename.exe";
    
    print "\n🔨 Building EXE package: $filename\n";
    print "=" x 60, "\n";
    
    # 步骤0：强制检查 NSIS
    print "📋 Step 0: Force checking NSIS...\n";
    my $nsis = $REQUIREMENTS{EXE};
    my $makensis_path = '';
    
    foreach my $path (split(/;/, $ENV{PATH})) {
        my $test = "$path\\makensis.exe";
        if (-f $test) {
            $makensis_path = $test;
            last;
        }
    }
    
    if ($makensis_path) {
        print "  ✅ NSIS found at: $makensis_path\n";
        $nsis = $makensis_path;
    } else {
        print "  ❌ NSIS not found, skipping\n";
        return undef;
    }
    
    # 步骤1：检查环境
    print "\n📋 Step 1: Checking environment...\n";
    print "  OS: $OS\n";
    print "  Source dir: $SOURCE\n";
    print "  Output dir: $DESTI\n";
    
    # 检查 Windows 环境
    if ($OS ne 'windows') {
        print "  ❌ EXE package can only be built on Windows\n";
        return undef;
    }
    print "  ✅ Windows environment OK\n";
    
    # 步骤2：检查 NSI 文件
    print "\n📋 Step 2: Checking NSI file...\n";
    my $nsi_file = File::Spec->catfile($SOURCE, 'make', 'exe', "$PROJECT.nsi");
    print "  Looking for: $nsi_file\n";
    
    unless (-f $nsi_file) {
        print "  ❌ NSI file not found\n";
        my $exe_dir = File::Spec->catfile($SOURCE, 'make', 'exe');
        if (-d $exe_dir) {
            if (opendir(my $dh, $exe_dir)) {
                while (my $f = readdir $dh) {
                    print "    - $f\n" if $f !~ /^\./;
                }
                closedir $dh;
            }
        }
        return undef;
    }
    print "  ✅ NSI file found\n";
    
    # 步骤3：检查构建目录
    print "\n📋 Step 3: Checking build directory...\n";
    my $build_dir = "$BUILDROOT/$PROJECT-$version";
    unless (-d $build_dir) {
        print "  ❌ Build directory not found: $build_dir\n";
        return undef;
    }
    print "  ✅ Build directory exists\n";
    
    # 清理旧的 exe
    unlink "$filename.exe";
    if (-f "$SOURCE/make/exe/$filename.exe") {
        unlink "$SOURCE/make/exe/$filename.exe";
    }
    
    # 步骤4：运行 NSIS
    print "\n📋 Step 4: Running NSIS...\n";
    my $command = "\"$nsis\" /DMUI_VERSION_DOT=$version \"$nsi_file\"";
    print "  Command: $command\n";
    
    my $nsis_result = `$command 2>&1`;
    my $nsis_status = $?;  
    
    print "  NSIS output:\n";
    print "-" x 40, "\n";
    print $nsis_result;
    print "-" x 40, "\n";
    print "  Exit code: $nsis_status\n";
    
    if ($nsis_status != 0) {
        print "  ❌ NSIS failed with code: $nsis_status\n";
        return undef;
    }
    
    # 步骤5：查找生成的 exe
    print "\n📋 Step 5: Locating generated EXE...\n";
    my $exe_file = File::Spec->catfile($SOURCE, 'make', 'exe', "$filename.exe");
    print "  Looking for: $exe_file\n";
    
    if (-f $exe_file) {
        my $size = -s $exe_file;
        print "  ✅ EXE found, size: " . int($size/1024) . " KB\n";
        move($exe_file, $output_file) or warn "  ❌ Failed to move: $!";
        print "  ✅ Moved to: $output_file\n";
        return $output_file;
    } else {
        print "  ❌ EXE not found\n";
        return undef;
    }
}

# 主函数
sub main {
    my $help = 0;
    my $targets = '';
    my $publish = 0;
    
    GetOptions(
        'help|?'     => \$help,
        'target=s'   => \$targets,
        'publish'    => \$publish
    ) or die "Invalid options";
    
    if ($help) {
        print <<"USAGE";
Usage: $0 [options]
Options:
  --target=LIST   Comma-separated list of targets (TGZ,ZIP,RPM,DEB,PKG,EXE)
  --publish       Publish to GitHub releases
  --help          Show this help

Examples:
  $0 --target=TGZ,ZIP
  $0 --target=RPM,DEB,PKG
  $0 --target=all --publish
USAGE
        exit 0;
    }
    
    init();
    
    my ($tag, $commit, $date) = get_git_version($SOURCE);
    print "Git tag: $tag\n";
    print "Commit: $commit\n";
    print "Date: $date\n\n";
    
    prepare_buildroot();
    
    my @build_targets;
    if ($targets) {
        if (lc($targets) eq 'all') {
            @build_targets = @TARGETS;
        } else {
            @build_targets = split(/[,\s]+/, uc($targets));
        }
    } else {
        @build_targets = @TARGETS;
    }
    
    my @built_files;
    foreach my $target (@build_targets) {
        next unless check_requirements($target);
        
        my $file;
        if ($target eq 'TGZ') {
            $file = build_tgz();
        }
        elsif ($target eq 'ZIP') {
            $file = build_zip();
        }
        elsif ($target eq 'RPM') {
            $file = build_rpm();
        }
        elsif ($target eq 'DEB') {
            $file = build_deb();
        }
        elsif ($target eq 'PKG') {
            $file = build_pkg();
        }
        elsif ($target eq 'EXE') {
            $file = build_exe();
        }
        else {
            print "Unknown target: $target\n";
            next;
        }
        
        if ($file && -f $file) {
            push @built_files, $file;
            print "✓ Built $target: $file\n";
        }
    }
    
    if (@built_files) {
        my $checksum_file = generate_checksums(@built_files);
        push @built_files, $checksum_file;
    }
    
    if ($publish && @built_files) {
        print "\n" . "=" x 60 . "\n";
        print "GitHub Release\n";
        print "=" x 60 . "\n";
        
        my $new_version = "$MAJOR.$MINOR";
        my $new_tag = "v$new_version";
        
        my $release_notes = generate_release_notes($SOURCE, $tag, $new_tag);
        publish_with_gh_cli($new_version, $release_notes, @built_files);
    }
    
    print "\n" . "=" x 60 . "\n";
    print "Summary\n";
    print "=" x 60 . "\n";
    
    foreach my $file (@built_files) {
        my $size = -s $file;
        printf "✓ %s (%d bytes)\n", $file, $size;
    }
    
    print "\nBuild completed\n";
}

main();
exit 0;