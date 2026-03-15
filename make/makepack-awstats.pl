#!/usr/bin/perl
#----------------------------------------------------------------------------
# \file         make/makepack-awstats.pl
# \brief        Package builder (tgz, zip, rpm, deb, exe) with Git automation
# \author       (c)2004-2026 Laurent Destailleur  <eldy@users.sourceforge.net>
#----------------------------------------------------------------------------

use strict;
use warnings;
use v5.20;
use Cwd;
use experimental qw(declared_refs);
use File::Path qw(remove_tree make_path);
use File::Copy;
use File::Basename;
use Getopt::Long;
use POSIX qw/strftime/;
use Digest::SHA qw(sha256_hex);
use Cwd qw(abs_path);
use File::Spec;

# 检测运行环境
my $IS_GITHUB_ACTIONS = $ENV{GITHUB_ACTIONS} ? 1 : 0;
my $IS_WINDOWS = ($^O =~ /win32/i) ? 1 : 0;

print "运行环境: " . ($IS_GITHUB_ACTIONS ? "GitHub Actions" : "本地") . "\n";
print "操作系统: " . ($IS_WINDOWS ? "Windows" : "Unix-like") . "\n";

# 项目配置
my $PROJECT = "awstats";
my $RPMSUBVERSION = "1";
my $WBMVERSION = "2.0";
my @TARGETS = ("TGZ", "ZIP", "RPM", "DEB");
my $GITHUB_REPO = "hestiacn/vstats";

# 工具依赖
my %REQUIREMENTS = (
    "TGZ" => "tar",
    "ZIP" => "7z",
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
    if ($^O =~ /linux/i || (-d "/etc" && -d "/var" && $^O !~ /cygwin/i)) { 
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
- [DEB Package](https://github.com/$GITHUB_REPO/releases/download/v$MAJOR.$MINOR/${PROJECT}_$MAJOR.$MINOR\_all.deb)

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
    } elsif ($OS eq 'linux' || $OS eq 'macosx') {
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
    print "Preparing build directory...\n";
    
    remove_tree($BUILDROOT) if -d $BUILDROOT;
    make_path($BUILDROOT);
    
    my $target_dir = "$BUILDROOT/$PROJECT-$MAJOR.$MINOR";
    make_path($target_dir);
    
    # 复制所有需要的目录
    my @dirs = qw(README.md docs tools wwwroot);
    foreach my $item (@dirs) {
        my $src = File::Spec->catfile($SOURCE, $item);
        if (-e $src) {
            print "Copying $item...\n";
            system("cp -pr '$src' '$target_dir/'");
        } else {
            print "Warning: $src not found\n";
        }
    }
    
    # 显式复制配置文件（确保它们存在）
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
    
    # 验证文件是否复制成功
    print "Verifying config files in buildroot:\n";
    system("ls -la $target_dir/wwwroot/cgi-bin/ | grep -E 'awstats\\.conf|awstats\\.model\\.conf' || echo '  ⚠️ Config files missing!'");
    
    # 执行完整清理（简化版）
    cleanup_buildroot($BUILDROOT, "$MAJOR.$MINOR");
    
    print "Build directory ready: $target_dir\n\n";
}

# 完整清理函数
sub cleanup_buildroot {
    my ($build_dir, $version) = @_;
    
    my $target_dir = "$build_dir/$PROJECT-$version";
    print "Cleaning files in $target_dir...\n";
    
    # 通用清理
    my @patterns = (
        'ChangeLog', '.cvsignore', '*.inc', '*.demo.conf',
        '*.mail.conf', '*.ftp.conf', '*.test*.conf', 'Thumbs.db',
        'CVS*', '.svn', '.git', '*.bak', '*~', '*.old'
    );
    
    foreach my $pattern (@patterns) {
        system("find '$target_dir' -name '$pattern' -exec rm -rf {} \\; 2>/dev/null");
    }
    
    # 旧版本中的特定文件清理
    my @specific_files = (
        "$target_dir/ChangeLog",
        "$target_dir/docs/awstats_loganalysispaper.html",
        "$target_dir/tools/urlalias.txt",
        "$target_dir/tools/xferlogconvert.pl",
        "$target_dir/tools/xslt/awstats*.sps",
        "$target_dir/tools/xslt/gen*.*",
        "$target_dir/wwwroot/cgi-bin/*.inc",
        # "$target_dir/wwwroot/cgi-bin/$PROJECT.conf",
        "$target_dir/wwwroot/cgi-bin/$PROJECT.demo.conf",
        "$target_dir/wwwroot/cgi-bin/$PROJECT.mail.conf",
        "$target_dir/wwwroot/cgi-bin/$PROJECT.ftp.conf",
        "$target_dir/wwwroot/cgi-bin/$PROJECT.www*.conf",
        "$target_dir/wwwroot/cgi-bin/$PROJECT.map24.conf",
        "$target_dir/wwwroot/cgi-bin/$PROJECT.common.conf",
        "$target_dir/wwwroot/cgi-bin/$PROJECT.test*.conf",
        "$target_dir/wwwroot/cgi-bin/$PROJECT.*com.conf",
        "$target_dir/wwwroot/cgi-bin/$PROJECT.*net.conf",
        "$target_dir/wwwroot/cgi-bin/$PROJECT??????.txt",
        "$target_dir/wwwroot/cgi-bin/$PROJECT??.*",
        "$target_dir/wwwroot/cgi-bin/$PROJECT*.athena.*",
        "$target_dir/wwwroot/cgi-bin/smallprof.*",
        "$target_dir/wwwroot/cgi-bin/.smallprof*",
        "$target_dir/wwwroot/cgi-bin/plugins/etf1*",
        "$target_dir/wwwroot/cgi-bin/plugins/readgz*",
        "$target_dir/wwwroot/cgi-bin/plugins/urlalias.txt",
        "$target_dir/wwwroot/cgi-bin/plugins/detectrefererspam.pm",
        "$target_dir/wwwroot/cgi-bin/plugins/testxxx.pm",
        "$target_dir/wwwroot/classes/src/AWGraphApplet.class",
    );
    
    foreach my $file (@specific_files) {
        system("rm -f $file 2>/dev/null");
    }
    
    # 删除特定目录
    my @remove_dirs = (
        "$target_dir/wwwroot/cgi-bin/plugins/testgeo*",
        "$target_dir/wwwroot/cgi-bin/plugins/Geo",
        "$target_dir/wwwroot/php",
        "$target_dir/make",
        "$target_dir/test",
    );
    
    foreach my $dir (@remove_dirs) {
        system("rm -fr $dir 2>/dev/null");
    }
    
    # 处理 webmin 目录
    if (-d "$target_dir/tools/webmin/awstats") {
        system("rm -fr $target_dir/tools/webmin/awstats 2>/dev/null");
    }
    
    # 检查 WBM 文件
    my $wbm_file = "$target_dir/tools/webmin/awstats-$WBMVERSION.wbm";
    if (! -f $wbm_file) {
        print "⚠ Warning: WBM file not found: $wbm_file\n";
        print "  You may need to run makepack-awstats_webmin.pl first\n";
    }
}

# 检查依赖工具
sub check_requirements {
    my $target = shift;
    my $req = $REQUIREMENTS{$target};
    
    print "Checking requirement for $target: $req... ";
    
    if ($OS eq 'windows') {
        $req .= ".exe" if $req !~ /\.exe$/;
        # Windows 上直接检查文件是否存在
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
        # Linux/Unix 保持原样
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
    
    unlink "$BUILDROOT/$filename.tar.gz";
    
    my $exclude_file = "$SOURCE/make/tgz/tar.exclude";
    my $exclude_opt = -f $exclude_file ? "--exclude-from='$exclude_file'" : "";
    
    my $cmd = "tar $exclude_opt --directory='$BUILDROOT' --mode=go-w -czvf '$BUILDROOT/$filename.tar.gz' $filename 2>&1";

    system($cmd) == 0 or warn "TGZ build failed";
    
    move("$BUILDROOT/$filename.tar.gz", $output_file) or warn "Failed to move TGZ file";
    return $output_file;
}

# 构建 ZIP 包
sub build_zip {
    my $version = "$MAJOR.$MINOR";
    my $filename = "$PROJECT-$version";
    my $output = "$DESTI/$filename.zip";
    
    print "\nBuilding ZIP package: $filename\n";
    print "  PATH: $ENV{PATH}\n";
    print "  which 7z: " . `which 7z 2>&1`;
    # 调试信息
    print "  Checking 7z command...\n";
    my $which_7z = `which 7z 2>&1`;
    print "  which 7z: $which_7z";
    
    my $version_check = `7z --version 2>&1`;
    print "  7z --version: $version_check";
    
    # 检查 7z 是否可用
    if ($which_7z =~ /not found/i || $version_check =~ /not found/i) {
        print "  ⚠️ 7z command not found, skipping ZIP build\n";
        return undef;
    }
    
    # 检查源目录
    my $source_dir = "$BUILDROOT/$filename";
    if (!-d $source_dir) {
        print "  ❌ Source directory not found: $source_dir\n";
        return undef;
    }
    
    # 列出源目录内容（调试）
    print "  Source directory contents:\n";
    system("ls -la '$source_dir' | head -20");
    
    unlink "$BUILDROOT/$filename.zip";
    
    chdir($BUILDROOT);
    my $cmd = "7z a -r -tzip -mx '$BUILDROOT/$filename.zip' '$filename' 2>&1";
    print "  Running: $cmd\n";
    my $result = system($cmd);
    print "  Return code: $result\n";
    
    if ($result != 0) {
        warn "ZIP build failed with code $result";
        # 尝试用不同参数重试
        print "  Retrying with different parameters...\n";
        $cmd = "7z a -r -tzip '$BUILDROOT/$filename.zip' '$filename/*' 2>&1";
        print "  Running: $cmd\n";
        $result = system($cmd);
        print "  Return code: $result\n";
        
        if ($result != 0) {
            return undef;
        }
    }
    
    # 检查生成的 ZIP 文件
    if (-f "$BUILDROOT/$filename.zip") {
        my $size = -s "$BUILDROOT/$filename.zip";
        print "  ✅ ZIP file created, size: " . int($size/1024) . " KB\n";
        move("$BUILDROOT/$filename.zip", $output) or warn "Failed to move ZIP file";
        return $output;
    } else {
        print "  ❌ ZIP file not created\n";
        return undef;
    }
}

sub build_rpm {
    my $version = "$MAJOR.$MINOR";
    my $filename = "$PROJECT-$version";
    my $output = "$DESTI/$PROJECT-$version-$RPMSUBVERSION.noarch.rpm";
    
    print "\nBuilding RPM package: $filename\n";
    
    # 调试信息
    print "  Current directory: " . Cwd::getcwd() . "\n";
    print "  BUILDROOT: $BUILDROOT\n";
    print "  RPMDIR: $RPMDIR\n";
    
    # 确保 SOURCES 目录存在
    make_path("$RPMDIR/SOURCES");
    
    # 创建源码包（直接到 SOURCES 目录）
    my $tgz_file = "$RPMDIR/SOURCES/$PROJECT-$version.tgz";
    unlink $tgz_file;
    
    my $exclude_file = "$SOURCE/make/tgz/tar.exclude";
    my $exclude_opt = -f $exclude_file ? "--exclude-from='$exclude_file'" : "";
    my $cmd = "tar $exclude_opt --directory='$BUILDROOT' -czvf '$tgz_file' $filename";
    
    print "  Creating source tarball: $cmd\n";
    system($cmd) == 0 or die "Failed to create source tarball";
    
    # 检查源码包
    if (-f $tgz_file) {
        my $size = -s $tgz_file;
        print "  ✅ Source tarball created: $tgz_file (" . int($size/1024) . " KB)\n";
    } else {
        die "❌ Source tarball not created";
    }
    
    # 查找 spec 文件
    my $spec_template = "rpm/$PROJECT.spec";
    print "  Looking for spec file at: $spec_template\n";
    
    if (-f $spec_template) {
        print "  ✅ Found spec file\n";

        # 读取并修改 spec 文件
        open my $spec_in, '<', $spec_template or die "Cannot open spec template: $spec_template";
        open my $spec_out, '>', "$TEMP/$PROJECT.spec" or die "Cannot create spec file";

        my $source_added = 0;
        while (<$spec_in>) {
            s/__VERSION__/$MAJOR.$MINOR/g;
            s/__RELEASE__/$RPMSUBVERSION/g;
            
            # 在 Name 后面添加 Source0，但只加一次
            if (/^Name:/ && !$source_added) {
                print $spec_out $_;
                print $spec_out "Source0: %{name}-%{version}.tgz\n";
                $source_added = 1;
                next;
            }
            
            # 跳过原有的 Source0 行（如果有）
            if (/^Source0:/) {
                # 如果已经添加过了，就跳过
                if ($source_added) {
                    next;
                } else {
                    # 否则保留原来的
                    print $spec_out $_;
                    $source_added = 1;
                }
                next;
            }
            
            # 确保 %prep 部分有正确的 %setup
            if (/^%prep/) {
                print $spec_out $_;
                print $spec_out "%setup -q -n %{name}-%{version}\n";
                # 跳过原有的 %setup 行
                while (<$spec_in>) {
                    last if !/^%setup/;
                }
                next;
            }
            print $spec_out $_;
        }
        close $spec_in;
        close $spec_out;
        
        # 显示生成的 spec 文件内容
        print "  Generated spec file preview:\n";
        system("head -20 '$TEMP/$PROJECT.spec'");
        
        # 运行 rpmbuild
        $cmd = "rpmbuild --clean -ba '$TEMP/$PROJECT.spec' 2>&1";
        print "  Running: $cmd\n";
        my $result = system($cmd);
        
        if ($result != 0) {
            warn "RPM build failed with code $result";
            print "  RPM build output:\n";
            system("tail -50 /tmp/rpmbuild.log 2>/dev/null || true");
            return undef;
        }
    } else {
        die "❌ RPM spec file not found at: $spec_template";
    }
    
    # 查找生成的 RPM 文件
    my $rpm_file = "$RPMDIR/RPMS/noarch/$PROJECT-$version-$RPMSUBVERSION.noarch.rpm";
    if (-f $rpm_file) {
        my $size = -s $rpm_file;
        print "  ✅ RPM package created: $rpm_file (" . int($size/1024) . " KB)\n";
        move($rpm_file, $output) or warn "Failed to move RPM file";
        return $output;
    } else {
        print "  ❌ RPM package not found at: $rpm_file\n";
        print "  Contents of $RPMDIR/RPMS/noarch/:\n";
        system("ls -la $RPMDIR/RPMS/noarch/ 2>/dev/null || echo 'directory not found'");
        return undef;
    }
}

# 构建 DEB 包（带详细检测）
sub build_deb {
    my $version = "$MAJOR.$MINOR";
    my $filename = "$PROJECT-$version";
    my $output = "$DESTI/${PROJECT}_$version\_all.deb";
    
    print "\n🔨 Building DEB package: $filename\n";
    print "=" x 60, "\n";
    
    # 步骤1: 检查依赖工具
    print "📋 Step 1: Checking build dependencies...\n";
    
    # 检查 dpkg-buildpackage
    my $dpkg_check = system("dpkg-buildpackage --version > /dev/null 2>&1");
    if ($dpkg_check != 0) {
        print "  ❌ dpkg-buildpackage not found. Please install dpkg-dev\n";
        return undef;
    }
    print "  ✅ dpkg-buildpackage found\n";
    
    # 检查 debhelper - 直接使用 which 命令更可靠
    my $dh_check = system("which dh > /dev/null 2>&1");
    if ($dh_check != 0) {
        print "  ⚠️ dh command not found via which, trying dh --version...\n";
        my $dh_version_check = system("dh --version > /dev/null 2>&1");
        if ($dh_version_check != 0) {
            print "  ❌ debhelper not found. Please install debhelper\n";
            return undef;
        }
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
    
    # 步骤4: 创建 debian 目录
    print "\n📋 Step 4: Creating debian packaging files...\n";
    make_path("$deb_packageroot/debian");
    print "  ✅ debian directory created\n";
    
    # 步骤5: 生成 control 文件
    print "  📄 Generating control file...\n";
    open my $fh, '>', "$deb_packageroot/debian/control" or do {
        print "  ❌ Cannot create control file: $!\n";
        return undef;
    };
    print $fh <<"EOF";
Source: $PROJECT
Section: web
Priority: optional
Maintainer: Laurent Destailleur <eldy\@users.sourceforge.net>
Build-Depends: debhelper (>= 13)
Standards-Version: 4.7.0
Rules-Requires-Root: no
Homepage: https://$PROJECT.org

Package: $PROJECT
Architecture: all
Depends: perl,
         libgeo-ip-perl,
         libgeo-ipfree-perl,
         geoip-database,
         libtimelocal-perl,
         libsocket-perl,
         libencode-perl,
         libjson-xs-perl,
         libtry-tiny-perl,
         \${misc:Depends}
Description: powerful and featureful web server log analyzer
 AWStats (Advanced Web Statistics) is a free powerful and featureful
 tool that generates advanced web (but also ftp or mail) server
 statistics, graphically.
 .
 This log analyzer works as a CGI or from command line and shows you
 all possible information your log contains, in few graphical web
 pages.
EOF
    close $fh;
    print "  ✅ control file created\n";
    
    # 步骤6: 生成 changelog 文件
    print "  📄 Generating changelog file...\n";
    my $date = strftime("%a, %d %b %Y %H:%M:%S %z", localtime);
    open $fh, '>', "$deb_packageroot/debian/changelog" or do {
        print "  ❌ Cannot create changelog: $!\n";
        return undef;
    };
    print $fh <<"EOF";
$PROJECT ($version-1) unstable; urgency=medium

  * New upstream release

 -- Laurent Destailleur <eldy\@users.sourceforge.net>  $date
EOF
    close $fh;
    print "  ✅ changelog file created\n";
    
    # 步骤7: 生成 compat 文件
    print "  📄 Generating compat file...\n";
    open $fh, '>', "$deb_packageroot/debian/compat" or do {
        print "  ❌ Cannot create compat: $!\n";
        return undef;
    };
    print $fh "13\n";
    close $fh;
    print "  ✅ compat file created (level 13)\n";
    
    # 步骤8: 生成 copyright 文件
    print "  📄 Generating copyright file...\n";
    open $fh, '>', "$deb_packageroot/debian/copyright" or do {
        print "  ❌ Cannot create copyright: $!\n";
        return undef;
    };
    print $fh <<"EOF";
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: $PROJECT
Source: https://github.com/$GITHUB_REPO

Files: *
Copyright: 2000-2026 Laurent Destailleur <eldy\@users.sourceforge.net>
License: GPL-2+
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.
 .
 On Debian systems, the full text of the GNU General Public License
 version 2 can be found in the file /usr/share/common-licenses/GPL-2.
EOF
    close $fh;
    print "  ✅ copyright file created\n";
    
    # 步骤9: 生成 rules 文件
    print "  📄 Generating rules file...\n";
    open $fh, '>', "$deb_packageroot/debian/rules" or do {
        print "  ❌ Cannot create rules: $!\n";
        return undef;
    };
    print $fh <<"EOF";
#!/usr/bin/make -f

%:
	dh \$@

override_dh_auto_install:
	# 创建必要的目录
	mkdir -p debian/$PROJECT/etc/$PROJECT
	mkdir -p debian/$PROJECT/usr/lib/cgi-bin
	mkdir -p debian/$PROJECT/var/lib/$PROJECT
	mkdir -p debian/$PROJECT/var/log/$PROJECT
	mkdir -p debian/$PROJECT/usr/share/doc/$PROJECT
	mkdir -p debian/$PROJECT/usr/share/$PROJECT
	
	# 复制文件
	cp -pr wwwroot/* debian/$PROJECT/usr/share/$PROJECT/ 2>/dev/null || true
	cp -pr docs/* debian/$PROJECT/usr/share/doc/$PROJECT/ 2>/dev/null || true
	cp -pr tools/* debian/$PROJECT/usr/share/$PROJECT/tools/ 2>/dev/null || true
	
	# 配置文件
	if [ -f wwwroot/cgi-bin/awstats.model.conf ]; then \\
		cp wwwroot/cgi-bin/awstats.model.conf debian/$PROJECT/etc/$PROJECT/awstats.conf; \\
	fi
	
	# 创建符号链接
	ln -sf /usr/share/$PROJECT/cgi-bin/awstats.pl debian/$PROJECT/usr/lib/cgi-bin/awstats.pl
	ln -sf /usr/share/$PROJECT/cgi-bin/awredir.pl debian/$PROJECT/usr/lib/cgi-bin/awredir.pl

override_dh_installchangelogs:
	dh_installchangelogs docs/CHANGELOG.md

override_dh_installdocs:
	dh_installdocs --link-doc=$PROJECT
EOF
    close $fh;
    chmod 0755, "$deb_packageroot/debian/rules";
    print "  ✅ rules file created and set executable\n";
    
    # 步骤10: 生成 install 文件
    print "  📄 Generating install file...\n";
    open $fh, '>', "$deb_packageroot/debian/install" or do {
        print "  ❌ Cannot create install: $!\n";
        return undef;
    };
    print $fh <<"EOF";
wwwroot/cgi-bin/awstats.pl usr/share/$PROJECT/cgi-bin/
wwwroot/cgi-bin/awredir.pl usr/share/$PROJECT/cgi-bin/
wwwroot/cgi-bin/plugins/* usr/share/$PROJECT/plugins/
wwwroot/cgi-bin/lib/* usr/share/$PROJECT/lib/
wwwroot/cgi-bin/lang/* usr/share/$PROJECT/lang/
wwwroot/icon/* usr/share/$PROJECT/icon/
wwwroot/css/* usr/share/$PROJECT/css/
wwwroot/js/* usr/share/$PROJECT/js/
wwwroot/classes/* usr/share/$PROJECT/classes/
tools/* usr/share/$PROJECT/tools/
README.md usr/share/doc/$PROJECT/
EOF
    close $fh;
    print "  ✅ install file created\n";
    
    # 步骤11: 生成 postinst 脚本
    print "  📄 Generating postinst script...\n";
    open $fh, '>', "$deb_packageroot/debian/postinst" or do {
        print "  ❌ Cannot create postinst: $!\n";
        return undef;
    };
    print $fh <<"EOF";
#!/bin/sh
set -e

case "\$1" in
    configure)
        mkdir -p /var/lib/awstats
        mkdir -p /var/log/awstats
        chmod 755 /usr/lib/cgi-bin/awstats.pl
        chmod 755 /usr/lib/cgi-bin/awredir.pl
        
        # 检查并下载 GeoIP 数据库
        if [ ! -f /usr/share/GeoIP/GeoLite2-City.mmdb ]; then
            echo "First-time setup: Downloading GeoLite2-City.mmdb (60MB)..."
            wget -q --show-progress -O /usr/share/GeoIP/GeoLite2-City.mmdb \
                https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb
        else
            echo "✓ GeoLite2-City.mmdb already exists, skipping download"
        fi
        
        # 启用 Apache CGI 模块
        if [ -x /usr/sbin/a2enmod ]; then
            a2enmod cgi > /dev/null 2>&1 || true
        fi

        # 生成 awredir.pl 的随机密钥
        if [ -f /usr/share/awstats/cgi-bin/awredir.pl ]; then
            echo "Generating random key for awredir.pl..."
            KEY=\$(perl -e 'use Digest::MD5 qw(md5_hex); print md5_hex(rand().time().\$\$)' 2>/dev/null || echo "defaultkey")
            if [ -n "\$KEY" ]; then
                sed -i "s/YOURKEYFORMD5/\$KEY/" /usr/share/awstats/cgi-bin/awredir.pl
                echo "✓ Random key generated for awredir.pl"
            fi
        fi

        echo
        echo "----- AWStats $version - UTF-8重构版 -----"
        echo "AWStats has been installed in /usr/share/awstats"
        echo "Configuration files are in /etc/awstats"
        echo "Documentation is in /usr/share/doc/awstats"
        echo "To configure AWStats, run: /usr/share/awstats/tools/awstats_configure.pl"
        echo
        ;;
esac

exit 0
EOF
    close $fh;
    chmod 0755, "$deb_packageroot/debian/postinst";
    print "  ✅ postinst script created\n";
    
    # 步骤12: 生成 prerm 脚本
    print "  📄 Generating prerm script...\n";
    open $fh, '>', "$deb_packageroot/debian/prerm" or do {
        print "  ❌ Cannot create prerm: $!\n";
        return undef;
    };
    print $fh <<"EOF";
#!/bin/sh
set -e

case "\$1" in
    remove|upgrade)
        # 卸载前清理（如果需要）
        ;;
esac

exit 0
EOF
    close $fh;
    chmod 0755, "$deb_packageroot/debian/prerm";
    print "  ✅ prerm script created\n";

    # 生成 preinst 脚本
    print "  📄 Generating preinst script...\n";
    open $fh, '>', "$deb_packageroot/debian/preinst" or do {
        print "  ❌ Cannot create preinst: $!\n";
        return undef;
    };
    print $fh <<"EOF";
#!/bin/sh
set -e

case "\$1" in
    install|upgrade)
        # 安装前准备工作
        ;;
esac

exit 0
EOF
    close $fh;
    chmod 0755, "$deb_packageroot/debian/preinst";
    print "  ✅ preinst script created\n";

    # 步骤13: 检查所有必需文件
    print "\n📋 Step 13: Verifying all required files...\n";
    my @required_files = qw(
        debian/control
        debian/changelog
        debian/compat
        debian/copyright
        debian/rules
        debian/install
        debian/postinst
        debian/prerm
    );
    
    my $all_ok = 1;
    foreach my $file (@required_files) {
        if (-f "$deb_packageroot/$file") {
            print "  ✅ $file\n";
        } else {
            print "  ❌ $file MISSING\n";
            $all_ok = 0;
        }
    }
    
    unless ($all_ok) {
        print "  ❌ Required files missing, aborting\n";
        return undef;
    }
    
    # 步骤14: 构建 DEB 包
    print "\n📋 Step 14: Building DEB package...\n";
    chdir($deb_packageroot);
    
    print "  Running: dpkg-buildpackage -us -uc -b\n";
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
    
    # 步骤15: 查找生成的 .deb 文件
    print "\n📋 Step 15: Locating generated .deb file...\n";
    opendir my $dh, $deb_buildroot or do {
        print "  ❌ Cannot open directory: $deb_buildroot\n";
        return undef;
    };
    
    my $found = 0;
    while (my $file = readdir $dh) {
        if ($file =~ /\.deb$/) {
            my $src = "$deb_buildroot/$file";
            print "  ✅ Found: $src\n";
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
    
    # 步骤16: 验证输出文件
    print "\n📋 Step 16: Verifying output file...\n";
    if (-f $output) {
        my $size = -s $output;
        print "  ✅ DEB package created successfully\n";
        print "  📦 $output (" . int($size/1024) . " KB)\n";
        return $output;
    } else {
        print "  ❌ Output file not found: $output\n";
        return undef;
    }
}

# 构建 EXE 包（带调试）
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
    
    # 步骤2：检查 NSI 文件（不再重复检查 NSIS）
    print "\n📋 Step 2: Checking NSI file...\n";
    my $nsi_file = File::Spec->catfile($SOURCE, 'make', 'exe', "$PROJECT.nsi");
    print "  Looking for: $nsi_file\n";
    
    unless (-f $nsi_file) {
        print "  ❌ NSI file not found\n";
        # 列出可能的位置
        print "  Files in make/exe:\n";
        my $exe_dir = File::Spec->catfile($SOURCE, 'make', 'exe');
        if (-d $exe_dir) {
            if (opendir(my $dh, $exe_dir)) {
                while (my $f = readdir $dh) {
                    print "    - $f\n" if $f !~ /^\./;
                }
                closedir $dh;
            } else {
                print "    ⚠️ Cannot open directory: $!\n";
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
  --target=LIST   Comma-separated list of targets (@TARGETS)
  --publish       Publish to GitHub releases
  --help          Show this help
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
        @build_targets = split(/[,\s]+/, uc($targets));
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