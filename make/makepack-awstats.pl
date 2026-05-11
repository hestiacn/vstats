#!/usr/bin/perl
#----------------------------------------------------------------------------
# \file         make/makepack-awstats.pl
# \brief        Package builder (tgz, zip, rpm, deb, exe) with Git automation
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
    my $skip_copy = shift || 0;
    
    if ($skip_copy) {
        print "Skipping buildroot preparation (using source directly for TGZ/ZIP)\n";
        $BUILDROOT = $SOURCE;
        return;
    }
    
    print "Preparing build directory for RPM/DEB/EXE...\n";
    
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
    print "Using source directory directly (no copy): $SOURCE\n";
    
    # 跳过复制，直接使用源码目录
    prepare_buildroot(1);
    
    # 删除旧的输出文件
    unlink $output_file if -f $output_file;
    
    # 切换到源码目录
    chdir($SOURCE);
    
    # 排除不需要的文件和目录
    my @excludes = (
        '.git', '.github', '.settings',
        'make', 'test',
        '.gitignore', '.gitattributes',
        '.project', '.cvsignore',
        'git2cvs.sh',
        '*.bak', '*~', '*.old'
    );
    
    my $exclude_args = '';
    foreach my $ex (@excludes) {
        $exclude_args .= " --exclude='$ex'";
    }
    
    # 打包命令：将当前目录打包，并在 tar 内重命名为项目名
    my $cmd = "tar $exclude_args -czvf '$output_file' --transform='s/^/$filename\\//' . 2>&1";
    
    print "Running: tar $exclude_args -czvf '$output_file' --transform='s/^/$filename\\//' .\n";
    my $result = system($cmd);
    
    if ($result != 0) {
        warn "TGZ build failed with code $result";
        return undef;
    }
    
    # 验证输出文件
    if (-f $output_file) {
        my $size = -s $output_file;
        print "✅ TGZ package created: $output_file (" . int($size/1024) . " KB)\n";
        return $output_file;
    } else {
        print "❌ TGZ package not created\n";
        return undef;
    }
}

# 构建 ZIP 包
sub build_zip {
    my $version = "$MAJOR.$MINOR";
    my $filename = "$PROJECT-$version";
    my $output_file = "$DESTI/$filename.zip";
    
    print "\nBuilding ZIP package: $filename\n";
    print "Using source directory directly (no copy): $SOURCE\n";
    
    # 检查 7z 是否可用
    my $which_7z = `which 7z 2>&1`;
    if ($which_7z =~ /not found/i) {
        print "⚠️ 7z command not found, skipping ZIP build\n";
        return undef;
    }
    
    # 跳过复制，直接使用源码目录
    prepare_buildroot(1);
    
    # 删除旧的输出文件
    unlink $output_file if -f $output_file;
    
    # 切换到源码目录
    chdir($SOURCE);
    
    # 排除不需要的文件和目录
    my @excludes = (
        '.git', '.github', '.settings',
        'make', 'test',
        '.gitignore', '.gitattributes',
        '.project', '.cvsignore',
        'git2cvs.sh'
    );
    
    my $exclude_args = '';
    foreach my $ex (@excludes) {
        $exclude_args .= " -xr!$ex";
    }
    
    # 使用 7z 打包
    my $cmd = "7z a -r -tzip -mx '$output_file' . $exclude_args 2>&1";
    print "Running: $cmd\n";
    
    my $result = system($cmd);
    
    if ($result != 0) {
        warn "ZIP build failed with code $result";
        return undef;
    }
    
    # 验证输出文件
    if (-f $output_file) {
        my $size = -s $output_file;
        print "✅ ZIP package created: $output_file (" . int($size/1024) . " KB)\n";
        return $output_file;
    } else {
        print "❌ ZIP package not created\n";
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
    my $output = "$DESTI/${PROJECT}_$version-${RPMSUBVERSION}_all.deb";  # 注意：DEB 格式用 - 不是 _
    
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
    my $spec_template = "$SOURCE/make/deb/awstats.spec";  # 使用绝对路径
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