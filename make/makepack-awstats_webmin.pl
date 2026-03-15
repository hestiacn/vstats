#!/usr/bin/perl
#----------------------------------------------------------------------------
# \file         make/makepack-awstats_webmin.pl
# \brief        Package builder (tgz, zip, rpm, deb, exe) for Webmin module
# \version      $Revision$
# \author       (c)2004-2026 Laurent Destailleur  <eldy@users.sourceforge.net>
#----------------------------------------------------------------------------

use strict;
use warnings;
use v5.20;
use Cwd qw(abs_path);
use File::Temp;
use File::Path qw(remove_tree make_path);
use File::Copy;
use File::Basename;
use Getopt::Long;
use POSIX qw/strftime/;

# 初始化配置
my $PROJECT = "awstats";
my ($MAJOR, $MINOR) = ("2", "0");
my $BUILD_ROOT;
my $SOURCE_DIR;
my $DEST_DIR;
my @TARGETS = ();

# 支持的包格式
my %REQUIREMENTS = (
    "WBM" => "tar",
    "TGZ" => "tar",
    "ZIP" => "zip",
    "RPM" => "rpmbuild",
    "DEB" => "dpkg-deb",
    "EXE" => "makensis"
);

# 获取版本信息
sub get_version {
    my $source_dir = shift;
    my $info_file = "$source_dir/$PROJECT/module.info";
    
    if (open my $fh, '<', $info_file) {
        while (<$fh>) {
            if (/version=(.+)/) {
                close $fh;
                return split(/\./, $1, 2);
            }
        }
        close $fh;
    }
    return ("2", "0");
}

# 检测操作系统
sub detect_os {
    if ($^O =~ /linux/i) { return 'linux'; }
    elsif ($^O =~ /darwin/i) { return 'macosx'; }
    elsif ($^O =~ /cygwin|msys|win32/i) { return 'windows'; }
    else { die "Unsupported OS: $^O"; }
}

# 检查依赖工具
sub check_requirements {
    my ($target) = @_;
    my $req = $REQUIREMENTS{$target};
    
    print "Checking requirement for $target: $req... ";
    
    if (detect_os() eq 'windows') {
        $req .= ".exe" if $req !~ /\.exe$/;
    }
    
    my $ret = system("$req --version > /dev/null 2>&1");
    if ($ret == 0) {
        print "OK\n";
        return 1;
    } else {
        print "FAILED\n";
        return 0;
    }
}

# 清理构建目录
sub clean_buildroot {
    my ($dir) = @_;
    if (-d $dir) {
        print "Cleaning $dir...\n";
        remove_tree($dir);
    }
}

# 准备构建环境
sub prepare_buildroot {
    my ($source, $build) = @_;
    
    print "Creating build directory: $build\n";
    make_path($build);
    
    print "Copying source from $source to $build/$PROJECT\n";
    system("cp -r '$source/$PROJECT' '$build/'") == 0 
        or die "Failed to copy source";
    
    print "Cleaning temporary files...\n";
    my @patterns = (
        'Thumbs.db', '*.wbm', '*.tar',
        'CVS', '.svn', '.git', '.hg',
        '*.bak', '*.old', '*~'
    );
    
    foreach my $pattern (@patterns) {
        find_and_delete($build, $pattern);
    }
}

# 递归查找并删除文件
sub find_and_delete {
    my ($dir, $pattern) = @_;
    return unless -d $dir;
    
    opendir my $dh, $dir or return;
    while (my $item = readdir $dh) {
        next if $item eq '.' or $item eq '..';
        
        my $path = "$dir/$item";
        if (-d $path) {
            find_and_delete($path, $pattern);
        } else {
            unlink $path if fnmatch($item, $pattern);
        }
    }
    closedir $dh;
}

# 简单的通配符匹配
sub fnmatch {
    my ($name, $pattern) = @_;
    $pattern =~ s/\*/.*/g;
    $pattern =~ s/\?/./g;
    return $name =~ /^$pattern$/;
}

# 构建 WBM 包
sub build_wbm {
    my ($build_dir, $version, $dest) = @_;
    
    my $pkg_name = "$PROJECT-$version.wbm";
    my $pkg_path = "$dest/$pkg_name";
    
    print "\nBuilding WBM package: $pkg_name\n";
    
    my $tar_cmd = "tar -C '$build_dir' -cf '$pkg_path' $PROJECT";
    system($tar_cmd) == 0 or die "Failed to create WBM package";
    
    print "WBM package created: $pkg_path\n";
    return 1;
}

# 主构建函数
sub build_packages {
    my ($source, $dest, @targets) = @_;
    
    my $build_root = File::Temp->newdir(
        "awstats-build-XXXXXX",
        TMPDIR => 1,
        CLEANUP => 1
    ) or die "Failed to create temp directory";
    
    prepare_buildroot($source, $build_root);
    
    foreach my $target (@targets) {
        $target = uc($target);
        next unless check_requirements($target);
        
        if ($target eq 'WBM') {
            build_wbm($build_root, "$MAJOR.$MINOR", $dest);
        }
        elsif ($target eq 'TGZ') {
            print "TGZ building not implemented yet\n";
        }
        elsif ($target eq 'ZIP') {
            print "ZIP building not implemented yet\n";
        }
        else {
            print "Target $target not implemented\n";
        }
    }
    
    print "\nBuild completed successfully!\n";
}

# 主程序
sub main {
    my $help = 0;
    my $targets = '';
    my $source = '';
    my $dest = '';
    
    GetOptions(
        'help|?'     => \$help,
        'target=s'   => \$targets,
        'source=s'   => \$source,
        'dest=s'     => \$dest,
    ) or die "Invalid options";
    
    if ($help) {
        print <<"USAGE";
Usage: $0 [options]
Options:
  --target=LIST   Comma-separated list of targets (WBM,TGZ,ZIP,RPM,DEB,EXE)
  --source=DIR    Source directory (default: auto-detect)
  --dest=DIR      Destination directory (default: ../make)
  --help          Show this help
USAGE
        exit 0;
    }
    
    my $script_dir = dirname(abs_path($0));
    $SOURCE_DIR = $source || "$script_dir/../../awstats/tools/webmin";
    $DEST_DIR = $dest || "$SOURCE_DIR/../../make";
    
    unless (-d "$SOURCE_DIR/$PROJECT") {
        die "Source directory not found: $SOURCE_DIR/$PROJECT";
    }
    
    ($MAJOR, $MINOR) = get_version($SOURCE_DIR);
    print "Building $PROJECT version $MAJOR.$MINOR\n";
    
    if ($targets) {
        @TARGETS = split(/[,\s]+/, uc($targets));
    } else {
        @TARGETS = ('WBM');
    }
    
    make_path($DEST_DIR) unless -d $DEST_DIR;
    build_packages($SOURCE_DIR, $DEST_DIR, @TARGETS);
}

main();
exit 0;