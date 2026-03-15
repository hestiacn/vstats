%define name awstats
%define version __VERSION__
%define release 1

Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{version}.tgz
Summary: AWStats is a free powerful and featureful server logfile analyzer.

License: GPL
Packager: Laurent Destailleur (Eldy) <eldy@users.sourceforge.net>
Vendor: Laurent Destailleur

BuildArchitectures: noarch
BuildRoot: /tmp/%{name}-buildroot
Group: Applications/Internet

Requires: perl, perl(Time::Local), perl(Socket), perl(Encode)
Requires: perl(JSON::XS), perl(Try::Tiny)
AutoReqProv: yes

%description
AWStats (Advanced Web Statistics) is a free powerful and featureful
tool that generates advanced web (but also ftp or mail) server
statistics, graphically.

This log analyzer works as a CGI or from command line and shows you
all possible information your log contains, in few graphical web
pages like visits, unique visitors, authenticated users, pages,
domains/countries, OS busiest times, robot visits, type of files,
search engines,keywords and keyphrases used, visits duration,
cluster balancing, HTTP errors and also screen size, web browser
java,flash,etc support and more...
Statistics can be updated from a browser or your scheduler.
AWStats uses a partial information file to be able to process large
log files, often and quickly.

It can analyze log files from IIS (W3C log format), Apache log files
(NCSA combined/XLF/ELF log format or common/CLF log format), WebStar
and most of all web, proxy, wap, streaming servers (and ftp servers
or mail logs).
The program also supports virtual servers, plugins and a lot of
features.

%description -l pl
awstats (Advanced Web Statistics - zaawansowane statystyki WWW) to
potężne i bogate w możliwości narzędzie generujące zaawansowane
graficzne statystyki serwera WWW. Ten analizator logów serwera
działa z linii poleceń lub jako CGI i pokazuje wszystkie informacje
zawarte w logu w postaci graficznych stron WWW. Może analizować logi
wielu serwerów WWW/WAP/proxy, takich jak Apache, IIS, Weblogic,
Webstar, Squid... ale także serwerów pocztowych lub ftp.

Ten program może mierzyć odwiedziny, odwiedzających, uwierzytelnionych
użytkowników, strony, domeny/kraje, najbardziej zajęte godziny,
odwiedziny robotów, rodzaje plików, używane wyszukiwarki i słowa
kluczowe, czasy trwania odwiedzin, błędy HTTP... a nawet więcej.
Statystyki mogą być uaktualniane z przeglądarki lub schedulera.
Program obsługuje także serwery wirtualne, wtyczki i wiele innych
rzeczy.

%description -l fr
AWStats (Advanced Web Statistics) est un outil pour générer des 
statistiques avancées d'un serveur web (mais aussi ftp ou mail)
de manière graphique.

Cet analyseur de log fonctionne en CGI ou en ligne de commande
et synthétise toutes les informations que vos logs contiennent en
quelques pages comme les visites, visiteurs uniques, logins,
pages vues, domaines/pays, heures de pointes, visites des robots, 
type de fichiers, moteurs de recherche, mots et phrases clés,
durée des visites, répartition clusters, erreurs HTTP mais aussi
support java,flash,etc des navigateurs, résolution d'écran,
estimation des ajouts aux favoris, etc...

Les statistiques peuvent etre mise à jour par un navigateur ou un
séquenceur.
AWStats génère un fichier d'informations consolidés pour pouvoir
traiter de large sites souvent et rapidement.

Il peut analyser des logs IIS (W3C log format), fichier log Apache
(format NCSA combined/XLF/ELF ou format common/CLF), WebStar et la
plupart des logs de serveur web, proxy, wap, streaming serveurs
(et aussi serveurs ftp et de mails).
Ce programme supporte de plus les serveurs virtuels, des plugins
et de nombreuses fonctionnalités.

#---- prep
%prep
%setup -q -n %{name}-%{version}
cp -pr $RPM_BUILD_DIR/%{name}-%{version}/docs/images/* $RPM_BUILD_DIR/%{name}-%{version}/ 2>/dev/null || true

#---- build
%build
# Nothing to build

#---- install
%install
rm -rf $RPM_BUILD_ROOT

# 创建标准目录结构
mkdir -p $RPM_BUILD_ROOT/usr/share/awstats
mkdir -p $RPM_BUILD_ROOT/usr/lib/cgi-bin
mkdir -p $RPM_BUILD_ROOT/etc/awstats
mkdir -p $RPM_BUILD_ROOT/var/lib/awstats
mkdir -p $RPM_BUILD_ROOT/var/log/awstats

# 批量复制所有文件
cp -pr docs $RPM_BUILD_ROOT/usr/share/awstats/
cp -pr wwwroot $RPM_BUILD_ROOT/usr/share/awstats/
cp -pr tools $RPM_BUILD_ROOT/usr/share/awstats/
cp -pr README.md $RPM_BUILD_ROOT/usr/share/awstats/

# 复制配置文件
echo "Current directory: $(pwd)"
echo "Files in wwwroot/cgi-bin:"
ls -la wwwroot/cgi-bin/ || echo "No files found"

# 复制配置文件（智能判断）
cp -pr wwwroot/cgi-bin/awstats.conf $RPM_BUILD_ROOT/etc/awstats/awstats.conf
cp -pr wwwroot/cgi-bin/awstats.model.conf $RPM_BUILD_ROOT/etc/awstats/awstats.model.conf

echo "Verifying copied files:"
ls -la $RPM_BUILD_ROOT/etc/awstats/

# 创建符号链接
ln -sf /usr/share/awstats/wwwroot/cgi-bin/awstats.pl $RPM_BUILD_ROOT/usr/lib/cgi-bin/awstats.pl
ln -sf /usr/share/awstats/wwwroot/cgi-bin/awredir.pl $RPM_BUILD_ROOT/usr/lib/cgi-bin/awredir.pl

#---- clean
%clean
rm -rf $RPM_BUILD_ROOT

#---- files
%files
%defattr(-,root,root)
%doc README.md
%doc /usr/share/awstats/docs/*
%config /etc/awstats/awstats.conf
%config /etc/awstats/awstats.model.conf
/usr/share/awstats/*
/usr/lib/cgi-bin/awstats.pl
/usr/lib/cgi-bin/awredir.pl
/var/lib/awstats
/var/log/awstats

#---- post
%post
echo
echo ----- AWStats %version - Laurent Destailleur -----
echo AWStats files have been installed in /usr/share/awstats
echo Configuration files are in /etc/awstats
echo CGI scripts are in /usr/lib/cgi-bin/
echo
echo If first install, follow instructions in documentation
echo \(/usr/share/awstats/docs/index.html\) to setup AWStats in 3 steps:
echo Step 1 : Install and Setup with awstats_configure.pl \(or manually\)
echo Step 2 : Build/Update Statistics with awstats.pl
echo Step 3 : Read Statistics
echo

%changelog