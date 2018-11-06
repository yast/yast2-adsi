#
# spec file for package yast-adsi
#
# Copyright (c) 2018 SUSE LINUX GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#


Name:           yast-adsi
Version:        0.1
Release:        0
Summary:        ADSI Edit for YaST
License:        GPL-3.0
Group:          Productivity/Networking/Samba
Url:            http://www.github.com/dmulder/yast-adsi
Source:         %{name}-%{version}.tar.bz2
BuildArch:      noarch
Requires:       krb5-client
Requires:       samba-client
Requires:       samba-python3
Requires:       yast2
Requires:       yast2-python3-bindings >= 4.0.0
Requires:       python3-ldap
Requires:       python3-gssapi
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  perl-XML-Writer
BuildRequires:  python3
BuildRequires:  update-desktop-files
BuildRequires:  yast2
BuildRequires:  yast2-devtools
BuildRequires:  yast2-testsuite

%description
The ADSI Edit for YaST module provides tools for viewing and modifying
an LDAP tree.

%prep
%setup -q

%build
autoreconf -if
%configure --prefix=%{_prefix}
make

%install
make DESTDIR=$RPM_BUILD_ROOT install

%clean
%{__rm} -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%dir %{_datadir}/YaST2/include/adsi
%{_datadir}/YaST2/clients/adsi.py
%{_datadir}/YaST2/include/adsi/complex.py
%{_datadir}/YaST2/include/adsi/dialogs.py
%{_datadir}/YaST2/include/adsi/wizards.py
%{_datadir}/YaST2/include/adsi/defaults.py
%{_datadir}/applications/YaST2/adsi.desktop
%dir %{_datadir}/doc/yast2-adsi
%{_datadir}/doc/yast2-adsi/COPYING

%changelog
