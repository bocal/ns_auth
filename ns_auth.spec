Name:           ns_auth
Version:	1.3
Release:	1
License:        BSD-2-Clause
BuildRequires:	python3
BuildArch:      noarch
Summary:	ns_auth bocal
Vendor:		Bocal
Url:            http://www.bocal.org
Group:          Basic

%description
ns_auth dump opensuse bocal

%prep

%build

%install
rm -fR %{buildroot};
mkdir -p %{buildroot}/usr/bin;
cd %{_sourcedir}
mv ns_auth %{buildroot}/usr/bin;

%files
%attr(755,root,root) /usr/bin/ns_auth
