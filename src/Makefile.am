# Makefile.am for adsi/src

yncludedir = ${prefix}/share/YaST2/include/adsi

clientdir = ${prefix}/share/YaST2/clients
client_DATA =			\
	adsi.py

#TODO: This must be modified to python can know from where can import!
ynclude_DATA =			\
	wizards.py		\
	dialogs.py		\
	complex.py

desktopdir = ${prefix}/share/applications/YaST2
desktop_DATA =			\
	org.opensuse.yast.ADSI.desktop

moduledir = ${prefix}/share/YaST2/modules

# create a symlink for local build, #145327
adsi:
	ln -sf . $@
ycpchook = adsi

EXTRA_DIST = $(client_DATA) $(ynclude_DATA) $(module_DATA) $(desktop_DATA)

CLEANFILES = *.pyc
