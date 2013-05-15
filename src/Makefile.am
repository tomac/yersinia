# $Id: Makefile.am 43 2007-04-27 11:07:17Z slay $

AUTOMAKE_OPTIONS = no-dependencies

DEFS = `$(LIBNET_CONFIG) --defines` @DEFS@

INCLUDES =

LIBS = @LIBS@ -lpcap -lnet

bin_PROGRAMS = yersinia

yersinia_SOURCES = xstp.c parser.c dtp.c dtp.h\
parser.h xstp.h global.h cdp.c cdp.h dhcp.c dhcp.h\
hsrp.h hsrp.c dot1q.h dot1q.c vtp.h vtp.c arp.h arp.c isl.h isl.c\
dot1x.h dot1x.c mpls.c mpls.h thread-util.h thread-util.c\
terminal.c terminal.h terminal-defs.h interfaces.h interfaces.c\
attack.h attack.c yersinia.h yersinia.c md5.c md5.h md5-sum.c\
md5-sum.h protocols.h protocols.c dlist.h dlist.c 

if HAS_CURSES
  INCLUDES += $(CURSES_INCLUDEDIR)
  LIBS += -lpanel $(CURSES_LIBS)
  yersinia_SOURCES +=\
  ncurses-gui.c ncurses-gui.h\
  ncurses-callbacks.c ncurses-callbacks.h\
  ncurses-interface.c ncurses-interface.h
endif

if HAVE_GTK
  INCLUDES += @PACKAGE_CFLAGS@
  DEFS += -DPACKAGE_DATA_DIR=\""$(datadir)"\" -DPACKAGE_LOCALE_DIR=\""$(prefix)/$(DATADIRNAME)/locale"\"
  yersinia_SOURCES += \
   gtk-gui.c gtk-gui.h\
	gtk-support.c gtk-support.h \
	gtk-interface.c gtk-interface.h \
	gtk-callbacks.c gtk-callbacks.h
  yersinia_LDADD = @PACKAGE_LIBS@ $(INTLLIBS)
endif

if HAVE_REMOTE_ADMIN
  yersinia_SOURCES += admin.c admin.h commands.c commands.h commands-struct.h
endif
