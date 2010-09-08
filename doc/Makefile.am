man_MANS = \
	dbus-cleanup-sockets.1 \
	dbus-daemon.1 \
	dbus-launch.1 \
	dbus-monitor.1 \
	dbus-send.1 \
	dbus-uuidgen.1

MAN_IN_FILES = dbus-daemon.1.in

MAN_HTML_FILES = \
	dbus-cleanup-sockets.1.html \
	dbus-daemon.1.html \
	dbus-launch.1.html \
	dbus-monitor.1.html \
	dbus-send.1.html \
	dbus-uuidgen.1.html

EXTRA_DIST= 					\
	busconfig.dtd				\
	diagram.png				\
	diagram.svg				\
	introspect.dtd				\
	dbus-faq.xml				\
	dbus-specification.xml			\
	dbus-test-plan.xml			\
	dbus-tutorial.xml			\
	dcop-howto.txt				\
	file-boilerplate.c			\
	introspect.xsl				\
	system-activation.txt			\
	$(MAN_IN_FILES) $(man_MANS)

HTML_FILES=					\
	dbus-faq.html				\
	dbus-specification.html			\
	dbus-test-plan.html			\
	dbus-tutorial.html

if DBUS_XML_DOCS_ENABLED
all-local:: $(HTML_FILES)

EXTRA_DIST += $(HTML_FILES)

dbus-specification.html: dbus-specification.xml
	$(XMLTO) html-nochunks $<

dbus-test-plan.html: dbus-test-plan.xml
	$(XMLTO) html-nochunks $<

dbus-tutorial.html: dbus-tutorial.xml
	$(XMLTO) html-nochunks $<

dbus-faq.html: dbus-faq.xml
	$(XMLTO) html-nochunks $<

endif

if DBUS_DOXYGEN_DOCS_ENABLED
# Use the index as a proxy for the entire doc tree.
DOXYGEN_HTML_INDEX = api/html/index.html

all-local:: $(DOXYGEN_HTML_INDEX)

$(DOXYGEN_HTML_INDEX): $(wildcard $(top_srcdir)/dbus/*.[ch])
	$(AM_V_GEN)cd $(top_builddir) && doxygen Doxyfile
endif

if DBUS_HAVE_MAN2HTML
all-local:: $(MAN_HTML_FILES)

%.1.html: %.1
	$(AM_V_GEN)( $(MAN2HTML) $< > $@.tmp && mv $@.tmp $@ )
endif

clean-local:
	rm -rf api
	rm -f *.1.html

maintainer-clean-local:
	rm -f $(HTML_FILES)
