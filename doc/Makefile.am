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

DTDS = \
	busconfig.dtd \
	introspect.dtd

STATIC_DOCS = \
	diagram.png \
	diagram.svg \
	dbus-faq.xml \
	dbus-specification.xml \
	dbus-test-plan.xml \
	dbus-tutorial.xml \
	dcop-howto.txt \
	introspect.xsl \
	system-activation.txt \
	$(DTDS)

EXTRA_DIST = \
	file-boilerplate.c \
	doxygen_to_devhelp.xsl \
	$(STATIC_DOCS) \
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
all-local:: doxygen.stamp

doxygen.stamp: $(wildcard $(top_srcdir)/dbus/*.[ch])
	$(AM_V_GEN)cd $(top_builddir) && doxygen Doxyfile
	@touch $@
endif

if DBUS_HAVE_MAN2HTML
all-local:: $(MAN_HTML_FILES)

%.1.html: %.1
	$(AM_V_GEN)( $(MAN2HTML) $< > $@.tmp && mv $@.tmp $@ )
endif

if DBUS_CAN_UPLOAD_DOCS
BONUS_FILES = \
	$(top_srcdir)/README \
	$(top_srcdir)/HACKING \
	$(top_srcdir)/AUTHORS \
	$(top_srcdir)/NEWS \
	$(top_srcdir)/COPYING \
	$(top_srcdir)/ChangeLog

dbus-docs: $(STATIC_DOCS) $(HTML_FILES) $(MAN_HTML_FILES) $(BONUS_FILES) doxygen.stamp
	$(AM_V_at)rm -rf $@
	$(AM_V_GEN)mkdir -p $@/api
	$(AM_V_at)cp $(STATIC_DOCS) $@
	$(AM_V_at)cp $(HTML_FILES) $@
	$(AM_V_at)cp $(MAN_HTML_FILES) $@
	$(AM_V_at)cp $(BONUS_FILES) $@
	$(AM_V_at)cp -r api/html $@/api

dbus-docs.tar.gz: dbus-docs
	$(AM_V_GEN)tar czf $@ $<

DOC_SERVER = dbus.freedesktop.org
DOC_WWW_DIR = /srv/dbus.freedesktop.org/www

SPECIFICATION_SERVER = specifications.freedesktop.org
SPECIFICATION_PATH = /srv/specifications.freedesktop.org/www/dbus/1.0

maintainer-upload-docs: dbus-docs.tar.gz dbus-docs
	scp dbus-docs.tar.gz $(DOC_SERVER):$(DOC_WWW_DIR)
	rsync -rvzP --chmod=Dg+s,ug+rwX,o=rX \
		dbus-docs/ $(DOC_SERVER):$(DOC_WWW_DIR)/doc/
	scp -p $(DTDS) $(SPECIFICATION_SERVER):$(SPECIFICATION_PATH)
else
maintainer-upload-docs:
	@echo "Can't upload documentation! Re-run configure with"
	@echo "  --enable-doxygen-docs --enable-xml-docs"
	@echo "and ensure that man2html is installed."
	@false
endif

clean-local:
	rm -rf api
	rm -rf dbus-docs
	rm -f *.1.html

maintainer-clean-local:
	rm -f $(HTML_FILES)
