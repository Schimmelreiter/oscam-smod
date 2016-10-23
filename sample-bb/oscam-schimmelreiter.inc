MAINTAINER = "Schimmelreiter <Ziggy.SpaceRat@gmx.de>"
SUMMARY = "OScam - Open Source Softcam - Schimmelreiter-Edition ${PV}"
DESCRIPTION = "Combining the benefits of\n \
- latest trunk\n \
- modern interface\n \
- emu support\n \
"

require conf/license/license-gplv2.inc
inherit cmake gitpkgv

LICENSE = "GPLv3"
LIC_FILES_CHKSUM = "file://COPYING;md5=d32239bcb673463ab874e80d47fae504"

SRCREV = "${AUTOREV}"
PV = "1.20+git${SRCPV}"
PKGV = "1.20+git${GITPKGV}"

SRC_URI="git://github.com/Schimmelreiter/oscam-schimmelreiter.git;protocol=git"

S = "${WORKDIR}/git/src"
F = "${WORKDIR}/git/files"

PACKAGE_ARCH = "${DEFAULTTUNE}"
#

DEPENDS = "libusb openssl"

EXTRA_OECMAKE += "\
	-DGIT_REV=${SRCREV} \
	-DWEBIF=1 \
	-DWEBIF_LIVELOG=1 \
	-DWEBIF_JQUERY=1 \
	-DTOUCH=1 \
	-DWITH_SSL=1 \
	-DWITH_STAPI=0 \
	-DHAVE_LIBUSB=1 \
	-DSTATIC_LIBUSB=0 \
	-DHAVE_PCSC=0 \
	"

do_install() {
    install -d ${D}/${bindir}
    install -m 0755 ${WORKDIR}/build/oscam ${D}/usr/bin/${BINFILE}
    install -d ${D}/${sysconfdir}/init.d
    install -m 0755 ${F}/softcam.oscam ${D}/${sysconfdir}/init.d/softcam.${BINFILE}
    install -d ${D}/${sysconfdir}/tuxbox/config/${BINFILE}
    install -m 0644 ${F}/oscam.conf ${D}/${sysconfdir}/tuxbox/config/${BINFILE}
    install -m 0644 ${F}/oscam.server ${D}/${sysconfdir}/tuxbox/config/${BINFILE}
    install -m 0644 ${F}/oscam.user ${D}/${sysconfdir}/tuxbox/config/${BINFILE}
    install -m 0644 ${F}/oscam.dvbapi ${D}/${sysconfdir}/tuxbox/config/${BINFILE}
    install -m 0644 ${F}/oscam.constcw ${D}/${sysconfdir}/tuxbox/config/${BINFILE}
    install -m 0644 ${F}/SoftCam.Key ${D}/${sysconfdir}/tuxbox/config/${BINFILE}
    sed -i s#config/oscam/oscam.constcw#config/${BINFILE}/oscam.constcw# ${D}/${sysconfdir}/tuxbox/config/${BINFILE}/oscam.server
}

FILES_${PN} = "/usr /etc/init.d /etc/tuxbox"
CONFFILES_${PN} = "/etc/tuxbox/config/${BINFILE}"

pkg_prerm_${PN} () {
	if [ "x$D" == "x" ]; then
		/etc/init.d/softcam.${BINFILE} stop 2>/dev/null || true
	fi
	OLDLINK="`readlink -f $D/etc/init.d/softcam`" 2>/dev/null
	rm -f "$D/etc/init.d/softcam"
	if [ "${OLDLINK}" == "$D/etc/init.d/softcam.${BINFILE}" -a -f $D/etc/init.d/softcam.None ]
	then
		echo "${BINFILE} was selected, now selecting None as softcam"
		ln -s "softcam.None" "$D/etc/init.d/softcam"
	fi
	exit 0
}

pkg_postinst_${PN} () {
	[ "x$D" == "x" ] && [ -e "/etc/init.d/softcam" ] && /etc/init.d/softcam stop 2>/dev/null || true
	#if [ ! -e "$D/etc/init.d/softcam" ] || [ "$D/etc/init.d/softcam.None" == "`readlink -f $D/etc/init.d/softcam`" ]
	#then
		rm -f "$D/etc/init.d/softcam" 2>/dev/null
		ln -s "softcam.${BINFILE}" "$D/etc/init.d/softcam"
		echo "Switching default softcam to ${BINFILE}"
	#fi

	if [ "x$D" == "x" ]; then
		if [ "$D/etc/init.d/softcam.${BINFILE}" == "`readlink -f $D/etc/init.d/softcam`" ]
		then
			echo "Softcam is selected as default, (re)starting ${BINFILE}"
			$D/etc/init.d/softcam.${BINFILE} restart || true
		fi
	fi
	exit 0
}

INSANE_SKIP_${PN} += "already-stripped"
