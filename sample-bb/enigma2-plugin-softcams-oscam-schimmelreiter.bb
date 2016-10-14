include oscam-schimmelreiter.inc

BINFILE = "oscam-schimmelreiter"

EXTRA_OECMAKE += "\
	-DIPV6SUPPORT=1 \
	"

DESCRIPTION += "- IPv6 support\nThis version can connect to servers using IPv6 and/or IPv4."

#RREPLACES_${PN} = "${PN}-ipv4"
#RCONFLICTS_${PN} = "${PN}-ipv4"