include oscam-schimmelreiter.inc

BINFILE = "oscam-schimmelreiter-ipv4"

EXTRA_OECMAKE += "\
	-DIPV6SUPPORT=0 \
	"
DESCRIPTION += "Note: You should never need this IPv4-ONLY version!"

#RREPLACES_${PN} = "${@'${PN}'.replace('-ipv4', '')}"
#RCONFLICTS_${PN} = "${@'${PN}'.replace('-ipv4', '')}"
