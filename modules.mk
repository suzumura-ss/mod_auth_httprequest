mod_auth_httprequest.la: mod_auth_httprequest.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_auth_httprequest.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_auth_httprequest.la
