# Source: https://github.com/f5devcentral/irules-toolbox/blob/master/security/http/cookies/samesite-attributes.tcl
# iRule: samesite_cookie_handling
# author: Simon Kowallik
# version: 1.6
#
# This iRule requires BIG-IP v12 or higher to use the HTTP::cookie attribute command. 
# Check https://github.com/f5devcentral/irules-toolbox/tree/master/security/http/cookies for a v11 iRule 
#    that doesn't use HTTP::cookie attribute (but uses more CPU cycles) 
#
# History: version - author - description
#	 1.0 - Simon Kowallik - initial version 
#	 1.1 - Aaron Hooley - updated to add support for setting SameSite to Strict|Lax|None for BIG-IP and app cookies in Set-Cookie headers
#			- Add option to remove SameSite=None cookies for incompatible browsers
#	 1.2 - Aaron Hooley - Added option to rewrite all cookies without naming them explicitly or with prefixes
#	 1.3 - Aaron Hooley - set samesite_compatible to 0 by default instead of a null string 
#	 1.4 - Aaron Hooley - Fixed issue with removing samesite=none cookies for incompatible clients and setting lax or strict
#	 1.5 - Aaron Hooley - Fixed issue noted in https://support.f5.com/csp/article/K23237429 by disabling the iRule if another response has already been sent
#        1.6 - Rene Geile - Change values to first letter uppercase, no upfront conversion, all inline comparison with tolower
#
# What the iRule does:
# Sets SameSite to Strict, Lax or None (and sets Secure when SameSite=None) for compatible user-agents
# Optionally removes SameSite attribute from all cookies for incompatible user-agents so they'll handle cookies as if they were SameSite=None
#
# The iRule works for:
# - LTM for web app cookies and persistence cookies, except those that the web app sets via Javascript
# - ASM for web app cookies and all ASM cookies except those that ASM or the web app sets via Javascript
# - APM for web app cookies and all APM cookies if set set_samesite_on_all=1 or configure the cookie names in the config variable $named_cookies, except those that the web app sets via Javascript
#
# The iRule requires BIG-IP v12 or greater to use the HTTP::cookie attribute command
#
# RFC "standards"
# https://tools.ietf.org/html/draft-west-cookie-incrementalism-00
# https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-05
# further reading:
# https://web.dev/samesite-cookies-explained/
# https://web.dev/samesite-cookie-recipes/
# https://blog.chromium.org/2019/10/developers-get-ready-for-new.html
# https://www.chromium.org/updates/same-site
# https://www.chromium.org/updates/same-site/incompatible-clients

proc checkSameSiteCompatible {user_agent} {
	# Procedure to check if a user-agent supports SameSite=None on cookies
	#
	# usage: 
	# set isSameSiteCompatible [call checkSameSiteCompatible {User-Agent-String}]
	#
	# check for incompatible user-agents: https://www.chromium.org/updates/same-site/incompatible-clients
	# based on https://devcentral.f5.com/s/articles/HTTP-cookie-SameSite-test-detection-of-browsers-with-incompatible-SameSite-None-handling
	switch -glob -- [set user_agent [string tolower $user_agent]] {
		{*chrome/5[1-9].[0-9]*} -
		{*chrome/6[0-6].[0-9]*} -
		{*chromium/5[1-9].[0-9]*} -
		{*chromium/6[0-6].[0-9]*} -
		{*ip?*; cpu *os 12*applewebkit*} -
		{*macintosh;*mac os x 10_14*version*safari*} -
		{mozilla*macintosh;*mac os x 10_14*applewebkit*khtml, like gecko*} {
			# no samesite support
			return 0
		}
		{*ucbrowser/*} {
			switch -glob -- $user_agent {
				{*ucbrowser/[1-9].*} -
				{*ucbrowser/1[0-1].*} -
				{*ucbrowser/12.[0-9].*} -
				{*ucbrowser/12.1[0-1].*} -
				{*ucbrowser/12.12.*} -
				{*ucbrowser/12.13.[0-2]*} {
					# no samesite support
					return 0
				}
			}
		}
	}
	# If the current user-agent didn't match any known incompatible browser list, assume it can handle SameSite=None 
	return 1

	# CPU Cycles on Executing (>100k test runs)
	#	 Average		 22000-42000 (fastest to slowest path)
	#	 Maximum		214263
	#	 Minimum		 13763
}

# the iRule code
when CLIENT_ACCEPTED priority 100 {

	# Set BIG-IP and app cookies found in Set-Cookie headers using this iRule to:
	#
	# None: Cookies will be sent in both first-party context and cross-origin requests; 
	#		however, the value must be explicitly set to None and all browser requests must 
	#		follow the HTTPS protocol and include the Secure attribute which requires an encrypted 
	#		connection. Cookies that don't adhere to that requirement will be rejected.
	#		Both attributes are required together. If just None is specified without Secure or 
	#		if the HTTPS protocol is not used, the third-party cookie will be rejected.
	#
	# Lax: Cookies will be sent automatically only in a first-party context and with HTTP GET requests. 
	#		SameSite cookies will be withheld on cross-site sub-requests, such as calls to load images or iframes, 
	#		but will be sent when a user navigates to the URL from an external site, e.g., by following a link.
	#
	# Strict: browser never sends cookies in requests to third party domains
	#
	#		Above definitions from: https://docs.microsoft.com/en-us/microsoftteams/platform/resources/samesite-cookie-update 
	#
	# Note: this iRule does not modify cookies set on the client using Javascript or other methods outside of Set-Cookie headers!
	set samesite_security "None"

	# Uncomment when using this iRule on an APM-enabled virtual server so the MRHSession cookies will be rewritten
	# The iRule cannot be saved on a virtual server with this option uncommented if there is no Access profile also enabled
	#ACCESS::restrict_irule_events disable

	# 1. If you want to set SameSite on all BIG-IP and web application cookies for compliant user-agents, set this option to 1
	# The next two configuration options will be ignored since we are rewriting samesite on all cookies
	# Else, if you want to use the next two options for rewriting explicit named cookies or cookie prefixes, set this option to 0
	set set_samesite_on_all 1

	# 2. Rewrite SameSite on specific named cookies
	#
	# To enable this, list the specific named cookies in the list command and comment out the second set command below
	# To disable this, set this variable to {} and comment out the first set command below
	# Cookie names from internal BZ ID761049
	set named_cookies [list {MRHSession} {LastMRH_Session} {F5_ST} {TIN}]
	#set named_cookies {}

	# 3. Rewrite cookies with a prefix like BIG-IP persistence cookies
	# To enable this, list the cookie name prefixes in the list command and comment out the second set command below
	# To disable this, set this variable to {} and comment out the first set command below
	set cookie_prefixes [list {BIGipServer} {TS}]
	#set cookie_prefixes {}

	# For incompatible user-agents, this iRule can remove the SameSite attribute from all cookies sent to the client via Set-Cookie headers
	# This should be enabled by default so user-agents that don't process samesite=none will get the cookies without samesite being set
	# This is only necessary if BIG-IP or the web application being load balanced sets SameSite=None for all clients
	# set to 1 to enable, 0 to disable
	set remove_samesite_for_incompatible_user_agents 1

	# Log debug to /var/log/ltm? 1=yes, 0=no
	# set to 0 after testing
	set samesite_debug 1

	# You shouldn't have to make changes to configuration below here

	# Track the user-agent and whether it supports the SameSite cookie attribute
	set samesite_none_compatible {}
	set user_agent {}

	if { $samesite_debug }{
		set prefix "[IP::client_addr]:[TCP::client_port]:"
		log local0. "$prefix [string repeat "=" 40]"
		log local0. "$prefix \$samesite_security=$samesite_security; \$set_samesite_on_all=$set_samesite_on_all; \$named_cookies=$named_cookies; \$cookie_prefixes=$cookie_prefixes, \
			\$remove_samesite_for_incompatible_user_agents=$remove_samesite_for_incompatible_user_agents"
	}
}

# Run this test event before any other iRule HTTP_REQUEST events to set the User-Agent header value 
# Comment out this event when done testing user-agents
#when HTTP_REQUEST priority 2 {

	# known compatible 
#	HTTP::header replace user-agent {my compatible user agent string}
	# known INcompatible 
#	HTTP::header replace user-agent {chrome/51.10}
#}

# Run this before any other iRule HTTP_REQUEST events on the virtual server
when HTTP_REQUEST priority 100 {

	if { $samesite_debug }{ 
		log local0. "$prefix [string repeat "-" 40]" 
		log local0. "$prefix [HTTP::host][HTTP::uri]"
	}

	# Check if user-agent can handle samesite=none if we're removing samesite=none cookies or if we're setting samesite=none

	# If we're removing samesite=none cookies for incompatible browsers or we're setting samesite to none, 
	#	we need to check the user-agent to see if it's compatible with samesite=none
	if { $remove_samesite_for_incompatible_user_agents == 1 or [string tolower $samesite_security] eq "none" }{

		# Inspect user-agent once per TCP session for higher performance if the user-agent hasn't changed
		if { $samesite_none_compatible == 0 or $user_agent ne [HTTP::header value {User-Agent}]} {
			set user_agent [HTTP::header value {User-Agent}]
			set samesite_none_compatible [call checkSameSiteCompatible $user_agent]
			if { $samesite_debug }{
				log local0. "$prefix Got \$samesite_none_compatible=$samesite_none_compatible and saved current \$user_agent: $user_agent"
			}
		}
	}
}
# Run this response event with priority 900 after all other iRules to parse the final cookies from the application and BIG-IP
when HTTP_RESPONSE_RELEASE priority 900 {

	# Don't do anything if a response has already been triggered for this request
	if {[HTTP::has_responded]}{
		if { $samesite_debug }{ log local0. "$prefix Exiting as response has already been triggered by another configuration option" }
		# exit this event in this iRule
		return
	}

	# Log the pre-existing Set-Cookie header values
	if { $samesite_debug }{ log local0. "$prefix Original Set-Cookie value(s): [HTTP::header values {Set-Cookie}]" }

	if { $samesite_none_compatible == 1 or [string tolower $samesite_security] ne "none" } {
		# user-agent is compatible with SameSite=None or we're setting samesite to lax or strict, so set SameSite on matching cookies

		if { $set_samesite_on_all }{
			if { $samesite_debug }{ log local0. "$prefix Setting SameSite=$samesite_security on all cookies and exiting" }
			foreach cookie [HTTP::cookie names] {

				if { $samesite_debug }{ log local0. "$prefix Set SameSite=$samesite_security on $cookie" }

				# Remove any prior instances of SameSite attributes
				HTTP::cookie attribute $cookie remove {samesite} 

				# Insert a new SameSite attribute
				HTTP::cookie attribute $cookie insert {samesite} $samesite_security

				# If samesite attribute is set to None, then the Secure flag must be set for browsers to accept the cookie
				if {[string tolower $samesite_security] eq "none" } {
					HTTP::cookie secure $cookie enable
				}
			}
			# Exit this event in this iRule as we've already rewritten all cookies with SameSite
			return
		}
		# Match named cookies exactly
		if { $named_cookies ne {} }{
			foreach cookie $named_cookies {
				if { [HTTP::cookie exists $cookie] } {
					# Remove any pre-existing SameSite attributes from this cookie as most clients use the most strict value if multiple instances are set
					HTTP::cookie attribute $cookie remove {SameSite}

					# Insert the SameSite attribute
					HTTP::cookie attribute $cookie insert {SameSite} $samesite_security

					# If samesite attribute is set to None, then the Secure flag must be set for browsers to accept the cookie
					if {[string tolower $samesite_security] eq "none" } {
						HTTP::cookie secure $cookie enable
					}
				if { $samesite_debug }{ log local0. "$prefix Matched explicitly named cookie $cookie, set SameSite=$samesite_security" }
				if { $samesite_debug }{ log local0. "$prefix " }
				}
			}
		}
		# Match a cookie prefix (cookie name starts with a prefix from the $cookie_prefixes list)
		if { $cookie_prefixes ne {} }{
			foreach cookie [HTTP::cookie names] {
				foreach cookie_prefix $cookie_prefixes {
					if { $cookie starts_with $cookie_prefix } {
						# Remove any pre-existing SameSite attributes from this cookie as most clients use the most strict value if multiple instances are set
						HTTP::cookie attribute $cookie remove {SameSite}

						# Insert the SameSite attribute
						HTTP::cookie attribute $cookie insert {SameSite} $samesite_security

						# If samesite attribute is set to None, then the Secure flag must be set for browsers to accept the cookie
						if { [string tolower $samesite_security] eq "none" } {
							HTTP::cookie secure $cookie enable
						}
						if { $samesite_debug }{ log local0. "$prefix Matched prefixed cookie $cookie, with prefix $cookie_prefix, set SameSite=$samesite_security, breaking from loop" }
						break
					}
				}
			}
		}
	} else {

		# User-agent can't handle SameSite=None
		if { $remove_samesite_for_incompatible_user_agents }{

			# User-agent can't handle SameSite=None, so remove SameSite attribute from all cookies if SameSite=None
			# This will use CPU cycles on BIG-IP so only enable it if you know BIG-IP or the web application is setting 
			# SameSite=None for all clients including incompatible ones
			foreach cookie [HTTP::cookie names] {
				if { [string tolower [HTTP::cookie attribute $cookie value SameSite]] eq "none" }{
					HTTP::cookie attribute $cookie remove SameSite
					if { $samesite_debug }{ log local0. "$prefix Removing SameSite for incompatible client from cookie=$cookie" }
				}
			}
		}
	}
	# Log the modified Set-Cookie header values
	if { $samesite_debug }{ log local0. "$prefix Final Set-Cookies: [HTTP::header values {Set-Cookie}]" }
}
