# QuickDefence - Web Application Firewall

## What is QuickDefence - WAF?

* It is a reverse proxy (nginx) based web application firewall.
* Nginx is full featured reverse proxy available on the internet, it is free. Nginx can solve load balancing problem, improve website performance drastically and cover up your web server vulnerabilities.
* Programmable rule writing in pure Lua.

## Features

* Programmable Rule Writing in Lua, to have more control on logical vulnerabilities as well. Lua is a very fast scripting language, so it wont affect the performance of the website
* Easy to deploy and easy to manage
* QuickDefence is based on Nginx, so it will boost the website performance drastically.
* Nginx can be used for efficient load balancing
* Easy response content and response header filtration. (For extended security and Data Leak Prevention (DLP))
* Block malicious users/bots for a certain period of time
* A Basic version of Profiling (Whitelisting approach) 

## YET TODO

* RULE WRITING: Lots and lots of generic rules
* WEB-UI TO MANAGE NGINX AND RULES REMOTELY
* Build Virtual Appliance
* ANALYTICS: A BASIC VERSION OF GOOGLE ANALYTICS.
* Tokenizer : CSRF Protection
* Extended Profiling Mode: Whitelisting approach instead of Blacklisting
* DoS/DDoS detection and ~protection
* Website Access control
	
## SAMPLE RULES

```
	xss = "((<.*>)|(prompt\\()|(alert\\()|(confirm\\()|(eval\\()|(window.)|(document\.)(fscommand)|(javascript:)|(onabort)|(onactivate)|(onafterprint)|(onafterupdate)|(onbeforeactivate)|(onbeforecopy)|(onbeforecut)|(onbeforedeactivate)|(onbeforeeditfocus)|(onbeforepaste)|(onbeforeprint)|(onbeforeunload)|(onbegin)|(onblur)|(onbounce)|(oncanplay)|(oncanplaythrough)|(oncellchange)|(onchange)|(onclick)|(oncontextmenu)|(oncontrolselect)|(oncopy)|(oncut)|(ondataavailable)|(ondatasetchanged)|(ondatasetcomplete)|(ondblclick)|(ondeactivate)|(ondragdrop)|(ondragend)|(ondragenter)|(ondragleave)|(ondragover)|(ondrag)|(ondragstart)|(ondrop)|(ondurationchange)|(onemptied)|(onended)|(onend)|(onerror)|(onerrorupdate)|(onfilterchange)|(onfinish)|(onfocusin)|(onfocusout)|(onfocus)|(onformchange)|(onforminput)|(onhashchange)|(onhelp)|(oninput)|(oninvalid)|(onkeydown)|(onkeypress)|(onkeyup)|(onlayoutcomplete)|(onloadeddata)|(onloadedmetadata)|(onload)|(onloadstart)|(onlosecapture)|(onmediacomplete)|(onmediaerror)|(onmessage)|(onmousedown)|(onmouseenter)|(onmouseleave)|(onmousemove)|(onmouseout)|(onmouseover)|(onmouseup)|(onmousewheel)|(onmoveend)|(onmove)|(onmovestart)|(onoffline)|(ononline)|(onoutofsync)|(onpagehide)|(onpageshow)|(onpaste)|(onpause)|(onplaying)|(onplay)|(onpopstate)|(onprogress)|(onpropertychange)|(onratechange)|(onreadystatechange)|(onredo)|(onrepeat)|(onreset)|(onresizeend)|(onresize)|(onresizestart)|(onresume)|(onreverse)|(onrowdelete)|(onrowexit)|(onrowinserted)|(onrowsenter)|(onscroll)|(onseeked)|(onseeking)|(onseek)|(onselectionchange)|(onselect)|(onselectstart)|(onshow)|(onstalled)|(onstart)|(onstop)|(onstorage)|(onsubmit)|(onsuspend)|(onsyncrestored)|(ontimeerror)|(ontimeupdate)|(ontrackchange)|(onundo)|(onunload)|(onurlflip)|(onvolumechange)|(onwaiting)|(seeksegmenttime)"

	-- sample comment in between

	if match("*", xss ,REGEX) or match("URI,QUERY_FIELDS,HEADER_VALUES", xss ,REGEX) then
		block("Blocked due to XSS problem")
	end
```

## INSTALLATION

As such there is no installation required. You just need to configure your Nginx, having HttpLuaModule module installed.

### Nginx & HttpLuaModule Installation
You can install [Nginx](http://wiki.nginx.org/Install) with [HttpLuaModule](http://wiki.nginx.org/HttpLuaModule) module manually

or

I would suggest to install [openresty](http://openresty.org/) package, which includes Nginx and Lua.

### Nginx Configuration
* Copy Conf/quickdefence.lua file into lualib folder (for me it is: /usr/local/openresty/lualib/quickdefence.lua)
* Edit /usr/local/openresty/nginx/conf/nginx.conf file to configure your web server
* Change the configuration as per below (This is a part of the file which needs to be changed)

```
init_by_lua 'waf = require "quickdefence"; waf.load_rules()';
server {
listen       80;
server_name  localhost;

default_type 'text/html';

location / {
	#content_by_lua 'ngx.say(rules)';

	access_by_lua 'waf.fetch_request();waf.get_cookies();waf.protect()';
	proxy_pass http://localhost:8080;
	header_filter_by_lua_file '/usr/local/openresty/nginx/conf/header_filter.lua';
	body_filter_by_lua_file '/usr/local/openresty/nginx/conf/body_filter.lua';
}
```
* As shown in above code, you need to configure paths for the header_filer.lua and body_filter.lua file. This is basically used for filtering webserver responses.
* Change the proxy_pass parameter to your own website to make it working. You can also redirect it to public facing website to test the waf. (like http://demo.testfire.net, http://webscantest.com, http://crackme.cenzic.com)
* Play around with /mnt/hgfs/myscanner/Extras/WAF/Rules/rules.txt rules file and virtually patch all the vulnerabilities
		
## Motive
	
* An easy to setup, programmable WAF.
	
## Got a Question?
	
* jaydipdave@gmail.com