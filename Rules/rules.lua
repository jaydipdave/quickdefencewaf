
if match("URI","/reload",REGEX) then
	reload_rules()
end

xss = "((<.*>)|(prompt\\()|(alert\\()|(confirm\\()|(eval\\()|(window.)|(document\.)(fscommand)|(javascript:)|(onabort)|(onactivate)|(onafterprint)|(onafterupdate)|(onbeforeactivate)|(onbeforecopy)|(onbeforecut)|(onbeforedeactivate)|(onbeforeeditfocus)|(onbeforepaste)|(onbeforeprint)|(onbeforeunload)|(onbegin)|(onblur)|(onbounce)|(oncanplay)|(oncanplaythrough)|(oncellchange)|(onchange)|(onclick)|(oncontextmenu)|(oncontrolselect)|(oncopy)|(oncut)|(ondataavailable)|(ondatasetchanged)|(ondatasetcomplete)|(ondblclick)|(ondeactivate)|(ondragdrop)|(ondragend)|(ondragenter)|(ondragleave)|(ondragover)|(ondrag)|(ondragstart)|(ondrop)|(ondurationchange)|(onemptied)|(onended)|(onend)|(onerror)|(onerrorupdate)|(onfilterchange)|(onfinish)|(onfocusin)|(onfocusout)|(onfocus)|(onformchange)|(onforminput)|(onhashchange)|(onhelp)|(oninput)|(oninvalid)|(onkeydown)|(onkeypress)|(onkeyup)|(onlayoutcomplete)|(onloadeddata)|(onloadedmetadata)|(onload)|(onloadstart)|(onlosecapture)|(onmediacomplete)|(onmediaerror)|(onmessage)|(onmousedown)|(onmouseenter)|(onmouseleave)|(onmousemove)|(onmouseout)|(onmouseover)|(onmouseup)|(onmousewheel)|(onmoveend)|(onmove)|(onmovestart)|(onoffline)|(ononline)|(onoutofsync)|(onpagehide)|(onpageshow)|(onpaste)|(onpause)|(onplaying)|(onplay)|(onpopstate)|(onprogress)|(onpropertychange)|(onratechange)|(onreadystatechange)|(onredo)|(onrepeat)|(onreset)|(onresizeend)|(onresize)|(onresizestart)|(onresume)|(onreverse)|(onrowdelete)|(onrowexit)|(onrowinserted)|(onrowsenter)|(onscroll)|(onseeked)|(onseeking)|(onseek)|(onselectionchange)|(onselect)|(onselectstart)|(onshow)|(onstalled)|(onstart)|(onstop)|(onstorage)|(onsubmit)|(onsuspend)|(onsyncrestored)|(ontimeerror)|(ontimeupdate)|(ontrackchange)|(onundo)|(onunload)|(onurlflip)|(onvolumechange)|(onwaiting)|(seeksegmenttime)"

--(abbr|accesskey|align|alt|axis|bgcolor|border|cellpadding|cellspacing|char|charoff|charset|cite|class|clear|color|colspan|compact|coords|dir|face|headers|height|href|hreflang|hspace|id|ismap|lang|longdesc|name|noshade|nowrap|rel|rev|rowspan|rules|scope|shape|size|src|start|summary|tabindex|target|title|type|usemap|valign|value|vspace|width|style)

sqli = ""

if match("*", xss ,REGEX) or match("URI,QUERY_FIELDS,HEADER_VALUES", xss ,REGEX) then
	block("oops")
end