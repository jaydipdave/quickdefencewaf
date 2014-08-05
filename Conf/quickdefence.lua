local _QD = {}

local method 		= ""
local args			= ""
local post_args		= ""
local post_body		= ""
local remote_ip 	= ""
local body 			= ""
local start_time	= ""
local http_version	= ""
local headers		= ""
local raw_header 	= ""
local file_name		= ""
local body_data		= ""
local last_match	= "" 
local cookies		= {}
local uri			= ""
local users			= {}
local REGEX			= 1
local STRING		= 2
local PATTERN		= 3
local allpatterns 	= {}
local rules			= assert(loadfile("/usr/local/openresty/nginx/conf/rules.lua"))

function vardump(value, depth, key)
  local linePrefix = ""
  local spaces = ""
  
  if key ~= nil then
    linePrefix = "["..key.."] = "
  end
  
  if depth == nil then
    depth = 0
  else
    depth = depth + 1
    for i=1, depth do spaces = spaces .. "  " end
  end
  
  if type(value) == 'table' then
    mTable = getmetatable(value)
    if mTable == nil then
      ngx.print(spaces ..linePrefix.."(table) \n")
    else
      ngx.print(spaces .."(metatable) \n")
        value = mTable
    end		
    for tableKey, tableValue in pairs(value) do
      vardump(tableValue, depth, tableKey)
    end
  elseif type(value)	== 'function' or 
      type(value)	== 'thread' or 
      type(value)	== 'userdata' or
      value		== nil
  then
    ngx.print(spaces..tostring(value).."\n")
  else
    ngx.print(spaces..linePrefix.."("..type(value)..") "..tostring(value).."\n")
  end
end

function _QD.trim(s)
  return s:match'^%s*(.*%S)' or ''
end

function _QD.in_table( e, t )
	if t==nil then
		return false
	end
	for _,v in pairs(t) do
		if (v==e) then return true end
	end
	return false
end


function _QD.fetch_request()
	ngx.req.read_body()
	method 			= ngx.req.get_method()
	args			= ngx.req.get_uri_args()
	post_args		= ngx.req.get_post_args()
	post_body		= ngx.req.get_body_data()
	remote_ip 		= ngx.var.remote_addr
	body 			= ngx.var.request_body
	start_time		= ngx.req.start_time()
	http_version	= ngx.req.http_version()
	headers			= ngx.req.get_headers()
	raw_header 		= ngx.req.raw_header()
	file_name		= ngx.req.get_body_file()
	body_data		= ngx.req.get_body_data()
	uri 			= ngx.var.uri
	_QD.get_cookies()
end

function _QD.deny_user(ip)
	os.run("echo \""..tostring(ip).."\" >> /etc/hosts.deny")
end

function _QD.check_regex_in_string(data,regex)
	
	if type(data) ~= 'string' then
		return false
	end
	if string.find(regex,"\n") == nil then
		regex = regex .. "\n"
	end
	
	for i_regex in string.gmatch(regex, "([^\r\n]+)") do
		if i_regex~=nil and i_regex~="" and ngx.re.match(string.lower(data),i_regex) ~= nil then
			last_match = ngx.re.match(string.lower(data),i_regex)[0]
			return true
		end
	end
	return false
end

function _QD.check_regex_in_data(data,regex,fieldname,checkkeys)
	if type(data) ~= 'table' then
		return false
	end
	if fieldname == "" or fieldname ==nil then
		fieldname = " | "
	end
	
	if regex == "\"<NULL>\"" then
		if data[fieldname] == nil then
			return true
		else
			return false
		end
	end
	
	fieldname = fieldname .. "|"
	
	local fields = {}
	for field in string.gmatch(fieldname, "([^|]+)|") do
		fields[#fields+1]=field
	end
	for key, val in pairs(data) do
		if type(val)~='string' then
			val = ""
		end
		if key == nil then
			key = ""
		end
		for k,field in pairs(fields) do
			if field == nil or _QD.trim(field) == "" or (string.upper(_QD.trim(field)) == string.upper(_QD.trim(key))) or (string.byte(field)==33 and string.upper(field:sub(2)) ~= string.upper(key) and _QD.in_table("!"..key,fields)==false) then
				if checkkeys == nil then
					if _QD.check_regex_in_string(val,regex) then
						return true
					end
				else
					if _QD.check_regex_in_string(key,regex) then
						return true
					end
				end
			end			
		end
	end
	return false
end


function _QD.get_cookie(str_cookies)
	local t_cookies = {}
	for k, v in string.gmatch(str_cookies, "(%S+)=(%S+)") do
		if v:sub(v:len())==";" then
			t_cookies[k]=v:sub(1,v:len()-1)
		else
			t_cookies[k]=v
		end
	end
	return t_cookies
end

function _QD.get_cookies()
	for word in string.gmatch(raw_header, "Cookie: ([^\r\n]+)") do
		cookies = _QD.get_cookie(word)
	end
end

function _QD.safe_string(badstring)
	return badstring:gsub("([%(%)%.%%%+%-%*%?%[%]%^%$])","%%%1")
end
--https://github.com/jaydipdave/quickdefencewaf
function _QD.extract_rule_field(fieldname)
	fieldname = _QD.trim(fieldname)
	fieldname = fieldname:gsub("URI","")
	fieldname = fieldname:gsub("HEADER_NAMES","")
	fieldname = fieldname:gsub("HEADER_VALUES","")
	fieldname = fieldname:gsub("QUERY_FIELDS","")
	fieldname = fieldname:gsub("QUERY_STRING","")
	fieldname = fieldname:gsub("PLAIN_URI_QUERY","")
	fieldname = fieldname:gsub("POST_FIELDS","")
	fieldname = fieldname:gsub("POST_DATA","")
	fieldname = fieldname:gsub("COOKIE_NAMES","")
	fieldname = fieldname:gsub("COOKIE_VALUES","")
	fieldname = fieldname:gsub("POST_BODY","")
	fieldname = fieldname:gsub("METHOD","")
	fieldname = _QD.trim(fieldname)
	if fieldname == "" then
		return ""
	end
	return fieldname:sub(2,fieldname:len()-1)
end

function _QD.preparefields(fields)
	local fields = fields:gsub("%s","")..","
	local match_criteria = {}
	for field in string.gmatch(fields, "([^,]+),") do
		fieldname = _QD.extract_rule_field(field)
		if field == "*" then
			fieldname = ""
		end
		if fieldname ~= "" then
			field = field:gsub("<".._QD.safe_string(fieldname)..">","")
		end
		if match_criteria[field] == nil then
			match_criteria[field] = fieldname
		else
			match_criteria[field] = match_criteria[field] .. ",".. fieldname
		end
	end
	return match_criteria
end
function log(message)
	ngx.log(ngx.ALERT, tostring(message))
end

function block(message, http_code,delay,block_url)
	ngx.log(ngx.ALERT, "[QuickDefence]["..tostring(message).."][BLOCKED]"..raw_header.."\n\n[MATCH: "..last_match.."]")
	if delay then
		ngx.sleep(delay)
	end
	if block_url then
		ngx.redirect(block_url,http_code)
	end
	if http_code then
		ngx.status = http_code
		ngx.exit(http_code)
	end
	ngx.exit(401)
end

function redirect(url)
	ngx.redirect(url,301)
end

function load_patterns(pattern_name, file)
	local patterns_f = io.open(file, "r"); 
	local patterns = ""
	if patterns_f then
		patterns = patterns_f:read("*all");
	else
		return nil
	end
	--allpatterns = 
	return patterns
end


function match(fields, match, match_type)
	local match_criteria = {}
	match_criteria = _QD.preparefields(fields)
	for field,fieldname in pairs(match_criteria) do
		if args ~= nil and (string.find(field,"QUERY_STRING")==1 or field=="*") then
			if _QD.check_regex_in_data(args,match,fieldname) then
				return {field,fieldname}
			end
		end
		
		if ngx.var.args ~= nil and (string.find(field,"PLAIN_URI_QUERY")==1 or field=="*") then
			if _QD.check_regex_in_string(ngx.var.args,match) then
				return {field,fieldname}
			end
		end
		
		if args ~= nil and string.find(field,"QUERY_FIELDS")==1 then
			if _QD.check_regex_in_data(args,match,fieldname,1) then
				return {field,fieldname}
			end
		end
		
		if string.find(field,"METHOD")==1 then
			if _QD.check_regex_in_string(method,match) then
				return {field,fieldname}
			end
		end
		
		if string.find(field,"URI")==1 then
			if _QD.check_regex_in_string(ngx.var.uri,match) then
				return {field,fieldname}
			end
		end
		
		if post_args ~= nil  and (string.find(field,"POST_DATA")==1 or field=="*") then
			if _QD.check_regex_in_data(post_args,match,fieldname) then
				return {field,fieldname}
			end
		end
		
		if post_args ~= nil  and string.find(field,"POST_FIELDS")==1 then
			if _QD.check_regex_in_data(post_args,match,fieldname,1) then
				return {field,fieldname}
			end
		end
		
		if post_body ~= nil  and (string.find(field,"POST_BODY")==1 or field=="*") then
			if _QD.check_regex_in_string(post_body,match) then
				return {field,fieldname}
			end
		end

		if cookies ~= nil and (string.find(field,"COOKIE_VALUES")==1 or field=="*") then
			if _QD.check_regex_in_data(cookies,match,fieldname) then
				return {field,fieldname}
			end
		end
											
		if cookies ~= nil and string.find(field,"COOKIE_NAMES")==1 then
			if _QD.check_regex_in_data(cookies,match,fieldname,1) then
				return {field,fieldname}
			end
		end
		
		if headers ~= nil and string.find(field,"HEADER_VALUES")==1 then
			if _QD.check_regex_in_data(headers,match,fieldname) then
				return {field,fieldname}
			end
		end
		
		if headers ~= nil and string.find(field,"HEADER_NAMES")==1 then
			if _QD.check_regex_in_data(headers,match,fieldname,1) then
				return {field,fieldname}
			end
		end
	end
	return nil
end

function reload_rules()
	rules = assert(loadfile("/usr/local/openresty/nginx/conf/rules.lua"))
end

function _QD.protect()
	local ok = false
	if ngx.var.uri:find(".jpg",1,true) == nil and ngx.var.uri:find(".jpg",1,true) == nil and ngx.var.uri:find(".js",1,true) == nil  and ngx.var.uri:find(".css",1,true) == nil and ngx.var.uri:find(".gif",1,true) == nil and ngx.var.uri:find(".png",1,true) == nil and ngx.var.uri:find(".jpeg",1,true) == nil and ngx.var.uri:find(".gif",1,true) == nil  then
		rules()
	else
		return
	end
	
end


return _QD
----------------------------------
