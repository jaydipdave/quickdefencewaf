
local _M = {}
local rules = {}

local method 			= ""
local args			= ""
local post_args		= ""
local post_body		= ""
local remote_ip 		= ""
local body 			= ""
local start_time		= ""
local http_version	= ""
local headers			= ""
local raw_header 		= ""
local file_name		= ""
local body_data		= ""
local cookies			= {}
local users			= {}

function _M.vardump(value, depth, key)
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
      _M.vardump(tableValue, depth, tableKey)
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

function _M.trim(s)
  return s:match'^%s*(.*%S)' or ''
end

function _M.in_table( e, t )
	if t==nil then
		return false
	end
	for _,v in pairs(t) do
		if (v==e) then return true end
	end
	return false
end

function _M.load_rules()
	users["recent"]	= {}
	users["suspicious"]	= {}
	users["blocked"]	= {}
	

	local f = io.open("/mnt/hgfs/myscanner/Extras/WAF/Rules/rules.txt", "r"); 
	local trules = f:read("*all");
	local current_rule = ""
	local sub_rule = ""
	local i = {}
	for rule in string.gmatch(trules, "([^\r\n]+)") do
		if rule ~= nil and _M.trim(rule)~="" then
			if string.byte(rule)~=9 then
				if string.find(rule,"RULE: ") then
					for trule,parameter in string.gmatch(rule, "RULE: ([%S]+) \"(.+)\"") do
						if trule=="LOAD_PATTERNS" then
							local patterns_f = io.open(parameter:sub(string.find(parameter,"=")+1), "r"); 
							local patterns = ""
							if patterns_f then
								patterns = patterns_f:read("*all");
							end
							local new_parameter = {}
							new_parameter[parameter:sub(1,string.find(parameter,"=")-1)]=patterns
							parameter = new_parameter
							if rules[trule] then
								for k,v in pairs(rules[trule]["value"]) do parameter[k] = v end
							end
						end
						rules[trule] = {}
						rules[trule]["value"] = parameter
						current_rule = trule
					end
				end
			else
				if string.byte(rule,2)~=9 then
					local nrule = _M.trim(rule)
					for trule,parameter in string.gmatch(nrule, "([%S]+): (.+)") do
						if rules[current_rule][trule] ~= nil and  rules[current_rule][trule][0] == nil then
							local tmp = rules[current_rule][trule]
							rules[current_rule][trule] = nil
							rules[current_rule][trule] = {}
							i[trule]=0
							rules[current_rule][trule][i[trule]] = tmp
							i[trule] = i[trule] + 1
							rules[current_rule][trule][i[trule]] = {}
							rules[current_rule][trule][i[trule]]["value"] = parameter
						else
							if rules[current_rule][trule] == nil then
								rules[current_rule][trule] = {}
								rules[current_rule][trule]["value"] = parameter
								sub_rule = trule
							else
								if  rules[current_rule][trule][0] ~= nil then
									i[trule] = i[trule] + 1
									rules[current_rule][trule][i[trule]] = {}
									rules[current_rule][trule][i[trule]]["value"] = parameter
								end
							end
						end
					end
				else
					if string.byte(rule,3)~=9 then
						local nrule = _M.trim(rule)
						for trule,parameter in string.gmatch(nrule, "([%S]+): (.+)") do
							if  rules[current_rule][sub_rule][i[sub_rule]] ~= nil then
								rules[current_rule][sub_rule][i[sub_rule]][trule] = parameter
							else
								rules[current_rule][sub_rule][trule] = parameter
							end
						end
					end
				end
			end
		end
	end
end 

function _M.fetch_request()
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
	_M.get_cookies()
end

function _M.deny_user(ip)
	os.run("echo \""..tostring(ip).."\" >> /etc/hosts.deny")
end

function _M.makeString(l)
        if l < 1 then return nil end -- Check for l < 1
        local s = "" -- Start string
		math.randomseed(os.time())
        for i = 1, l do
            s = s .. string.char(math.random(97, 122)) -- Generate random number from 32 to 126, turn it into character and add to string
        end
        return s -- Return string
end

function _M.user_hit(ip)
	local token = ''
	local new_token = ''
	if users["recent"][ip] then
		users["recent"][ip]["hit_time"] = start_time
		users["recent"][ip]["hit_count"] = users["recent"][ip]["hit_count"] + 1
		token = users["recent"][ip]["token"]
		users["recent"][ip]["token"] = _M.makeString(44)
		new_token = users["recent"][ip]["token"]
	elseif users["suspicious"][ip] then
		users["suspicious"][ip]["hit_time"] = start_time
		users["suspicious"][ip]["hit_count"] = users["suspicious"][ip]["hit_count"] + 1
		token = users["suspicious"][ip]["token"]
		users["suspicious"][ip]["token"] = _M.makeString(44)
		new_token = users["suspicious"][ip]["token"]
	elseif users["blocked"][ip] then
		users["blocked"][ip]["hit_time"] = start_time
		users["blocked"][ip]["hit_count"] = users["blocked"][ip]["hit_count"] + 1
		token = users["blocked"][ip]["token"]
		users["blocked"][ip]["token"] = _M.makeString(44)
		new_token = users["blocked"][ip]["token"]
	else
		users["recent"][ip] = {}
		users["recent"][ip]["hit_time"] = start_time
		users["recent"][ip]["hit_count"] = 1
		users["recent"][ip]["score"] = 0
		users["recent"][ip]["first_visit"] = start_time
		users["recent"][ip]["token"] = _M.makeString(44)
		token = users["recent"][ip]["token"]
		new_token = users["recent"][ip]["token"]
	end
	
		local cookie_val = {}
		local tmp = cookies["management_id"]
		for k,v in pairs(cookies) do if k~="management_id" then table.insert(cookie_val, k .. "=" .. v .. "; ") end end
		
		table.insert(cookie_val,"management_id" .. "=" .. new_token .. ";")
		--if token ~= tmp then
			--ngx.log(ngx.ALERT, tostring(tmp) .. " ---- " .. token )
		--end
		ngx.header['Set-Cookie'] = cookie_val
end

function _M.block_user(ip,score,block,deny_ip)
	if users["blocked"][ip] then
		users["blocked"][ip]["score"] = users["blocked"][ip]["score"] + score
	elseif users["suspicious"][ip] then
		if block then
			users["blocked"][ip] = users["recent"][ip]
			users["recent"][ip] = nil
			users["blocked"][ip]["score"] = users["blocked"][ip]["score"] + score
		else
			users["suspicious"][ip]["score"] = users["suspicious"][ip]["score"] + score
		end
	else
		if block then
			users["blocked"][ip] = users["recent"][ip]
			users["recent"][ip] = nil
			users["blocked"][ip]["score"] = users["blocked"][ip]["score"] + score
		else
			users["recent"][ip]["score"] = users["recent"][ip]["score"] + score
		end
	end
end

function _M.abort_request(attack, url,score, block,block_action,deny_ip)
	
	--_M.block_user(remote_ip,score,block,deny_ip)
	if block then
		ngx.log(ngx.ALERT, "[QuickDefence]["..attack.."][BLOCKED]["..tostring(score).."] on URI "..url)
		local http_code = nil
		local block_url = nil
		local sleep = nil
		block_action = block_action .. ";"
		for action in string.gmatch(block_action, "([^;]+)") do
			local para = action:sub(1,action:find("=")-1)
			local value = action:sub(action:find("=")+1)
			if para=="HTTP_CODE" then
				http_code = tonumber(value)
			elseif para =="SLEEP" then
				sleep = tonumber(value)
			elseif para == "REDIRECT" then
				block_url = value
			end
		end
		if sleep then
			ngx.sleep(sleep)
		end
		if block_url then
			ngx.redirect(block_url,http_code)
		end
		if http_code then
			ngx.status = http_code
			ngx.exit(http_code)
		end
		--ngx.redirect("/")
	else
		ngx.log(ngx.ALERT, "[QuickDefence]["..attack.."][LOGGED]["..tostring(score).."] on URI "..url)
	end
    return 
end

function _M.extract_rule_field(fieldname)
	fieldname = _M.trim(fieldname)
	fieldname = fieldname:gsub("QUERY_STRING","")
	fieldname = fieldname:gsub("POST_DATA","")
	fieldname = fieldname:gsub("COOKIES","")
	fieldname = fieldname:gsub("URI","")
	fieldname = fieldname:gsub("COOKIE_NAMES","")
	fieldname = fieldname:gsub("HEADER_NAMES","")
	fieldname = fieldname:gsub("HEADERS","")
	fieldname = fieldname:gsub("QUERY_FIELDS","")
	fieldname = fieldname:gsub("POST_FIELDS","")
	fieldname = fieldname:gsub("POST_BODY","")
	fieldname = fieldname:gsub("METHOD","")
	fieldname = _M.trim(fieldname)
	if fieldname == "" then
		return ""
	end
	return fieldname:sub(2,fieldname:len()-1)
end

function _M.check_regex_in_string(data,regex)
	
	if type(data) ~= 'string' then
		return false
	end
	if string.find(regex,"\n") == nil then
		regex = regex:sub(2,regex:len()-1) .. "\n"
	end
	for i_regex in string.gmatch(regex, "([^\r\n]+)") do
		if _M.trim(i_regex)~=nil and _M.trim(i_regex)~="" and ngx.re.match(string.lower(data:gsub("%s","")),_M.trim(i_regex)) ~= nil then
			return true
		end
	end
	return false
end

function _M.check_regex_in_data(data,regex,fieldname,checkkeys)
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
		for k,field in pairs(fields) do
			if field == nil or _M.trim(field) == "" or (string.upper(field) == string.upper(key)) or (string.byte(field)==33 and string.upper(field:sub(2)) ~= string.upper(key) and _M.in_table("!"..key,fields)==false) then
				if checkkeys == nil then
					if _M.check_regex_in_string(val,regex) then
						return true
					end
				else
					if _M.check_regex_in_string(key,regex) then
						return true
					end
				end
			end			
		end
	end
	return false
end


function _M.get_cookie(str_cookies)
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

function _M.get_cookies()
	for word in string.gmatch(raw_header, "Cookie: ([^\r\n]+)") do
		cookies = _M.get_cookie(word)
	end
end

function _M.safe_string(badstring)
	return badstring:gsub("([%(%)%.%%%+%-%*%?%[%]%^%$])","%%%1")
end

function _M.protect()
	if ngx.var.uri:find(".jpg") == nil and ngx.var.uri:find(".jpg") == nil and ngx.var.uri:find(".js") == nil  and ngx.var.uri:find(".css") == nil and ngx.var.uri:find(".gif") == nil and ngx.var.uri:find(".png") == nil and ngx.var.uri:find(".jpeg") == nil and ngx.var.uri:find(".gif") == nil  then
		_M.user_hit(remote_ip)
	else
		return
	end
	local allowed_methods = ",GET,POST,"
	local rule_methods = allowed_methods
	local rule_url = ""
	local rule_name = ""
	local deny_ip = false
	local block_action = ''
	local block = false

	if rules["ALLOWED_METHODS"]~=nil then
		allowed_method = rules["ALLOWED_METHODS"]["value"]
	end
	if rules["DENY_IP"]~=nil then
		if rules["DENY_IP"]["value"]=="TRUE" then
			deny_ip = true
		end
	end
	if rules["TRIGGER_ACTION"]~=nil then
		if rules["TRIGGER_ACTION"]['value']=="BLOCK" then
			block = true
		end
	end
	if rules["BLOCK_ACTION"]['value'] then
		block_action = rules["BLOCK_ACTION"]['value']
	end

	for i,rule in pairs(rules) do 
		local score = 0
		local rule_deny_ip = deny_ip
		local rule_block = block
		local rule_block_action = block_action
		rule_name = i
		rule_url = rule["value"]
				
		if type(rule_url)=='table' or string.find(ngx.var.uri,rule_url)==1 then
			if type(rule) == "table" then
				for j,srule in pairs(rule) do 
					if j=="ALLOWED_METHODS" then
						rule_methods = srule["value"]
						rule_methods = rule_methods:sub(2,rule_methods:len()-1)
					end
					if j=="DENY_IP" then
						if srule["value"]:sub(2,srule["value"]:len()-1)=="TRUE" then
							rule_deny_ip = true
						else
							rule_deny_ip = false
						end
					end
					if j=="TRIGGER_ACTION" then
						if srule['value']:sub(2,srule['value']:len()-1)=="BLOCK" then
							rule_block = true
						end
					end
					if j=="BLOCK_ACTION" then
						rule_block_action = srule['value']:sub(2,srule['value']:len()-1)
					end
					if j=="MATCHES" then
						for k,match in pairs(srule) do
							
							local matches = match["value"]:gsub("%s","")..","
							local pattern = rule["PATTERN"][k]["value"]
							local match_score =  0
							if type(rule["PATTERN"][k]["SCORE"])=='string' then
								match_score = tonumber(_M.trim(rule["PATTERN"][k]["SCORE"]))
							end
							if string.byte(pattern,2) == string.byte("<")  then
								if rules["LOAD_PATTERNS"]["value"][pattern:sub(3,string.len(pattern)-2)] then
									pattern = rules["LOAD_PATTERNS"]["value"][pattern:sub(3,string.len(pattern)-2)] 
								end
							end
							
							local match_criteria = {}
							for field in string.gmatch(matches, "([^,]+),") do
								fieldname = _M.extract_rule_field(field)
								if fieldname ~= "" then
									field = field:gsub("<".._M.safe_string(fieldname)..">","")
								end
								if match_criteria[field] == nil then
									match_criteria[field] = fieldname
								else
									match_criteria[field] = match_criteria[field] .. ",".. fieldname
								end
							end
							for field,fieldname in pairs(match_criteria) do
								if args ~= nil and string.find(field,"QUERY_STRING")==1 then
									if _M.check_regex_in_data(args,pattern,fieldname) then
										score = score + tonumber(match_score)
									end
								end
								
								if args ~= nil and string.find(field,"QUERY_FIELDS")==1 then
									if _M.check_regex_in_data(args,pattern,fieldname,1) then
										score = score + tonumber(match_score)
									end
								end
								
								if string.find(field,"METHOD")==1 then
									if _M.check_regex_in_string(method,pattern) then
										score = score + tonumber(match_score)
									end
								end
								
								if string.find(field,"URI")==1 then
									if _M.check_regex_in_string(ngx.var.uri,pattern) then
										score = score + tonumber(match_score)
									end
								end
								
								if post_args ~= nil  and string.find(field,"POST_DATA")==1 then
									if _M.check_regex_in_data(post_args,pattern,fieldname) then
										score = score + tonumber(match_score)
									end
								end
								
								if post_args ~= nil  and string.find(field,"POST_FIELDS")==1 then
									if _M.check_regex_in_data(post_args,pattern,fieldname,1) then
										score = score + tonumber(match_score)
									end
								end
								
								if post_body ~= nil  and string.find(field,"POST_BODY")==1 then
									if _M.check_regex_in_string(post_body,pattern) then
										score = score + tonumber(match_score)
									end
								end

								if cookies ~= nil and string.find(field,"COOKIES")==1 then
									if _M.check_regex_in_data(cookies,pattern,fieldname) then
										score = score + tonumber(match_score)
									end
								end
																	
								if cookies ~= nil and string.find(field,"COOKIE_NAMES")==1 then
									if _M.check_regex_in_data(cookies,pattern,fieldname,1) then
										score = score + tonumber(match_score)
									end
								end
								
								if headers ~= nil and string.find(field,"HEADERS")==1 then
									if _M.check_regex_in_data(headers,pattern,fieldname) then
										score = score + tonumber(match_score)
									end
								end
								
								if headers ~= nil and string.find(field,"HEADER_NAMES")==1 then
									if _M.check_regex_in_data(args,pattern,fieldname,1) then
										score = score + tonumber(match_score)
									end
								end
							end
						end
					end
				end
			end
		end

		if score >=100 then
			_M.abort_request(rule_name, ngx.var.uri,score, rule_block,rule_block_action,rule_deny_ip)
		--elseif score>0 then
			--_M.abort_request(rule_name, ngx.var.uri,score, false,'',false)
		end
		if rule_methods == "" or rule_methods == nil then
			rule_methods = allowed_method
		end
		
		if not string.match(string.upper(rule_methods:gsub("%s",""))..",","[,|:]"..method..",") then
			_M.abort_request(rule_name, ngx.var.uri,score, rule_block,rule_deny_ip)
		end
	end
end

return _M
----------------------------------
