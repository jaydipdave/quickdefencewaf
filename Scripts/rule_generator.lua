
local profile_rules = {}
local md5 = require 'md5'


function split(pString, pPattern)
   local Table = {}  -- NOTE: use {n = 0} in Lua-5.0
   local fpat = "(.-)" .. pPattern
   local last_end = 1
   local s, e, cap = pString:find(fpat, 1)
   while s do
      if s ~= 1 or cap ~= "" then
     table.insert(Table,cap)
      end
      last_end = e+1
      s, e, cap = pString:find(fpat, last_end)
   end
   if last_end <= #pString then
      cap = pString:sub(last_end)
      table.insert(Table, cap)
   end
   return Table
end

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
      print(spaces ..linePrefix.."(table) \n")
    else
      print(spaces .."(metatable) \n")
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
    print(spaces..tostring(value).."\n")
  else
    print(spaces..linePrefix.."("..type(value)..") "..tostring(value).."\n")
  end
end


function rank_input(value)
	-- ViewState
	-- Email
	-- Date
	-- URL
	-- Phone
	-- username
	-- password
	-- file (Type)
	-- 
	if type(value)~="string" then
		return {"3","",-1}
	end
	local i_type = 0
	local symbs = ""
	for i = 1, #value do
		local c = value:sub(i,i)
		if (string.byte(c) >= 65 and string.byte(c) <= 90) or (string.byte(c) >= 97 and string.byte(c) <= 122) then
			if i_type == 0 then 
				i_type = 1 
			elseif i_type == 2 then
				i_type = 3
			end
		elseif (string.byte(c) >= 48 and string.byte(c) <= 57) then
			if i_type == 0 then 
				i_type = 2
			elseif i_type == 1 then
				i_type = 3
			end
		else
			if symbs:find(c,1,true) == nil then
				symbs = symbs .. c 
			end
		end
	end
	return {tostring(i_type), symbs , #value }
end


function profile_rule(method,uri,input,value)
	local old_type = ""
	if not profile_rules[md5.sumhexa(method..uri..input)] then
		profile_rules[md5.sumhexa(method..uri..input)] = {}
		profile_rules[md5.sumhexa(method..uri..input)]["min"] = 0
		profile_rules[md5.sumhexa(method..uri..input)]["max"] = 0
		profile_rules[md5.sumhexa(method..uri..input)]["symbs"] = ""
	end
	local rank = rank_input(value)
	profile_rules[md5.sumhexa(method..uri..input)]["method"] = method
	profile_rules[md5.sumhexa(method..uri..input)]["uri"] = uri
	profile_rules[md5.sumhexa(method..uri..input)]["field"] = input
	if profile_rules[md5.sumhexa(method..uri..input)]["valuetype"] == nil then
		profile_rules[md5.sumhexa(method..uri..input)]["valuetype"] = rank[1]
	elseif profile_rules[md5.sumhexa(method..uri..input)]["valuetype"] ~= rank[1] then
		profile_rules[md5.sumhexa(method..uri..input)]["valuetype"] = 3
	end
	for i= 1, #rank[2] do
		local c = rank[2]:sub(i,i)
		if profile_rules[md5.sumhexa(method..uri..input)]["symbs"]:find(c,1,true) == nil then
			profile_rules[md5.sumhexa(method..uri..input)]["symbs"] = profile_rules[md5.sumhexa(method..uri..input)]["symbs"] .. "\\" .. c
		end
	end
	
	--vardump(rank)
	--exit(200)
	if profile_rules[md5.sumhexa(method..uri..input)]["min"] > tonumber(rank[3]) then
		profile_rules[md5.sumhexa(method..uri..input)]["min"] = tonumber(rank[3])
	end
	if profile_rules[md5.sumhexa(method..uri..input)]["max"] < tonumber(rank[3]) then
		profile_rules[md5.sumhexa(method..uri..input)]["max"] = tonumber(rank[3])
	end
end

local f = io.open("/mnt/hgfs/myscanner/Extras/WAF/Rules/profile_rules.txt", "r"); 
local data = f:read("*all");
	for rule in string.gmatch(data, "([^\r\n]+)") do
		local http = split(rule,"\t")
		if http[1]=="GET" or http[1]=="POST" then
			profile_rule(http[1],http[2],http[3],http[4])
		end
	end
	
	
	
	for hash,value in pairs(profile_rules) do
		local regexes = {"[^a-zA-Z"..value['symbs'].."]+", "[^0-9"..value['symbs'].."]+", "[^a-zA-Z0-9"..value['symbs'].."]+" }
		print("RULE: PROFILE_GEN_".. hash .. " \"" .. value['uri'] .. "\"\n\tMATCHES: POST_DATA<"..value["field"]..">,QUERY_STRING<"..value["field"]..">\n\tPATTERN: \"" .. tostring(regexes[tonumber(value['valuetype'])]) .. "\"\n\t\tSCORE: 100\n\n")
	end
	--vardump(profile_rules)