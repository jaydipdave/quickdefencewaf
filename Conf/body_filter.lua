body = ngx.arg[1]
        body = body:gsub("1.888.245.5550", "x.xxx.xxx.xxxx")
	body = body:gsub("Syntax error in string in query expression[^\\.]+.","")

	body = body:gsub("System.[Data.OleDb.OleDbException|Web|IO][^<]+", "")
	body = body:gsub("You have an error in your SQL[^<]+", "")

	body = body:gsub("<%?php", "")
	body = body:gsub("<%%", "")
	ngx.arg[1] = body
        return
