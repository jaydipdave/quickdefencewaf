body = ngx.arg[1]
	body = body:gsub("Syntax error in string in query expression[^\\.]+.","")
	body = body:gsub("System.[Data.OleDb.OleDbException|Web|IO][^<]+", "")
	body = body:gsub("You have an error in your SQL[^<]+", "")
	--body = body:gsub("<html>", method)
	body = body:gsub("<%?php", "")
	body = body:gsub("<%%", "")
ngx.arg[1] = body
return
