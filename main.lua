local VS = require('vulscan')

-- use love-fs relative paths
local function love_vuln_db(file)
	local ret = {}
	for line in love.filesystem.lines (file) do
	  table.insert(ret, line)
	end 
	return ret
end

-- preload the databases
local dbs = {
	xforce = love_vuln_db("xforce.csv"),
	securitytracker = love_vuln_db("securitytracker.csv"),
	securityfocus = love_vuln_db("securityfocus.csv"),
	scipvuldb = love_vuln_db("scipvuldb.csv"),
	osvdb = love_vuln_db("osvdb.csv"),
	openvas = love_vuln_db("openvas.csv"),
	exploitdb = love_vuln_db("exploitdb.csv"),
	cve = love_vuln_db("cve.csv")
}

local function love_vuln_scanner(product, version)
	local ret = {}
	for i,db in pairs(dbs) do
		for k, result in pairs(VS:find(db, product, version)) do
			result.db = i
			table.insert(ret, result)
		end
	end
	return ret
end


local results = {}

function love:load()
	print("Please wait while I get vulnerabilities.")
	results = love_vuln_scanner("Apache Tomcat/Coyote JSP engine")
	for i,result in pairs(results) do
		print(result.id .. "  - " .. result.title)
	end
end

function love:draw()
	love.graphics.print("See console for output", (love.graphics.getWidth()/2) - 50, (love.graphics.getHeight()/2) - 5)
end