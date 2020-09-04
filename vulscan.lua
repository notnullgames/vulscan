-- standalone lua version of vulnscamn (for use in luajit or love)

-- USAGE
-- VS:find("Apache Tomcat/Coyote JSP engine", "1.1", "cve.csv")

local function strsplit(sep, s)
    local fields = {}
    local sep = sep or " "
    local pattern = string.format("([^%s]+)", sep)
    string.gsub(s, pattern, function(c) fields[#fields + 1] = c end)
    return fields
end

-- We don't like unescaped things
local function escape(s)
	s = string.gsub(s, "%%", "%%%%")
	return s
end

-- Get the row of a CSV file
local function extract_from_table(line, col, del)
	local val = strsplit(del, line)
	if type(val[col]) == "string" then
		return val[col]
	end
end


local VS = {}


-- Read a file
function VS:read_from_file(file)
	local ret = {}
	for line in io.lines (file) do
	  table.insert(ret, line)
	end 
	return ret
end


-- Find the product matches in the vulnerability databases
function VS:find(prod, ver, db)
	local v = {}			-- matching vulnerabilities
	local v_id			-- id of vulnerability
	local v_title			-- title of vulnerability
	local v_title_lower		-- title of vulnerability in lowercase for speedup
	local v_found			-- if a match could be found

	-- Load database
	local v_entries
	if (type(db) == "table") then
		v_entries = db
	else
		v_entries = VS:read_from_file(db)
	end

	-- Clean useless dataparts (speeds up search and improves accuracy)
	prod = string.gsub(prod, " httpd", "")
	prod = string.gsub(prod, " smtpd", "")
	prod = string.gsub(prod, " ftpd", "")

	local prod_words = strsplit(" ", prod)

	-- Iterate through the vulnerabilities in the database
	for i=1, #v_entries, 1 do
		v_id		= extract_from_table(v_entries[i], 1, ";")
		v_title		= extract_from_table(v_entries[i], 2, ";")

		if type(v_title) == "string" then
			v_title_lower = string.lower(v_title)

			-- Find the matches for the database entry
			for j=1, #prod_words, 1 do
				v_found = string.find(v_title_lower, escape(string.lower(prod_words[j])), 1)
				if type(v_found) == "number" then
					if #v == 0 then
						-- Initiate table
						v[1] = {
							id		= v_id,
							title	= v_title,
							product	= prod_words[j],
							version	= "",
							matches	= 1
						}
					elseif v[#v].id ~= v_id then
						-- Create new entry
						v[#v+1] = {
							id		= v_id,
							title	= v_title,
							product	= prod_words[j],
							version	= "",
							matches	= 1
						}
					else
						-- Add to current entry
						v[#v].product = v[#v].product .. " " .. prod_words[j]
						v[#v].matches = v[#v].matches+1
					end
				end
			end

			-- Additional version matching
			if ver ~= nil and ver ~= "" then
				if v[#v] ~= nil and v[#v].id == v_id then
					for k=0, string.len(ver)-1, 1 do
						v_version = string.sub(ver, 1, string.len(ver)-k)
						v_found = string.find(string.lower(v_title), string.lower(" " .. v_version), 1)

						if type(v_found) == "number" then
							v[#v].version = v[#v].version .. v_version .. " "
							v[#v].matches = v[#v].matches+1
						end
					end
				end
			end
		end
	end

	return v
end

return VS