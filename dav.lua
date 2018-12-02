lfs = require "lfs"

local function findSize(directory)
    local size = 0
    if not lfs.attributes(directory,"mode") == "file" then
        for file in lfs.dir(directory) do
            if lfs.attributes(directory.."/"..file,"mode") == "file" then
                --            print("found file, "..file)
                size = size + lfs.attributes(directory.."/"..file, "size")
            elseif lfs.attributes(directory.."/"..file,"mode") == "directory" and file ~= "." and file ~= ".." then
                --                print("found dir, "..file," containing:")
                size = size + findSize(directory.."/"..file) + lfs.attributes(directory.."/"..file, "size")
            end
        end
    else
        size = lfs.attributes(directory, "size")
    end

    return size
end

--Modified Scan function from https://gist.github.com/angeloxx/97714f9108b3642460564acdcd37b34a to run without Mod Security
-- or without any subrequest
local function scan(filename)
    local clamdscan = "/usr/bin/clamdscan"
    local clamscan = "/usr/bin/clamscan"

    -- failoverOnClamdFailure: failover to clamscan if clamdscan report an error
    local failoverOnClamdFailure = true

    -- fail (and block) if clamdscan (and clamscan) fails
    local failOnError = false

    -- local var
    local agent = "clamdscan"

    if filename == nil or findSize(filename) == nil or findSize(filename) == 0 then
        ngx.log(ngx.NOTICE, "Nothing to scan..")
        return nil
    end

    -- The system command we want to call with fdpass flag to
    -- do not incur in a permission issue

    local cmd = clamdscan .. " --fdpass --stdout --no-summary"

    -- Run the command and get the output
    local f = io.popen(cmd .. " " .. filename .. " || true")
    local l = f:read("*a")
    f:close()

    -- Check the output for the FOUND or ERROR strings which indicate
    -- an issue we want to block access on
    local isVuln = string.find(l, "FOUND")
    local isError = string.find(l, "ERROR")
    if lfs.attributes(clamdscan, "mode") == nil then
        isError = true
    end

    -- If clamdscan fails and you want failover to the traditional clamscan...
    if isError and failoverOnClamdFailure then
        -- Try to use the clamscan program
        ngx.log(ngx.NOTICE, "[clamdscan fails (" .. l .. "), failover to clamscan]")
        agent = "clamscan"
        cmd = clamscan .. " --stdout --no-summary"
        f = io.popen(cmd .. " " .. filename .. " || true")
        l = f:read("*a")
        f:close()
        isVuln = string.find(l, "FOUND")
        isError = string.find(l, "ERROR")
    end

    if isVuln then
        ngx.log(ngx.NOTICE, "[" .. agent .. " scanner message: " .. l .. "]")
        return "Virus Detected"
    elseif isError and failOnError then
        -- is a error (not a virus) a failure event?
        ngx.log(ngx.NOTICE, "[" .. agent .. " scanner message: " .. l .. "]")
        return "Error Detected"
    else
        return nil
    end

end


ngx.req.read_body()
local filename = ngx.req.get_body_file()
-- Currently on error (not a virus) file is passed and not blocked.
if ngx.req.get_method() == "PUT" then
    if scan(filename) ~= nil then
        ngx.header.content_type = "text/plain"
        ngx.status = 412
        ngx.say("Suspicious File")
        return
    end
    if tonumber(ngx.var.quota) < findSize(filename)/1000000 + findSize('/var/dav')/1000000 then
        ngx.header.content_type = "text/plain"
        ngx.status = 413
        ngx.say("File exceeds Quota")
    end
end