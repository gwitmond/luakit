--------------------------------------------------------
-- DNSSEC DANE plugin for luakit                      --
-- (C) 2012 Guido Witmond <guido@witmond.nl>          --
-- License: GPL v3 or later                           --
--------------------------------------------------------


require "base64"


-- called from webview.init_funcs signal handler.
function dane_navigation_request(uri)
   _, _, host = string.find(uri, "^https://([^/]+)/")
   if host then
      info("dane: GOT HTTPS!")
      ub_result = dane_lookup(host)  
      local tmpca = os.tmpname()
      local f = io.open(tmpca, "w")
      for i, tlsa in ipairs(ub_result) do
	 -- look for full certificates or authorities
	 if (tlsa.usage == 2 or tlsa.usage == 3) and tlsa.selector == 0 and tlsa.match_type == 0 then
	    f:write(dane_der_to_pem(tlsa.cert_ass))
	 end
      end
      f:close()
      -- set them as accepted CA certificates.
      -- if there are no TLSA-records with full keys, tmpca is empty, 
      -- which leads to rejecting all ssl-connections. That is correct!
      soup.ssl_ca_file = tmpca
   else
      info("dane: no HTTPS!!!")
   end
   return false
end
      
-- dump tables
function info_record(result) 
   for k, v in pairs(result) do
      if type(v) == "table" then
	 info("info_record: %s -> record", k)
	 info_record(v, 2)
      else
	 info("info_record: %s -> %q", k, tostring(v))
      end
   end
end


function dane_der_to_pem(der)
   return "-----BEGIN CERTIFICATE-----\n" .. 
           base64.enc(der) .. 
          "\n-----END CERTIFICATE-----\n"
end

function dane_lookup(host)
   info("DANE_trusted has host: %s", host)
   local port = 443

   -- _443._tcp.www.host.tld
   local lookup = "_" .. port .. "._tcp." .. host
   local result = unbound:resolve(lookup, 52)
   return result
end

function dane_validate(host) 
   info("DANE_trusted has host: %s", host)
   local port = 443

   -- _443._tcp.www.host.tld
   local lookup = "_" .. port .. "._tcp." .. host
   local result = unbound:resolve(lookup, 52)
   info_record(result)
   return result.qname
end

