return (function()
    local _a=string.char;local _b=string.byte;local _c=string.sub;local _d=table.concat;local _e=table.insert;local _f=math.ldexp;local _g=getfenv or function()return _ENV end;local _h=setmetatable;local _i=select;local _j=unpack or table.unpack;local _k=tonumber;
    
    local function _l(_m,_n,...)
        local function _o(_p)
            local _q={}
            local _r=1
            local _s=1
            while _r<=#_p do
                local _t=_b(_p,_r)
                _r=_r+1
                _q[_s]=_t
                _s=_s+1
            end
            return _q
        end
        
        local _u={
            "HVX_Havoc:Username:Username:Username:",
            
            "USERID USERID USERID USERID",
            
            "{ClientID:ClientID:ClientID:ClientID:}",
            
            "{HWID:HWID:HWID:HWID:HWID:}"
        }
        
        local function _v(_w)
            local _x={}
            for _y in _w:gmatch("[^:]+") do
                table.insert(_x,_y)
            end
            return _x
        end
        
        local function _z(_A)
            local _B={}
            for _C in _A:gmatch("%S+") do
                table.insert(_B,tonumber(_C))
            end
            return _B
        end
        
        local function _D(_E)
            _E=_E:gsub("{",""):gsub("}","")
            return _v(_E)
        end
        
        return {
            Usernames=_v(_u[1]),
            UserIds=_z(_u[2]),
            ClientIds=_D(_u[3]),
            HWIDs=_D(_u[4])
        }
    end
    
    return _l()
end)()
