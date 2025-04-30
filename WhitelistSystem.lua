local WhitelistCore = {}

local SecurityUtils = loadstring(game:HttpGet("https://raw.githubusercontent.com/N9661/Fluent_Renewed/refs/heads/main/whitelist_core.lua"))()
local IdentityVerification = loadstring(game:HttpGet("https://raw.githubusercontent.com/N9661/Fluent_Renewed/refs/heads/main/identity_verification.lua"))()
local WhitelistData = loadstring(game:HttpGet("https://raw.githubusercontent.com/N9661/Fluent_Renewed/refs/heads/main/whitelist_data.lua"))()

local _G = _G or getgenv()
if not _G.__WhitelistState then
    _G.__WhitelistState = {
        initialized = false,
        lastVerification = nil,
        verificationCount = 0
    }
end

function WhitelistCore.isUserWhitelisted(identity)
    for _, user in ipairs(WhitelistData) do
        if user.username == identity.username and user.userId == identity.userId then
            if IdentityVerification.compareClientIdFirstThreeParts(user.clientId, identity.clientId) then
                return true, "Fully authorized"
            else
                return false, "Client ID mismatch"
            end
        end
    end
    
    return false, "User not in whitelist"
end

function WhitelistCore.verifyUser()
    SecurityUtils.captureOriginalFunctions()
    
    local tamperingEvidence = SecurityUtils.checkForTampering()
    if #tamperingEvidence > 0 then
        _G.__SecurityState.tamperingDetected = true
        return false, "Tampering detected: " .. tamperingEvidence[1]
    end
    
    local identity = IdentityVerification.verifyIdentity()
    
    if identity.spoofingDetected then
        return false, "Identity spoofing detected"
    end
    
    local whitelisted, reason = WhitelistCore.isUserWhitelisted(identity)
    
    _G.__WhitelistState.lastVerification = {
        timestamp = os.time(),
        identity = identity,
        whitelisted = whitelisted,
        reason = reason
    }
    _G.__WhitelistState.verificationCount = _G.__WhitelistState.verificationCount + 1
    
    return whitelisted, reason
end

function WhitelistCore.initialize()
    if _G.__WhitelistState.initialized then
        local errorCode = math.random(1000, 9999)
        SecurityUtils.restoreOriginalFunctions()
        SecurityUtils.secureKick(game.Players.LocalPlayer, "Multiple execution detected (Error Code: " .. errorCode .. ")")
        error("Multiple execution detected: Error code 0x" .. string.format("%x", errorCode))
        return false
    end
    
    _G.__WhitelistState.initialized = true
    
    local authorized, reason = WhitelistCore.verifyUser()
    
    if authorized then
        print("Access granted - Welcome to the script!")
        return true
    else
        wait(math.random(1, 3))
        SecurityUtils.restoreOriginalFunctions()
        
        local errorCode = math.random(1000, 9999)
        SecurityUtils.secureKick(game.Players.LocalPlayer, "Unauthorized access (Error Code: " .. errorCode .. ")")
        error("Script initialization failed: Error code 0x" .. string.format("%x", errorCode))
        return false
    end
end

return WhitelistCore
