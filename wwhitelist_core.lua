local SecurityUtils = {}

local _G = _G or getgenv()

-- Initialize security state if it doesn't exist
if not _G.__SecurityState then
    _G.__SecurityState = {
        originalFunctions = {},
        attempts = 0,
        lastCheck = os.time(),
        tamperingDetected = false,
        initialized = false
    }
end

-- Capture original function references to detect hooking
function SecurityUtils.captureOriginalFunctions()
    -- Only capture once to prevent capturing already hooked functions
    if _G.__SecurityState.initialized then
        return _G.__SecurityState.originalFunctions
    end

    local originalFunctions = {}
    
    pcall(function()
        -- Player functions
        if game.Players.LocalPlayer then
            originalFunctions.kick = game.Players.LocalPlayer.Kick
        end
        
        -- Service functions
        originalFunctions.getNameFromUserIdAsync = game:GetService("Players").GetNameFromUserIdAsync
        originalFunctions.getPlayers = game:GetService("Players").GetPlayers
        
        -- Analytics functions
        if game:GetService("RbxAnalyticsService") then
            originalFunctions.getClientId = game:GetService("RbxAnalyticsService").GetClientId
        end
        
        -- HTTP functions
        originalFunctions.generateGUID = game:GetService("HttpService").GenerateGUID
        
        -- Metatable functions
        local success, mt = pcall(getrawmetatable, game)
        if success and mt then
            originalFunctions.index = mt.__index
            originalFunctions.namecall = mt.__namecall
        end
    end)
    
    _G.__SecurityState.originalFunctions = originalFunctions
    _G.__SecurityState.initialized = true
    
    return originalFunctions
end

-- Detect if functions have been hooked/replaced
function SecurityUtils.detectFunctionHooking()
    local hookedFunctions = {}
    local originalFunctions = _G.__SecurityState.originalFunctions
    
    -- Ensure we have original functions to compare against
    if not originalFunctions or not next(originalFunctions) then
        return {"No original functions captured"}
    end
    
    pcall(function()
        -- Check player functions
        if game.Players.LocalPlayer and originalFunctions.kick and 
           originalFunctions.kick ~= game.Players.LocalPlayer.Kick then
            table.insert(hookedFunctions, "Player.Kick")
        end
        
        -- Check service functions
        if originalFunctions.getNameFromUserIdAsync and 
           originalFunctions.getNameFromUserIdAsync ~= game:GetService("Players").GetNameFromUserIdAsync then
            table.insert(hookedFunctions, "GetNameFromUserIdAsync")
        end
        
        -- Check analytics functions
        if game:GetService("RbxAnalyticsService") and originalFunctions.getClientId and 
           originalFunctions.getClientId ~= game:GetService("RbxAnalyticsService").GetClientId then
            table.insert(hookedFunctions, "RbxAnalyticsService.GetClientId")
        end
        
        -- Check HTTP functions
        if originalFunctions.generateGUID and 
           originalFunctions.generateGUID ~= game:GetService("HttpService").GenerateGUID then
            table.insert(hookedFunctions, "HttpService.GenerateGUID")
        end
        
        -- Check metatable functions
        local success, mt = pcall(getrawmetatable, game)
        if success and mt then
            if originalFunctions.index and originalFunctions.index ~= mt.__index then
                table.insert(hookedFunctions, "Metatable.__index")
            end
            if originalFunctions.namecall and originalFunctions.namecall ~= mt.__namecall then
                table.insert(hookedFunctions, "Metatable.__namecall")
            end
        end
    end)
    
    return hookedFunctions
end

-- Attempt to restore original functions (may not always work due to protections)
function SecurityUtils.restoreOriginalFunctions()
    local originalFunctions = _G.__SecurityState.originalFunctions
    local restoredFunctions = {}
    
    -- Ensure we have original functions to restore
    if not originalFunctions or not next(originalFunctions) then
        return restoredFunctions
    end
    
    pcall(function()
        -- Restore player functions
        if game.Players.LocalPlayer and originalFunctions.kick and 
           originalFunctions.kick ~= game.Players.LocalPlayer.Kick then
            game.Players.LocalPlayer.Kick = originalFunctions.kick
            table.insert(restoredFunctions, "Player.Kick")
        end
        
        -- Restore service functions
        if originalFunctions.getNameFromUserIdAsync and 
           originalFunctions.getNameFromUserIdAsync ~= game:GetService("Players").GetNameFromUserIdAsync then
            game:GetService("Players").GetNameFromUserIdAsync = originalFunctions.getNameFromUserIdAsync
            table.insert(restoredFunctions, "GetNameFromUserIdAsync")
        end
        
        -- Restore analytics functions
        if game:GetService("RbxAnalyticsService") and originalFunctions.getClientId and 
           originalFunctions.getClientId ~= game:GetService("RbxAnalyticsService").GetClientId then
            game:GetService("RbxAnalyticsService").GetClientId = originalFunctions.getClientId
            table.insert(restoredFunctions, "RbxAnalyticsService.GetClientId")
        end
        
        -- Restore HTTP functions
        if originalFunctions.generateGUID and 
           originalFunctions.generateGUID ~= game:GetService("HttpService").GenerateGUID then
            game:GetService("HttpService").GenerateGUID = originalFunctions.generateGUID
            table.insert(restoredFunctions, "HttpService.GenerateGUID")
        end
        
        -- Restore metatable functions
        local success, mt = pcall(getrawmetatable, game)
        if not success or not mt then return end
        
        local readonlySuccess = pcall(function()
            setreadonly(mt, false)
        end)
        
        if not readonlySuccess then return end
        
        if originalFunctions.index and mt.__index ~= originalFunctions.index then
            mt.__index = originalFunctions.index
            table.insert(restoredFunctions, "Metatable.__index")
        end
        
        if originalFunctions.namecall and mt.__namecall ~= originalFunctions.namecall then
            mt.__namecall = originalFunctions.namecall
            table.insert(restoredFunctions, "Metatable.__namecall")
        end
        
        pcall(function()
            setreadonly(mt, true)
        end)
    end)
    
    return restoredFunctions
end

-- Check for suspicious global variables that might indicate tampering
function SecurityUtils.checkForSuspiciousGlobals()
    local suspiciousGlobals = {
        -- Username spoofing
        "_G.SpoofedUsername", "_G.FakeUsername", "_G.BypassWhitelist",
        -- ID spoofing
        "_G.SpoofedClientId", "_G.FakeId", "_G.OriginalKick",
        -- Shared variables
        "shared.OriginalUsername", "shared.BypassFunctions", "_G.WhitelistBypass",
        -- Function hooking
        "_G.OriginalFunctions", "_G.OriginalNamecall", "_G.OriginalIndex",
        "_G.HookedFunctions", "_G.BypassedFunctions", "_G.ClientIdSpoof",
        -- Additional common exploit globals
        "_G.Spoofing", "_G.Bypass", "_G.AntiKick", "_G.AntiWhitelist",
        "shared.SpoofedValues", "shared.BypassSystem"
    }
    
    local foundGlobals = {}
    
    for _, globalVar in ipairs(suspiciousGlobals) do
        pcall(function()
            local parts = string.split(globalVar, ".")
            local current = _G
            
            if parts[1] == "shared" then
                current = shared
            elseif parts[1] == "_G" then
                current = _G
                table.remove(parts, 1) -- Remove "_G" from parts
            end
            
            for i = 2, #parts do
                if current and type(current) == "table" then
                    current = current[parts[i]]
                else
                    return nil
                end
            end
            
            if current ~= nil then
                table.insert(foundGlobals, globalVar)
            end
        end)
    end
    
    return foundGlobals
end

-- Track and limit execution attempts to prevent brute forcing
function SecurityUtils.checkExecutionAttempts()
    _G.__SecurityState.attempts = _G.__SecurityState.attempts + 1
    
    if _G.__SecurityState.lastCheck then
        local timeSinceLastCheck = os.time() - _G.__SecurityState.lastCheck
        if timeSinceLastCheck < 5 then
            return true, "Suspicious timing: checks too frequent"
        end
    end
    
    _G.__SecurityState.lastCheck = os.time()
    
    if _G.__SecurityState.attempts > 3 then
        return true, "Multiple verification attempts detected"
    end
    
    return false, ""
end

-- Secure kick function that tries multiple methods to ensure the player is removed
function SecurityUtils.secureKick(player, reason)
    reason = reason or "Security violation detected"
    
    -- Mark tampering as detected
    _G.__SecurityState.tamperingDetected = true
    
    -- Try original kick function first
    local kickFunction = _G.__SecurityState.originalFunctions.kick or player.Kick
    
    pcall(function()
        kickFunction(player, reason)
    end)
    
    -- Fallback methods
    pcall(function()
        player:Kick(reason)
    end)
    
    pcall(function()
        game:Shutdown()
    end)
    
    -- Last resort - infinite loop to freeze the client
    pcall(function()
        while true do
            wait()
        end
    end)
end

-- Comprehensive check for any signs of tampering
function SecurityUtils.checkForTampering()
    local signs = {}
    
    -- Check for suspicious globals
    local foundGlobals = SecurityUtils.checkForSuspiciousGlobals()
    for _, globalVar in ipairs(foundGlobals) do
        table.insert(signs, "Found suspicious global: " .. globalVar)
    end
    
    -- Check for hooked functions
    local hookedFunctions = SecurityUtils.detectFunctionHooking()
    for _, funcName in ipairs(hookedFunctions) do
        table.insert(signs, "Function hooked: " .. funcName)
    end
    
    -- Check for suspicious execution patterns
    local suspicious, reason = SecurityUtils.checkExecutionAttempts()
    if suspicious then
        table.insert(signs, reason)
    end
    
    -- Check if tampering was previously detected
    if _G.__SecurityState.tamperingDetected then
        table.insert(signs, "Previous tampering detected")
    end
    
    return signs
end

-- Initialize security on module load
SecurityUtils.captureOriginalFunctions()

return SecurityUtils
