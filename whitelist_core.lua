local SecurityUtils = {}

local _G = _G or getgenv()
if not _G.__SecurityState then
    _G.__SecurityState = {
        originalFunctions = {},
        attempts = 0,
        lastCheck = os.time(),
        tamperingDetected = false
    }
end

function SecurityUtils.captureOriginalFunctions()
    local originalFunctions = {}
    
    pcall(function()
        originalFunctions.kick = game.Players.LocalPlayer.Kick
        originalFunctions.getNameFromUserIdAsync = game:GetService("Players").GetNameFromUserIdAsync
        originalFunctions.getPlayers = game:GetService("Players").GetPlayers
        originalFunctions.getClientId = game:GetService("RbxAnalyticsService").GetClientId
        originalFunctions.generateGUID = game:GetService("HttpService").GenerateGUID
        
        local mt = getrawmetatable(game)
        if mt then
            originalFunctions.index = mt.__index
            originalFunctions.namecall = mt.__namecall
        end
    end)
    
    _G.__SecurityState.originalFunctions = originalFunctions
    return originalFunctions
end

function SecurityUtils.detectFunctionHooking()
    local hookedFunctions = {}
    local originalFunctions = _G.__SecurityState.originalFunctions
    
    pcall(function()
        if originalFunctions.kick ~= game.Players.LocalPlayer.Kick then
            table.insert(hookedFunctions, "Player.Kick")
        end
        
        if originalFunctions.getNameFromUserIdAsync ~= game:GetService("Players").GetNameFromUserIdAsync then
            table.insert(hookedFunctions, "GetNameFromUserIdAsync")
        end
        
        if originalFunctions.getClientId ~= game:GetService("RbxAnalyticsService").GetClientId then
            table.insert(hookedFunctions, "RbxAnalyticsService.GetClientId")
        end
        
        if originalFunctions.generateGUID ~= game:GetService("HttpService").GenerateGUID then
            table.insert(hookedFunctions, "HttpService.GenerateGUID")
        end
        
        local mt = getrawmetatable(game)
        if mt then
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

function SecurityUtils.restoreOriginalFunctions()
    local originalFunctions = _G.__SecurityState.originalFunctions
    
    pcall(function()
        if originalFunctions.kick and originalFunctions.kick ~= game.Players.LocalPlayer.Kick then
            game.Players.LocalPlayer.Kick = originalFunctions.kick
        end
        
        if originalFunctions.getNameFromUserIdAsync and
           originalFunctions.getNameFromUserIdAsync ~= game:GetService("Players").GetNameFromUserIdAsync then
            game:GetService("Players").GetNameFromUserIdAsync = originalFunctions.getNameFromUserIdAsync
        end
        
        if originalFunctions.getClientId and
           originalFunctions.getClientId ~= game:GetService("RbxAnalyticsService").GetClientId then
            game:GetService("RbxAnalyticsService").GetClientId = originalFunctions.getClientId
        end
        
        if originalFunctions.generateGUID and
           originalFunctions.generateGUID ~= game:GetService("HttpService").GenerateGUID then
            game:GetService("HttpService").GenerateGUID = originalFunctions.generateGUID
        end
        
        local mt = getrawmetatable(game)
        if not mt then return end
        
        local success = pcall(function()
            setreadonly(mt, false)
        end)
        
        if not success then return end
        
        if originalFunctions.index and mt.__index ~= originalFunctions.index then
            mt.__index = originalFunctions.index
        end
        
        if originalFunctions.namecall and mt.__namecall ~= originalFunctions.namecall then
            mt.__namecall = originalFunctions.namecall
        end
        
        pcall(function()
            setreadonly(mt, true)
        end)
    end)
end

function SecurityUtils.checkForSuspiciousGlobals()
    local suspiciousGlobals = {
        "_G.SpoofedUsername", "_G.FakeUsername", "_G.BypassWhitelist",
        "_G.SpoofedClientId", "_G.FakeId", "_G.OriginalKick",
        "shared.OriginalUsername", "shared.BypassFunctions", "_G.WhitelistBypass",
        "_G.OriginalFunctions", "_G.OriginalNamecall", "_G.OriginalIndex",
        "_G.HookedFunctions", "_G.BypassedFunctions", "_G.ClientIdSpoof"
    }
    
    local foundGlobals = {}
    
    for _, globalVar in ipairs(suspiciousGlobals) do
        pcall(function()
            local parts = string.split(globalVar, ".")
            local current = _G
            
            if parts[1] == "shared" then
                current = shared
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

function SecurityUtils.secureKick(player, reason)
    local kickFunction = _G.__SecurityState.originalFunctions.kick or player.Kick
    
    pcall(function()
        kickFunction(player, reason)
    end)
    
    pcall(function()
        game:Shutdown()
    end)
    
    pcall(function()
        while true do
            wait()
        end
    end)
end

function SecurityUtils.checkForTampering()
    local signs = {}
    
    local foundGlobals = SecurityUtils.checkForSuspiciousGlobals()
    for _, globalVar in ipairs(foundGlobals) do
        table.insert(signs, "Found suspicious global: " .. globalVar)
    end
    
    local hookedFunctions = SecurityUtils.detectFunctionHooking()
    for _, funcName in ipairs(hookedFunctions) do
        table.insert(signs, "Function hooked: " .. funcName)
    end
    
    local suspicious, reason = SecurityUtils.checkExecutionAttempts()
    if suspicious then
        table.insert(signs, reason)
    end
    
    return signs
end

return SecurityUtils
