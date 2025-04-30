local IdentityVerification = {}

function IdentityVerification.getClientId()
    local clientId = ""
    
    local success, result = pcall(function()
        return game:GetService("RbxAnalyticsService"):GetClientId()
    end)
    
    if success and result and result ~= "" then
        clientId = result
    else
        local success2, result2 = pcall(function()
            return game:GetService("HttpService"):GenerateGUID(false)
        end)
        
        if success2 and result2 then
            clientId = result2
        end
    end
    
    return clientId
end

function IdentityVerification.getHWID()
    local hwid = ""
    
    local success, result = pcall(function()
        local placeId = game.PlaceId
        local jobId = game.JobId
        local clientId = IdentityVerification.getClientId()
        
        local combinedString = tostring(placeId) .. tostring(jobId) .. tostring(clientId)
        
        -- More reliable hash function for Lua
        local hash = 0
        for i = 1, #combinedString do
            hash = (hash * 31 + string.byte(combinedString, i)) % 2147483647
        end
        
        return tostring(hash)
    end)
    
    if success and result then
        hwid = result
    end
    
    return hwid
end

function IdentityVerification.compareClientIdFirstThreeParts(whitelistedId, userClientId)
    if not whitelistedId or not userClientId then return false end
    
    local whitelistedParts = string.split(whitelistedId, "-")
    local userParts = string.split(userClientId, "-")
    
    if #whitelistedParts < 3 or #userParts < 3 then return false end
    
    local whitelistedFirstThree = table.concat({whitelistedParts[1], whitelistedParts[2], whitelistedParts[3]}, "-")
    local userFirstThree = table.concat({userParts[1], userParts[2], userParts[3]}, "-")
    
    return whitelistedFirstThree == userFirstThree
end

function IdentityVerification.getUsername()
    local results = {}
    
    -- Try to get username from LocalPlayer
    pcall(function()
        if game.Players.LocalPlayer then
            table.insert(results, {name = game.Players.LocalPlayer.Name, weight = 1})
        end
    end)
    
    -- Try alternative method
    pcall(function()
        if game:GetService("Players").LocalPlayer then
            table.insert(results, {name = game:GetService("Players").LocalPlayer.Name, weight = 1})
        end
    end)
    
    -- Try to get name from UserId
    pcall(function()
        local player = game.Players.LocalPlayer
        if player and player.UserId then
            local success, result = pcall(function()
                return game:GetService("Players"):GetNameFromUserIdAsync(player.UserId)
            end)
            
            if success and result then
                table.insert(results, {name = result, weight = 5})
            end
        end
    end)
    
    -- Try to get name from PlayerGui parent
    pcall(function()
        if game.Players.LocalPlayer and game.Players.LocalPlayer:FindFirstChild("PlayerGui") then
            local name = game.Players.LocalPlayer.PlayerGui.Parent.Name
            table.insert(results, {name = name, weight = 1})
        end
    end)
    
    return IdentityVerification._processResults(results)
end

function IdentityVerification.getUserId()
    local results = {}
    
    pcall(function()
        if game.Players.LocalPlayer then
            table.insert(results, {id = game.Players.LocalPlayer.UserId, weight = 1})
        end
    end)
    
    pcall(function()
        if game:GetService("Players").LocalPlayer then
            table.insert(results, {id = game:GetService("Players").LocalPlayer.UserId, weight = 1})
        end
    end)
    
    return IdentityVerification._processResults(results, "id", "userId")
end

-- Helper function to process results and detect spoofing
function IdentityVerification._processResults(results, keyName, returnKeyName)
    keyName = keyName or "name"
    returnKeyName = returnKeyName or "username"
    
    local valueCount = {}
    local highestCount = 0
    local mostLikelyValue = nil
    
    for _, result in ipairs(results) do
        if result and result[keyName] then
            local value = result[keyName]
            valueCount[value] = (valueCount[value] or 0) + result.weight
            
            if valueCount[value] > highestCount then
                highestCount = valueCount[value]
                mostLikelyValue = value
            end
        end
    end
    
    -- Check for spoofing
    local spoofingDetected = false
    local uniqueValues = 0
    for _ in pairs(valueCount) do
        uniqueValues = uniqueValues + 1
    end
    
    if uniqueValues > 1 then
        spoofingDetected = true
    end
    
    local result = {
        spoofingDetected = spoofingDetected,
        confidence = highestCount
    }
    result[returnKeyName] = mostLikelyValue
    
    return result
end

-- Comprehensive identity verification
function IdentityVerification.verifyIdentity()
    local usernameInfo = IdentityVerification.getUsername()
    local userIdInfo = IdentityVerification.getUserId()
    local clientId = IdentityVerification.getClientId()
    local hwid = IdentityVerification.getHWID()
    
    local spoofingDetected = usernameInfo.spoofingDetected or userIdInfo.spoofingDetected
    
    return {
        username = usernameInfo.username,
        userId = userIdInfo.userId,
        clientId = clientId,
        hwid = hwid,
        spoofingDetected = spoofingDetected,
        usernameConfidence = usernameInfo.confidence,
        userIdConfidence = userIdInfo.confidence
    }
end

return IdentityVerification
