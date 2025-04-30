local IdentityVerification = {}

function IdentityVerification.getClientId()
    local clientId = ""
    
    pcall(function()
        clientId = game:GetService("RbxAnalyticsService"):GetClientId()
    end)
    
    if clientId == "" then
        pcall(function()
            clientId = game:GetService("HttpService"):GenerateGUID(false)
        end)
    end
    
    return clientId
end

function IdentityVerification.getHWID()
    local hwid = ""
    
    pcall(function()
        local placeId = game.PlaceId
        local jobId = game.JobId
        local clientId = IdentityVerification.getClientId()
        
        local combinedString = tostring(placeId) .. tostring(jobId) .. tostring(clientId)
        
        local hash = 0
        for i = 1, #combinedString do
            hash = ((hash << 5) - hash) + string.byte(combinedString, i)
            hash = hash & hash -- Convert to 32bit integer
        end
        
        hwid = tostring(hash)
    end)
        
    return hwid
end

function IdentityVerification.compareClientIdFirstThreeParts(whitelistedId, userClientId)
    if not whitelistedId or not userClientId then return false end
    
    local whitelistedParts = string.split(whitelistedId, "-")
    if #whitelistedParts < 3 then return false end
    local whitelistedFirstThree = whitelistedParts[1] .. "-" .. whitelistedParts[2] .. "-" .. whitelistedParts[3]
    
    local userParts = string.split(userClientId, "-")
    if #userParts < 3 then return false end
    local userFirstThree = userParts[1] .. "-" .. userParts[2] .. "-" .. userParts[3]
    
    return whitelistedFirstThree == userFirstThree
end

function IdentityVerification.getUsername()
    local results = {}
    
    pcall(function()
        if game.Players.LocalPlayer then
            table.insert(results, {name = game.Players.LocalPlayer.Name, weight = 1})
        end
    end)
    
    pcall(function()
        if game:GetService("Players").LocalPlayer then
            table.insert(results, {name = game:GetService("Players").LocalPlayer.Name, weight = 1})
        end
    end)
    
    pcall(function()
        local player = game.Players.LocalPlayer
        if not player then return end
        
        local userId = player.UserId
        if not userId then return end
        
        local success, result = pcall(function()
            return game:GetService("Players"):GetNameFromUserIdAsync(userId)
        end)
        
        if success and result then
            table.insert(results, {name = result, weight = 5})
        end
    end)
    
    pcall(function()
        if game.Players.LocalPlayer and game.Players.LocalPlayer:FindFirstChild("PlayerGui") then
            local name = game.Players.LocalPlayer.PlayerGui.Parent.Name
            table.insert(results, {name = name, weight = 1})
        end
    end)
    
    local nameCount = {}
    local highestCount = 0
    local mostLikelyName = nil
    
    for _, result in ipairs(results) do
        if result and result.name then
            if not nameCount[result.name] then
                nameCount[result.name] = 0
            end
            nameCount[result.name] = nameCount[result.name] + result.weight
            
            if nameCount[result.name] > highestCount then
                highestCount = nameCount[result.name]
                mostLikelyName = result.name
            end
        end
    end
    
    local spoofingDetected = false
    local uniqueNames = 0
    for _ in pairs(nameCount) do
        uniqueNames = uniqueNames + 1
    end
    
    if uniqueNames > 1 then
        spoofingDetected = true
    end
    
    return {
        username = mostLikelyName,
        confidence = highestCount,
        spoofingDetected = spoofingDetected
    }
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
    
    local idCount = {}
    local highestCount = 0
    local mostLikelyId = nil
    
    for _, result in ipairs(results) do
        if result and result.id then
            if not idCount[result.id] then
                idCount[result.id] = 0
            end
            idCount[result.id] = idCount[result.id] + result.weight
            
            if idCount[result.id] > highestCount then
                highestCount = idCount[result.id]
                mostLikelyId = result.id
            end
        end
    end
    
    -- Check for spoofing
    local spoofingDetected = false
    local uniqueIds = 0
    for _ in pairs(idCount) do
        uniqueIds = uniqueIds + 1
    end
    
    if uniqueIds > 1 then
        spoofingDetected = true
    end
    
    return {
        userId = mostLikelyId,
        confidence = highestCount,
        spoofingDetected = spoofingDetected
    }
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
