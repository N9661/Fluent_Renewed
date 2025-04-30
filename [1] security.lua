local Security = {}

-- Utility functions (obfuscated names to make it harder to bypass)
local _env = getfenv()
local _g = _env._G
local _rawget = rawget
local _rawset = rawset
local _setmetatable = setmetatable
local _getmetatable = getmetatable
local _type = type
local _pairs = pairs
local _tostring = tostring
local _pcall = pcall
local _error = error
local _wait = wait
local _game = game
local _players = _game:GetService("Players")
local _runService = _game:GetService("RunService")
local _httpService = _game:GetService("HttpService")
local _teleportService = _game:GetService("TeleportService")
local _localPlayer = _players.LocalPlayer

-- Anti-hook protection
local _originalFunctions = {}
local _protectedFunctions = {
    "kick", "Kick", "remove", "Remove", "Destroy", "destroy",
    "Teleport", "teleport", "TeleportToPlaceInstance", "teleportToPlaceInstance"
}

-- Store original functions to prevent hooking
for _, funcName in _pairs(_protectedFunctions) do
    if _players[funcName] then
        _originalFunctions[funcName] = _players[funcName]
    end
    if _localPlayer[funcName] then
        _originalFunctions["player_" .. funcName] = _localPlayer[funcName]
    end
    if _game[funcName] then
        _originalFunctions["game_" .. funcName] = _game[funcName]
    end
    if _teleportService[funcName] then
        _originalFunctions["teleport_" .. funcName] = _teleportService[funcName]
    end
end

-- Store original player properties to detect spoofing
local _originalPlayerProps = {
    Name = _localPlayer.Name,
    DisplayName = _localPlayer.DisplayName,
    UserId = _localPlayer.UserId,
    AccountAge = _localPlayer.AccountAge
}

-- Generate a unique client identifier
function Security.generateClientId()
    local hwid = ""
    local success, result = _pcall(function()
        -- Attempt to get hardware ID through multiple methods
        local method1 = _httpService:GenerateGUID(false)
        local method2 = _tostring(_localPlayer.UserId) .. _tostring(_game.JobId)
        local method3 = _tostring(_localPlayer.DisplayName) .. _tostring(_localPlayer.Name)
        
        -- Combine methods for a more unique identifier
        return method1 .. "-" .. method2 .. "-" .. method3
    end)
    
    if success then
        hwid = result
    else
        -- Fallback method
        hwid = _tostring(_localPlayer.UserId) .. "-" .. _tostring(_game.PlaceId) .. "-" .. _tostring(_game.JobId)
    end
    
    -- Create a hash of the HWID
    return Security.hash(hwid)
end

-- Hash function to create consistent identifiers
function Security.hash(input)
    local hash = 0
    for i = 1, #input do
        hash = ((hash << 5) - hash) + string.byte(input, i)
        hash = hash & 0xFFFFFFFF -- Convert to 32bit integer
    end
    return _tostring(hash)
end

-- Get user information
function Security.getUserInfo()
    return {
        Username = _localPlayer.Name,
        DisplayName = _localPlayer.DisplayName,
        UserId = _localPlayer.UserId,
        ClientId = Security.generateClientId(),
        HWID = Security.generateHWID(),
        AccountAge = _localPlayer.AccountAge,
        MembershipType = _tostring(_localPlayer.MembershipType),
        GameVersion = _game.PlaceVersion
    }
end

-- Generate HWID using multiple methods for redundancy
function Security.generateHWID()
    local components = {
        _tostring(_localPlayer.UserId),
        _tostring(_game.PlaceId),
        _tostring(_game.JobId),
        _tostring(_localPlayer.DisplayName),
        _tostring(_localPlayer.Name),
        _tostring(_localPlayer.AccountAge)
    }
    
    -- Add some hardware-specific identifiers if possible
    local success, result = _pcall(function()
        return _httpService:GenerateGUID(false)
    end)
    
    if success then
        table.insert(components, result)
    end
    
    -- Combine all components and hash
    return Security.hash(table.concat(components, "-"))
end

-- Advanced username spoofing detection
function Security.detectUsernameSpoofing()
    local detected = false
    local reason = ""
    
    -- Method 1: Check if Name property has been tampered with via metatable
    local mt = _getmetatable(_localPlayer)
    if mt and mt.__index then
        local success, result = _pcall(function()
            -- Try to access the raw property
            local rawName = _rawget(_localPlayer, "Name")
            if rawName and rawName ~= _localPlayer.Name then
                return true, "Username metatable spoofing detected"
            end
            return false
        end)
        
        if success and result then
            detected = true
            reason = "Username metatable spoofing detected"
        end
    end
    
    -- Method 2: Cross-reference UserId with actual username from Roblox API
    if not detected then
        local success, apiUsername = _pcall(function()
            return _players:GetNameFromUserIdAsync(_localPlayer.UserId)
        end)
        
        if success and apiUsername ~= _localPlayer.Name then
            detected = true
            reason = "Username-UserId mismatch: API returned " .. apiUsername
        end
    end
    
    -- Method 3: Check if the player object has been replaced
    if not detected then
        local success, result = _pcall(function()
            -- Check if the original player object is still valid
            if _players.LocalPlayer ~= _localPlayer then
                return true, "LocalPlayer object has been replaced"
            end
            return false
        end)
        
        if success and result then
            detected = true
            reason = "LocalPlayer object has been replaced"
        end
    end
    
    -- Method 4: Check for inconsistencies in player properties
    if not detected then
        local success, result = _pcall(function()
            -- Check if AccountAge matches the expected value for this UserId
            local playerInfo = _players:GetPlayerByUserId(_localPlayer.UserId)
            if playerInfo and playerInfo.AccountAge ~= _localPlayer.AccountAge then
                return true, "AccountAge mismatch for UserId"
            end
            return false
        end)
        
        if success and result then
            detected = true
            reason = "AccountAge mismatch for UserId"
        end
    end
    
    -- Method 5: Check for environment tampering that could allow spoofing
    if not detected then
        local success, result = _pcall(function()
            -- Check if critical environment functions have been tampered with
            if getfenv ~= _env.getfenv or setfenv ~= _env.setfenv then
                return true, "Environment function tampering detected"
            end
            return false
        end)
        
        if success and result then
            detected = true
            reason = "Environment function tampering detected"
        end
    end
    
    -- Method 6: Check for hooking of Player property getters
    if not detected then
        local success, result = _pcall(function()
            -- Create a test player object and check if properties are consistent
            local testPlayer = Instance.new("Player")
            local originalNameDescriptor = testPlayer:GetPropertyChangedSignal("Name")
            local localPlayerNameDescriptor = _localPlayer:GetPropertyChangedSignal("Name")
            
            if typeof(originalNameDescriptor) ~= typeof(localPlayerNameDescriptor) then
                testPlayer:Destroy()
                return true, "Player property descriptor mismatch"
            end
            
            testPlayer:Destroy()
            return false
        end)
        
        if success and result then
            detected = true
            reason = result
        end
    end
    
    return detected, reason
end

-- Anti-spoof detection system
function Security.detectSpoofing(whitelistData, userInfo)
    -- First check for username spoofing specifically
    local usernameSpoof, usernameReason = Security.detectUsernameSpoofing()
    if usernameSpoof then
        return true, usernameReason
    end
    
    local detectionMethods = {
        -- Check for environment tampering
        function()
            local env = getfenv(2)
            if env ~= _env then
                return true, "Environment tampering detected"
            end
            return false
        end,
        
        -- Check for metatable manipulation
        function()
            local mt = _getmetatable(_localPlayer)
            if mt and mt.__index then
                local originalName = _rawget(_localPlayer, "Name")
                local indexedName = _localPlayer.Name
                if originalName and originalName ~= indexedName then
                    return true, "Metatable manipulation detected"
                end
            end
            return false
        end,
        
        -- Check for function hooking
        function()
            for funcName, originalFunc in _pairs(_originalFunctions) do
                local currentTarget = _localPlayer
                if funcName:find("game_") then
                    currentTarget = _game
                    funcName = funcName:gsub("game_", "")
                elseif funcName:find("teleport_") then
                    currentTarget = _teleportService
                    funcName = funcName:gsub("teleport_", "")
                elseif funcName:find("player_") then
                    currentTarget = _localPlayer
                    funcName = funcName:gsub("player_", "")
                else
                    currentTarget = _players
                end
                
                if currentTarget[funcName] ~= originalFunc then
                    return true, "Function hooking detected: " .. funcName
                end
            end
            return false
        end,
        
        -- Check for inconsistent user data
        function()
            local userId = _localPlayer.UserId
            local success, result = _pcall(function()
                return _players:GetNameFromUserIdAsync(userId)
            end)
            
            if success and result ~= _localPlayer.Name then
                return true, "Username-UserId mismatch"
            end
            return false
        end,
        
        -- Check for property value changes from original
        function()
            if _originalPlayerProps.Name ~= _localPlayer.Name then
                return true, "Player Name changed since initialization"
            end
            if _originalPlayerProps.UserId ~= _localPlayer.UserId then
                return true, "Player UserId changed since initialization"
            end
            if _originalPlayerProps.DisplayName ~= _localPlayer.DisplayName then
                return true, "Player DisplayName changed since initialization"
            end
            return false
        end,
        
        -- Check for memory address manipulation
        function()
            local success, result = _pcall(function()
                local address1 = tostring(_localPlayer):match("0x%x+")
                _wait(0.1)
                local address2 = tostring(_localPlayer):match("0x%x+")
                
                if address1 ~= address2 then
                    return true, "Player object memory address changed"
                end
                return false
            end)
            
            return success and result
        end
    }
    
    -- Run all detection methods
    for _, method in _pairs(detectionMethods) do
        local detected, reason = method()
        if detected then
            return true, reason
        end
    end
    
    return false, ""
end

-- Verify user against whitelist
function Security.verifyUser(whitelistData, userInfo)
    local verified = false
    local matchedEntry = nil
    
    -- Check username matches
    for _, username in _pairs(whitelistData.Usernames or {}) do
        if username == userInfo.Username then
            for _, userId in _pairs(whitelistData.UserIds or {}) do
                if _tostring(userId) == _tostring(userInfo.UserId) then
                    verified = true
                    matchedEntry = {type = "Username+UserId", value = username .. ":" .. userId}
                    break
                end
            end
            
            if verified then break end
        end
    end
    
    -- If not verified by username+userId, check ClientId
    if not verified then
        for _, clientId in _pairs(whitelistData.ClientIds or {}) do
            if clientId == userInfo.ClientId then
                verified = true
                matchedEntry = {type = "ClientId", value = clientId}
                break
            end
        end
    end
    
    -- If still not verified, check HWID
    if not verified then
        for _, hwid in _pairs(whitelistData.HWIDs or {}) do
            if hwid == userInfo.HWID then
                verified = true
                matchedEntry = {type = "HWID", value = hwid}
                break
            end
        end
    end
    
    return verified, matchedEntry
end

-- Enforce security measures
function Security.enforceSecurity(whitelistData)
    local userInfo = Security.getUserInfo()
    local spoofDetected, spoofReason = Security.detectSpoofing(whitelistData, userInfo)
    local verified, matchedEntry = Security.verifyUser(whitelistData, userInfo)
    
    -- Set up continuous monitoring with multiple check methods
    local monitorId = "SecurityMonitor_" .. _httpService:GenerateGUID(false)
    _runService:BindToRenderStep(monitorId, Enum.RenderPriority.Last.Value, function()
        local currentUserInfo = Security.getUserInfo()
        local currentSpoofDetected, currentSpoofReason = Security.detectSpoofing(whitelistData, currentUserInfo)
        local currentVerified, currentMatchedEntry = Security.verifyUser(whitelistData, currentUserInfo)
        
        if currentSpoofDetected or not currentVerified then
            Security.punishUser(currentSpoofReason or "Unauthorized access")
        end
    end)
    
    -- Secondary monitoring using a different method
    spawn(function()
        while _wait(1) do
            local currentUserInfo = Security.getUserInfo()
            local currentSpoofDetected, currentSpoofReason = Security.detectSpoofing(whitelistData, currentUserInfo)
            local currentVerified, currentMatchedEntry = Security.verifyUser(whitelistData, currentUserInfo)
            
            if currentSpoofDetected or not currentVerified then
                Security.punishUser(currentSpoofReason or "Unauthorized access (secondary check)")
            end
        end
    end)
    
    -- Initial check
    if spoofDetected or not verified then
        Security.punishUser(spoofReason or "Unauthorized access")
        return false
    end
    
    return true, matchedEntry
end

-- Apply punishment to unauthorized users
function Security.punishUser(reason)
    -- Try multiple punishment methods to bypass anti-kick
    local methods = {
        function()
            -- Method 1: Direct kick
            _originalFunctions["player_Kick"](_localPlayer, reason)
        end,
        function()
            -- Method 2: Teleport to invalid place
            _teleportService:Teleport(0, _localPlayer)
        end,
        function()
            -- Method 3: Crash client with memory allocation
            local memoryHog = {}
            while true do
                for i = 1, 1000000 do
                    table.insert(memoryHog, string.rep("a", 10000))
                end
            end
        end,
        function()
            -- Method 4: Freeze player
            if _localPlayer.Character and _localPlayer.Character:FindFirstChild("HumanoidRootPart") then
                _localPlayer.Character.HumanoidRootPart.Anchored = true
                for _, part in _pairs(_localPlayer.Character:GetDescendants()) do
                    if part:IsA("BasePart") then
                        part.Anchored = true
                    end
                end
            end
        end,
        function()
            -- Method 5: Disable controls
            if _localPlayer.Character then
                local humanoid = _localPlayer.Character:FindFirstChildOfClass("Humanoid")
                if humanoid then
                    humanoid.WalkSpeed = 0
                    humanoid.JumpPower = 0
                    humanoid:ChangeState(Enum.HumanoidStateType.Physics)
                    
                    -- Hook the WalkSpeed and JumpPower to prevent changes
                    local mt = {}
                    mt.__index = function(t, k)
                        if k == "WalkSpeed" then return 0 end
                        if k == "JumpPower" then return 0 end
                        return humanoid[k]
                    end
                    mt.__newindex = function(t, k, v)
                        if k == "WalkSpeed" or k == "JumpPower" then return end
                        humanoid[k] = v
                    end
                    _setmetatable(humanoid, mt)
                end
            end
        end,
        function()
            -- Method 6: Corrupt character
            if _localPlayer.Character then
                for _, part in _pairs(_localPlayer.Character:GetDescendants()) do
                    if part:IsA("BasePart") then
                        -- Move parts far away
                        part.CFrame = CFrame.new(999999, 999999, 999999)
                    end
                end
            end
        end,
        function()
            -- Method 7: Infinite yield/hang
            local renderConnection
            renderConnection = _runService.RenderStepped:Connect(function()
                renderConnection:Disconnect()
                while true do
                    -- Create an infinite loop that consumes CPU
                    for i = 1, 10000000 do end
                end
            end)
        end,
        function()
            -- Method 8: Force error in critical path
            _game:GetService("RunService"):BindToRenderStep("CrashStep", Enum.RenderPriority.First.Value, function()
                error("Security violation: " .. reason)
            end)
        end,
        function()
            -- Method 9: Corrupt game services
            for _, service in _pairs(_game:GetChildren()) do
                _pcall(function()
                    service.Parent = nil
                end)
            end
        end,
        function()
            -- Method 10: Attempt to break script context
            _setfenv(1, {})
        end
    }
    
    -- Try each method until one works
    for _, method in _pairs(methods) do
        local success = _pcall(method)
        if success then
            _wait(0.5) -- Give some time for the method to take effect
        end
    end
    
    -- Last resort: infinite loop to hang the client
    _game:GetService("RunService"):BindToRenderStep("SecurityLockdown", 199, function()
        while true do end
    end)
    
    -- If we somehow get here, just loop forever
    while true do
        _wait()
    end
end

return Security
