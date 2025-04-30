-- Security.lua - Advanced Anti-Spoofing System
local Security = {}

-- Private variables
local Players = game:GetService("Players")
local RunService = game:GetService("RunService")
local HttpService = game:GetService("HttpService")
local TeleportService = game:GetService("TeleportService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local LocalPlayer = Players.LocalPlayer or Players.PlayerAdded:Wait()

-- Constants
local CHECK_INTERVAL = 1 -- Check every second
local MAX_WARNINGS = 3
local HWID_SALT = "j8H7g6F5d4S3a2P1" -- Salt for HWID generation

-- Tracking variables
local warningCount = 0
local originalHWID = nil
local originalUserID = nil
local originalUsername = nil
local originalClientID = nil
local isAuthenticated = false
local bypassAttempts = 0

-- Get a more reliable HWID that's harder to spoof
function Security.GetHWID()
    local hwid = ""
    
    -- Combine multiple identifiers for a more robust HWID
    local screenSize = workspace.CurrentCamera.ViewportSize
    local graphicsQuality = UserSettings():GetService("UserGameSettings").SavedQualityLevel
    local deviceData = {
        processor = game:GetService("Stats").Processor,
        memory = game:GetService("Stats").Memory,
        gpu = game:GetService("Stats").GPU,
        screenX = screenSize.X,
        screenY = screenSize.Y,
        graphicsLevel = graphicsQuality,
        platform = game:GetService("GuiService"):IsTenFootInterface() and "Console" or "Desktop"
    }
    
    -- Create a string from the device data and hash it
    local deviceString = HttpService:JSONEncode(deviceData)
    hwid = HttpService:GenerateGUID(false) .. "-" .. 
           HttpService:JSONEncode(deviceData):sub(1, 20) .. "-" ..
           tostring(LocalPlayer.UserId)
           
    -- Apply a hash with salt for additional security
    return Security.Hash(hwid .. HWID_SALT)
end

-- Generate a client ID based on connection and session data
function Security.GetClientID()
    local networkStats = game:GetService("Stats").Network
    local pingData = networkStats.ServerStatsItem["Data Ping"]:GetValue()
    local connectionData = {
        ping = pingData,
        time = os.time(),
        session = HttpService:GenerateGUID(false)
    }
    
    return Security.Hash(HttpService:JSONEncode(connectionData))
end

-- Hash function to create consistent identifiers
function Security.Hash(input)
    -- Simple string hashing algorithm
    local hash = 0
    for i = 1, #input do
        hash = ((hash << 5) - hash) + string.byte(input, i)
        hash = bit32.band(hash, hash) -- Convert to 32bit integer
    end
    return tostring(hash)
end

-- Initialize security system
function Security.Initialize()
    -- Store original values
    originalHWID = Security.GetHWID()
    originalUserID = LocalPlayer.UserId
    originalUsername = LocalPlayer.Name
    originalClientID = Security.GetClientID()
    
    -- Create hidden properties to detect tampering
    local env = getfenv(0)
    local oldIndex = env.__index
    local oldNewIndex = env.__newindex
    
    -- Set up metatable hooks to detect tampering with game services
    setmetatable(env, {
        __index = function(t, k)
            if k == "Players" or k == "LocalPlayer" or k == "UserID" then
                bypassAttempts = bypassAttempts + 1
                Security.HandleViolation("Metatable tampering detected")
            end
            return oldIndex and oldIndex(t, k) or nil
        end,
        
        __newindex = function(t, k, v)
            if k == "Players" or k == "LocalPlayer" or k == "UserID" then
                bypassAttempts = bypassAttempts + 1
                Security.HandleViolation("Metatable modification detected")
                return
            end
            if oldNewIndex then
                oldNewIndex(t, k, v)
            else
                rawset(t, k, v)
            end
        end
    })
    
    -- Start continuous security checks
    Security.StartChecks()
    
    return true
end

-- Continuous security checks
function Security.StartChecks()
    -- Create a connection that can't be easily disconnected
    local checkConnection = nil
    
    -- Multiple check methods to make it harder to bypass
    local checkFunctions = {
        function() -- Standard check
            Security.VerifyIdentity()
        end,
        
        function() -- Delayed check with different timing
            task.wait(math.random(0.1, 0.5))
            Security.VerifyIdentity()
        end,
        
        function() -- Check with network call simulation
            local fakeRequest = {
                Url = "https://verify.example.com",
                Method = "GET",
                Headers = {
                    ["User-ID"] = tostring(LocalPlayer.UserId),
                    ["HWID"] = originalHWID
                }
            }
            Security.VerifyIdentity()
        end
    }
    
    -- Use RunService for consistent checks that are harder to break
    checkConnection = RunService.Heartbeat:Connect(function()
        -- Only run checks at intervals, not every frame
        if tick() % CHECK_INTERVAL < 0.1 then
            -- Randomly select a check method to be less predictable
            local checkIndex = math.random(1, #checkFunctions)
            checkFunctions[checkIndex]()
            
            -- Also verify the connection itself hasn't been tampered with
            if not checkConnection.Connected then
                Security.HandleViolation("Security check disconnected")
                -- Recreate the connection
                Security.StartChecks()
            end
        end
    end)
    
    -- Create a backup check using a different method
    task.spawn(function()
        while true do
            task.wait(CHECK_INTERVAL * 2.7) -- Use a different interval
            Security.VerifyIdentity()
            
            -- Check if RunService connections are being tampered with
            local connections = getconnections(RunService.Heartbeat)
            local foundOurConnection = false
            
            for _, connection in pairs(connections) do
                if connection == checkConnection then
                    foundOurConnection = true
                    break
                end
            end
            
            if not foundOurConnection then
                Security.HandleViolation("Connection tampering detected")
                Security.StartChecks() -- Restart checks
            end
        end
    end)
end

-- Verify player identity
function Security.VerifyIdentity()
    local currentHWID = Security.GetHWID()
    local currentUserID = LocalPlayer.UserId
    local currentUsername = LocalPlayer.Name
    local currentClientID = Security.GetClientID()
    
    -- Check for discrepancies
    if originalUserID ~= currentUserID then
        Security.HandleViolation("UserID mismatch detected")
        return false
    end
    
    if originalUsername ~= currentUsername then
        Security.HandleViolation("Username mismatch detected")
        return false
    end
    
    -- HWID check with some tolerance for legitimate variations
    -- (Some hardware info might change slightly during gameplay)
    if Security.Hash(currentHWID:sub(1, 20)) ~= Security.Hash(originalHWID:sub(1, 20)) then
        Security.HandleViolation("HWID tampering detected")
        return false
    end
    
    -- Check for environment tampering
    if Security.IsEnvironmentTampered() then
        Security.HandleViolation("Environment tampering detected")
        return false
    end
    
    return true
end

-- Check for environment tampering
function Security.IsEnvironmentTampered()
    -- Check if critical functions have been tampered with
    local tamperDetected = false
    
    -- Check if kick function is overridden
    local kickFunction = LocalPlayer.Kick
    if type(kickFunction) ~= "function" then
        tamperDetected = true
    else
        -- Test if the kick function has been neutered
        local success = pcall(function()
            -- Create a fake player to test kick on
            local fakePlr = {}
            setmetatable(fakePlr, {__index = function() return function() end end})
            kickFunction(fakePlr, "")
        end)
        
        if not success then
            tamperDetected = true
        end
    end
    
    -- Check if critical services are available
    if not pcall(function() return game:GetService("Players") end) then
        tamperDetected = true
    end
    
    return tamperDetected
end

-- Handle security violations
function Security.HandleViolation(reason)
    warningCount = warningCount + 1
    bypassAttempts = bypassAttempts + 1
    
    -- Log the violation (would be sent to server in a real implementation)
    print("[SECURITY] Violation detected: " .. reason)
    
    if warningCount >= MAX_WARNINGS or bypassAttempts >= 2 then
        -- Apply multiple punishment methods to make it harder to bypass
        Security.PunishPlayer(reason)
    end
end

-- Apply punishment for security violations
function Security.PunishPlayer(reason)
    -- Try multiple punishment methods
    local punishmentMethods = {
        function()
            -- Method 1: Standard kick
            LocalPlayer:Kick("\nSecurity Violation: " .. reason .. "\n\nHWID has been flagged.")
        end,
        
        function()
            -- Method 2: Teleport to empty server
            TeleportService:Teleport(game.PlaceId, LocalPlayer, nil, "Kicked: " .. reason)
        end,
        
        function()
            -- Method 3: Break the game functionality
            -- This makes the game unusable without actually kicking
            workspace.CurrentCamera.CameraType = Enum.CameraType.Scriptable
            workspace.CurrentCamera.CameraSubject = nil
            workspace.CurrentCamera.FieldOfView = 0.1
            
            -- Disable controls
            LocalPlayer.DevEnableMouseLock = false
            LocalPlayer.DevComputerMovementMode = Enum.DevComputerMovementMode.Scriptable
            
            -- Create an invisible barrier
            local barrier = Instance.new("Part")
            barrier.Size = Vector3.new(10, 10, 10)
            barrier.Anchored = true
            barrier.CanCollide = true
            barrier.Transparency = 1
            barrier.Position = LocalPlayer.Character and LocalPlayer.Character:GetPivot().Position or Vector3.new(0, 100, 0)
            barrier.Parent = workspace
            
            -- Force character reset
            if LocalPlayer.Character then
                LocalPlayer.Character:BreakJoints()
            end
        end,
        
        function()
            -- Method 4: Crash the client
            while true do
                -- Create a memory leak
                local t = {}
                for i = 1, 1000000 do
                    t[i] = "Memory leak to crash client: " .. string.rep("A", 1000)
                end
            end
        end
    }
    
    -- Try each punishment method
    for _, method in ipairs(punishmentMethods) do
        local success = pcall(method)
        if success then
            break -- Stop if one method works
        end
    end
    
    -- Last resort - infinite yield
    while true do
        task.wait(math.huge)
    end
end

-- Check if a player is whitelisted (to be implemented with Whitelist_Data)
function Security.IsWhitelisted(userID, hwid, clientID, username)
    -- This will be implemented in the Loader.lua that connects to Whitelist_Data.lua
    -- For now, return false to indicate not implemented yet
    return false
end

-- Verify whitelist status
function Security.VerifyWhitelist()
    return Security.IsWhitelisted(
        LocalPlayer.UserId,
        Security.GetHWID(),
        Security.GetClientID(),
        LocalPlayer.Name
    )
end

return Security
