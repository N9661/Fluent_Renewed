local Security = {}

-- Services
local Players = game:GetService("Players")
local RunService = game:GetService("RunService")
local HttpService = game:GetService("HttpService")
local TeleportService = game:GetService("TeleportService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local MarketplaceService = game:GetService("MarketplaceService")
local NetworkServer = game:GetService("NetworkServer")
local DataStoreService = game:GetService("DataStoreService")

-- Private variables with obfuscated names
local _w = {} -- Whitelist data
local _c = {} -- Cache
local _v = {} -- Verification tokens
local _f = {} -- Failed checks
local _m = {} -- Monitoring data
local _b = {} -- Blacklisted
local _s = {} -- Session data
local _p = {} -- Player verification states
local _t = {} -- Timestamps
local _h = {} -- Heuristic data
local _r = {} -- Random keys for encryption
local _x = {} -- Extra security measures

-- Constants (obfuscated)
local _MAX_FAILS = 2
local _CHECK_INTERVAL = 0.5
local _VERIFICATION_TIMEOUT = 15
local _SECURITY_VERSION = HttpService:GenerateGUID(false)
local _SECURE_KEY = HttpService:GenerateGUID(false)

-- Generate a secure key for this session
for i = 1, 32 do
    _r[i] = string.char(math.random(33, 126))
end
local _SESSION_KEY = table.concat(_r)

-- Encryption functions
local function _encrypt(data)
    if type(data) ~= "string" then
        data = HttpService:JSONEncode(data)
    end
    
    local encrypted = ""
    for i = 1, #data do
        local char = string.byte(data, i)
        local keyChar = string.byte(_SESSION_KEY, (i % #_SESSION_KEY) + 1)
        encrypted = encrypted .. string.char(bit32.bxor(char, keyChar))
    end
    
    return encrypted
end

local function _decrypt(data)
    local decrypted = ""
    for i = 1, #data do
        local char = string.byte(data, i)
        local keyChar = string.byte(_SESSION_KEY, (i % #_SESSION_KEY) + 1)
        decrypted = decrypted .. string.char(bit32.bxor(char, keyChar))
    end
    
    local success, result = pcall(function()
        return HttpService:JSONDecode(decrypted)
    end)
    
    return success and result or decrypted
end

-- Hash function with salt
local function _hash(data, salt)
    salt = salt or _SECURE_KEY
    local combined = tostring(data) .. tostring(salt)
    
    local hash = 0
    for i = 1, #combined do
        hash = ((hash << 5) - hash) + string.byte(combined, i)
        hash = bit32.band(hash, 0xFFFFFFFF) -- Convert to 32bit integer
    end
    
    return string.format("%08x", hash)
end

-- Advanced client info collection
function Security:GetClientInfo(player)
    if not player then return nil end
    
    -- Basic info
    local info = {
        Username = player.Name,
        DisplayName = player.DisplayName,
        UserID = player.UserId,
        AccountAge = player.AccountAge,
        MembershipType = tostring(player.MembershipType),
        FollowUserId = player.FollowUserId,
        CharacterAppearanceId = player.CharacterAppearanceId,
        GameJoinData = player.GameJoinData,
        Locale = player.LocaleId,
        Platform = "Unknown", -- Will be set by client
        DeviceData = {}, -- Will be set by client
        ConnectionData = {}, -- Network info
        HWID = nil, -- Will be set by client
        ClientToken = nil, -- Will be set by client
        VerificationToken = _hash(player.UserId .. _SECURITY_VERSION),
        JoinTime = os.time(),
        LastVerified = 0,
    }
    
    -- Generate a unique session ID
    info.SessionId = _hash(info.UserID .. info.JoinTime .. _SECURITY_VERSION)
    
    -- Try to get network info
    pcall(function()
        local networkPeer = NetworkServer:GetChildren()[1]
        if networkPeer then
            info.ConnectionData.Address = tostring(networkPeer.Address)
            info.ConnectionData.Port = tostring(networkPeer.Port)
            info.ConnectionData.Protocol = tostring(networkPeer.Protocol)
        end
    end)
    
    -- Try to get additional profile data
    pcall(function()
        local success, result = pcall(function()
            return MarketplaceService:GetProductInfo(info.UserID, Enum.InfoType.Asset)
        end)
        
        if success and result then
            info.ProfileData = {
                Created = result.Created,
                Updated = result.Updated,
                Creator = result.Creator and result.Creator.Id
            }
        end
    end)
    
    return info
end

-- Advanced verification system
function Security:VerifyPlayer(player, clientData)
    if not player or not _w then return false end
    
    -- Get server-side info
    local serverInfo = self:GetClientInfo(player)
    if not serverInfo then return false end
    
    -- Update with client data
    if clientData then
        serverInfo.HWID = clientData.HWID
        serverInfo.Platform = clientData.Platform
        serverInfo.DeviceData = clientData.DeviceData
        serverInfo.ClientToken = clientData.ClientToken
        serverInfo.LastVerified = os.time()
    end
    
    -- Store in session cache
    _s[player.UserId] = serverInfo
    
    -- Check if blacklisted
    if _b[player.UserId] or _b[serverInfo.HWID] then
        self:LogSpoofAttempt(player, "Blacklisted user attempted to join")
        return false
    end
    
    -- Check against whitelist with multiple verification points
    local isWhitelisted = false
    local matchedEntry = nil
    
    for _, entry in pairs(_w) do
        -- Primary check: UserID
        if entry.UserID == serverInfo.UserID then
            matchedEntry = entry
            
            -- Secondary checks
            local usernameMatch = entry.Username == serverInfo.Username
            local hwidMatch = not entry.HWID or not serverInfo.HWID or entry.HWID == serverInfo.HWID
            
            -- If all checks pass
            if usernameMatch and hwidMatch then
                isWhitelisted = true
                break
            else
                -- Log which check failed
                if not usernameMatch then
                    self:LogSpoofAttempt(player, "Username mismatch: expected " .. entry.Username .. ", got " .. serverInfo.Username)
                end
                
                if not hwidMatch and serverInfo.HWID then
                    self:LogSpoofAttempt(player, "HWID mismatch: expected " .. (entry.HWID or "nil") .. ", got " .. serverInfo.HWID)
                end
                
                return false
            end
        end
    end
    
    -- If not found in whitelist
    if not isWhitelisted then
        self:LogSpoofAttempt(player, "User not in whitelist")
        return false
    end
    
    -- Advanced heuristic checks
    if clientData then
        -- Check for impossible platform combinations
        if clientData.Platform == "Mobile" and clientData.DeviceData.ScreenSize and 
           clientData.DeviceData.ScreenSize.X > 3000 then
            self:LogSpoofAttempt(player, "Suspicious device data: mobile with large screen")
            return false
        end
        
        -- Check for suspicious HWID patterns
        if serverInfo.HWID and (serverInfo.HWID:match("^0+$") or #serverInfo.HWID < 10) then
            self:LogSpoofAttempt(player, "Suspicious HWID pattern")
            return false
        end
        
        -- Check for token validity
        if not clientData.ClientToken or clientData.ClientToken ~= _hash(serverInfo.VerificationToken .. serverInfo.UserID) then
            self:LogSpoofAttempt(player, "Invalid verification token")
            return false
        end
    end
    
    -- Update verification state
    _p[player.UserId] = {
        Verified = true,
        LastCheck = os.time(),
        MatchedEntry = matchedEntry
    }
    
    return true
end

-- Enhanced logging with more details
function Security:LogSpoofAttempt(player, reason)
    local playerName = player and player.Name or "Unknown"
    local playerId = player and player.UserId or 0
    
    -- Get additional context
    local context = {
        Timestamp = os.time(),
        PlayerInfo = self:GetClientInfo(player),
        Reason = reason,
        SessionData = _s[playerId]
    }
    
    -- Log to console
    warn("[SECURITY] Spoofing attempt detected!")
    warn("  Player: " .. playerName .. " (ID: " .. playerId .. ")")
    warn("  Reason: " .. reason)
    warn("  Time: " .. os.date("%Y-%m-%d %H:%M:%S", context.Timestamp))
    
    -- Store in monitoring data
    _m[playerId] = _m[playerId] or {}
    table.insert(_m[playerId], context)
    
    -- Increment failed checks counter
    _f[playerId] = (_f[playerId] or 0) + 1
    
    -- Take action if too many failed checks
    if _f[playerId] >= _MAX_FAILS then
        -- Add to blacklist
        _b[playerId] = true
        if context.PlayerInfo and context.PlayerInfo.HWID then
            _b[context.PlayerInfo.HWID] = true
        end
        
        -- Enforce punishment
        self:EnforcePunishment(player)
    end
    
    -- Try to save violation data
    pcall(function()
        local securityLog = DataStoreService:GetDataStore("SecurityViolations")
        local logKey = "Violation_" .. playerId .. "_" .. context.Timestamp
        securityLog:SetAsync(logKey, {
            PlayerID = playerId,
            PlayerName = playerName,
            Reason = reason,
            Timestamp = context.Timestamp,
            HWID = context.PlayerInfo and context.PlayerInfo.HWID
        })
    end)
end

-- Enhanced punishment system with multiple layers
function Security:EnforcePunishment(player)
    if not player then return end
    
    -- Create a unique punishment ID
    local punishmentId = HttpService:GenerateGUID(false)
    
    -- Apply multiple punishment methods in parallel
    task.spawn(function()
        -- Method 1: Standard kick with delay to allow other methods to work
        task.delay(0.5, function()
            pcall(function()
                player:Kick("Security violation detected [" .. punishmentId .. "]")
            end)
        end)
        
        -- Method 2: Break character and freeze
        pcall(function()
            if player.Character then
                -- Disable scripts first
                for _, obj in pairs(player.Character:GetDescendants()) do
                    if obj:IsA("Script") or obj:IsA("LocalScript") then
                        obj.Disabled = true
                    end
                end
                
                -- Anchor all parts
                for _, part in pairs(player.Character:GetDescendants()) do
                    if part:IsA("BasePart") then
                        part.Anchored = true
                        part.CanCollide = false
                        part.Massless = true
                    end
                end
                
                -- Break joints
                player.Character:BreakJoints()
                
                -- Remove humanoid
                local humanoid = player.Character:FindFirstChildOfClass("Humanoid")
                if humanoid then
                    humanoid.Health = 0
                    humanoid:Destroy()
                end
            end
        end)
        
        -- Method 3: Teleport to empty reserved server
        pcall(function()
            local reservedServerCode = TeleportService:ReserveServer(game.PlaceId)
            TeleportService:TeleportToPrivateServer(game.PlaceId, reservedServerCode, {player})
        end)
        
        -- Method 4: Create network lag
        pcall(function()
            -- Create massive network load for this player
            local folder = Instance.new("Folder")
            folder.Name = "SecurityMeasure_" .. punishmentId
            folder.Parent = player
            
            -- Create many objects to cause network stress
            for i = 1, 1000 do
                local obj = Instance.new("StringValue")
                obj.Name = "SecurityObject_" .. i
                obj.Value = string.rep("X", 1000) -- Large string
                obj.Parent = folder
            end
        end)
        
        -- Method 5: Client crash (send malformed remote events)
        pcall(function()
            local crashRemote = Instance.new("RemoteEvent")
            crashRemote.Name = "SecurityUpdate_" .. punishmentId
            crashRemote.Parent = ReplicatedStorage
            
            -- Send large amounts of data
            for i = 1, 50 do
                crashRemote:FireClient(player, string.rep("X", 50000))
            end
        end)
        
        -- Method 6: Remove player from Players service (if possible)
        pcall(function()
            player:Destroy()
        end)
    end)
    
    -- Clean up after punishment
    task.delay(5, function()
        pcall(function()
            -- Remove any objects we created
            for _, obj in pairs(ReplicatedStorage:GetChildren()) do
                if obj.Name:match("SecurityUpdate_" .. punishmentId) then
                    obj:Destroy()
                end
            end
            
            if player and player:FindFirstChild("SecurityMeasure_" .. punishmentId) then
                player.SecurityMeasure:Destroy()
            end
        end)
    end)
end

-- Advanced anti-exploit measures
function Security:RemoveAntiKickScripts(player)
    if not player then return end
    
    pcall(function()
        -- Find and disable potential anti-kick scripts
        for _, obj in pairs(player.Character:GetDescendants()) do
            if obj:IsA("Script") or obj:IsA("LocalScript") then
                -- Check for suspicious script names
                local name = obj.Name:lower()
                if name:match("anti") or name:match("kick") or name:match("bypass") or
                   name:match("protect") or name:match("secure") then
                    warn("[SECURITY] Found suspicious script: " .. obj.Name)
                    obj.Disabled = true
                    obj:Destroy()
                end
                
                -- Disable all scripts to be safe
                obj.Disabled = true
            end
        end
        
        -- Clear player backpack
        player.Backpack:ClearAllChildren()
        
        -- Remove any suspicious instances
        for _, obj in pairs(player:GetDescendants()) do
            local name = obj.Name:lower()
            if name:match("anti") or name:match("kick") or name:match("bypass") or
               name:match("protect") or name:match("secure
