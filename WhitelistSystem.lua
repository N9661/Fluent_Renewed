local WhitelistCore = {}

-- Load dependencies
local SecurityUtils = loadstring(game:HttpGet("https://raw.githubusercontent.com/N9661/Fluent_Renewed/refs/heads/main/wwhitelist_core.lua"))()
local IdentityVerification = loadstring(game:HttpGet("https://raw.githubusercontent.com/N9661/Fluent_Renewed/refs/heads/main/iidentity_verification.lua"))()
local WhitelistData = loadstring(game:HttpGet("https://raw.githubusercontent.com/N9661/Fluent_Renewed/refs/heads/main/whitelist_data.lua"))()

local _G = _G or getgenv()

-- Initialize whitelist state if it doesn't exist
if not _G.__WhitelistState then
    _G.__WhitelistState = {
        initialized = false,
        lastVerification = nil,
        verificationCount = 0,
        lastVerificationTime = 0,
        failedAttempts = 0
    }
end

-- Check if a user is in the whitelist and has matching client ID
function WhitelistCore.isUserWhitelisted(identity)
    -- Validate input
    if not identity or not identity.username or not identity.userId or not identity.clientId then
        return false, "Invalid identity data"
    end
    
    -- Check against whitelist data
    for _, user in ipairs(WhitelistData) do
        -- Match by username and userId
        if user.username == identity.username and user.userId == identity.userId then
            -- Verify client ID
            if IdentityVerification.compareClientIdFirstThreeParts(user.clientId, identity.clientId) then
                return true, "Fully authorized"
            else
                -- Log the mismatch for debugging
                local mismatchInfo = string.format(
                    "Client ID mismatch for user %s (%d)",
                    identity.username,
                    identity.userId
                )
                return false, "Client ID mismatch"
            end
        end
    end
    
    return false, "User not in whitelist"
end

-- Verify the current user against the whitelist
function WhitelistCore.verifyUser()
    -- Rate limiting to prevent brute force attempts
    local currentTime = os.time()
    if currentTime - _G.__WhitelistState.lastVerificationTime < 3 then
        _G.__WhitelistState.failedAttempts = _G.__WhitelistState.failedAttempts + 1
        
        if _G.__WhitelistState.failedAttempts > 3 then
            return false, "Too many verification attempts"
        end
        
        -- Add a small delay to slow down brute force attempts
        wait(math.random(1, 3))
    else
        -- Reset failed attempts counter if enough time has passed
        _G.__WhitelistState.failedAttempts = 0
    end
    
    _G.__WhitelistState.lastVerificationTime = currentTime
    
    -- Capture original functions to detect tampering
    SecurityUtils.captureOriginalFunctions()
    
    -- Check for signs of tampering
    local tamperingEvidence = SecurityUtils.checkForTampering()
    if #tamperingEvidence > 0 then
        _G.__SecurityState.tamperingDetected = true
        return false, "Tampering detected: " .. tamperingEvidence[1]
    end
    
    -- Verify user identity
    local identity = IdentityVerification.verifyIdentity()
    
    -- Check for identity spoofing
    if identity.spoofingDetected then
        return false, "Identity spoofing detected"
    end
    
    -- Check if user is whitelisted
    local whitelisted, reason = WhitelistCore.isUserWhitelisted(identity)
    
    -- Store verification results
    _G.__WhitelistState.lastVerification = {
        timestamp = os.time(),
        identity = identity,
        whitelisted = whitelisted,
        reason = reason
    }
    _G.__WhitelistState.verificationCount = _G.__WhitelistState.verificationCount + 1
    
    return whitelisted, reason
end

-- Initialize the whitelist system
function WhitelistCore.initialize()
    -- Prevent multiple initializations
    if _G.__WhitelistState.initialized then
        local errorCode = math.random(1000, 9999)
        
        -- Try to restore original functions before kicking
        pcall(function()
            SecurityUtils.restoreOriginalFunctions()
        end)
        
        -- Kick the player with a random error code
        pcall(function()
            SecurityUtils.secureKick(game.Players.LocalPlayer, "Multiple execution detected (Error Code: " .. errorCode .. ")")
        end)
        
        -- Throw an error with a formatted hex code
        error("Multiple execution detected: Error code 0x" .. string.format("%x", errorCode))
        return false
    end
    
    -- Mark as initialized
    _G.__WhitelistState.initialized = true
    
    -- Verify the user
    local authorized, reason
    local success, result = pcall(function()
        return WhitelistCore.verifyUser()
    end)
    
    if success then
        authorized, reason = result, reason
    else
        authorized, reason = false, "Verification error: " .. tostring(result)
    end
    
    -- Handle authorization result
    if authorized then
        -- Success path
        pcall(function()
            print("Access granted - Welcome to the script!")
        end)
        return true
    else
        -- Failure path - add random delay to make timing attacks harder
        wait(math.random(1, 3))
        
        -- Try to restore original functions
        pcall(function()
            SecurityUtils.restoreOriginalFunctions()
        end)
        
        -- Generate random error code
        local errorCode = math.random(1000, 9999)
        
        -- Kick with error code
        pcall(function()
            SecurityUtils.secureKick(game.Players.LocalPlayer, "Unauthorized access (Error Code: " .. errorCode .. ")")
        end)
        
        -- Throw error with formatted hex code
        error("Script initialization failed: Error code 0x" .. string.format("%x", errorCode))
        return false
    end
end

-- Periodic verification function to continuously check whitelist status
function WhitelistCore.startPeriodicVerification(interval)
    interval = interval or 60 -- Default to 60 seconds
    
    -- Create a new thread for periodic checks
    spawn(function()
        while wait(interval) do
            local authorized, reason = WhitelistCore.verifyUser()
            
            if not authorized then
                -- If verification fails, kick the player
                local errorCode = math.random(1000, 9999)
                
                pcall(function()
                    SecurityUtils.restoreOriginalFunctions()
                end)
                
                pcall(function()
                    SecurityUtils.secureKick(game.Players.LocalPlayer, "Verification failed: " .. reason .. " (Error Code: " .. errorCode .. ")")
                end)
                
                break
            end
        end
    end)
end

-- Get the last verification result
function WhitelistCore.getLastVerification()
    return _G.__WhitelistState.lastVerification
end

return WhitelistCore
