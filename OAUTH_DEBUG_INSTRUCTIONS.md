# OAuth Authentication Debug Instructions

## 🚨 CRITICAL: Follow These Steps Exactly

The user is experiencing OAuth authentication issues. Use these step-by-step instructions to identify the exact problem.

## Step 1: Initial Setup (5 minutes)

1. **Open the application** in the published domain (NOT the development preview)
2. **Open browser Developer Tools** (F12 or Right-click → Inspect)
3. **Go to Console tab** - you should see debugging messages starting with "🔍 [Browser Debug]"
4. **Clear the console** (click the clear button or press Ctrl+L)
5. **Refresh the page** - you should see a "page_load" debug message

**✅ Expected:** Debug messages appear  
**❌ If no debug messages:** JavaScript is blocked or not loading

## Step 2: Check Authentication State (2 minutes)

1. In the browser console, type: `authDebugger.checkAuthState()`
2. Press Enter and wait for the result
3. **Record the output** - this shows current session status

**✅ Expected:** JSON object with session and user data  
**❌ If error:** Network or server issues

## Step 3: Test Session Diagnostics (2 minutes)

1. Open a new browser tab
2. Go to: `[YOUR_DOMAIN]/api/debug/session`
3. **Record the JSON response** - this shows server-side session state

**✅ Expected:** Detailed session diagnostics  
**❌ If 500 error:** Server-side session issues

## Step 4: Sign In Button Test (CRITICAL - 10 minutes)

### Part A: Monitor Click
1. **Go back to the main page** (landing page with Sign In button)
2. **Keep Developer Tools Console open and visible**
3. **Click the "Sign In" button**
4. **IMMEDIATELY AFTER CLICKING:** Look for these console messages:
   - `🖱️ [Frontend Debug] === SIGN IN CLICKED ===`
   - Details about browser state
   - "About to redirect to: /api/auth/google"

### Part B: Check Server Logs
After clicking, check if you see ANY of these server logs:
- `🔐 [OAuth Debug] === OAUTH INITIATION ===`
- Server details about the OAuth request

### Part C: Check Google Redirect
1. **Watch the URL bar** - did it change to Google's OAuth page?
2. **If redirected to Google:** Record the URL
3. **If NOT redirected:** This is the core problem

## Step 5: Network Request Analysis (5 minutes)

1. Go to **Network tab** in Developer Tools
2. **Clear network requests** (click clear button)
3. **Click Sign In button again**
4. **Check if there's a request to `/api/auth/google`**

**✅ Expected:** Request to `/api/auth/google` followed by redirect  
**❌ If no request:** Frontend navigation is failing  
**❌ If request fails:** Server/network issue

## Step 6: Browser Compatibility Check (3 minutes)

1. In console, type: `authDebugger.exportDebugData()`
2. **Copy the entire output** and save it
3. Check for these specific items in the data:
   - `cookieEnabled: true`
   - No JavaScript errors
   - No blocked network requests

## Step 7: Alternative Browser Test (5 minutes)

1. **Try a different browser** (Chrome, Firefox, Edge, Safari)
2. **Repeat Steps 1-6** in the new browser
3. **Compare results** - is the issue browser-specific?

## Step 8: Incognito/Private Mode Test (3 minutes)

1. **Open incognito/private window**
2. **Go to the application**
3. **Try the Sign In flow**
4. **Record if behavior changes**

## 🔍 Debugging Decision Tree

### If NO debug messages appear in Step 1:
- JavaScript is disabled or blocked
- Content blockers interfering
- Network connectivity issues

### If click is detected but NO server logs:
- Network request is being blocked
- Firewall or proxy issues
- DNS resolution problems

### If server logs show OAuth initiation but no Google redirect:
- Google OAuth configuration issue
- Callback URL mismatch
- Client ID/Secret problems

### If redirected to Google but authentication fails:
- User authorization denied
- Google OAuth callback issues
- Session persistence problems

## 📊 Key Data to Collect

For each test, record:

1. **Browser Console Output** (all debug messages)
2. **Network Tab Requests** (especially /api/auth/google)
3. **Session Diagnostics** (from /api/debug/session)
4. **Auth State Check** (from authDebugger.checkAuthState())
5. **Any Error Messages** (red text in console)
6. **URL Changes** (especially if redirects occur)

## 🚨 Most Likely Issues (Based on Symptoms)

Given the user sees 401 errors on `/api/auth/user` but no OAuth initiation:

### Scenario 1: User Not Clicking Sign In
- Debug messages show page loads but no click events
- Solution: User education or UI issue

### Scenario 2: JavaScript/Network Blocking
- No frontend debug messages appear
- Solution: Check browser settings, extensions, network

### Scenario 3: Request Blocking
- Click detected but no server OAuth logs
- Solution: Check firewall, proxy, DNS

### Scenario 4: Session Issues
- OAuth works but session doesn't persist
- Solution: Check cookie settings, domain configuration

## 📞 Next Steps

1. **Complete all steps above**
2. **Document exact findings**
3. **Compare results across browsers**
4. **Focus on the FIRST step that fails**
5. **Report specific error messages and browser console output**

The debugging system will capture comprehensive data to identify the exact failure point in the authentication flow.