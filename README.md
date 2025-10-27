# 🚀 Azure ARM Enumeration Toolkit

> Simple automation for Azure ARM enumeration using tokens

## 🎯 What's This About?

Some scripts to automate enumeration of Azure ARM resources using tokens or current logged user. Useful for **CARTP certification**, **Azure Red Team Labs from Altered Security** or **Red Teams**.

Basically, if you're tired of enumerating resources using Powershell and AZ Cli, or you face a CTF or you simple want to see the different resources that can be accesed using a token without a lot of manual commands, you've come to the right place. These scripts will make you look smart at parties (the kind of parties where people discuss PowerShell... so, very exclusive parties).

## 🔥 The Star of the Show

### 🎪 Enum-AzureARM.ps1 - *The Azure Whisperer*

This magnificent beast of a script will enumerate Azure resources faster than you can say "unauthorized access". It's like having X-ray vision for Azure subscriptions, but legal (**Ensure you have explicit permission**).

**What it does:**

- 🕵️ **Finds ALL the things**: VMs, Storage Accounts, Key Vaults, Web Apps, Function Apps, and more
- 🔐 **Extract Key Vault secrets** (if you're allowed, obviously)
- 👥 **Maps role assignments** like a social network stalker
- 📊 **Generates beautiful reports** that will make your boss think you're a wizard
- 🎭 **Multiple authentication methods** (Bearer tokens, current user credentials, and more)
- 🚫 **SSL bypass capabilities** for those special CTF moments when certificates are more like suggestions
- 🗣️ **Verbose output** because sometimes you need to know what's happening under the hood

**How to use it like a pro:**

```powershell
# The "I'm already logged in" approach (recommended for lazy people)
.\Enum-AzureARM.ps1 -UseCurrentUser

# The "I have tokens and I'm not afraid to use them" approach
.\Enum-AzureARM.ps1 -AccessTokenARM $armToken -AccessTokenGraph $graphToken -AccountId $userId

# The "Tell me EVERYTHING" approach
.\Enum-AzureARM.ps1 -UseCurrentUser -Verbose

# The "I just want Graph data because ARM is being mean" approach
.\Enum-AzureARM.ps1 -AccessTokenGraph $graphToken -GraphOnly
```

## 🌐 The Supporting Cast

### 🎯 **port-scanner.ps1** - *The Network Script Ninja*

When you need to know what's alive on a network but don't want to install nmap (or can't because corporate policies hate fun).

```powershell
# The "knock knock, who's there?" approach
.\port-scanner.ps1 -NetworkRange "192.168.1.0/24"

# The "I have trust issues" approach (scan the ports)
.\port-scanner.ps1 -NetworkRange "10.0.1.1-50" -Ports "22,80,443,3389,5985,5986"
```

### ✍️ create-script-without-gui.ps1 - *The Script Whisperer*

For when you want to create PowerShell scripts but notepad gives you anxiety and ISE is too mainstream or maybe you don't have a GUI to use.

```powershell
# The "I'm feeling creative" approach
.\create-script-without-gui.ps1 -OutputFile "MyMasterpiece.ps1" -IncludeHeader
```

## 🎭 Other Random Utilities

We've also got some other scripts lying around because why not:

- **Enhanced-CTF-Enumeration.ps1** - For when regular enumeration isn't extra enough
- **Quick-CTF-Test.ps1** - Quick and dirty testing (emphasis on dirty)
- **check_credentials.ps1** - Does what it says on the tin
- Various other scripts that may or may not work depending on the phase of the moon

## 🏆 What Makes These Scripts Actually Good

### 🛡️ They Don't Crash (Much)

- Error handling so good it makes Python developers jealous
- Input validation that would make your mother proud
- Retry logic for when Azure is having a bad day (which is Tuesday)

### 📚 Documentation That Actually Helps

- Help files that don't assume you're a mind reader
- Examples that actually work (revolutionary!)
- Parameter descriptions written in human language

### 🎨 User Experience That Doesn't Suck

- Progress bars so you know it's not frozen
- Color-coded output because we're not savages
- Verbose mode for when you need to know what your computer is thinking

### 📊 Output That Makes Sense

- JSON for the APIs, CSV for the spreadsheet warriors
- Timestamps because "when did this happen?" is always the first question
- Full data because truncation is the enemy of knowledge

## 🔧 What You Need to Get Started

### Minimum Requirements (AKA The Bare Minimum)

- **PowerShell 5.1+** (if you're still on 2.0, we need to talk)
- **An Azure account or token** (shocking, I know)
- **Basic reading skills** (you're doing great so far!)

### Optional But Recommended

- **Az.Accounts module** - for the fancy authentication
- **Microsoft.Graph module** - for when you want to be extra thorough
- **Coffee** - for moral support during long enumeration sessions

## 🚀 Getting Started (The Easy Way)

### Step 1: Get the Scripts

```powershell
git clone https://github.com/oscarintherocks/Enum-AzureARM.git
# Or download the ZIP like it's 2005
```

### Step 2: Deal with PowerShell's Trust Issues

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
# PowerShell: "I don't trust this script!"
# You: "It's fine, I made it myself"
```

### Step 3: Install the Good Stuff (Optional)

```powershell
Install-Module Az.Accounts -Force
Install-Module Microsoft.Graph -Force
# Now you're ready to enumerate like a pro
```

## ⚠️ Legal Disclaimer (The "Don't Sue Me" Section)

**IMPORTANT**: Only use these scripts on systems you own or have explicit permission to test. I'm not responsible if you:

- Get fired for "testing" your company's production environment
- Accidentally enumerate someone else's Azure tenant
- Discover your CEO's secret cryptocurrency mining operation
- Find out how much money your company actually wastes on Azure

## 🐛 When Things Go Wrong (Troubleshooting for Humans)

### PowerShell Doesn't Trust You

```powershell
# The nuclear option (use responsibly)
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

### Azure is Being Difficult

1. **"Invalid token"** - Your token expired (tokens are like milk, they go bad)
2. **"Access denied"** - You need more permissions (ask nicely)
3. **"Rate limited"** - Azure is tired, try again later

### General "It's Broken" Issues

```powershell
# The universal fix
Get-Help .\scriptname.ps1 -Examples
# If that doesn't work, try turning it off and on again
```

## 🤝 Contributing (If You're Feeling Generous)

Want to make these scripts even better? Here's how not to mess things up:

1. **Don't break existing stuff** (revolutionary concept)
2. **Add error handling** (because users will always find new ways to break things)
3. **Write help that helps** (amazing!)
4. **Test your changes** (I know, I know, testing is for mortals)

## 📈 Version History (The Journey)

### Version 2.0 - "The Great Refactoring"

- Made everything actually work properly
- Added so much error handling it became self-aware
- Documentation that doesn't make you cry
- SSL bypasses for those special CTF moments
- Full secret values because truncation is evil

### Version 1.0 - "The Dark Times"

- Basic functionality (if you were lucky)
- Error handling? What's that?
- Documentation written by someone who clearly hated users

## 📜 License

It's open source, do whatever you want. Just don't blame me when it breaks.
For more details read the [LICENSE](LICENSE) file

---

## 🎯 TL;DR - The Cheat Sheet

| Script | What It Does | How to Use It |
|--------|-------------|---------------|
| `Enum-AzureARM.ps1` | Finds all your Azure stuff | `.\Enum-AzureARM.ps1 -UseCurrentUser` |
| `port-scanner.ps1` | Scans networks | `.\port-scanner.ps1 -NetworkRange "192.168.1.0/24"` |
| `create-script-without-gui.ps1` | Copy and paste util when no graphic interface is available | `.\create-script-without-gui.ps1` |

**Pro Tip**: When in doubt, use `-Verbose` to see what's actually happening. Knowledge is power!

---

*Made with ☕ and 90% using AI with nice prompts, including most of this fancy documentation*
