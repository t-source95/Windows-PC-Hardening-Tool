#Requires -Version 5.1
<#
.SYNOPSIS
    PC Hardening Provisioning Tool - a GUI utility for applying and reverting
    Windows privacy / telemetry / AI-feature hardening settings via registry,
    modeled after O&O ShutUp10-style toggles.

.DESCRIPTION
    - Presents a checklist of hardening settings grouped by category.
    - Checking a box marks a setting for hardening (privacy-friendly value).
    - "Apply Checked" pushes those values to the registry (auto-elevates).
    - "Revert Checked" restores the Windows default value for checked items.
    - "Refresh Status" reads the live registry to show current state.
    - Profiles (the checked/unchecked selection) can be exported/imported as
      JSON so the same configuration can be provisioned across a fleet of
      machines silently via -Silent -Import.

.PARAMETER Import
    Path to a JSON profile to apply silently (no GUI), e.g. for provisioning
    scripts / RMM deployment.

.PARAMETER Silent
    Suppresses the GUI. Requires -Import. Applies the profile and exits.

.EXAMPLE
    .\PC-Hardening-Tool.ps1
        Launches the interactive GUI.

.EXAMPLE
    .\PC-Hardening-Tool.ps1 -Silent -Import .\StandardHardening.json
        Applies a saved profile with no UI, e.g. from an RMM script step.
#>

[CmdletBinding()]
param(
    [string]$Import,
    [switch]$Silent
)

# ---------------------------------------------------------------------------
# Elevation check - re-launch elevated if needed (skip when running -Silent
# under an RMM/SYSTEM context that is already elevated)
# ---------------------------------------------------------------------------
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    if ($Silent) {
        Write-Error "Not running elevated. Re-run this script as Administrator."
        exit 1
    }
    $argList = @()
    if ($Import) { $argList += @('-Import', "`"$Import`"") }
    if ($Silent) { $argList += '-Silent' }
    $psArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"") + $argList
    Start-Process -FilePath 'powershell.exe' -ArgumentList $psArgs -Verb RunAs
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ---------------------------------------------------------------------------
# Setting definitions
#
# Each setting can push multiple registry values ("Actions"). "On" = the
# hardened / privacy-friendly state (what gets applied when checked).
# "Off" = the Windows default, used by Revert.
# Type 'Service' actions toggle a service's StartupType instead of a value.
# ---------------------------------------------------------------------------
function New-Action {
    param($Path, $Name, $Type, $On, $Off)
    [PSCustomObject]@{ Path = $Path; Name = $Name; Type = $Type; On = $On; Off = $Off }
}

$Settings = @(

    # ======================= Privacy =======================
    [PSCustomObject]@{ Id='PRIV-ADID'; Recommended='Yes'; Category='Privacy'; Name='Disable Advertising ID'
        Description='Stops apps from using the per-user advertising identifier.'
        Actions=@( New-Action 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' 'Enabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='PRIV-CEIP'; Recommended='Yes'; Category='Privacy'; Name='Disable Customer Experience Improvement Program'
        Description='Stops Windows from sending usage statistics to Microsoft.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' 'CEIPEnable' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='PRIV-WER'; Recommended='Yes'; Category='Privacy'; Name='Disable Windows Error Reporting'
        Description='Stops crash/error data from being sent to Microsoft.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' 'Disabled' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='PRIV-TELEMETRY'; Recommended='Yes'; Category='Privacy'; Name='Set diagnostic data to minimum (telemetry)'
        Description='Sets AllowTelemetry to the lowest level permitted by the SKU.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 'DWord' 0 3 ) },
    [PSCustomObject]@{ Id='PRIV-TAILORED'; Recommended='Yes'; Category='Privacy'; Name='Disable tailored experiences with diagnostic data'
        Description='Prevents Microsoft from using diagnostic data to personalize tips/ads for this user.'
        Actions=@( New-Action 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy' 'TailoredExperiencesWithDiagnosticDataEnabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='PRIV-FEEDBACK'; Recommended='Yes'; Category='Privacy'; Name='Disable feedback reminders'
        Description='Stops Windows from periodically prompting for feedback.'
        Actions=@(
            New-Action 'HKCU:\Software\Microsoft\Siuf\Rules' 'NumberOfSIUFInPeriod' 'DWord' 0 1
            New-Action 'HKCU:\Software\Microsoft\Siuf\Rules' 'PeriodInNanoSeconds'  'DWord' 0 1
        ) },
    [PSCustomObject]@{ Id='PRIV-CONSUMERFEATURES'; Recommended='Yes'; Category='Privacy'; Name='Disable Windows consumer features'
        Description='Stops Windows from auto-installing suggested/promoted Store apps.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='PRIV-SPOTLIGHT'; Recommended='Yes'; Category='Privacy'; Name='Disable Windows Spotlight'
        Description='Turns off Spotlight suggestions on the lock screen and elsewhere.'
        Actions=@( New-Action 'HKCU:\Software\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsSpotlightFeatures' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='PRIV-TIPS'; Recommended='Yes'; Category='Privacy'; Name='Disable Windows Tips / Welcome Experience'
        Description='Stops Windows from showing tips, tricks, and "did you know" suggestions.'
        Actions=@( New-Action 'HKCU:\Software\Policies\Microsoft\Windows\CloudContent' 'DisableSoftLanding' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='PRIV-CONSUMERACCT'; Recommended='Yes'; Category='Privacy'; Name='Disable cloud consumer account state content'
        Description='Blocks account-related promotional content pulled from the cloud.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableConsumerAccountStateContent' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='PRIV-LOCKSCREENCAM'; Recommended='Yes'; Category='Privacy'; Name='Disable camera on the logon/lock screen'
        Description='Removes the swipe-to-camera shortcut from the lock screen.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' 'NoLockScreenCamera' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='PRIV-INKING'; Recommended='Yes'; Category='Privacy'; Name='Disable sharing of handwriting/typing data'
        Description='Stops Windows from collecting inking and typing samples used to improve suggestions.'
        Actions=@(
            New-Action 'HKCU:\Software\Policies\Microsoft\InputPersonalization' 'RestrictImplicitInkCollection' 'DWord' 1 0
            New-Action 'HKCU:\Software\Policies\Microsoft\InputPersonalization' 'RestrictImplicitTextCollection' 'DWord' 1 0
        ) },
    [PSCustomObject]@{ Id='PRIV-MSGSYNC'; Recommended='Yes'; Category='Privacy'; Name='Disable backup of text messages to the cloud'
        Description='Prevents SMS/MMS message sync/backup via a Microsoft account.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Messaging' 'AllowMessageSync' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='PRIV-BIOMETRICS'; Recommended='Limited'; Category='Privacy'; Name='Disable biometric features (Windows Hello)'
        Description='Blocks the use of fingerprint/face sign-in system-wide.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics' 'Enabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='PRIV-INVENTORY'; Recommended='Yes'; Category='Privacy'; Name='Disable Inventory Collector'
        Description='Turns off the Program Compatibility Assistant''s application inventory collection.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' 'DisableInventory' 'DWord' 1 0 ) },

    # ============ Activity History and Clipboard ============
    [PSCustomObject]@{ Id='ACT-FEED'; Recommended='Yes'; Category='Activity History and Clipboard'; Name='Disable recordings of user activity'
        Description='Stops Windows Timeline from recording what you do on this device.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableActivityFeed' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='ACT-PUBLISH'; Recommended='Yes'; Category='Activity History and Clipboard'; Name='Disable storing users'' activity history'
        Description='Prevents activity history from being stored locally at all.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'PublishUserActivities' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='ACT-UPLOAD'; Recommended='Yes'; Category='Activity History and Clipboard'; Name='Disable submission of user activities to Microsoft'
        Description='Stops locally stored activity history from being uploaded to Microsoft.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'UploadUserActivities' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='ACT-CLIPHIST'; Recommended='Yes'; Category='Activity History and Clipboard'; Name='Disable storage of clipboard history'
        Description='Turns off the Win+V clipboard history feature.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'AllowClipboardHistory' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='ACT-CLIPCLOUD'; Recommended='Yes'; Category='Activity History and Clipboard'; Name='Disable clipboard transfer to other devices via the cloud'
        Description='Turns off cross-device clipboard sync.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'AllowCrossDeviceClipboard' 'DWord' 0 1 ) },

    # ======================= App Privacy =======================
    [PSCustomObject]@{ Id='APP-ACCOUNTINFO'; Recommended='Yes'; Category='App Privacy'; Name='Disable app access to user account information'
        Description='Blocks Store/UWP apps from reading account name/picture.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessAccountInfo' 'DWord' 2 0 ) },
    [PSCustomObject]@{ Id='APP-DIAG'; Recommended='Yes'; Category='App Privacy'; Name='Disable app access to diagnostics information'
        Description='Blocks apps from reading diagnostic information about other apps.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessDiagnosticInfo' 'DWord' 2 0 ) },
    [PSCustomObject]@{ Id='APP-GENAI'; Recommended='Yes'; Category='App Privacy'; Name='Deny app access to generative AI'
        Description='Blocks apps from calling generative-AI system features.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessGenerativeAI' 'DWord' 2 0 ) },
    [PSCustomObject]@{ Id='APP-LOCATION'; Recommended='Limited'; Category='App Privacy'; Name='Disable app access to device location'
        Description='Blocks Store/UWP apps from reading device location.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessLocation' 'DWord' 2 0 ) },
    [PSCustomObject]@{ Id='APP-CAMERA'; Recommended='Limited'; Category='App Privacy'; Name='Disable app access to camera'
        Description='Blocks Store/UWP apps from using the camera.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessCamera' 'DWord' 2 0 ) },
    [PSCustomObject]@{ Id='APP-MIC'; Recommended='Limited'; Category='App Privacy'; Name='Disable app access to microphone'
        Description='Blocks Store/UWP apps from using the microphone.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessMicrophone' 'DWord' 2 0 ) },
    [PSCustomObject]@{ Id='APP-NOTIF'; Recommended='Limited'; Category='App Privacy'; Name='Disable app access to notifications'
        Description='Blocks apps from reading notifications sent to other apps.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessNotifications' 'DWord' 2 0 ) },
    [PSCustomObject]@{ Id='APP-MOTION'; Recommended='Limited'; Category='App Privacy'; Name='Disable app access to movements (motion sensors)'
        Description='Blocks apps from reading accelerometer/motion sensor data.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessMotion' 'DWord' 2 0 ) },
    [PSCustomObject]@{ Id='APP-CONTACTS'; Recommended='Limited'; Category='App Privacy'; Name='Disable app access to contacts'
        Description='Blocks Store/UWP apps from reading the contacts list.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessContacts' 'DWord' 2 0 ) },
    [PSCustomObject]@{ Id='APP-CALENDAR'; Recommended='Limited'; Category='App Privacy'; Name='Disable app access to calendar'
        Description='Blocks Store/UWP apps from reading the calendar.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessCalendar' 'DWord' 2 0 ) },
    [PSCustomObject]@{ Id='APP-PHONECALLS'; Recommended='Limited'; Category='App Privacy'; Name='Disable app access to phone calls'
        Description='Blocks apps from making/managing phone calls.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessPhone' 'DWord' 2 0 ) },
    [PSCustomObject]@{ Id='APP-CALLHIST'; Recommended='Limited'; Category='App Privacy'; Name='Disable app access to call history'
        Description='Blocks apps from reading call history.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessCallHistory' 'DWord' 2 0 ) },
    [PSCustomObject]@{ Id='APP-EMAIL'; Recommended='Limited'; Category='App Privacy'; Name='Disable app access to email'
        Description='Blocks apps from reading/sending email via system APIs.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessEmail' 'DWord' 2 0 ) },
    [PSCustomObject]@{ Id='APP-TASKS'; Recommended='Limited'; Category='App Privacy'; Name='Disable app access to tasks'
        Description='Blocks apps from reading/writing the system task list.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessTasks' 'DWord' 2 0 ) },
    [PSCustomObject]@{ Id='APP-MESSAGES'; Recommended='Limited'; Category='App Privacy'; Name='Disable app access to messages'
        Description='Blocks apps from reading/sending SMS/MMS messages.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessMessaging' 'DWord' 2 0 ) },
    [PSCustomObject]@{ Id='APP-RADIOS'; Recommended='Limited'; Category='App Privacy'; Name='Disable app access to wireless connections'
        Description='Blocks apps from controlling radios (Wi-Fi/Bluetooth/cellular on/off).'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessRadios' 'DWord' 2 0 ) },
    [PSCustomObject]@{ Id='APP-TRUSTEDDEV'; Recommended='Limited'; Category='App Privacy'; Name='Disable app access to loosely coupled devices'
        Description='Blocks apps from communicating with paired/nearby devices.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessTrustedDevices' 'DWord' 2 0 ) },
    [PSCustomObject]@{ Id='APP-DOCS'; Recommended='Limited'; Category='App Privacy'; Name='Disable app access to documents'
        Description='Blocks apps from reading the Documents library.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessDocumentsLibrary' 'DWord' 2 0 ) },
    [PSCustomObject]@{ Id='APP-PICTURES'; Recommended='Limited'; Category='App Privacy'; Name='Disable app access to images'
        Description='Blocks apps from reading the Pictures library.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessPicturesLibrary' 'DWord' 2 0 ) },
    [PSCustomObject]@{ Id='APP-VIDEOS'; Recommended='Limited'; Category='App Privacy'; Name='Disable app access to videos'
        Description='Blocks apps from reading the Videos library.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsAccessVideosLibrary' 'DWord' 2 0 ) },

    # ======================= Security =======================
    [PSCustomObject]@{ Id='SEC-PWREVEAL'; Recommended='Yes'; Category='Security'; Name='Disable password reveal button'
        Description='Removes the "eye" icon that reveals typed passwords in logon UI.'
        Actions=@( New-Action 'HKLM:\Software\Policies\Microsoft\Windows\CredUI' 'DisablePasswordReveal' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='SEC-DIAGTRACK'; Recommended='Yes'; Category='Security'; Name='Disable telemetry (Connected User Experiences and Telemetry service)'
        Description='Sets the DiagTrack service to Disabled.'
        Actions=@( New-Action 'DiagTrack' $null 'Service' 'Disabled' 'Automatic' ) },
    [PSCustomObject]@{ Id='SEC-STEPSRECORDER'; Recommended='Yes'; Category='Security'; Name='Disable user steps recorder'
        Description='Turns off Steps Recorder (psr.exe), which can capture screenshots of activity.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' 'DisableUAR' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='SEC-WMDRM'; Recommended='Limited'; Category='Security'; Name='Disable Internet access of Windows Media DRM'
        Description='Prevents Windows Media DRM components from reaching the internet.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\WMDRM' 'DisableOnline' 'DWord' 1 0 ) },

    # ======================= Microsoft Edge =======================
    [PSCustomObject]@{ Id='EDGE-TRACKING'; Recommended='Yes'; Category='Microsoft Edge'; Name='Set tracking prevention to Strict'
        Description='Blocks the majority of trackers across sites in Edge.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'TrackingPrevention' 'DWord' 3 1 ) },
    [PSCustomObject]@{ Id='EDGE-PAYMENTCHECK'; Recommended='Yes'; Category='Microsoft Edge'; Name='Disable check for saved payment methods by sites'
        Description='Stops sites from querying whether you have saved payment info.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'PaymentMethodQueryEnabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-PERSONALIZE'; Recommended='Yes'; Category='Microsoft Edge'; Name='Disable personalizing ads, search, news, and other services'
        Description='Stops Edge from sending browsing history/usage data to Microsoft for personalization.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'PersonalizationReportingEnabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-FEEDBACK'; Recommended='Yes'; Category='Microsoft Edge'; Name='Disable user feedback in toolbar'
        Description='Removes the Send Feedback option/icon.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'UserFeedbackAllowed' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-CCSTORE'; Recommended='Yes'; Category='Microsoft Edge'; Name='Disable storing/autocompleting credit card data'
        Description='Stops Edge from offering to save and autofill payment card details.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'AutofillCreditCardEnabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-FORMSUGGEST'; Recommended='Yes'; Category='Microsoft Edge'; Name='Disable form (address) suggestions'
        Description='Stops Edge from saving and suggesting address/contact form data.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'AutofillAddressEnabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-SEARCHSUGGEST'; Recommended='Yes'; Category='Microsoft Edge'; Name='Disable search and website suggestions'
        Description='Stops Edge from sending address-bar keystrokes to the search provider for suggestions.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SearchSuggestEnabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-SHOPPING'; Recommended='Yes'; Category='Microsoft Edge'; Name='Disable shopping assistant in Microsoft Edge'
        Description='Turns off Edge''s built-in shopping/coupon assistant.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'EdgeShoppingAssistantEnabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-SIDEBAR'; Recommended='Yes'; Category='Microsoft Edge'; Name='Disable sidebar in Microsoft Edge'
        Description='Hides the Edge Hubs sidebar (Copilot, Discover, apps, etc).'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'HubsSidebarEnabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-SPELLCHECK'; Recommended='Yes'; Category='Microsoft Edge'; Name='Disable Enhanced (cloud) Spell Checking'
        Description='Stops typed text from being sent to Microsoft''s cloud spell-check service.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SpellingServiceEnabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-FIRSTRUN'; Recommended='Yes'; Category='Microsoft Edge'; Name='Hide first run experience and splash screen'
        Description='Skips the welcome/first-run screens on launch.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'HideFirstRunExperience' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='EDGE-RECOMMEND'; Recommended='Yes'; Category='Microsoft Edge'; Name='Disable spotlight experiences and recommendations'
        Description='Turns off in-product recommendations shown in Settings and elsewhere.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'ShowRecommendationsEnabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-BINGCHAT'; Recommended='Yes'; Category='Microsoft Edge'; Name='Disable Bing Chat on new tab page'
        Description='Removes the Copilot/Bing Chat module from the new tab page.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'NewTabPageBingChatEnabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-NTPCONTENT'; Recommended='Yes'; Category='Microsoft Edge'; Name='Disable content on new tab page'
        Description='Removes news/feed content from the new tab page.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'NewTabPageContentEnabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-NTPTOPSITES'; Recommended='Limited'; Category='Microsoft Edge'; Name='Hide default top sites on new tab page'
        Description='Removes Microsoft''s pre-populated shortcuts from the new tab page.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'NewTabPageHideDefaultTopSites' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='EDGE-COPILOTCTX'; Recommended='Yes'; Category='Microsoft Edge'; Name='Disable Copilot access to page context'
        Description='Prevents Edge Copilot from reading the content of the current page.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'CopilotPageContext' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-DEFBROWSERCAMP'; Recommended='Yes'; Category='Microsoft Edge'; Name='Disable default browser campaigns'
        Description='Stops periodic nag prompts urging you to set Edge as default.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'DefaultBrowserSettingsCampaignEnabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-DIAG'; Recommended='Yes'; Category='Microsoft Edge'; Name='Disable diagnostic data collection'
        Description='Stops Edge from sending usage/diagnostic metrics to Microsoft.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'MetricsReportingEnabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-M365COPILOT'; Recommended='Yes'; Category='Microsoft Edge'; Name='Hide Microsoft 365 Copilot chat icon'
        Description='Removes the M365 Copilot Chat icon from the toolbar.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'Microsoft365CopilotChatIconEnabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-REWARDS'; Recommended='Yes'; Category='Microsoft Edge'; Name='Hide Microsoft Rewards'
        Description='Removes Microsoft Rewards experiences and notifications from Edge.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'ShowMicrosoftRewards' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-SECURENETWORK'; Recommended='Yes'; Category='Microsoft Edge'; Name='Disable Edge Secure Network (built-in VPN)'
        Description='Turns off Edge''s built-in metered VPN-style traffic proxying feature.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'EdgeSecureNetworkEnabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-NAVERRORS'; Recommended='Limited'; Category='Microsoft Edge'; Name='Disable use of web service to resolve navigation errors'
        Description='Stops Edge from calling home when a page can''t be found.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'AlternateErrorPagesEnabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-PRELOAD'; Recommended='Limited'; Category='Microsoft Edge'; Name='Disable preload of pages for faster browsing'
        Description='Stops Edge from speculatively preloading likely-next pages.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'NetworkPredictionOptions' 'DWord' 2 0 ) },
    [PSCustomObject]@{ Id='EDGE-SAVEPW'; Recommended='Limited'; Category='Microsoft Edge'; Name='Disable saving passwords for websites'
        Description='Stops Edge''s built-in password manager from offering to save credentials.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'PasswordManagerEnabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-IEREDIRECT'; Recommended='Limited'; Category='Microsoft Edge'; Name='Disable automatic redirection from Internet Explorer to Edge'
        Description='Turns off IE mode integration and the redirect prompt for legacy sites.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'InternetExplorerIntegrationLevel' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-STARTUPBOOST'; Recommended='Limited'; Category='Microsoft Edge'; Name='Disable startup boost'
        Description='Stops Edge from pre-launching at sign-in / staying resident to speed up opening.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'StartupBoostEnabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-ACROBATBTN'; Recommended='Limited'; Category='Microsoft Edge'; Name='Hide Adobe Acrobat subscription button'
        Description='Removes the Adobe Acrobat sign-up promotion from the PDF toolbar.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'ShowAcrobatSubscriptionButton' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-MSASIGNIN'; Recommended='Limited'; Category='Microsoft Edge'; Name='Disable the Microsoft Account Sign-In Button'
        Description='Removes the browser-level sign-in prompt/button.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'BrowserSignin' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='EDGE-SMARTSCREEN'; Recommended='No'; Category='Microsoft Edge'; Name='Disable SmartScreen Filter'
        Description='NOT recommended by most hardening guides (reduces phishing/malware protection). Included for parity only.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled' 'DWord' 0 1 ) },

    # ================== Cortana (Personal Assistant) ==================
    [PSCustomObject]@{ Id='CORTANA-DISABLE'; Recommended='Yes'; Category='Cortana (Personal Assistant)'; Name='Disable Cortana'
        Description='Turns off Cortana entirely.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowCortana' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='CORTANA-LOCATION'; Recommended='Yes'; Category='Cortana (Personal Assistant)'; Name='Cortana and Search are disallowed to use location'
        Description='Blocks Search/Cortana from reading device location.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowSearchToUseLocation' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='CORTANA-CLOUDSEARCH'; Recommended='Yes'; Category='Cortana (Personal Assistant)'; Name='Disable cloud search'
        Description='Stops Search from pulling in results synced from the cloud (OneDrive/SharePoint).'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowCloudSearch' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='CORTANA-ABOVELOCK'; Recommended='Yes'; Category='Cortana (Personal Assistant)'; Name='Disable Cortana above lock screen'
        Description='Stops Cortana from being invoked while the device is locked.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowCortanaAboveLock' 'DWord' 0 1 ) },

    # ======================= Copilot & Windows AI =======================
    [PSCustomObject]@{ Id='AI-COPILOT'; Recommended='Yes'; Category='Copilot & Windows AI'; Name='Disable the Windows Copilot'
        Description='Removes/disables the Windows Copilot entry point and functionality.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='AI-COPILOTAPP'; Recommended='Yes'; Category='Copilot & Windows AI'; Name='Remove the Microsoft Copilot app'
        Description='Flags the standalone Copilot app package for removal/blocking.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' 'RemoveMicrosoftCopilotApp' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='AI-RECALL'; Recommended='Yes'; Category='Copilot & Windows AI'; Name='Disable Windows Copilot+ Recall'
        Description='Prevents Recall from taking/storing periodic screenshots of activity.'
        Actions=@(
            New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis' 'DWord' 1 0
            New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'AllowRecallEnablement'  'DWord' 0 1
        ) },
    [PSCustomObject]@{ Id='AI-IMAGECREATOR'; Recommended='Yes'; Category='Copilot & Windows AI'; Name='Disable the Image Creator in Microsoft Paint'
        Description='Removes the AI Image Creator entry point from Paint.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' 'DisableImageCreator' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='AI-COCREATOR'; Recommended='Yes'; Category='Copilot & Windows AI'; Name='Disable Cocreator in Microsoft Paint'
        Description='Removes the Cocreator AI drawing-assist feature from Paint.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' 'DisableCocreator' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='AI-GENFILL'; Recommended='Yes'; Category='Copilot & Windows AI'; Name='Disable AI-powered image (generative) fill in Microsoft Paint'
        Description='Removes the Generative Fill feature from Paint.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' 'DisableGenerativeFill' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='AI-CLICKTODO'; Recommended='Yes'; Category='Copilot & Windows AI'; Name='Disable Click to Do'
        Description='Turns off the Click to Do AI overlay.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'DisableClickToDo' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='AI-SETTINGSAGENT'; Recommended='Yes'; Category='Copilot & Windows AI'; Name='Disable the Settings agent'
        Description='Turns off the AI-driven natural language Settings agent.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'DisableSettingsAgent' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='AI-NOTEPAD'; Recommended='Yes'; Category='Copilot & Windows AI'; Name='Disable AI features in Notepad'
        Description='Removes Rewrite/Copilot-style AI features from Notepad.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\WindowsNotepad' 'DisableAIFeatures' 'DWord' 1 0 ) },

    # ======================= Location Services =======================
    [PSCustomObject]@{ Id='LOC-DISABLE'; Recommended='Yes'; Category='Location Services'; Name='Disable functionality to locate the system'
        Description='Disables location sensing system-wide via policy.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' 'DisableLocation' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='LOC-SCRIPTING'; Recommended='Yes'; Category='Location Services'; Name='Disable scripting functionality to locate the system'
        Description='Blocks web/script-based location queries specifically.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' 'DisableLocationScripting' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='LOC-FINDMYDEVICE'; Recommended='Yes'; Category='Location Services'; Name='Disable Find My Device'
        Description='Turns off the Find My Device feature.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\FindMyDevice' 'AllowFindMyDevice' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='LOC-SENSORS'; Recommended='Limited'; Category='Location Services'; Name='Disable sensors for locating the system and its orientation'
        Description='Disables the underlying location/orientation sensor drivers.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' 'DisableSensors' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='LOC-GEOSERVICE'; Recommended='Limited'; Category='Location Services'; Name='Disable Windows Geolocation Service'
        Description='Sets the Geolocation Service (lfsvc) to Disabled.'
        Actions=@( New-Action 'lfsvc' $null 'Service' 'Disabled' 'Manual' ) },

    # ======================= User Behavior =======================
    [PSCustomObject]@{ Id='UB-APPTELEMETRY'; Recommended='Yes'; Category='User Behavior'; Name='Disable application telemetry'
        Description='Turns off Application Impact Telemetry (compatibility data collection).'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' 'AITEnable' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='UB-TAILOREDDEVICE'; Recommended='Yes'; Category='User Behavior'; Name='Disable diagnostic data from customizing user experiences'
        Description='Device-wide version of the tailored-experiences setting.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DisableTailoredExperiencesWithDiagnosticData' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='UB-DIAGLOG'; Recommended='Yes'; Category='User Behavior'; Name='Disable diagnostic log collection'
        Description='Limits the diagnostic logs that can be collected for support/telemetry.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'LimitDiagnosticLogCollection' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='UB-ONESETTINGS'; Recommended='Yes'; Category='User Behavior'; Name='Disable downloading of OneSettings configuration'
        Description='Stops the device from downloading Microsoft''s remote feature-flag configuration.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DisableOneSettingsDownloads' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='UB-DEVICENAME'; Recommended='Yes'; Category='User Behavior'; Name='Do not send device name in diagnostic data'
        Description='Strips the device name from telemetry payloads.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowDeviceNameInTelemetry' 'DWord' 0 1 ) },

    # ======================= Windows Update =======================
    [PSCustomObject]@{ Id='WU-P2P'; Recommended='Yes'; Category='Windows Update'; Name='Disable Windows Update via peer-to-peer'
        Description='Restricts update delivery optimization to the local network/HTTP only.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' 'DODownloadMode' 'DWord' 0 3 ) },
    [PSCustomObject]@{ Id='WU-DEVICEMETA'; Recommended='Limited'; Category='Windows Update'; Name='Disable automatic download of manufacturers'' apps/icons for devices'
        Description='Stops Windows from fetching branded device metadata online.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata' 'PreventDeviceMetadataFromNetwork' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='WU-DRIVERUPD'; Recommended='Limited'; Category='Windows Update'; Name='Disable automatic driver updates through Windows Update'
        Description='Excludes driver packages from quality updates.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'ExcludeWUDriversInQualityUpdate' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='WU-DYNAMICUPD'; Recommended='Limited'; Category='Windows Update'; Name='Disable Windows dynamic configuration and update rollouts'
        Description='Opts out of gradual/controlled feature rollout targeting for this device.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DisableDynamicUpdates' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='WU-OPTIONAL'; Recommended='Limited'; Category='Windows Update'; Name='Disable optional updates (including preview updates)'
        Description='Stops optional/preview updates from being offered.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsUpdate' 'AllowOptionalContent' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='WU-AUTOUPDATE'; Recommended='No'; Category='Windows Update'; Name='Disable automatic Windows Updates'
        Description='NOT recommended for most users/fleets — leaves the device unpatched. Included for parity only.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='WU-OTHERMS'; Recommended='No'; Category='Windows Update'; Name='Disable Windows Updates for other Microsoft products (e.g. Office)'
        Description='Turns off "Microsoft Update" so only OS updates are offered.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'AllowMUUpdateService' 'DWord' 0 1 ) },

    # ======================= Windows Explorer =======================
    [PSCustomObject]@{ Id='EXP-ONEDRIVEPRELOGON'; Recommended='Limited'; Category='Windows Explorer'; Name='Disable OneDrive network access before login'
        Description='Stops OneDrive from syncing over the network prior to user sign-in.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' 'PreventNetworkTrafficPreUserSignIn' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='EXP-ONEDRIVE'; Recommended='No'; Category='Windows Explorer'; Name='Disable Microsoft OneDrive'
        Description='NOT recommended if you rely on OneDrive sync. Included for parity only.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' 'DisableFileSyncNGSC' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='EXP-SYNCNOTIF'; Recommended='Yes'; Category='Windows Explorer'; Name='Disable third-party suggestions/ads in File Explorer'
        Description='Hides "sync provider" and sponsored suggestions in Explorer.'
        Actions=@( New-Action 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'ShowSyncProviderNotifications' 'DWord' 0 1 ) },

    # =========== Microsoft Defender and Microsoft SpyNet ===========
    [PSCustomObject]@{ Id='DEF-SPYNET'; Recommended='Limited'; Category='Microsoft Defender and Microsoft SpyNet'; Name='Disable Microsoft SpyNet membership'
        Description='Opts out of Defender cloud-protection (MAPS) membership and reporting.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'SpynetReporting' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='DEF-SAMPLES'; Recommended='Limited'; Category='Microsoft Defender and Microsoft SpyNet'; Name='Disable submitting data samples to Microsoft'
        Description='Stops Defender from automatically uploading suspicious file samples.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'SubmitSamplesConsent' 'DWord' 2 1 ) },

    # ======================= Search =======================
    [PSCustomObject]@{ Id='SEARCH-BING'; Recommended='Yes'; Category='Search'; Name='Disable extension of Windows search with Bing'
        Description='Keeps Start menu search local-only, no web/Bing results.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'BingSearchEnabled' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='SEARCH-WEBSEARCH'; Recommended='Yes'; Category='Search'; Name='Disable web search from Windows Desktop Search'
        Description='Stops desktop search queries from being sent online.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'DisableWebSearch' 'DWord' 1 0 ) },

    # ======================= Taskbar =======================
    [PSCustomObject]@{ Id='TASKBAR-NEWS'; Recommended='Yes'; Category='Taskbar'; Name='Disable news and interests in the task bar'
        Description='Removes the News and Interests / Widgets feed from the taskbar.'
        Actions=@(
            New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds' 'EnableFeeds' 'DWord' 0 1
            New-Action 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds' 'ShellFeedsTaskbarViewMode' 'DWord' 2 0
        ) },
    [PSCustomObject]@{ Id='TASKBAR-MEETNOW'; Recommended='Limited'; Category='Taskbar'; Name='Disable "Meet Now" in the task bar'
        Description='Removes the Meet Now / chat icon from the taskbar.'
        Actions=@( New-Action 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'HideSCAMeetNow' 'DWord' 1 0 ) },

    # ======================= Miscellaneous =======================
    [PSCustomObject]@{ Id='MISC-REMOTEASSIST'; Recommended='Yes'; Category='Miscellaneous'; Name='Disable remote assistance connections to this computer'
        Description='Prevents others from remotely assisting this PC via Remote Assistance.'
        Actions=@( New-Action 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='MISC-REMOTECONN'; Recommended='No'; Category='Miscellaneous'; Name='Disable remote connections to this computer (RDP)'
        Description='CAUTION: this disables inbound Remote Desktop. Do not apply to a machine you manage remotely without another access path.'
        Actions=@( New-Action 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='MISC-KMS'; Recommended='Limited'; Category='Miscellaneous'; Name='Disable Key Management Service online activation'
        Description='Blocks outbound KMS activation traffic (use only if you activate via other means).'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform' 'NoGenTicket' 'DWord' 1 0 ) },
    [PSCustomObject]@{ Id='MISC-MAPDATA'; Recommended='Limited'; Category='Miscellaneous'; Name='Disable automatic download and update of map data'
        Description='Stops Windows from pre-downloading offline map tiles automatically.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps' 'AutoDownloadAndUpdateMapData' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='MISC-MAPTRAFFIC'; Recommended='Limited'; Category='Miscellaneous'; Name='Disable unsolicited network traffic on the offline maps settings page'
        Description='Stops the Maps settings page from making background network calls just by being opened.'
        Actions=@( New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps' 'AllowUntriggeredNetworkTrafficOnSettingsPage' 'DWord' 0 1 ) },
    [PSCustomObject]@{ Id='MISC-NCSI'; Recommended='No'; Category='Miscellaneous'; Name='Disable Network Connectivity Status Indicator (active probing)'
        Description='NOT generally recommended — breaks the "no internet access" taskbar indicator accuracy. Included for parity only.'
        Actions=@( New-Action 'HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet' 'EnableActiveProbing' 'DWord' 0 1 ) },

    # ======================= Gaming =======================
    [PSCustomObject]@{ Id='GAME-GAMEDVR'; Recommended='Limited'; Category='Gaming'; Name='Disable Xbox Game Bar and Game DVR'
        Description='Turns off background game recording and the Game Bar overlay.'
        Actions=@(
            New-Action 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' 'AppCaptureEnabled' 'DWord' 0 1
            New-Action 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'       'AllowGameDVR'       'DWord' 0 1
        ) }
)

# ---------------------------------------------------------------------------
# Registry / service helpers
# ---------------------------------------------------------------------------
function Set-RegistryAction {
    param($Action, [bool]$TurnOn)
    $value = if ($TurnOn) { $Action.On } else { $Action.Off }

    if ($Action.Type -eq 'Service') {
        try {
            $startType = if ($TurnOn) { 'Disabled' } else { 'Automatic' }
            Set-Service -Name $Action.Path -StartupType $startType -ErrorAction Stop
            if ($TurnOn) { Stop-Service -Name $Action.Path -Force -ErrorAction SilentlyContinue }
            return $true
        } catch { return $false }
    }

    try {
        if (-not (Test-Path $Action.Path)) {
            New-Item -Path $Action.Path -Force | Out-Null
        }
        New-ItemProperty -Path $Action.Path -Name $Action.Name -Value $value -PropertyType $Action.Type -Force | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Get-ActionState {
    # Returns $true (On/hardened), $false (Off/default), or $null (unknown/not set)
    param($Action)

    if ($Action.Type -eq 'Service') {
        try {
            $svc = Get-Service -Name $Action.Path -ErrorAction Stop
            $startType = (Get-CimInstance Win32_Service -Filter "Name='$($Action.Path)'").StartMode
            return ($startType -eq 'Disabled')
        } catch { return $null }
    }

    try {
        $current = (Get-ItemProperty -Path $Action.Path -Name $Action.Name -ErrorAction Stop).($Action.Name)
        if ($null -eq $current) { return $null }
        return ($current -eq $Action.On)
    } catch {
        return $null
    }
}

function Get-SettingState {
    param($Setting)
    $states = $Setting.Actions | ForEach-Object { Get-ActionState $_ }
    if ($states -contains $false) { return $false }
    if ($states -notcontains $null -and $states.Count -gt 0) { return $true }
    return $null
}

function Apply-Setting {
    param($Setting, [bool]$TurnOn)
    $ok = $true
    foreach ($a in $Setting.Actions) {
        if (-not (Set-RegistryAction -Action $a -TurnOn $TurnOn)) { $ok = $false }
    }
    return $ok
}

# ---------------------------------------------------------------------------
# Silent / provisioning mode - apply a JSON profile with no UI
# JSON profile format: { "PRIV-ADID": true, "AI-RECALL": true, ... }
# ---------------------------------------------------------------------------
if ($Silent) {
    if (-not $Import -or -not (Test-Path $Import)) {
        Write-Error "Silent mode requires a valid -Import <profile.json> path."
        exit 1
    }
    $profileData = Get-Content $Import -Raw | ConvertFrom-Json
    $log = @()
    foreach ($s in $Settings) {
        if ($profileData.PSObject.Properties.Name -contains $s.Id) {
            $want = [bool]$profileData.$($s.Id)
            $result = Apply-Setting -Setting $s -TurnOn $want
            $log += "[{0}] {1} -> {2}: {3}" -f $s.Id, $s.Name, $(if ($want) {'ON'} else {'OFF'}), $(if ($result) {'OK'} else {'FAILED'})
        }
    }
    $logPath = Join-Path $env:TEMP "PC-Hardening-Tool_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    $log | Out-File -FilePath $logPath -Encoding UTF8
    Write-Output "Applied profile '$Import'. Log: $logPath"
    exit 0
}

# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = "PC Hardening Provisioning Tool"
$form.Size = New-Object System.Drawing.Size(1300, 780)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24)
$form.ForeColor = [System.Drawing.Color]::White
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# Top toolbar
$toolbar = New-Object System.Windows.Forms.Panel
$toolbar.Dock = 'Top'
$toolbar.Height = 46
$toolbar.BackColor = [System.Drawing.Color]::FromArgb(32, 32, 32)
$form.Controls.Add($toolbar)

function New-ToolButton {
    param($Text, $X)
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $Text
    $btn.Location = New-Object System.Drawing.Point($X, 8)
    $btn.Size = New-Object System.Drawing.Size(140, 30)
    $btn.FlatStyle = 'Flat'
    $btn.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
    $btn.ForeColor = [System.Drawing.Color]::White
    return $btn
}

$btnRefresh   = New-ToolButton "Refresh Status" 10
$btnSelectAll = New-ToolButton "Select All" 160
$btnSelectRec = New-ToolButton "Select Recommended" 310
$btnSelectNone= New-ToolButton "Select None" 470
$btnApply     = New-ToolButton "Apply Checked" 620
$btnRevert    = New-ToolButton "Revert Checked" 770
$btnExport    = New-ToolButton "Export Profile" 920
$btnImport    = New-ToolButton "Import Profile" 1070
$toolbar.Controls.AddRange(@($btnRefresh,$btnSelectAll,$btnSelectRec,$btnSelectNone,$btnApply,$btnRevert,$btnExport,$btnImport))

# Status bar
$statusBar = New-Object System.Windows.Forms.StatusStrip
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Text = "Ready. $($Settings.Count) settings loaded. Not yet elevated-checked / refreshed."
$statusBar.Items.Add($statusLabel) | Out-Null
$form.Controls.Add($statusBar)

# Filter box, docked under the toolbar
$searchPanel = New-Object System.Windows.Forms.Panel
$searchPanel.Dock = 'Top'
$searchPanel.Height = 30
$searchPanel.BackColor = [System.Drawing.Color]::FromArgb(28,28,28)
$lblSearch2 = New-Object System.Windows.Forms.Label
$lblSearch2.Text = "Filter:"
$lblSearch2.Location = New-Object System.Drawing.Point(10,6)
$lblSearch2.AutoSize = $true
$lblSearch2.ForeColor = [System.Drawing.Color]::Gainsboro
$txtFilter = New-Object System.Windows.Forms.TextBox
$txtFilter.Location = New-Object System.Drawing.Point(55,3)
$txtFilter.Size = New-Object System.Drawing.Size(300,22)
$searchPanel.Controls.AddRange(@($lblSearch2,$txtFilter))
$form.Controls.Add($searchPanel)

# Main ListView (grouped by category, with checkboxes)
$listView = New-Object System.Windows.Forms.ListView
$listView.Dock = 'Fill'
$listView.View = 'Details'
$listView.CheckBoxes = $true
$listView.FullRowSelect = $true
$listView.GridLines = $true
$listView.BackColor = [System.Drawing.Color]::FromArgb(18,18,18)
$listView.ForeColor = [System.Drawing.Color]::White
$listView.Columns.Add("Category", 200) | Out-Null
$listView.Columns.Add("Recommended", 100) | Out-Null
$listView.Columns.Add("Setting", 320) | Out-Null
$listView.Columns.Add("Current State", 110) | Out-Null
$listView.Columns.Add("Description", 560) | Out-Null
$form.Controls.Add($listView)
$listView.BringToFront()

# Alternating background tint per category, so rows for the same category
# are visually banded even though the Category is "just" a column (WinForms
# ListView group headers render inconsistently across Windows themes, so a
# column is the reliable choice).
$categoryColors = @(
    [System.Drawing.Color]::FromArgb(18,18,18),
    [System.Drawing.Color]::FromArgb(26,26,30)
)
$categories = @()
foreach ($s in $Settings) { if ($categories -notcontains $s.Category) { $categories += $s.Category } }
$categoryColorMap = @{}
for ($i = 0; $i -lt $categories.Count; $i++) { $categoryColorMap[$categories[$i]] = $categoryColors[$i % 2] }

# Populate items, tag = setting Id. Column order: Category, Recommended, Setting, State, Description
foreach ($s in $Settings) {
    $item = New-Object System.Windows.Forms.ListViewItem($s.Category)
    $item.SubItems.Add($s.Recommended) | Out-Null
    $item.SubItems.Add($s.Name) | Out-Null
    $item.SubItems.Add("Unknown") | Out-Null
    $item.SubItems.Add($s.Description) | Out-Null
    $item.Tag = $s.Id
    $item.UseItemStyleForSubItems = $false
    $rowColor = $categoryColorMap[$s.Category]
    $item.BackColor = $rowColor
    foreach ($sub in $item.SubItems) { $sub.BackColor = $rowColor; $sub.ForeColor = [System.Drawing.Color]::White }
    $recColor = switch ($s.Recommended) {
        'Yes'     { [System.Drawing.Color]::LightGreen }
        'Limited' { [System.Drawing.Color]::Orange }
        'No'      { [System.Drawing.Color]::FromArgb(255,120,120) }
        default   { [System.Drawing.Color]::White }
    }
    $item.SubItems[1].ForeColor = $recColor
    $listView.Items.Add($item) | Out-Null
}

function Get-SettingById($id) { return $Settings | Where-Object { $_.Id -eq $id } }

function Refresh-Status {
    $statusLabel.Text = "Refreshing current registry state..."
    [System.Windows.Forms.Application]::DoEvents()
    foreach ($item in $listView.Items) {
        $s = Get-SettingById $item.Tag
        $state = Get-SettingState $s
        $item.SubItems[3].Text = if ($null -eq $state) { "Not Set" } elseif ($state) { "Hardened" } else { "Default" }
        $item.SubItems[3].ForeColor = if ($null -eq $state) { [System.Drawing.Color]::Gray } elseif ($state) { [System.Drawing.Color]::LightGreen } else { [System.Drawing.Color]::Orange }
        $item.Checked = [bool]$state
    }
    $statusLabel.Text = "Status refreshed for $($listView.Items.Count) settings."
}

$btnRefresh.Add_Click({ Refresh-Status })

$btnSelectAll.Add_Click({ foreach ($item in $listView.Items) { $item.Checked = $true } })
$btnSelectRec.Add_Click({
    foreach ($item in $listView.Items) {
        $s = Get-SettingById $item.Tag
        $item.Checked = ($s.Recommended -eq 'Yes')
    }
    $statusLabel.Text = "Selected all 'Recommended: Yes' settings. Review, then click Apply Checked."
})
$btnSelectNone.Add_Click({ foreach ($item in $listView.Items) { $item.Checked = $false } })

$btnApply.Add_Click({
    $checkedItems = $listView.CheckedItems
    if ($checkedItems.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No settings are checked.", "Nothing to apply") | Out-Null; return }
    $confirm = [System.Windows.Forms.MessageBox]::Show("Apply hardening to $($checkedItems.Count) checked setting(s)?", "Confirm Apply", 'YesNo', 'Question')
    if ($confirm -ne 'Yes') { return }
    $ok = 0; $fail = 0
    foreach ($item in $checkedItems) {
        $s = Get-SettingById $item.Tag
        if (Apply-Setting -Setting $s -TurnOn $true) { $ok++ } else { $fail++ }
    }
    $statusLabel.Text = "Applied: $ok succeeded, $fail failed."
    Refresh-Status
})

$btnRevert.Add_Click({
    $checkedItems = $listView.CheckedItems
    if ($checkedItems.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No settings are checked.", "Nothing to revert") | Out-Null; return }
    $confirm = [System.Windows.Forms.MessageBox]::Show("Revert $($checkedItems.Count) checked setting(s) to Windows default?", "Confirm Revert", 'YesNo', 'Question')
    if ($confirm -ne 'Yes') { return }
    $ok = 0; $fail = 0
    foreach ($item in $checkedItems) {
        $s = Get-SettingById $item.Tag
        if (Apply-Setting -Setting $s -TurnOn $false) { $ok++ } else { $fail++ }
    }
    $statusLabel.Text = "Reverted: $ok succeeded, $fail failed."
    Refresh-Status
})

$btnExport.Add_Click({
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = "JSON profile (*.json)|*.json"
    $sfd.FileName = "HardeningProfile.json"
    if ($sfd.ShowDialog() -eq 'OK') {
        $profileObj = [ordered]@{}
        foreach ($item in $listView.Items) { $profileObj[$item.Tag] = [bool]$item.Checked }
        ($profileObj | ConvertTo-Json) | Out-File -FilePath $sfd.FileName -Encoding UTF8
        $statusLabel.Text = "Profile exported to $($sfd.FileName)"
    }
})

$btnImport.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = "JSON profile (*.json)|*.json"
    if ($ofd.ShowDialog() -eq 'OK') {
        $data = Get-Content $ofd.FileName -Raw | ConvertFrom-Json
        foreach ($item in $listView.Items) {
            if ($data.PSObject.Properties.Name -contains $item.Tag) {
                $item.Checked = [bool]$data.$($item.Tag)
            }
        }
        $statusLabel.Text = "Profile imported from $($ofd.FileName). Review selections, then click Apply Checked."
    }
})

$txtFilter.Add_TextChanged({
    $filter = $txtFilter.Text.ToLower()
    foreach ($item in $listView.Items) {
        $s = Get-SettingById $item.Tag
        $match = ($s.Name.ToLower().Contains($filter)) -or ($s.Description.ToLower().Contains($filter)) -or ($s.Category.ToLower().Contains($filter)) -or ($s.Recommended.ToLower().Contains($filter))
        if ($match -or $filter -eq '') {
            $recColor = switch ($s.Recommended) {
                'Yes'     { [System.Drawing.Color]::LightGreen }
                'Limited' { [System.Drawing.Color]::Orange }
                'No'      { [System.Drawing.Color]::FromArgb(255,120,120) }
                default   { [System.Drawing.Color]::White }
            }
            $item.SubItems[0].ForeColor = [System.Drawing.Color]::White
            $item.SubItems[1].ForeColor = $recColor
            $item.SubItems[2].ForeColor = [System.Drawing.Color]::White
            $item.SubItems[4].ForeColor = [System.Drawing.Color]::White
        } else {
            $dim = [System.Drawing.Color]::FromArgb(65,65,65)
            foreach ($sub in $item.SubItems) { $sub.ForeColor = $dim }
        }
    }
})

# Initial load
$form.Add_Shown({ Refresh-Status })

[void]$form.ShowDialog()
