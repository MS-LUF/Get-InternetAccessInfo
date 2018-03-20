#
# Created by: lucas.cueff[at]lucas-cueff.com
#
# v0.1 : initial release 
# Released on: 03/2018
#
#'(c) 2018 lucas-cueff.com - Distributed under Artistic Licence 2.0 (https://opensource.org/licenses/artistic-license-2.0).'

<#
	.SYNOPSIS 
	simple PowerShell module to get all information regarding the way your endpoint is connected to internet

	.DESCRIPTION
    multiple functions are used to retrieve all information regarding your external network access
    usefull on a unknown host to find how the external network access is working
    informations retrieved :
    - network status from network location awareness / network location manager
    - settings of NLA service
    - all settings (proxy mainly) set for each network connections
    - winhttp settings
    - internet settings
    - wpad settings
    	
	.EXAMPLE
	C:\PS> import-module Get-InternetAccessInfo.psm1
#>
function Get-NLAInfo {
<#
	.SYNOPSIS 
    function used to retrieve Network Location Awareness information

    .DESCRIPTION
    Network location awareness automates several network test (icmp, dns, http) to detect the current network environment (type, category, connectivity)
	
    .PARAMETER NetworkStatus 
    -NetworkStatus string from the following list : 'AllNetworks','ConnectedNetworks','DisconnectedNetworks'
    mandatory
    type of network interface you want to check : all, only the connected ones, only the disconnected ones.
    
	.OUTPUTS
        TypeName : System.Management.Automation.PSCustomObject

        Name                 MemberType   Definition
        ----                 ----------   ----------
        Equals               Method       bool Equals(System.Object obj)
        GetHashCode          Method       int GetHashCode()
        GetType              Method       type GetType()
        ToString             Method       string ToString()
        Domain Type          NoteProperty string Domain Type=NLM_DOMAIN_TYPE_NON_DOMAIN_NETWORK
        Network Category     NoteProperty string Network Category=NLM_NETWORK_CATEGORY_PUBLIC
        Network Connectivity NoteProperty Object[] Network Connectivity=System.Object[]
        Network Name         NoteProperty string Network Name=XYZ
       
    .EXAMPLE
    Get all information from NLA for the connected network interfaces
    C:\PS> Get-NLAInfo -NetworkStatus ConnectedNetworks
#>  
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true)] 
        [ValidateSet('AllNetworks','ConnectedNetworks','DisconnectedNetworks')]
            [string]$NetworkStatus
    )
    $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID('DCB00C01-570F-4A9B-8D69-199FDBA5723B'))
    $NLM_ENUM_NETWORK_CONNECTED=1
    $NLM_ENUM_NETWORK_DISCONNECTED=2
    $NLM_ENUM_NETWORK_ALL=3
    $NetCategories = @{
        0x00="NLM_NETWORK_CATEGORY_PUBLIC";
        0x01="NLM_NETWORK_CATEGORY_PRIVATE";
        0x02="NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED"
    }
    $DomainTypes = @{
        0x00="NLM_DOMAIN_TYPE_NON_DOMAIN_NETWORK";
        0x01="NLM_DOMAIN_TYPE_DOMAIN_NETWORK";
        0x02="NLM_DOMAIN_TYPE_DOMAIN_AUTHENTICATED"
    }
    $NLMConnectivity = @{
        0x0000="NLM_CONNECTIVITY_DISCONNECTED";
        0x0001="NLM_CONNECTIVITY_IPV4_NOTRAFFIC";
        0x0002="NLM_CONNECTIVITY_IPV6_NOTRAFFIC";
        0x0010="NLM_CONNECTIVITY_IPV4_SUBNET";
        0x0020="NLM_CONNECTIVITY_IPV4_LOCALNETWORK";
        0x0040="NLM_CONNECTIVITY_IPV4_INTERNET";
        0x0100="NLM_CONNECTIVITY_IPV6_SUBNET";
        0x0200="NLM_CONNECTIVITY_IPV6_LOCALNETWORK";
        0x0400="NLM_CONNECTIVITY_IPV6_INTERNET"
    }
    Switch ($NetworkStatus) {
        'AllNetworks' {$Networks = $NetworkListManager.GetNetworks($NLM_ENUM_NETWORK_ALL)}
        'ConnectedNetworks' {$Networks = $NetworkListManager.GetNetworks($NLM_ENUM_NETWORK_CONNECTED)}
        'DisconnectedNetworks' {$Networks = $NetworkListManager.GetNetworks($NLM_ENUM_NETWORK_DISCONNECTED)} 
    }
    $AllNetworkObjects = @()
    foreach($Network in $Networks){
        $AllConnectivityStatus = @()
        foreach($Key in $NLMConnectivity.Keys){
            $KeyBand = $Key -band $Network.GetConnectivity()
            if($KeyBand -gt 0){
                $AllConnectivityStatus += $NLMConnectivity.Get_Item($KeyBand)
            }
        }
        $NetworkObject = [PSCustomObject]@{
            'Network Name' = $Network.GetName()
            'Domain Type' = $DomainTypes.Get_Item($Network.GetDomainType())
            'Network Category' =  $NetCategories.Get_Item($Network.GetCategory())
            'Network Connectivity' = $AllConnectivityStatus
        }
        $AllNetworkObjects += $NetworkObject
    }
    return $AllNetworkObjects
}

Function Get-WinHttpProxy {
<#
	.SYNOPSIS 
    function used to retrieve proxy set for local machine web layer aka winhttp

    .DESCRIPTION
    retrieve proxy set for local machine web layer aka winhttp
	    
	.OUTPUTS
        TypeName : System.Management.Automation.PSCustomObject

        Name                      MemberType   Definition
        ----                      ----------   ----------
        Equals                    Method       bool Equals(System.Object obj)
        GetHashCode               Method       int GetHashCode()
        GetType                   Method       type GetType()
        ToString                  Method       string ToString()
        Winhttp proxy             NoteProperty string Winhttp proxy=Direct Access
        Winhttp proxy bypass list NoteProperty string Winhttp proxy bypass list=(none)
       
    .EXAMPLE
    Get all information about winhttp proxy
    C:\PS> Get-WinHttpProxy
#>              
    [CmdletBinding()]            
    Param()                       
       try {
           $Conprx = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name WinHttpSettings).WinHttpSettings
       } catch {
            $Conprx = $null
       } finally {
            if ($Conprx) {
            $proxylength = $Conprx[12]            
                if ($proxylength -gt 0) {            
                    $proxy = -join ($Conprx[(12+3+1)..(12+3+1+$proxylength-1)] | ForEach-Object {([char]$_)})            
                    $bypasslength = $Conprx[(12+3+1+$proxylength)]            
                    if ($bypasslength -gt 0) {            
                        $bypasslist = -join ($Conprx[(12+3+1+$proxylength+3+1)..(12+3+1+$proxylength+3+1+$bypasslength)] | ForEach-Object {([char]$_)})            
                    } else {            
                        $bypasslist = '(none)'            
                    }            
                    $result = [PSCustomObject]@{
                        "Winhttp proxy" = $proxy
                        "Winhttp proxy bypass list" = $bypasslist
                    }                 
                } else {                                
                    $result = [PSCustomObject]@{
                        "Winhttp proxy" = "Direct Access"
                        "Winhttp proxy bypass list" = "(none)"
                    } 
                }
            } else {
                $result = [PSCustomObject]@{
                    "Winhttp proxy" = "error - not able to read registry entry"
                    "Winhttp proxy bypass list" = "error - not able to read registry entry"
                } 
            }
       }
       return $result                  
}

Function Get-UserconnectionProxy {
<#
	.SYNOPSIS 
    function used to retrieve proxy information for all network connection used by the current user context

    .DESCRIPTION
    retrieve proxy information for all network connection used by the current user context
	    
	.OUTPUTS
        TypeName : System.Management.Automation.PSCustomObject

        Name                       MemberType   Definition
        ----                       ----------   ----------
        Equals                     Method       bool Equals(System.Object obj)
        GetHashCode                Method       int GetHashCode()
        GetType                    Method       type GetType()
        ToString                   Method       string ToString()
        User proxy                 NoteProperty string User proxy=proxy.cc.dddddd.io:8080
        User proxy bypass list     NoteProperty string User proxy bypass list=test;<local>)
        User proxy connection name NoteProperty string User proxy connection name=SavedLegacySettings
        User proxy PAC             NoteProperty string User proxy PAC=http://xxxxxx.yy.zzzz.io:8080/

    .EXAMPLE
    Get all information about user connections 
    C:\PS> Get-UserconnectionProxy
#>  
    [CmdletBinding()]            
    Param()                       
    try {
        $Conprx = Get-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
    } catch {
        $Conprx = $null
    } finally {
        $results = @()
        if ($Conprx) {
                $ConRegValues = $Conprx.GetValueNames()
            foreach ($value in $ConRegValues) {
                $result = [PSCustomObject]@{
                    "User proxy connection name" = $value
                }
                $tmpvalue = $Conprx.GetValue($value)
                $pacentr = $null
                for($i=0;$i -le $tmpvalue.length;$i++){
                    if (($tmpvalue[$i] -eq 36) -or ($tmpvalue[$i] -eq 41)) {
                        $pacentr = $i
                        break
                    }
                }
                if ($pacentr) {        
                    $proxypac = -join ($tmpvalue[($pacentr+3+1)..($pacentr+3+1+$tmpvalue.length-1)] | ForEach-Object {([char]$_)})
                    $Result | add-member -MemberType NoteProperty -Name "User proxy PAC" -Value $proxypac                  
                } else {
                    $Result | add-member -MemberType NoteProperty -Name "User proxy PAC" -Value "none" 
                }
                $proxylength = $tmpvalue[12]            
                if ($proxylength -gt 0) {            
                    $proxy = -join ($tmpvalue[(12+3+1)..(12+3+1+$proxylength-1)] | ForEach-Object {([char]$_)})            
                    $bypasslength = $tmpvalue[(12+3+1+$proxylength)]            
                    if ($bypasslength -gt 0) {            
                        $bypasslist = -join ($tmpvalue[(12+3+1+$proxylength+3+1)..(12+3+1+$proxylength+3+1+$bypasslength)] | ForEach-Object {([char]$_)})            
                    } else {            
                        $bypasslist = '(none)'            
                    }            
                    $Result | add-member -MemberType NoteProperty -Name "User proxy" -Value $proxy
                    $Result | add-member -MemberType NoteProperty -Name "User proxy bypass list" -value $bypasslist                 
                } else {            
                    $Result | add-member -MemberType NoteProperty -Name "User proxy" -value "Direct Access"
                    $Result | add-member -MemberType NoteProperty -Name "User proxy bypass list" -value "(none)"      
                }
                $results += $result
            }
        } else {
            $result = [PSCustomObject]@{
                "User connection proxy" = "error - not able to read registry entry"
            }
            $results += $result
        }
    }
    return $results
}

Function Get-NLAServiceInfo {
<#
	.SYNOPSIS 
    function used to retrieve windows service paramareters for all NLA service

    .DESCRIPTION
    function used to retrieve windows service paramareters for all NLA service :
    - DNS, HTTP endpoint used for test, IPV4 and IPV6 endpoint used for test
	    
	.OUTPUTS
        TypeName : System.Management.Automation.PSCustomObject

        Name                         MemberType   Definition
        ----                         ----------   ----------
        Equals                       Method       bool Equals(System.Object obj)
        GetHashCode                  Method       int GetHashCode()
        GetType                      Method       type GetType()
        ToString                     Method       string ToString()
        NLA Check Disabled By Policy NoteProperty bool NLA Check Disabled By Policy=False
        NLA Service Settings         NoteProperty hashtable NLA Service Settings=System.Collections.Hashtable

    .EXAMPLE
    Get all information about NLA service parameters 
    C:\PS> Get-NLAServiceInfo
#> 
    [CmdletBinding()]            
    Param()  
    $NLASettings=@{}
    try {
        $NLASVCSettings = Get-Item "hklm:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet"
    } catch {
        $NLASVCSettings = $null
    } finally {
        if ($NLASVCSettings) {
            $SvcRegValues = $NLASVCSettings.GetValueNames()
        }
        foreach ($value in $SvcRegValues) {
            $NLASettings.add($value,$NLASVCSettings.GetValue($value))
        }
    }
    try {
        $NLAPolicyKey = Get-Item "hklm:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator"
        $NLAPolicyIndicatorValue = $NLAPolicyKey.GetValue("EnableActiveProbing")
    } catch {
        $NLAPolicyKey = $null
    } Finally {
        if ($NLAPolicyIndicatorValue -eq 0) {
            $NLACheckDisabledByPolicy = $true
        } Else {
            $NLACheckDisabledByPolicy = $false
        }
    }
    $SettingsObject = [PSCustomObject]@{
        'NLA Service Settings' = $NLASettings
        'NLA Check Disabled By Policy' = $NLACheckDisabledByPolicy
    }
    return $SettingsObject
}

Function Get-InternetAccessInfo {
<#
	.SYNOPSIS 
    main function calling all other functions available in the module do build a global summary of all available information regarding the internet access of the computer/user

    .DESCRIPTION
    main function calling all other functions available in the module do build a global summary of all available information regarding the internet access of the computer/user
	    
	.OUTPUTS
        TypeName : System.Management.Automation.PSCustomObject

        Name              MemberType   Definition
        ----              ----------   ----------
        Equals            Method       bool Equals(System.Object obj)
        GetHashCode       Method       int GetHashCode()
        GetType           Method       type GetType()
        ToString          Method       string ToString()
        Internet settings NoteProperty System.Management.Automation.PSCustomObject Internet settings=@{User Proxy=False; Use...
        NLA               NoteProperty Object[] NLA=System.Object[]
        NLA service       NoteProperty System.Management.Automation.PSCustomObject NLA service=@{NLA Service Settings=System...
        User connections  NoteProperty Object[] User connections=System.Object[]
        Winhttp           NoteProperty System.Management.Automation.PSCustomObject Winhttp=@{Winhttp proxy=Direct Access; Wi...

    .EXAMPLE
    Get all information about current user/machine internet access 
    C:\PS> Get-InternetAccessInfo
#>
    [CmdletBinding()]            
    Param()  
    $Result = [PSCustomObject]@{
        "NLA" = (Get-NLAInfo -NetworkStatus 'ConnectedNetworks')
        "NLA service"= Get-NLAServiceInfo
        "Winhttp" = Get-WinHttpProxy
        "User connections" = Get-UserconnectionProxy
        "Internet settings" = Get-UserInternetSettings
    }
    return $Result
}

Function Get-UserInternetSettings {
<#
	.SYNOPSIS 
    function used to get : 
    - all information regarding your basic internet settings used by Internet Explorer/Edge or third party browser like Goole Chrome/Chromium
    - wpad settings

    .DESCRIPTION
    function used to get : 
    - all information regarding your basic internet settings used by Internet Explorer/Edge or third party browser like Goole Chrome/Chromium
    - wpad settings
	    
	.OUTPUTS
        TypeName : System.Management.Automation.PSCustomObject

        Name                      MemberType   Definition
        ----                      ----------   ----------
        Equals                    Method       bool Equals(System.Object obj)
        GetHashCode               Method       int GetHashCode()
        GetType                   Method       type GetType()
        ToString                  Method       string ToString()
        Force Disable WPAD        NoteProperty bool Force Disable WPAD=False
        User Proxy                NoteProperty bool User Proxy=False
        User Proxy Autoconfig URL NoteProperty object User Proxy Autoconfig URL=null
        User Proxy HTTP1.1        NoteProperty bool User Proxy HTTP1.1=False
        User Proxy Migrate        NoteProperty bool User Proxy Migrate=True
        User Proxy server         NoteProperty string User Proxy server=proxy.xx.yyyyyyyyyyyyyyy.io:8080
        User Proxy WPAD           NoteProperty bool User Proxy WPAD=False
        WPAD Service Status       NoteProperty ServiceControllerStatus WPAD Service Status=Running

    .EXAMPLE
    Get all information regarding your basic internet settings 
    C:\PS> Get-UserInternetSettings
#>
    [CmdletBinding()]            
    Param()  
    $Results=[PSCustomObject]@{}
    try {
        $InternetSettings = Get-Item "hkcu:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    } catch {
        $InternetSettings = $null
    } finally {
        if ($InternetSettings) {
            try {
                [bool]$booltmp = $InternetSettings.GetValue("ProxyEnable")
            } catch {
                $booltmp = $false
            } finally {
                $Results | add-member -MemberType NoteProperty -Name "User Proxy" -Value $booltmp
            }
            try {
                [bool]$booltmp2 = $InternetSettings.GetValue("ProxyHTTP1.1")
            } catch {
                $booltmp2 = $false
            } finally {
                $Results | add-member -MemberType NoteProperty -Name "User Proxy HTTP1.1" -Value $booltmp2
            }
            $Results | add-member -MemberType NoteProperty -Name "User Proxy server" -Value $InternetSettings.GetValue("ProxyServer")
            $Results | add-member -MemberType NoteProperty -Name "User Proxy Autoconfig URL" -Value $InternetSettings.GetValue("AutoConfigURL")
            try {
                [bool]$booltmp3 = $InternetSettings.GetValue("AutoDetect")
            } catch {
                $booltmp3 = $false
            } finally {
                $Results | add-member -MemberType NoteProperty -Name "User Proxy WPAD" -Value $booltmp3
            }
            try {
                [bool]$booltmp4 = $InternetSettings.GetValue("MigrateProxy")
            } catch {
                $booltmp4 = $false
            } finally {
                $Results | add-member -MemberType NoteProperty -Name "User Proxy Migrate" -Value $booltmp4
            }
        }
    }
    try {
        $WPADSettings = Get-Item "hkcu:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\WPAD"
    } catch {
        $WPADSettings = $null
    } finally {
        if ($WPADSettings.GetValue("WpadOverride")) {
            [bool]$booltmp5 = $WPADSettings.GetValue("WpadOverride")
            $Results | add-member -MemberType NoteProperty -Name "Force Disable WPAD" -Value $booltmp5
        } Else {
            $Results | add-member -MemberType NoteProperty -Name "Force Disable WPAD" -Value $false
        }
    }
    try {
        $WPADServiceStatus = (Get-Service WinHttpAutoProxySvc).status
    } catch {
        $WPADServiceStatus = $null
    } finally {
        If ($WPADServiceStatus) {
            $Results | add-member -MemberType NoteProperty -Name "WPAD Service Status" -Value $WPADServiceStatus
        } else {
            $Results | add-member -MemberType NoteProperty -Name "WPAD Service Status" -Value "N/A"
        }
    }
    return $results
}

Export-ModuleMember -Function Get-NLAInfo,Get-NLAServiceInfo,Get-UserconnectionProxy,Get-WinHttpProxy,Get-InternetAccessInfo,Get-UserInternetSettings