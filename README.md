![image](https://www.lucas-cueff.com/files/gallery.png)
# Get-InternetAccessInfo
Simple PowerShell module to get all information regarding the way your endpoint is connected to internet.

Multiple functions are used to retrieve all information regarding your external network access.
Could be usefull on a unknown host to find how the external network access is working or was working (artefact of previous proxy conf are also managed)
informations retrieved :
- network status from network location awareness / network location manager
- settings of NLA service
- all settings (proxy mainly) set for each network connections
- winhttp settings
- internet settings
- wpad settings

(c) 2018-2019 lucas-cueff.com Distributed under Artistic Licence 2.0 (https://opensource.org/licenses/artistic-license-2.0).

## install Get-InternetAccessInfo from PowerShell Gallery repository
You can easily install it from powershell gallery repository
https://www.powershellgallery.com/packages/Get-InternetAccessInfo/
using a simple powershell command and an internet access :-) 
```
	Install-Module -Name Get-InternetAccessInfo
```
## import module from PowerShell 
```	
	.EXAMPLE
	C:\PS> import-module Get-InternetAccessInfo.psd1
```
## module content
###  Get-NLAInfo function
```
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
```
###  Get-WinHttpProxy function
```
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
```
###  Get-UserconnectionProxy function
```
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
```
###  Get-NLAServiceInfo function
```
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
```
###  Get-InternetAccessInfo function
```
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
```
###  Get-UserInternetSettings function
```
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
```
