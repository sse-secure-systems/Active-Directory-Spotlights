<#
.SYNOPSIS
  Script to enumerate Active Directory Trusts


.PARAMETER ShowGraphNotation
    Displays a textual graph representation at the end.
    This output can be pasted to a text file and displayed in a graph-like representation, e.g. with the Linux tool 'graph-easy', as follows:
        graph-easy <TextFileWithGraphOutput.txt>
    
.PARAMETER IncludeReason
    Displays why a cerain trust characteristic was displayed with the given value

.OUTPUTS
  None

.NOTES
  Version:        1.0
  Author:         Carsten Sandker (@0xcsandker)
  Creation Date:  17 Jul 2021
  Purpose/Change: Initial script development
  
.EXAMPLE
  .\Enum-ADTrusts.ps1
#>

#---------------------------------------------------------[Param Definition]--------------------------------------------------------

[CmdletBinding()]

PARAM ( 
    [Switch]
    $IncludeReason = $false,
    [Switch]
    $ShowGraphNotation = $false,
    [String]
    $Domain
)

#----------------------------------------------------------[Declarations]----------------------------------------------------------

## Script Version
$sScriptVersion = "1.0"

## Globals
$global:gTrustTree = @{}
$global:gUnreachableDomains = @{}

enum TrustDirection {
    InBound = 1
    OutBound = 2
    BiDirectional = 3
}

enum TrustTypeID {
    DOWNLEVEL = 0x00000001
    UPLEVEL = 0x00000002
    MIT = 0x00000003
    TRUST_TYPE_DCE = 0x00000004
}

[Flags()] enum TrustAttributes {
    TRUST_ATTRIBUTE_NON_TRANSITIVE = 0x00000001
    TRUST_ATTRIBUTE_UPLEVEL_ONLY = 0x00000002
    TRUST_ATTRIBUTE_QUARANTINED_DOMAIN = 0x00000004
    TRUST_ATTRIBUTE_FOREST_TRANSITIVE = 0x00000008
    TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x00000010
    TRUST_ATTRIBUTE_WITHIN_FOREST = 0x00000020
    TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL = 0x00000040
    TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION = 0x00000080
    TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION = 0x00000200
    TRUST_ATTRIBUTE_PIM_TRUST = 0x00000400
    TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION = 0x00000800
}

[Flags()] enum SupportedEncryptionTypes {
    DES_CBC_CRC = 0x01
    DES_CBC_MD5 = 0x02 
    RC4_HMAC = 0x04
    AES128_CTS_HMAC_SHA1_96 = 0x08
    AES256_CTS_HMAC_SHA1_96 = 0x10 
}


## equivalent to https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectory.trusttype?view=net-5.0
enum TrustFlavor {
    TreeRoot = 0
    ParentChild = 1
    CrossLink = 2 ## aka "Shortcut"
    External = 3
    Forest = 4
    Kerberos = 5 ## aka "Realm"
    Unknown = 6
}

$gTrustAttributeMap = @{
    "TRUST_DIRECTION" = "trustdirection";
    "TRUST_PARTNER" = "trustpartner";
    "TRUST_ATTRIBUTES" = "trustAttributes";
    "TRUST_TYPE_ID" = "trustType";
    "TRUST_SUPPORTED_ENCRYPTION_TYPES" = "msds-supportedencryptiontypes";
}

#-----------------------------------------------------------[Functions]------------------------------------------------------------

Function TrustPropertyTrustDirection {
    Param(
        [Object]
        $TrustProperties
    )
    Process {
        if( $TrustProperties -ne $null ){
            $trustDirectionID = $TrustProperties['TRUST_DIRECTION']
            $trustDirection = [TrustDirection].GetEnumName($trustDirectionID)
            return $trustDirection
        }
        else {
            return "Unknown"
        }
    }
}

Function TrustPropertyTrustFlavor {
    Param(
        [Object]
        $TrustProperties,
        [String]
        $TrustNode,
        [String]
        $TrustPartner
    )
    Process {
        ## Check if TrustFlavor already saved in $gTrustTree
        if( 
            ( $gTrustTree.Keys -Contains $TrustNode ) -AND
            ( $gTrustTree[$TrustNode][$TrustPartner].Keys -Contains "TRUST_FLAVOR" )
        ){
            $trustFlavor = $gTrustTree[$TrustNode][$TrustPartner]["TRUST_FLAVOR"]
            return $trustFlavor
        }
        else{
            ## If not contained in $gTrustTree, query for it
            if( $TrustProperties -ne $null ){
                $trustAttributes = $TrustProperties['TRUST_ATTRIBUTES']
                $trustTypeID = $TrustProperties['TRUST_TYPE_ID']
                $trustFlavor = GetTrustFlavor -requestingNodeName $TrustNode -requestedNodeName $TrustPartner -trustTypeID $trustTypeID -trustAttributes $trustAttributes
                try {
                    $gTrustTree[$TrustNode][$TrustPartner].Add("TRUST_FLAVOR", $trustFlavor)
                } Catch {}
                return $trustFlavor
            }else {
                Try{
                    $gTrustTree[$TrustNode][$TrustPartner].Add("TRUST_FLAVOR", [TrustFlavor]::Unknown)
                }Catch {}
                return [TrustFlavor]::Unknown
            }
        }
    }
}

Function TrustPropertyAuthenticationLevel {
    Param(
        [Object]
        $TrustProperties
    )
    Process {
        $sStatus = "Unknown"
        $sReason = "Unknown"
        if( $TrustProperties -ne $null ){
            $trustAttributes = $TrustProperties['TRUST_ATTRIBUTES']
            $trustAuthenticationLevelStatus = GetTrustAuthenticationLevel -trustAttributes $trustAttributes
            $sStatus = $trustAuthenticationLevelStatus.sStatus
            $sReason = $trustAuthenticationLevelStatus.sReason
        }
        $resultObj = CreateStatusResultObject -status $sStatus -reason $sReason
        return $resultObj
    }
}

Function TrustPropertyTransitivity {
    Param(
        [Object]
        $TrustProperties,
        [TrustFlavor]
        $TrustFlavor
    )
    Process {
        $sStatus = "Unknown"
        $sReason = "Unknown"
        if( $TrustProperties -ne $null ){
            $trustAttributes = $TrustProperties['TRUST_ATTRIBUTES']
            $trustTransitivityStatus = GetTrustTransitivtyStatus -trustAttributes $trustAttributes -trustFlavor $TrustFlavor
            $sStatus = $trustTransitivityStatus.sStatus
            $sReason = $trustTransitivityStatus.sReason
        }
        $resultObj = CreateStatusResultObject -status $sStatus -reason $sReason
        return $resultObj
    }
}

Function TrustPropertySIDFiltering {
    Param(
        [Object]
        $TrustProperties,
        [TrustFlavor]
        $TrustFlavor,
        [String]
        $TrustPartner
    )
    Process {
        $sStatus = "Unknown"
        $sReason = "Unknown"
        if( $TrustProperties -ne $null ){
            $trustAttributes = $TrustProperties['TRUST_ATTRIBUTES']
            $trustSIDFilteringStatus = GetTrustSIDFilteringStatus -trustAttributes $trustAttributes -TrustFlavor $TrustFlavor -trustedDomain $TrustPartner
            $sStatus = $trustSIDFilteringStatus.sStatus
            $sReason = $trustSIDFilteringStatus.sReason
        }
        $resultObj = CreateStatusResultObject -status $sStatus -reason $sReason
        return $resultObj
    }
}

Function TrustPropertyTGTDelegation {
    Param(
        [Object]
        $TrustProperties
    )
    Process {
        $sStatus = "Unknown"
        $sReason = "Unknown"
        if( $TrustProperties -ne $null ){
            $trustAttributes = $TrustProperties['TRUST_ATTRIBUTES']
            $trustTGTDelegationStatus = GetTrustTGTDelegationStatus -trustAttributes $trustAttributes
            $sStatus = $trustTGTDelegationStatus.sStatus
            $sReason = $trustTGTDelegationStatus.sReason
        }
        $resultObj = CreateStatusResultObject -status $sStatus -reason $sReason
        return $resultObj
    }
}

Function TrustPropertyTrustFlagsStr {
    Param(
        [Object]
        $TrustProperties
    )
    Process {
        if( $TrustProperties -ne $null ){
            $trustAttributes = $TrustProperties['TRUST_ATTRIBUTES']
            $trustAttributeFlags = GetTrustAttributesFlags -trustAttributes $trustAttributes
            if( $trustAttributeFlags ){
                $trustAttributeFlagsStr = [String]::join(', ', $trustAttributeFlags)
                return $trustAttributeFlagsStr
            }
            elseif ( ([String]::Empty -eq $trustAttributeFlags) -OR ($trustAttributeFlags -eq $NULL) ){
                return "[None]"
            }
            else {
                return $trustAttributeFlags
            }
        }
        else {
            return "Unknown"
        }
    }
}

Function TrustPropertySupportedEncryptionType {
    Param(
        [Object]
        $TrustProperties
    )
    Process {
        $sStatus = "Unknown"
        $sReason = "Unknown"
        if( $TrustProperties -ne $null ){
            $trustSupportedEncryptionTypes = $TrustProperties['TRUST_SUPPORTED_ENCRYPTION_TYPES']
            $supportedEncryptionTypesStatus = GetTrustSupportedEncryptionTypes -SupportedEncryptionTypes $trustSupportedEncryptionTypes
            $sStatus = $supportedEncryptionTypesStatus.sStatus
            $sReason = $supportedEncryptionTypesStatus.sReason
        }
        $resultObj = CreateStatusResultObject -status $sStatus -reason $sReason
        return $resultObj
    }
}


Function PrintTrustRelationship {
    Param(
        [String]
        $trustNodeOne,
        [Object]
        $trustNodeOnes_Properties,
        [String]
        $trustNodeTwo,
        [Object]
        $trustNodeTwos_Properties
    )
    Process {

        $outputTable = @()
        $outputTable += [pscustomobject]@{"Attribute" = ""; "Domain: $trustNodeOne" = ""; "Domain: $trustNodeTwo" = ""}
        
        ## Print: TrustDirection
        $trustDirectionOne = TrustPropertyTrustDirection -TrustProperties $trustNodeOnes_Properties
        $trustDirectionTwo = TrustPropertyTrustDirection -TrustProperties $trustNodeTwos_Properties
        $outputTable += [pscustomobject]@{"Attribute" = "TrustDirection:"; "Domain: $trustNodeOne" = "$trustDirectionOne"; "Domain: $trustNodeTwo" = "$trustDirectionTwo"}
                
        ## Print: TrustFlavor
        $trustFlavorOne = TrustPropertyTrustFlavor -TrustProperties $trustNodeOnes_Properties -TrustNode $trustNodeOne -TrustPartner $trustNodeTwo
        $trustFlavorTwo = TrustPropertyTrustFlavor -TrustProperties $trustNodeTwos_Properties -TrustNode $trustNodeTwo -TrustPartner $trustNodeOne
        $outputTable += [pscustomobject]@{"Attribute" = "TrustFlavor:"; "Domain: $trustNodeOne" = "$trustFlavorOne"; "Domain: $trustNodeTwo" = "$trustFlavorTwo"}

        ## Print: Authentication Level
        $trustAuthenticationLevelStatusOne = TrustPropertyAuthenticationLevel -TrustProperties $trustNodeOnes_Properties
        $trustAuthenticationLevelStatusTwo = TrustPropertyAuthenticationLevel -TrustProperties $trustNodeTwos_Properties
        $outputTable += [pscustomobject]@{"Attribute" = "AuthenticationLevel:"; "Domain: $trustNodeOne" = "$($trustAuthenticationLevelStatusOne.sStatus)"; "Domain: $trustNodeTwo" = "$($trustAuthenticationLevelStatusTwo.sStatus)"}
        if( $IncludeReason ){
            $outputTable += [pscustomobject]@{"Attribute" = "AuthenticationLevel (Reason):"; "Domain: $trustNodeOne" = "$($trustAuthenticationLevelStatusOne.sReason)"; "Domain: $trustNodeTwo" = "$($trustAuthenticationLevelStatusTwo.sReason)"}
        }

        ## Print: Transitivity
        $trustTransitivityStatusOne = TrustPropertyTransitivity -TrustProperties $trustNodeOnes_Properties -TrustFlavor $trustFlavorOne
        $trustTransitivityStatusTwo = TrustPropertyTransitivity -TrustProperties $trustNodeTwos_Properties -TrustFlavor $trustFlavorTwo
        $outputTable += [pscustomobject]@{"Attribute" = "Transivivity:"; "Domain: $trustNodeOne" = "$($trustTransitivityStatusOne.sStatus)"; "Domain: $trustNodeTwo" = "$($trustTransitivityStatusTwo.sStatus)"}
        if( $IncludeReason ){
            $outputTable += [pscustomobject]@{"Attribute" = "Transitivity (Reason):"; "Domain: $trustNodeOne" = "$($trustTransitivityStatusOne.sReason)"; "Domain: $trustNodeTwo" = "$($trustTransitivityStatusTwo.sReason)"}
        }
        
        ## Print: SID Filtering
        $trustSIDFilteringStatusOne = TrustPropertySIDFiltering -TrustProperties $trustNodeOnes_Properties -TrustFlavor $trustFlavorOne -TrustPartner $trustNodeTwo
        $trustSIDFilteringStatusTwo = TrustPropertySIDFiltering -TrustProperties $trustNodeTwos_Properties -TrustFlavor $trustFlavorTwo -TrustPartner $trustNodeOne
        $outputTable += [pscustomobject]@{"Attribute" = "SID Filtering:"; "Domain: $trustNodeOne" = "$($trustSIDFilteringStatusOne.sStatus)"; "Domain: $trustNodeTwo" = "$($trustSIDFilteringStatusTwo.sStatus)"}
        if( $IncludeReason ){
            $outputTable += [pscustomobject]@{"Attribute" = "SID Filtering (Reason):"; "Domain: $trustNodeOne" = "$($trustSIDFilteringStatusOne.sReason)"; "Domain: $trustNodeTwo" = "$($trustSIDFilteringStatusTwo.sReason)"}
        }

        ## Print: TGTDelegation
        $trustTGTDelegationStatusOne = TrustPropertyTGTDelegation -TrustProperties $trustNodeOnes_Properties
        $trustTGTDelegationStatusTwo = TrustPropertyTGTDelegation -TrustProperties $trustNodeTwos_Properties
        $outputTable += [pscustomobject]@{"Attribute" = "TGT Delegation:"; "Domain: $trustNodeOne" = "$($trustTGTDelegationStatusOne.sStatus)"; "Domain: $trustNodeTwo" = "$($trustTGTDelegationStatusTwo.sStatus)"}
        if( $IncludeReason ){
            $outputTable += [pscustomobject]@{"Attribute" = "TGT Delegation (Reason):"; "Domain: $trustNodeOne" = "$($trustTGTDelegationStatusOne.sReason)"; "Domain: $trustNodeTwo" = "$($trustTGTDelegationStatusTwo.sReason)"}
        }

        ## Print: TrustFlags
        $trustAttributeFlagsStrOne = TrustPropertyTrustFlagsStr -TrustProperties $trustNodeOnes_Properties
        $trustAttributeFlagsStrTwo = TrustPropertyTrustFlagsStr -TrustProperties $trustNodeTwos_Properties
        $outputTable += [pscustomobject]@{"Attribute" = "TrustFlags:"; "Domain: $trustNodeOne" = "$trustAttributeFlagsStrOne"; "Domain: $trustNodeTwo" = "$trustAttributeFlagsStrTwo"}

        ## Print: Trust Supported Encryption Types
        $trustSupportedEncryptionTypesStatusOne = TrustPropertySupportedEncryptionType -TrustProperties $trustNodeOnes_Properties
        $trustSupportedEncryptionTypesStatusTwo = TrustPropertySupportedEncryptionType -TrustProperties $trustNodeTwos_Properties
        $outputTable += [pscustomobject]@{"Attribute" = "Supported Encryption Types:"; "Domain: $trustNodeOne" = "$($trustSupportedEncryptionTypesStatusOne.sStatus)"; "Domain: $trustNodeTwo" = "$($trustSupportedEncryptionTypesStatusTwo.sStatus)"}
        if( $IncludeReason ){
            $outputTable += [pscustomobject]@{"Attribute" = "Supported Encryption Types (Reason):"; "Domain: $trustNodeOne" = "$($trustSupportedEncryptionTypesStatusOne.sReason)"; "Domain: $trustNodeTwo" = "$($trustSupportedEncryptionTypesStatusTwo.sReason)"}
        }

        ## Output as table       
        $outputTable | Format-Table -AutoSize
    }
}

Function TrustFlavorGraphAbbr {
    Param(
        [TrustFlavor]
        $TrustFlavor
    )
    Process {
        switch ($TrustFlavor)                         
        {                        
            $([TrustFlavor]::TreeRoot) { return "TR" }
            $([TrustFlavor]::ParentChild) { return "PC" }
            $([TrustFlavor]::CrossLink) { return "CL" }
            $([TrustFlavor]::Forest) { return "F" }
            $([TrustFlavor]::External) { return "E" }
            $([TrustFlavor]::Kerberos) { return "KRB" }
            $([TrustFlavor]::Unknown) { return "UNKW" }                                               
            Default { return "UNKW" }                        
        }
    }
}

Function TrustRelationshipDirectedNodeStr {
    Param(
        [String]
        $TrustNode,
        [String]
        $TrustPartner,
        [TrustDirection]
        $TrustDirection
    )
    Process {
        ## If Outbound or BiDirectional: A --> B
        if( ( $TrustDirection -eq [TrustDirection]::OutBound ) -OR ( $TrustDirection -eq [TrustDirection]::BiDirectional ) ){
            return "`"$($TrustNode)`" -> `"$($TrustPartner)`""
        }
        ## Else: B -> A
        else {
          return "`"$($TrustPartner)`" -> `"$($TrustNode)`""
        }
    }
}

Function PrintGraphNotation {
    Param(
        [Object]
        $TrustTree
    )
    Process {
        $graphPrintHead = ""
        $graphPrintBody = ""
        ForEach($trustNode in $TrustTree.Keys){
            ## Extend graph Header
            $graphPrintHead += "`t`"$($trustNode)`" [shape=box]`n"
            ## Add trust Relationships
            ForEach( $trustPartner in $gTrustTree[$trustNode].Keys ){
                $trustProperties = $gTrustTree[$trustNode][$trustPartner]
                $edgeLabel = ""
                ## TrustDirection
                $trustDirection  = TrustPropertyTrustDirection -TrustProperties $trustProperties
                
                ## TrustFlavor
                $trustFlavor = TrustPropertyTrustFlavor -TrustProperties $trustProperties -TrustNode $trustNode -TrustPartner $trustPartner
                $trustFlavorAbbr = TrustFlavorGraphAbbr -TrustFlavor $trustFlavor
                $edgeLabel += "F: $($trustFlavorAbbr)\n"
                
                ## TrustTransitvity
                $trustTransitivityStatus = TrustPropertyTransitivity -TrustProperties $trustProperties -TrustFlavor $trustFlavor
                if($trustTransitivityStatus.sStatus -eq "Enabled"){ $edgeLabel += "T: E\n" } else { $edgeLabel += "T: D\n" }

                ## TrustAuthentication
                $trustAuthenticationStatus = TrustPropertyAuthenticationLevel -TrustProperties $trustProperties
                if( $trustAuthenticationStatus.sStatus -eq "ForestWideAuthentication" ){ $edgeLabel += "AL: FWA\n" } else { $edgeLabel += "AL: SA\n" }

                ## SIDFiltering
                $trustSIDFilteringStatus = TrustPropertySIDFiltering -TrustProperties $trustProperties -TrustFlavor $trustFlavor -TrustPartner $trustPartner
                if( $trustSIDFilteringStatus.sStatus -eq "Enabled" ){ $edgeLabel += "SIDF: E\n" } else { $edgeLabel += "SIDF: D\n" }

                ## TGTDelegation
                $trustTGTDelegationStatus = TrustPropertyTGTDelegation -TrustProperties $trustProperties
                if( $trustTGTDelegationStatus.sStatus -eq "Enabled" ){ $edgeLabel += "TGTD: E\n" } elseif ( $trustTGTDelegationStatus.sStatus-eq "Disabled" ) { $edgeLabel += "TGTD: D\n" } else { $edgeLabel += "TGTD: UNKW\n" }

                ## TrustFlags
                $trustFlagsStr = TrustPropertyTrustFlagsStr -TrustProperties $trustProperties

                ## Supported Encryption Types
                $trustSupportedEncryptionTypesStatus = TrustPropertySupportedEncryptionType -TrustProperties $trustProperties
                if( $trustSupportedEncryptionTypesStatus.sStatus ){ 
                    $edgeLabel += "SET: $($trustSupportedEncryptionTypesStatus.sStatus)\n"
                } 

                $directedNodeStr = TrustRelationshipDirectedNodeStr -TrustNode $trustNode -TrustPartner $trustPartner -TrustDirection $trustDirection
                $graphPrintBody += "`t$($directedNodeStr) [style=dashed, color=grey, label=`"$($edgeLabel)`"] // TrustFlags: $($trustFlagsStr)`n"
            }
        }
        Write-Output "`ndigraph.txt --- START"
        Write-Output "digraph Trusts {`n`n`tlabel=`"### Legend ###\nFlavor (F):\n-- TreeRoot (TR)\n-- ParentChild (PC)\n-- CrossLink (CL)\n-- External (E)\n-- Forest (F)\n-- Kerberos (KRB)\n-- Unknown (UNKW)\nTransitivity (T):\n-- Enabled (E)\n-- Disabled (D)\nAuthentication Level (AL):\n-- ForestWideAuthentication (FWA)\n-- SelecticeAuthentication (SA)\nSID Filtering (SIDF):\n-- Enabled (E)\n-- Disabled (D)\nTGT Delegation (TGTD):\n-- Enabled (E)\n-- Not Disabled (D)\n-- Unknown (UNKW)\nSupportedEncryptionTypes (SET)\n`"`n`tlabeljust=l`n`tlabelloc=t`n`n$($graphPrintHead)`n$($graphPrintBody)`n}"
        Write-Output "digraph.txt --- END"
    }
}

Function PrintTrustTree {
    Param(
        [Object]
        $trustTreeObject
    )
    Process {
        $printedTrustNodes = @()
        ForEach($trustNode in $trustTreeObject.Keys){
    
            $trustRelationshipTree = $gTrustTree[$trustNode]
            ForEach( $trustRelationshipNode in $trustRelationshipTree.Keys ){
        
                $nodeName_SideNode = $trustNode
                $nodeName_SidePartner = $trustRelationshipNode
                $trustAttributes_SideNode = $gTrustTree[$trustNode][$trustRelationshipNode]
                $trustAttributes_SidePartner = $null
        
                if( $gTrustTree.Contains( $nodeName_SidePartner ) -and ( $gTrustTree[$nodeName_SidePartner].Contains($nodeName_SideNode) ) ){
                    $trustAttributes_SidePartner = $gTrustTree[$nodeName_SidePartner][$nodeName_SideNode]
                }
        
                if( -Not $printedTrustNodes.Contains( $nodeName_SidePartner ) ){
                    ## Only print trust relationship if this node has not already been printed
                    PrintTrustRelationship -trustNodeOne $nodeName_SideNode -trustNodeOnes_Properties $trustAttributes_SideNode -trustNodeTwo $nodeName_SidePartner -trustNodeTwos_Properties $trustAttributes_SidePartner
                }

            }
            ## Add current node to list of printed nodes
            $printedTrustNodes += $nodeName_SideNode
        }
    }
}

Function ConvertFromDNToDCs {
    Param(
        [String]
        $DistinguishedName
    )
    Process {
        $DC = ''
        ForEach ( $item in ($DistinguishedName.replace('\,','~').split(","))) {
            switch ($item.TrimStart().Substring(0,2)) {
                'DC' {$DC += $item.Replace("DC=","");$DC += '.'}
            }
        }
        $CanonicalName = $DC.Substring(0,$DC.length - 1)
        return $CanonicalName
    }
}

Function ConvertFromDCToDN {
    Param(
        [String]
        $DomainName
    )
    Process {
        return "DC=" + $DomainName.Replace('.', ',DC=')
    }
}

Function GetCNFromDN {
    Param(
        [String]
        $DN,
        [Int]
        $Position
    )
    Process {
        $splited = $DN -split ',*..='
        return $splited[$Position]
    }
}

Function GetNetBiosNameFromDomainName {
    Param(
        [String]
        $DomainName
    )
    Process {
        return $DomainName.split('.')[0]
    }
}

Function GetDomainGCServer{
    Param(
        [String]
        $Domain
    )
    Process {
        try{
            $primaryServer = (Resolve-DnsName "_gc._tcp.$Domain" -Verbose:$false -ErrorAction SilentlyContinue).PrimaryServer
            if( $primaryServer ){
                return $primaryServer
            }
        } catch {
            ## In case of error return $null
            return $null
        }
        return $null
    }
}

Function GetDomainLDAPServer{
    Param(
        [String]
        $Domain
    )
    Process {
        try{
            $primaryServer = (Resolve-DnsName "_ldap._tcp.$Domain" -Verbose:$false -ErrorAction SilentlyContinue).PrimaryServer
            if( $primaryServer ){
                return $primaryServer
            }
        } catch {
            ## In Case of error return $null
            return $null
        }
        return $null
    }
}

Function BuildLDAPSearchRoots {
    Param(
        [String]
        $Domain,
        [Switch]
        $NoGC=$false
    )
    Process {
        $searchRoots = [Ordered]@{}
        $prioNum = 0
        $prots = @()
        ## Get GlobalCatalog Server
        if($NoGC){
            $domainGCSrv = $null
             $prots = @("LDAP")
        }else {
            $domainGCSrv = GetDomainGCServer -Domain $Domain
            $prots = @("GC", "LDAP")
        }
        ## Get LDAP Server
        $domainLDAPSrv = GetDomainLDAPServer -Domain $Domain
        ## Loop through servers
        ForEach($prot in $prots){
            if($domainGCSrv) { 
                $searchRoots.Add($prioNum, "$($prot)://$domainGCSrv")
                $prioNum += 1
            }
            if( $domainLDAPSrv -And ($domainLDAPSrv -ne $domainGCSrv) ){
                $searchRoots.Add($prioNum, "$($prot)://$domainLDAPSrv")
                $prioNum += 1
            }
            $searchRoots.Add($prioNum, "$($prot)://$Domain")
            $prioNum += 1
        }
        return $searchRoots
    }
}

Function GetADSIAttribute {
    Param(
        [String]
        $Domain,
        [String]
        $DistinguishedName,
        [String]
        $Property,
        [Switch]
        $NoGC = $false
    )
    Process {
        $result = $false
        $searchRoots = BuildLDAPSearchRoots -Domain $Domain -NoGC:$NoGC
        ForEach( $searchRoot in $searchRoots.Values){
            Write-Verbose "Trying to fetch $($Property): [ADSI]'$searchRoot/$($DistinguishedName)'...."
            Try{
                $object = ([ADSI]"$($searchRoot)/$($DistinguishedName)")

                ## If $Property is set to $null just return the object
                if( $Property -eq [String]::Empty -And $object ){
                    Write-Verbose "`t...Success"
                    return $object
                }
                elseif( $object ){
                    $result = $object.InvokeGet($Property)
                    Write-Verbose "`t...Success. $($Property): $($result)"
                    return $result
                }
            }
            Catch{
                Write-Verbose "`t...Failed. Error: $($_.Exception.Message)" 
                Continue
            }
        }
        return $result
    }
}

Function CreateStatusResultObject {
    Param(
        [String]
        $status,
        [String]
        $reason
    )
    Process {
        return (New-Object PSObject -Property  @{ sStatus = $status; sReason = $reason })
    }
}

Function GetCurrentDomainFQDN {
    return (Get-WmiObject Win32_ComputerSystem).Domain
    ## Another option
    ## return $ENV:USERDNSDOMAIN
}

Function trustAttributeObjectToString {
    Param(
        [Object]
        $trustAttributes,
        [switch]
        $reason
    )
    Process {
        $trustDirectionStr = $gTrustDirectionIDs[ $trustAttributes[$gTrustAttributeMap.TRUST_PARTNER] ]
        $trustDirectionReason = ""
        return "Direction: $trustDirectionStr"
    }
}

Function BuildTrustAttributeObject {
    Param(
        [Object]
        $trustPropertyObject
    )
    Process {
        $trustAttributes = @{}
        ForEach( $gAttributeName in $gTrustAttributeMap.Keys ){
            $trustAttribute = $gTrustAttributeMap.$gAttributeName
            $trustAttributeVal = $trustPropertyObject[$trustAttribute][0]
            $trustAttributes.Add($gAttributeName, $trustAttributeVal)
        }
        
        return $trustAttributes
    }
}

Function GetTrustAttributesFlags {
    Param(
        [Int]
        $trustAttributes
    )
    Begin{
       $trustAttributes = [Int]($trustAttributes)
    }
    Process {
        $activeAttributes = @()
        ForEach($trustAttributeFlag in [TrustAttributes].GetEnumNames()){
            $trustAttributeFlagVal = [Int]([TrustAttributes]::$trustAttributeFlag.value__)
           
            if( $trustAttributes -band [TrustAttributes]::$trustAttributeFlag.value__ ){
                   $activeAttributes += $trustAttributeFlag
            }
        }
        return $activeAttributes
    }
}

Function GetTrustAuthenticationLevel {
    Param(
        [Int]
        $trustAttributes
    )
    Begin{
       $trustAttributes = [Int]($trustAttributes)
    }
    Process {
        $statusStr = ""
        $reasonStr = ""
        
        if( $trustAttributes -band [TrustAttributes]::TRUST_ATTRIBUTE_WITHIN_FOREST.value__ ){
            $statusStr = "ForestWideAuthentication"
            $reasonStr = "trustAttribute flag $([TrustAttributes]::TRUST_ATTRIBUTE_WITHIN_FOREST)"
        }
        elseif( $trustAttributes -band [TrustAttributes]::TRUST_ATTRIBUTE_CROSS_ORGANIZATION.value__ ){
            $statusStr = "SelectiveAuthentication"
            $reasonStr = "trustAttribute flag $([TrustAttributes]::TRUST_ATTRIBUTE_CROSS_ORGANIZATION)"
        }
        else { 
            $statusStr = "DomainWideAuthentication"
            $reasonStr = "missing trustAttribute flag $([TrustAttributes]::TRUST_ATTRIBUTE_CROSS_ORGANIZATION)" 
        }

        $resultObj = CreateStatusResultObject -status $statusStr -reason $reasonStr
        return $resultObj
    }
}

Function GetTrustFlavor {
    Param(
        [String]
        $requestingNodeName,
        [String]
        $requestedNodeName,
        [Int]
        $trustTypeID,
        [Int]
        $trustAttributes
    )
    Process {
        if( $trustTypeID -eq [TrustTypeID]::MIT.value__ ){
            return [TrustFlavor]::Kerberos
        }
        elseif ( $trustTypeID -eq [TrustTypeID]::TRUST_TYPE_DCE.value__ ){
            return [TrustFlavor]::Unknown # "DCE (Historical, not used anymore)"
        }
        else {
            ## Check if partners are in the same forest        
            if( $trustAttributes -band [TrustAttributes]::TRUST_ATTRIBUTE_WITHIN_FOREST.value__ ){
                ## Partners are in the same forest
                
                ## Get TrustParent of RequestingNode
                $netBiosNameRequestingNode = GetNetBiosNameFromDomainName -DomainName $requestingNodeName
                $dnRootRequestingNode = GetADSIAttribute -Domain $requestingNodeName -DistinguishedName "RootDSE" -Property "rootDomainNamingContext"
                if( $dnRootRequestingNode ){
                    $trustParentRequestingNode = GetADSIAttribute -Domain $requestingNodeName -DistinguishedName "CN=$netBiosNameRequestingNode,CN=Partitions,CN=Configuration,$dnRootRequestingNode" -Property "trustParent" -NoGC
                    $trustParentCNRequestingNode = GetCNFromDN -DN $trustParentRequestingNode -Position 1
                }
                ## Get TrustParent of RequestedNode
                $netBiosNameRequestedNode = GetNetBiosNameFromDomainName -DomainName $requestedNodeName
                $dnRootRequestedNode = GetADSIAttribute -Domain $requestedNodeName -DistinguishedName "RootDSE" -Property "rootDomainNamingContext"
                if($dnRootRequestedNode){
                    $trustParentRequestedNode = GetADSIAttribute -Domain $requestedNodeName -DistinguishedName "CN=$netBiosNameRequestedNode,CN=Partitions,CN=Configuration,$dnRootRequestedNode" -Property "trustParent" -NoGC
                    $trustParentCNRequestedNode = GetCNFromDN -DN $trustParentRequestedNode -Position 1
                }

                ## if rootDomains could not be found ...
                if(
                    (-NOT $dnRootRequestingNode) -OR
                    (-NOT $dnRootRequestedNode)
                ){
                    ## ...make decision based on domain names
                    if( 
                        ( $requestingNodeName.toLower().Contains(($requestedNodeName).toLower()) ) -OR
                        ( $requestedNodeName.toLower().Contains(($requestingNodeName).toLower()) )
                    ) {
                        return [TrustFlavor]::ParentChild
                    } else {
                        Write-Verbose "The Trust flavor for the trust between 'requestingNodeName' and 'requestedNodeName' could not be determined as rootDomain could not be found."
                        return [TrustFlavor]::Unknown
                    }
                }

                ### Check if ParentChild Relationship
                if( 
                    ($trustParentCNRequestingNode -eq $netBiosNameRequestedNode) -OR
                    ($trustParentCNRequestedNode -eq $netBiosNameRequestingNode )
                ){
                    return [TrustFlavor]::ParentChild
                }
                else {
                    ## Partners are in the same forest, but not ParentChild
                    if($dnRootRequestingNode -And $dnRootRequestedNode ){
                        return [TrustFlavor]::CrossLink
                    }else {
                        return [TrustFlavor]::TreeRoot
                    }
                }
            }else {
                ## Partners not in the same forest
                if( $trustAttributes -band [TrustAttributes]::TRUST_ATTRIBUTE_FOREST_TRANSITIVE ){
                    return [TrustFlavor]::Forest
                }else {
                    return [TrustFlavor]::External
                }
            }
            ## Fallback
            return [TrustFlavor]::Unknown
        }
    }
}

Function GetTrustTGTDelegationStatus {
    Param(
        [Int]
        $trustAttributes
    )
    Begin{
       $trustAttributes = [Int]($trustAttributes)
    }
    Process {
        ## As per[MS-KILE] section 3.3.5.7.5
        $statusStr = "Unknown"
        $reasonStr = "Unknown"
        if ( $trustAttributes -band [TrustAttributes]::TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION.value__  ) {
            $statusStr = "Disabled"
            $reasonStr = "trustAttribute flag $([TrustAttributes]::TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION)"
        }
        elseif ( $trustAttributes -band [TrustAttributes]::TRUST_ATTRIBUTE_QUARANTINED_DOMAIN.value__ ) {
            $statusStr = "Disabled"
            $reasonStr = "trustAttribute flag $([TrustAttributes]::TRUST_ATTRIBUTE_QUARANTINED_DOMAIN)"

        }
        elseif ( $trustAttributes -band [TrustAttributes]::TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION.value__ ) {
            $statusStr = "Enabled"
            $reasonStr = "trustAttribute flag $([TrustAttributes]::TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION)"

        }
        elseif ( $trustAttributes -band [TrustAttributes]::TRUST_ATTRIBUTE_WITHIN_FOREST.value__ ) {
            $statusStr = "Enabled"
            $reasonStr = "trustAttribute flag $([TrustAttributes]::TRUST_ATTRIBUTE_WITHIN_FOREST)"

        }

        $resultObj = CreateStatusResultObject -status $statusStr -reason $reasonStr
        return $resultObj
    }
}

Function GetTrustSIDFilteringStatus {
    Param(
        [Int]
        $trustAttributes,
        [TrustFlavor]
        $trustFlavor,
        [String]
        $trustedDomain
    )
    Begin{
       $trustAttributes = [Int]($trustAttributes)
    }
    Process {
        $SIDFilteringStatus = "Unknown"
        $reason = "Unknown"
        ## Trust within a Forest
        if( ( $trustFlavor -eq [TrustFlavor]::ParentChild ) -or ( $trustFlavor -eq [TrustFlavor]::CrossLink ) -or ( $trustFlavor -eq [TrustFlavor]::TreeRoot ) ){
            ### Quarantined Trust
            if( $trustAttributes -band [TrustAttributes]::TRUST_ATTRIBUTE_QUARANTINED_DOMAIN.value__ ){
                $SIDFilteringStatus = "Enabled (Only SIDs from $trustedDomain are allowed)"
                $reason = "trustAttribute flag $([TrustAttributes]::TRUST_ATTRIBUTE_QUARANTINED_DOMAIN)"
            }
            ### Default ParentChild/Shortcut/TreeRoot Trust
            else {
                $SIDFilteringStatus = "Disabled (Only specific¹ SIDs are filtered)"
                $reason = "missing trustAttribute flag $([TrustAttributes]::TRUST_ATTRIBUTE_QUARANTINED_DOMAIN)"
            }
        }
        ## Forest Trust
        elseif( $trustFlavor -eq [TrustFlavor]::Forest ){
            ### Quarantined Forest Trusts
            if( $trustAttributes -band [TrustAttributes]::TRUST_ATTRIBUTE_QUARANTINED_DOMAIN.value__ ){
                $SIDFilteringStatus = "Enabled (Only SIDs from $trustedDomain are allowed)"
                $reason = "trustAttribute flag $([TrustAttributes]::TRUST_ATTRIBUTE_QUARANTINED_DOMAIN)"
            }
            ### PIM Forest Trust
            elseif ( ( $trustAttributes -band [TrustAttributes]::TRUST_ATTRIBUTE_PIM_TRUST.value__ ) -and ($trustAttributes -band [TrustAttributes]::TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL.value__) ) {
                $SIDFilteringStatus = "Disabled (Only specific¹ SIDs are filtered)"
                $reason = "missing trustAttribute flag $([TrustAttributes]::TRUST_ATTRIBUTE_QUARANTINED_DOMAIN)"
            }
            ### Treated As External Forest Trust
            elseif ( $trustAttributes -band [TrustAttributes]::TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL.value__ ) {
                $SIDFilteringStatus = "Disabled (Only specific¹ SIDs are filtered)"
                $reason = "missing trustAttribute flag $([TrustAttributes]::TRUST_ATTRIBUTE_QUARANTINED_DOMAIN)"
            }
            ### Forest Trust Without any Flags
            elseif ( $trustAttributes -eq 0x0 ) {
                $SIDFilteringStatus = "Disabled (Only specific¹ SIDs are filtered)"
                $reason = "missing trustAttribute flags"
                $asterixIncluded = $true
            }
            ### Default Forest Trust
            else {
                $SIDFilteringStatus = "Enabled (Only SIDs from the forest of $trustedDomain are allowed)"
                $reason = "default Forest Trust behaviour"
            }
        }
        ## External Trust
        elseif( $trustFlavor -eq [TrustFlavor]::External ){
            ### Quarantined Forest Trusts
            if( $trustAttributes -band [TrustAttributes]::TRUST_ATTRIBUTE_QUARANTINED_DOMAIN.value__ ){
                $SIDFilteringStatus = "Enabled (Only SIDs from $trustedDomain are allowed)"
                $reason = "trustAttribute flag $([TrustAttributes]::TRUST_ATTRIBUTE_QUARANTINED_DOMAIN)"
            }
            ### Treated As External Trust
            elseif ( $trustAttributes -band [TrustAttributes]::TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL.value__ ) {
                $SIDFilteringStatus = "Disabled (Only specific¹ SIDs are filtered)"
                $reason = "missing trustAttribute flag $([TrustAttributes]::TRUST_ATTRIBUTE_QUARANTINED_DOMAIN)"
            }
            ### External Trust Without any Flags
            elseif ( $trustAttributes -eq 0x0 ) {
                $SIDFilteringStatus = "Disabled (Only specific¹ SIDs are filtered)"
                $reason = "missing trustAttribute flags"
            }
        }
        elseif( $trustFlavor -eq [TrustFlavor]::Unknown ){
            $SIDFilteringStatus = "Unknown"
            $reason = "TrustFlavor is Unknown"
        }
        else {
            $SIDFilteringStatus = "Unknown ($($trustFlavor) not yet implemented)"
            $reason= "$($trustFlavor) not yet implemented"
        }
        
        $resultObj = CreateStatusResultObject -status $SIDFilteringStatus -reason $reason
        return $resultObj
    }
}

Function GetTrustTransitivtyStatus {
    Param(
        [Int]
        $trustAttributes,
        [TrustFlavor]
        $trustFlavor
    )

    Process{
        $sStatus = ""
        $sReason = ""
        ## If TRUST_ATTRIBUTE_NON_TRANSITIVE
        if( $trustAttributes -band [TrustAttributes]::TRUST_ATTRIBUTE_NON_TRANSITIVE.value__ ){
            $sStatus = "Disabled"
            $sReason = "trustAttribute flag $([TrustAttributes]::TRUST_ATTRIBUTE_NON_TRANSITIVE)"
        }else {
            ## Transitivity Enabled by default for relationships within a forest boundary
            if( ($trustFlavor -eq [TrustFlavor]::ParentChild ) -or ( $trustFlavor -eq [TrustFlavor]::CrossLink ) -or ( $trustFlavor -eq [TrustFlavor]::TreeRoot ) ){
                $sStatus = "Enabled"
                $sReason = "by default enabled for trusts within a forest."
            }
            ## Trust relationship across forest boundaries
            else {
                ## Transitivity must explicitly be enabled for relationships outside a forest boundary
                if( $trustAttributes -band [TrustAttributes]::TRUST_ATTRIBUTE_FOREST_TRANSITIVE.value__  ) {
                    $sStatus = "Enabled"
                    $sReason = "trustAttribute flag $([TrustAttributes]::TRUST_ATTRIBUTE_FOREST_TRANSITIVE)"
                }
                ## Disabled if not explicitly enabled for cross-forest trust relationships
                else {
                    ## Transitivity must explicitly be enabled for relationships outside a forest boundary
                    $sStatus = "Disabled"
                    $sReason = "missing trustAttribute flag $([TrustAttributes]::TRUST_ATTRIBUTE_FOREST_TRANSITIVE)"
                
                }
            }
        }

        $resultObj = CreateStatusResultObject -status $sStatus -reason $sReason
        return $resultObj
    }
}

Function GetTrustSupportedEncryptionTypes {
    Param(
        [Int]
        $SupportedEncryptionTypes
    )
    Begin{
       $supportedEncryptionTypes = [Int]($SupportedEncryptionTypes)
    }
    Process {
        $supportedEncTypes = ''
        ForEach( $encryptionType in [SupportedEncryptionTypes].GetEnumValues() ){
            If( $supportedEncryptionTypes -band $encryptionType.value__ ){
                $supportedEncTypes += "$($encryptionType) "
            }
        }
        $statusStr = $supportedEncTypes
        $reasonStr = "msds-supportedEncryptionTypes: '$($supportedEncryptionTypes)'"
        $resultObj = CreateStatusResultObject -status $statusStr -reason $reasonStr
        return $resultObj
    }
}


Function ExtendTrustTree {
    Param(
        [String]
        $trustNodeName,
        [String]
        $trustPartner,
        [Object]
        $trustProperties
    )
    
    Process {
        if( -Not $gTrustTree.Contains($trustNodeName) ){
            # Adding $trustNodeName to global trustTree
            $gTrustTree.Add($trustNodeName, @{})
        }
        $trustSubTree = $gTrustTree[$trustNodeName]
        
        if( -Not $trustSubTree.Contains( $trustPartner ) ){
            $trustAttributes = BuildTrustAttributeObject -trustPropertyObject $trustProperties
            $trustSubTree.Add( $trustPartner, $trustAttributes )
            
            # save the current color
            $fc = $host.UI.RawUI.ForegroundColor
            # set the new color
            $host.UI.RawUI.ForegroundColor = "Green"
            Write-Output "[+] Added Trust between '$trustNodeName' & '$trustPartner'" # -ForegroundColor "Green"
            # restore the original color
            $host.UI.RawUI.ForegroundColor = $fc
        }
    }
}

Function SpiderTrustTree {
    Param(
        [Object]
        $trustTree
    )
    Begin {
        ## Needs to be cloned, cause the trustTree might be extended, which would crash the loop
        $clonedTrustTree = $trustTree.Clone()
    }
    Process {
        ForEach($subTree in $clonedTrustTree.Values){
            ForEach($node in $subTree.Keys){
                if( ($gTrustTree.Keys -notcontains $node) -And ( $gUnreachableDomains.Keys -notcontains $node ) ){
                    BuildTrustTree $node
                }
            }
        }
    }
}

Function GetTrusts {
    Param(
        [String]
        $Domain
    )

    Process{
        ## Prepare LDAP Query
        $trustAttributes = @("securityidentifier", "distinguishedname", "instancetype", "adspath", "trustdirection", "trustattributes", "trustpartner", "trusttype", "msds-supportedencryptiontypes")
        $searcher = [adsisearcher]"(objectclass=trustedDomain)"
        $searcher.PropertiesToLoad.AddRange($trustAttributes)
        
        ## Prepare Endpoints to query
        $trusts = $null
        $success = $false
        $errors = @()
        $searchRoots = BuildLDAPSearchRoots -Domain $Domain
        ForEach( $searchRoot in $searchRoots.Values ){
            try {
                Write-Verbose "Trying to fetch trusts from '$($searchRoot)'"
                $searcher.SearchRoot = $searchRoot
                $trusts = $searcher.FindAll()
                ## Some attributes are not propagated to the global catalog, adding those manually here
                ForEach($trustResultObj in $trusts){
                    ## Adding: msds-supportedencryptiontypes
                    If( "msds-supportedencryptiontypes" -Notin $trustResultObj.Properties ){
                        $msDsSupportedEncTypes = GetADSIAttribute -Domain $Domain -DistinguishedName $trustResultObj.Properties.distinguishedname[0] -Property 'msds-supportedencryptiontypes' -NoGC
                        $trustResultObj["msds-supportedencryptiontypes"] = $msDsSupportedEncTypes
                    }
                }
                $success = $true
                break
            }
            catch {
                $ErrorMessage = $_.Exception.Message
                $errMsg = "Error while fetching trusts from '$($searchRoot)'. Error was: $ErrorMessage"
                $errors += $errMsg
                Write-Verbose $errMsg
                continue
            }
        }
        if( -Not $success ){
            $gUnreachableDomains.Add($Domain, @{"Errors" = $errors})
        }
        return $trusts
    }
}

Function BuildTrustTree{
    Param(
        [String]
        $Domain
    )
    Begin {
        Write-Verbose "[*] Building TrustTree for: $Domain"
    }
    Process {
        $trusts = GetTrusts -Domain $Domain
        ForEach($trust in $trusts){
            $trustNode = ConvertFromDNToDCs -DistinguishedName $trust.Properties.distinguishedname
            $trustPartner = $trust.Properties.trustpartner
            ExtendTrustTree -trustNodeName $trustNode -trustPartner $trustPartner -trustProperties $trust.Properties
        }
        SpiderTrustTree -trustTree $gTrustTree
    }
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

## Build Trust Tree
if( $Domain ){
    $targetDomain = $Domain
}else {
    $targetDomain = GetCurrentDomainFQDN
}
BuildTrustTree -Domain $targetDomain

## Print Trust Tree
PrintTrustTree -trustTreeObject $gTrustTree

## Print Legend
Write-Output "Legend:"
Write-Output "¹as per [MS-PAC] Section 4.1.2.2"
Write-Output "'CrossLink' trusts are more generally known as 'Shortcut' trusts"
Write-Output "'unknown' often indicates that the trust partner could not be contacted"

## Print Graph Notation
if( $ShowGraphNotation ){
    PrintGraphNotation -TrustTree $gTrustTree
}
