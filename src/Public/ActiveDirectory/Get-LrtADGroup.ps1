using namespace System
using namespace System.Collections.Generic
using namespace Microsoft.ActiveDirectory.Management

Function Get-LrtADGroup {
    <#
    .SYNOPSIS
        Encapsulation of Get-ADGroup that will use the settings found in LogRhythm.Tools configuration
        for populating the <Server> and <Credential> parameters of that cmdlet.

        For more information, run:
        > Get-Help Get-ADGroup
    .DESCRIPTION
        The purpose of this cmdlet is to serve as a SIMPLE interface to the standard ActiveDirectory module
        command Get-ADGroup, and is not intended to replace it or any other ActiveDirectory module commands.

        This cmdlet merely runs Get-ADGroup and automatically supplies the values for <Credential> and <Server>
        with the corresponding values found in LrtConfig.
    .PARAMETER Identity
        Specifies an Active Directory group object by providing one of the following values. The
        identifier in parentheses is the LDAP display name for the attribute.
            Distinguished Name
            GUID
            Security Identifier (objectSid)
            Security Accounts Manager (SAM) Account Name (sAMAccountName)
    .PARAMETER Properties
        Reflects the Properties parameter of the Get-ADGroup cmdlet.
    .PARAMETER Server
        Specifies the Active Directory Domain Services instance to connect to, by providing one
        of the following values for a corresponding domain name or directory server. The service
        may be any of the following:  
            Active Directory Lightweight Domain Services,
            Active Directory Domain Services
            Active Directory Snapshot instance
    .PARAMETER Credential
        Credential parameter, which by default is the the value stored in 
        LrtConfig.ActiveDirectory.Credential
    .INPUTS
        None or Microsoft.ActiveDirectory.Management.ADGroup
        A group object is received by the Identity parameter.
    .OUTPUTS
        Microsoft.ActiveDirectory.Management.ADGroup
        Returns one or more group objects.
    .EXAMPLE
        PS C:\> Get-ADGroup administrators


        DistinguishedName : CN=Administrators,CN=Builtin,DC=Fabrikam,DC=com
        GroupCategory     : Security
        GroupScope        : DomainLocal
        Name              : Administrators
        ObjectClass       : group
        ObjectGUID        : 02ce3874-dd86-41ba-bddc-013f34019978
        SamAccountName    : Administrators
        SID               : S-1-5-32-544

        Description

        -----------

        Get the group with samAccountName administrators.
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>



    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [ADGroup] $Identity,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet(
            '*',
            'CanonicalName',
            'CN',
            'Created',
            'createTimeStamp',
            'Deleted',
            'Description',
            'DisplayName',
            'DistinguishedName',
            'dSCorePropagationData',
            'GroupCategory',
            'GroupScope',
            'groupType',
            'HomePage',
            'instanceType',
            'isDeleted',
            'LastKnownParent',
            'ManagedBy',
            'member',
            'MemberOf',
            'Members',
            'Modified',
            'modifyTimeStamp',
            'Name',
            'nTSecurityDescriptor',
            'ObjectCategory',
            'ObjectClass',
            'ObjectGUID',
            'objectSid',
            'ProtectedFromAccidentalDeletion',
            'SamAccountName',
            'sAMAccountType',
            'sDRightsEffective',
            'SID',
            'SIDHistory',
            'uSNChanged',
            'uSNCreated',
            'whenChanged',
            'whenCreated'
        )]
        [string[]] $Properties,

        [Parameter(Mandatory = $false, Position = 2)]
        [string] $Server = $LrtConfig.ActiveDirectory.Server,


        [Parameter(Mandatory = $false, Position = 3)]
        [pscredential] $Credential = $LrtConfig.ActiveDirectory.Credential
    )


    Begin {
        # Import Module ActiveDirectory
        if (! (Import-LrtADModule)) {
            throw [Exception] "LogRhythm.Tools Failed to load ActiveDirectory module."
        }
    }


    Process {
        # Run the appropriate variation of Get-ADGroup
        try {
            if ($Server) {
                if ($Credential) {
                    Write-Verbose "Get-ADGroup Options: +Credential +Server"
                    $Group = Get-ADGroup -Identity $Identity -Server $Server -Credential $Credential
                } else {
                    Write-Verbose "Get-ADGroup Options: +Server"
                    $Group = Get-ADGroup -Identity $Identity -Server $Server
                }
            } else {
                if ($Credential) {
                    Write-Verbose "Get-ADGroup Options: +Credential"
                    $Group = Get-ADGroup -Identity $Identity -Credential $Credential
                } else {
                    Write-Verbose "Get-ADGroup Options: None"
                    $Group = Get-ADGroup -Identity $Identity
                }
            }
        } catch {
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
        
        return $Group
    }


    End { }
}