#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author: twitter: @b00010111

# windows: tshark needs to be in path: https://stackoverflow.com/questions/44272416/how-to-add-a-folder-to-path-environment-variable-in-windows-10-with-screensho
# windows: get windump for -s parameter: https://www.winpcap.org/windump/install/default.htm

# definition l2t format: # https://www.forensicswiki.org/wiki/L2T_CSV

#if new opnum, operating below smb protocol, is added:
#	change export string tsharkfilter method for smb_filter and smb2_filter
#	change enrich_opnum method
#	change tmp_d in normalizeCSV method for smb_filter and smb2_filter
#	change process to split multiple commands in normalizeCSV method for smb_filter and smb2_filter


#########################################################################################################################################################################
#																a lot of supporting dicts and lists																		#
#########################################################################################################################################################################
#samr dict
#samr.opnum
# => https://docs.microsoft.com/en-us/openspecs/windows_protocols/MS-SAMR/4df07fab-1bbc-452f-8e92-7853a3c7e380
#samr.samr_LookupNames.names
#-> issue with NAMES.. following them goes really down to details in the traffic.. lookup searches for name returns rid.. openuser uses rid and delivers samr.user_handle
#-> user handle is used later in queryUserInfoetc.
#->-> this would mean: we need a dict name to rid, rid to user_handle, in on session to enrich with name
#-> same with SID if used
smb_samr_dict = {'0':'SamrConnect: returns handle to server object','1':'SamrCloseHandle: closes any context handle of RPC interface','2':'SamrSetSecurityObject: set access control on object','3':'SamrQuerySecurityObject: query access control on object','4':'Opnum4NotUsedOnWire: opnum reserved for local use','5':'SamrLookupDomainInSamServer: obtains SID of object','6':'SamrEnumerateDomainsInSamServer: listing all domains hosted by server','7':'SamrOpenDomain: get handle to domain object via SID','8':'SamrQueryInformationDomain: get attributes from a domain object','9':'SamrSetInformationDomain: updates attributes on a domain object','10':'SamrCreateGroupInDomain: creates group object within domain','11':'SamrEnumerateGroupsInDomain: enumerates all groups','12':'SamrCreateUserInDomain: creates a user','13':'SamrEnumerateUsersInDomain: enumerates all user','14':'SamrCreateAliasInDomain: creates an alias','15':'SamrEnumerateAliasesInDomain: enumerates all aliases','16':'SamrGetAliasMembership: obtains list of aliases given set of SIDs is a member','17':'SamrLookupNamesInDomain: translates set of account names into set of RIDs','18':'SamrLookupIdsInDomain: translates a set of RIDs into account names','19':'SamrOpenGroup: get handle to group via RID','20':'SamrQueryInformationGroup: obtains attributes from a group object','21':'SamrSetInformationGroup: updates attributes on group object','22':'SamrAddMemberToGroup: add member to group','23':'SamrDeleteGroup: removes a group object','24':'SamrRemoveMemberFromGroup: removes member from group','25':'SamrGetMembersInGroup: get members of group','26':'SamrSetMemberAttributesOfGroup: set member attributes of group','27':'SamrOpenAlias: get handle to alias by RID','28':'SamrQueryInformationAlias: get attributes from an alias','29':'SamrSetInformationAlias: updates attributes on an alias','30':'SamrDeleteAlias: delete alias by handle','31':'SamrAddMemberToAlias: adds member (via SID) to alias','32':'SamrRemoveMemberFromAlias: removes member (via SID) from alias','33':'SamrGetMembersInAlias: get membership SID list of alias','34':'SamrOpenUser: get handle for User by RID','35':'SamrDeleteUser: delete a user','36':'SamrQueryInformationUser: get attributes from user object','37':'SamrSetInformationUser: updates attributes on user object','38':'SamrChangePasswordUser: change password of user object','39':'SamrGetGroupsForUser: get RID of groups given user object is member of','40':'SamrQueryDisplayInformation: get list of accounts in ascending name-sorted order, starting at given index','41':'SamrGetDisplayEnumerationIndex: get index into an ascending account-name–sorted list of accounts','42':'Opnum42NotUsedOnWire: opnum reserved for local use','43':'Opnum43NotUsedOnWire: opnum reserved for local use','44':'SamrGetUserDomainPasswordInformation: get password policy info for domain given user belongs to','45':'SamrRemoveMemberFromForeignDomain: removes member (by sid) from all aliases','46':'SamrQueryInformationDomain2: get attributes from domain object','47':'SamrQueryInformationUser2: get attributes from user object','48':'SamrQueryDisplayInformation2: get list of accounts in ascending name-sorted order, starting at given index','49':'SamrGetDisplayEnumerationIndex2: get index into an ascending account-name–sorted list of accounts,given a prefix to match','50':'SamrCreateUser2InDomain: creates a user with given name','51':'SamrQueryDisplayInformation3: get list of accounts in ascending name-sorted order, starting at given index','52':'SamrAddMultipleMembersToAlias: adds multiple member SIDs to alias','53':'SamrRemoveMultipleMembersFromAlias: remove multiple member SIDs from alias','54':'SamrOemChangePasswordUser2: changes a user\'s password by given user name','55':'SamrUnicodeChangePasswordUser2: changes a user\'s password by given user name','56':'SamrGetDomainPasswordInformation: get password policy information without authenticating','57':'SamrConnect2: returns handle to server object','58':'SamrSetInformationUser2: updates attributes on a user object','59':'Opnum59NotUsedOnWire: opnum reserved for local use','60':'Opnum60NotUsedOnWire: opnum reserved for local use','61':'Opnum61NotUsedOnWire: opnum reserved for local use','62':'SamrConnect4: returns handle to server object','63':'Opnum63NotUsedOnWire: opnum reserved for local use','64':'SamrConnect5: returns handle to server object','65':'SamrRidToSid: get SID of account by given RID','66':'SamrSetDSRMPassword: sets a local recovery password for user RID','67':'SamrValidatePassword: validate password agains stored policy','68':'Opnum68NotUsedOnWire: opnum reserved for local use','69':'Opnum69NotUsedOnWire: opnum reserved for local use'}
#smb_samr_extendList = [2,6,9,10,12,14,21,22,23,24,26,29,30,31,32,35,37,38,45,50,52,53,54,55,58,66]


# lsarpc dict
# lsarpc.opnum
#Local Security Authority (Domain Policy) Remote Protocol is used to manage various machine and domain security policies.
#MS-LSAD => https://docs.microsoft.com/en-us/openspecs/windows_protocols/MS-LSAD/1b5471ef-4c33-4a91-b079-dfcbb82f05cc
# lsarpc.lsa_OpenPolicy2.system_name == "\\\\CONTROLLER" -> could be used to enrich target info
smb_lsarpc_dict = {'0':'LsarClose: closes an open handle','1':'Opnum1NotUsedOnWire: Not used on wire','2':'LsarEnumeratePrivileges: enumerate all privileges known to server (answer in fragments)','3':'LsarQuerySecurityObject: get security descriptor for object','4':'LsarSetSecurityObject: set security descriptor for object','5':'Opnum5NotUsedOnWire: Not used on wire','6':'LsarOpenPolicy: opens context handle to the RPC server,must be called first to contact server','7':'LsarQueryInformationPolicy: called to query values representing the server\'s information policy','8':'LsarSetInformationPolicy: set policy on server','9':'Opnum9NotUsedOnWire: Not used on wire','10':'LsarCreateAccount: create new account object in server\'s database','11':'LsarEnumerateAccounts: request list of account objects from server (answer in fragments)','12':'LsarCreateTrustedDomain: create an object of type trusted domain in database','13':'LsarEnumerateTrustedDomains: request a list of trusted domain objects in database','14':'Lsar_LSA_TM_14: no further info in standard','15':'Lsar_LSA_TM_15: no further info in standard','16':'LsarCreateSecret: create a new secret object in database','17':'LsarOpenAccount: get handle to account object by SID','18':'LsarEnumeratePrivilegesAccount: get list of privileges for account','19':'LsarAddPrivilegesToAccount: add new privileges to existing account','20':'LasrRemovePrivilegesFromAccount: remove privileges from account','21':'Opnum21NotUsedOnWire: Not used on wire','22':'Opnum22NotUsedOnWire: Not used on wire','23':'LsarGetSystemAccessAccount: get system access account flags for account','24':'LsarSetSystemAccessAccount: set system access account flags for account','25':'LsarOpenTrustedDomain: open trusted domain by SID','26':'LsarQueryInfoTrustedDomain: get information about trusted domain','27':'LsarSetInformationTrustedDomain: set information about trusted domain','28':'LsarOpenSecret: get handle to existing secret object','29':'LsarSetSecret: set the current and old values of secret object','30':'LsarQuerySecret: get current and old (or previous) value of secret object','31':'LsarLookupPrivilegeValue: map name of privilege into locally (SERVER) unique identifier (LUID)','32':'LsarLookupPrivilegeName: map locally unique identifier (LUID) of privilege to name (SERVER)','33':'LsarLookupPrivilegeDisplayName: map name of a privilege into display text string in callers language','34':'LsarDeleteObject: delete open account object, secret object, or trusted domain object','35':'LsarEnumerateAccountsWithUserRight: get list of account objects that match the passed-in user rights value','36':'LsarEnumerateAccountRights: get list of rights for given account object','37':'LsarAddAccountRights: add new rights to an account object (will be created if not existed)','38':'LsarRemoveAccountRights: remove rights from account','39':'LsarQueryTrustedDomainInfo: get information on trusted domain object','40':'LsarSetTrustedDomainInfo: set information on trusted domain object (will be created if not existed)','41':'LsarDeleteTrustedDomain: delete trusted domain object','42':'LsarStorePrivateData: store secret value under given key name','43':'LsarRetrievePrivateData: get secret value via given key name','44':'LsarOpenPolicy2: opens context handle to the RPC server,must be called first to contact server','45':'Lsar_LSA_TM_45: no further info in standard','46':'LsarQueryInformationPolicy2: called to query values representing the server\'s information policy','47':'LsarSetInformationPolicy2: set policy on server','48':'LsarQueryTrustedDomainInfoByName: get information about trusted domain object by given string name','49':'LsarSetTrustedDomainInfoByName: set information about trusted domain object by given string name','50':'LsarEnumerateTrustedDomainsEx: enumerate all trusted domain objects known to server (answer in fragments)','51':'LsarCreateTrustedDomainEx: create trusted domain object','52':'Opnum52NotUsedOnWire: Not used on wire','53':'LsarQueryDomainInformationPolicy: get additional policy settings','54':'LsarSetDomainInformationPolicy: set additional policy settings','55':'LsarOpenTrustedDomainByName: open trusted domain object by given name','56':'Opnum56NotUsedOnWire: Not used on wire','57':'Lsar_LSA_TM_57: no further info in standard','58':'Lsar_LSA_TM_58: no further info in standard','59':'LsarCreateTrustedDomainEx2: create trusted domain object','60':'Opnum60NotUsedOnWire: Not used on wire','61':'Opnum61NotUsedOnWire: Not used on wire','62':'Opnum62NotUsedOnWire: Not used on wire','63':'Opnum63NotUsedOnWire: Not used on wire','64':'Opnum64NotUsedOnWire: Not used on wire','65':'Opnum65NotUsedOnWire: Not used on wire','66':'Opnum66NotUsedOnWire: Not used on wire','67':'Opnum67NotUsedOnWire: Not used on wire','68':'Lsar_LSA_TM_68: no further info in standard','69':'Opnum69NotUsedOnWire: Not used on wire','70':'Opnum70NotUsedOnWire: Not used on wire','71':'Opnum71NotUsedOnWire: Not used on wire','72':'Opnum72NotUsedOnWire: Not used on wire','73':'LsarQueryForestTrustInformation: get information about trust relationship with another forest','74':'LsarSetForestTrustInformation: establish a trust relationship with another forest'}
#smb_lsarpc_extendList = [4,8,10,12,16,19,20,24,27,29,34,37,38,40,41,42,47,49,51,54,59,74]

# smb.trans/smb.trans2 and smb2.ioctl
# we do not care about if it carries browser,lanman,eventlog,dssetup,
# DSSETUp -> https://wiki.wireshark.org/DSSETUP

#
# smb_trans and smb2_ioctl: 
# SRVSVC
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/accf23b0-0f57-441c-9185-43041f1b0ee9 -> SRVSVC see section 3.1.4
# named pipe to /srvsvc is used to communicate with Microsoft's Server Service DLL (srvsvc.dll)
# smb.cmd == 0x25 and (srvsvc.opnum)
smb_srvsvc_dict = {'8':'NetrConnectionEnum: list connections','9':'NetrFileEnum: get info about open files','10':'NetrFileGetInfo: get info about specific open file','11':'NetrFileClose: close specified File,device,named pipe','12':'NetrSessionEnum: list established sessions','13':'NetrSessionDel: close specified session','14':'NetrShareAdd: shares a server resource','15':'NetrShareEnum: get info about shared resources','16':'NetrShareGetInfo: get info about specific shared resource','17':'NetrShareSetInfo: Set parameter for specific shared ressource','18':'NetrShareDel: ends sharing of a server resource (closes all connections)','19':'NetrShareDelSticky: marks the share as nonpersistent','20':'NetrShareCheck : test if server is sharing a device','21':'NetrServerGetInfo : get configuration information for server','22':'NetrServerSetInfo: Sets a server’s operating parameters','23':'NetrServerDiskEnum : get list of disk drives on a server','24':'NetrServerStatisticsGet : get operating stats for service','25':'NetrServerTransportAdd : Binds server to transport protocol.','26':'NetrServerTransportEnum: enumerates the information about transport protocols that the server manages','27':'NetrServerTransportDel : disconnects transport protocol from server','28':'NetrRemoteTOD : gets servers time of day info','30':'NetprPathType : checks path name to determine type','31':'NetprPathCanonicalize : converts path name','32':'NetprPathCompare : compare two paths','33':'NetprNameValidate : validates name','34':'NetprNameCanonicalize : converts name to canonical format for type','35':'NetprNameCompare : compares two names','36':'NetrShareEnumSticky : gets info about sticky shares','37':'NetrShareDelStart : initial phase of a two-phase share delete','38':'NetrShareDelCommit : final phase of a two-phase share delete','39':'NetrpGetFileSecurity : gets security descriptor for file/directory','40':'NetrpSetFileSecurity : sets the security of a file or directory','41':'NetrServerTransportAddEx : binds the specified server to the transport protocol','43':'NetrDfsGetVersion : check if server is a DFS server and returns version','44':'NetrDfsCreateLocalPartition : marks a share as being a DFSshare','45':'NetrDfsDeleteLocalPartition : deletes a DFSshare (Prefix)','46':'NetrDfsSetLocalVolumeState : sets a local DFSshare online or offline','48':'NetrDfsCreateExitPoint : creates a DFS link on server','49':'NetrDfsDeleteExitPoint : deletes a DFS link on server','50':'NetrDfsModifyPrefix : changes the path that corresponds to a DFS link on server)','51':'NetrDfsFixLocalVolume : adds knowledge of a new DFS share on server','52':'NetrDfsManagerReportSiteInfo : Gets Active Directory site information','53':'NetrServerTransportDelEx : Unbinds transport protocol','54':'NetrServerAliasAdd : attaches an alias name to an existing server name and inserts Alias objects into AliasList','55':'NetrServerAliasEnum : Retrieves alias information for server','56':'NetrServerAliasDel : deletes an alias name from server alias list','57':'NetrShareDelEx : Deletes a share name list of shared resources'}
# define interesting events: operation on file/resource (getInfo,close,add,setInfo,delete,check,transportadd,setfilesecurity,Dfs*LocalPartition,Dfs*LocalVolume,NetrDfs*ExitPoint,NetrDfsModifyPrefix,NetrServerAliasAdd,NetrServerAliasDel,NetrShareDelEx
#smb_srvsvc_extendList = [10,11,13,14,16,17,18,19,37,38,20,21,22,25,41,27,53,40,44,45,46,48,50,49,51,54,56,57]
# 
# wkssvc
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/5bb08058-bc36-4d3c-abeb-b132228281b7 -> WKSSVC see section 3.2.4
# named pipe to /wkssvc is used to communicate with Microsoft's Workstation service dll (wkssvc.dll)
# smb.cmd == 0x25 and (wkssvc.opnum)
smb_wkssvc_dict = {'0':'NetrWkstaGetInfo: get configuration info about workstation','1':'NetrWkstaSetInfo: configures settings for workstation','2':'NetrWkstaUserEnum: get info about all users currently logged on to a workstation','5':'NetrWkstaTransportEnum: get info about transport protocols enabled for use by SMB','6':'NetrWkstaTransportAdd: enables smb to use transport protocol','7':'NetrWkstaTransportDel: unbinds transport protocol used by smb','8':'NetrUseAdd: establishes a connection between workstation server and SMB server','9':'NetrUseGetInfo: get info from remote workstation about connection to shared resource on an SMB server','10':'NetrUseDel: Disconnects connection between workstation server and SMB server','11':'NetrUseEnum: get information about connections between the workstation server and an SMB server.','13':'NetrWorkstationStatisticsGet: get workstation statistics','20':'NetrGetJoinInformation: get join-status information for specified computer','22':'NetrJoinDomain2 : Uses encrypted credentials to join a computer to a workgroup/domain','23':'NetrUnjoinDomain2: Uses encrypted credentials to unjoin a computer to a workgroup/domain','24':'NetrRenameMachineInDomain2: Uses encrypted credentials to rename a computer in a domain','25':'NetrValidateName2: Uses encrypted credentials to verify the validity of a computer, workgroup, or domain name','26':'NetrGetJoinableOUs2: Uses encrypted credentials to retrieve a list of organizational units (OUs)for account creation','27':'NetrAddAlternateComputerName: Adds alternate name for specified server','28':'NetrRemoveAlternateComputerName : Removes alternate name for specified server','29':'NetrSetPrimaryComputerName: Sets primary computer name for specified server','30':'NetrEnumerateComputerNames : gets list of computer names for specified server'}
# define interesting events: setInfo,transportadd,transportdel,useadd,usegetinfo,usedel,unjoin,renamemaschineindomain,Netr*AlternateComputerName,NetrSetPrimaryComputerName  
#smb_wkssvc_extendList = [1,6,7,8,9,10,23,24,27,28,29]
# 
# WINREG
# smb.cmd == 0x25 and (winreg.opnum)
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/MS-RRP/0fa3191d-bb79-490a-81bd-54c2601b7a78  -> Section 3.1.5
smb_winreg_dict = {'0': 'OpenClassesRoot : opens HKEY_CLASSES_ROOT key','1': 'OpenCurrentUser : opens HKEY_CURRENT_USER key','2': 'OpenLocalMachine : opens HKEY_LOCAL_MACHINE key','3': 'OpenPerformanceData : opens HKEY_PERFORMANCE_DATA key','4': 'OpenUsers : opens HKEY_USERS key','5': 'BaseRegCloseKey : close handle to specified registry key','6': 'BaseRegCreateKey : creates specified registry key, if key already exists it will be opened','7': 'BaseRegDeleteKey : deletes specified subkey','8': 'BaseRegDeleteValue : removes named value from specified registry key','9': 'BaseRegEnumKey : enumerate and return subkey','10': 'BaseRegEnumValue : enumerates and return value at specified index','11': 'BaseRegFlushKey : flushed/writes all attributes of specified open registry key into registry','12': 'BaseRegGetKeySecurity : gets copy of security descriptor protecting specified open registry key','13': 'BaseRegLoadKey : creates a subkey under HKEY_USERS or HKEY_LOCAL_MACHINE and stores registration information from specified file in that subkey','15': 'BaseRegOpenKey : opens specified key for access, returning handle','16': 'BaseRegQueryInfoKey : gets relevant information about key identified by specified key handle','17': 'BaseRegQueryValue : gets data from default value of specified registry open key','18': 'BaseRegReplaceKey : target MUST read the registry information from specified file and replace specified key with content of file','19': 'BaseRegRestoreKey : reads registry information in a specified file and copies it over the specified key','20': 'BaseRegSaveKey : saves specified key and all its subkeys and values to specified file','21': 'BaseRegSetKeySecurity : sets security descriptor for specified open registry key','22': 'BaseRegSetValue : sets the data for the default value of a specified registry key','23': 'BaseRegUnLoadKey : unloads/removes specified discrete body of keys, subkeys, and values','26': 'BaseRegGetVersion : get version of destination registry server','27': 'OpenCurrentConfig : opens and returns handle to predefined HKEY_CURRENT_CONFIG key','29': 'BaseRegQueryMultipleValues : get type and data for list of value names associated with specified registry key','31': 'BaseRegSaveKeyEx : saves specified key and all its subkeys/values to specified file','32': 'OpenPerformanceText : opens and returns handle to predefined HKEY_PERFORMANCE_TEXT key','33': 'OpenPerformanceNlsText : opens and returns handle to predefined HKEY_PERFORMANCE_NLSTEXT key','34': 'BaseRegQueryMultipleValues2 : get type and data for list of value names associated with specified registry key','35': 'BaseRegDeleteKeyEx : Delete specified registry key'}
# define interesting events:
#smb_winreg_extendList = [0,1,2,4,5,6,7,8,9,10,13,15,17,18,19,20,22,27,29,31,34,35]
# winreg.opnum -> registry key or value to registry_info field; ONLY works for smb1!
## opnum: 15 winreg.winreg_OpenKey.keyname, opnum: 6 winreg.winreg_CreateKey.name, opnum: 13 winreg.winreg_LoadKey.keyname
## opnum: 17:winreg.winreg_QueryValue.value_name, opnum: 22 winreg.winreg_SetValue.name, opnum: 8 winreg.winreg_DeleteValue.value

#
# SVCCTL (MS-SCMR)
# smb.cmd == 0x25 AND (svcctl.opnum == ....)
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f
smb_svcctl_dict = {'0': 'RCloseServiceHandle : close handles to SCM and any other associated services','1': 'RControlService : send control code for specific service handle','2': 'RDeleteService :  marks specified service for deletion','3': 'RLockServiceDatabase :  acquires a lock on an SCM database','4': 'RQueryServiceObjectSecurity : get copy of SECURITY_DESCRIPTOR structure associated with service','5': 'RSetServiceObjectSecurity : sets SECURITY_DESCRIPTOR structure associated with service','6': 'RQueryServiceStatus : get current status of specified service','7': 'RSetServiceStatus :  updates SCM status information for calling service','8': 'RUnlockServiceDatabase : releases a lock on a service database','9': 'RNotifyBootConfigStatus :  reports boot status to the SCM','11': 'RChangeServiceConfigW : changes configuration parameters for service','12': 'RCreateServiceW :  creates service record in the SCM','13': 'REnumDependentServicesW : get ServiceName, DisplayName, and ServiceStatus of service records that are listed as dependents of specified service','14': 'REnumServicesStatusW : get list of services matching specified service handle,type and state','15': 'ROpenSCManagerW :  establishes connection to server and opens SCM database','16': 'ROpenServiceW : creates RPC context handle to existing service','17': 'RQueryServiceConfigW : get configuration parameters of specified service','18': 'RQueryServiceLockStatusW : get lock status of specified SCM database','19': 'RStartServiceW : starts a specified service','20': 'RGetServiceDisplayNameW : get display name of the specified service','21': 'RGetServiceKeyNameW : get ServiceName of service with specified DisplayName','23': 'RChangeServiceConfigA :  changes configuration parameters for service','24': 'RCreateServiceA : creates service record in the SCM','25': 'REnumDependentServicesA : get ServiceName, DisplayName, and ServiceStatus of service records that are listed as dependents of specified service','26': 'REnumServicesStatusA : get list of services matching specified service handle,type and state','27': 'ROpenSCManagerA : establishes connection to server and opens SCM database','28': 'ROpenServiceA : creates RPC context handle to existing service','29': 'RQueryServiceConfigA : get configuration parameters of specified service','30': 'RQueryServiceLockStatusA : get lock status of specified SCM database','31': 'RStartServiceA : starts a specified service','32': 'RGetServiceDisplayNameA : get display name of the specified service','33': 'RGetServiceKeyNameA : get ServiceName of service with specified DisplayName','35': 'REnumServiceGroupW : get members of service group','36': 'RChangeServiceConfig2A : SHOULD change optional configuration parameters for service','37': 'RChangeServiceConfig2W : changes optional configuration parameters for service','38': 'RQueryServiceConfig2A : get optional configuration parameters of specified service','39': 'RQueryServiceConfig2W : get optional configuration parameters of specified service','40': 'RQueryServiceStatusEx : get current status of specified service','41': 'REnumServicesStatusExA : get list of services matching specified service handle,type and state','42': 'REnumServicesStatusExW : get list of services matching specified service handle,type and state','44': 'RCreateServiceWOW64A : creates service record for 32-bit service on 64-bit system','45': 'RCreateServiceWOW64W : creates service record for 32-bit service on 64-bit system','47': 'RNotifyServiceStatusChange : register for notifications when and check if specified service is created or deleted or changed status','48': 'RGetNotifyResults : get notification information for previously registered notification','49': 'RCloseNotifyHandle : unregisters from receiving future notifications for a service about start or stop or changed status','50': 'RControlServiceExA : send control code for specific service','51': 'RControlServiceExW : send control code for specific service','56': 'RQueryServiceConfigEx : get optional  configuration parameters of specified service','60': 'RCreateWowService : creates a service whose binary is compiled for specified computer architecture','64': 'ROpenSCManager2 : establishes a connection to server and opens the SCM database'}
# define interesting events:
# include all opnums, only a few seem to be no really interesting, including them seems to be acceptable
#smb_svcctl_extendList = [0,1,2,5,6,7,11,12,13,14,15,16,17,19,20,21,23,24,25,26,27,28,29,30,31,32,33,35,36,37,38,39,40,41,42,44,45,47,49,50,51]
#
# ATSVC
# smb.cmd == 0x25 AND (atsvc.opnum == ...)
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931 -> see section 3.2.5.2
smb_atsvc_dict = {'0': 'NetrJobAdd : adds single AT task to task store','1': 'NetrJobDel : deletes specified range of tasks from task store','2': 'NetrJobEnum : get enumeration of all AT tasks on specified server','3': 'NetrJobGetInfo : get information for a specified ATSvc task'}

# smb2.ioctl.function -> https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5c03c9d6-15de-48a2-9835-8fb37f8a79d8 see ctlCode  guessing-> ioctl is like trans2
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/efbfe127-73ad-4140-9967-ec6500e66d5e
# don't use caps in keys for characters, they will not match!
smb2_ioctl_function_dict = {'0x00060194':'FSCTL_DFS_GET_REFERRALS : request distributed file system referrals','0x0011400c':'FSCTL_PIPE_PEEK : requests server to copy named pipe\'s data into returned buffer (for preview) without removing it','0x00110018':'FSCTL_PIPE_WAIT : requests server to wait until a time-out elapses or for an instance of the specified named pipe is available for connection','0x0011c017':'FSCTL_PIPE_TRANSCEIVE : send and receive data from an open pipe','0x001440f2':'FSCTL_SRV_COPYCHUNK : server-side data movement, aka copy data with server and destination on the same server','0x00144064':'FSCTL_SRV_ENUMERATE_SNAPSHOTS : enumerate available previous versions for a share','0x00140078':'FSCTL_SRV_REQUEST_RESUME_KEY : retrieve an opaque file reference for use with the IOCTL_COPYCHUNK','0x001441bb':'FSCTL_SRV_READ_HASH : retrieve data from the Content Information File associated with a specified file','0x001480f2':'FSCTL_SRV_COPYCHUNK_WRITE : server-side data movement, aka copy data with server and destination on the same server','0x001401d4':'FSCTL_LMR_REQUEST_RESILIENCY : request resilient/durable handle for specified open file, handle survives a short network outage','0x001401fc':'FSCTL_QUERY_NETWORK_INTERFACE_INFO : query network info from server','0x000900a4':'FSCTL_SET_REPARSE_POINT : Sets a reparse point on a file or directory.Reparse point: An attribute that can be added to a file to store a collection of user-defined data that is opaque to NTFS or ReFS.','0x000601b0':'FSCTL_DFS_GET_REFERRALS_EX : request distributed file system referrals'}
# Durable file handles allow a connection to an SMB server to survive a short network outage; resilient file handles are durable file handles opened by a IOCTL request

smb2_cmd_dict = {'0x00':'smb2_negotiation','0x01':'smb2_session_establishment','0x02':'smb2_logoff','0x03':'smb2_tree_connect','0x04':'smb2_tree_disconnect','0x05':'smb2_open_file','0x06':'smb2_close_file','0x07':'smb2_flush','0x08':'smb2_read_file','0x09':'smb2_write_file','0x0a':'smb2_locking','0x0b':'smb2_ioctl','0x0c':'smb2_cancel','0x0d':'smb2_echo','0x0e':'smb2_find','0x0f':'smb2_change_notify','0x10':'smb2_query_info','0x11':'smb2_set_info','0x12':'smb2_oplock_break'}
smb2_share_type_dict = {'0x00000001':'Physical Disk','0x00000002':'Named Pipe'}

#smb create action:  0 -> extsted,deleted and new created (FILE_SUPERSEDED), 1 -> existed & opened(FILE_OPENED), 2-> didn't exist & created(FILE_CREATED), 3 existed & truncated/overwritten(FILE_OVERWRITTEN)
create_action_dict = {'0':'File existed, deleted and new created','1':'File existed & opened','2':'new File created and opened','3':'File existed & overwritten'}

smb_cmd_dict = {'0x01':'smb_delete_directory', '0x04':'smb_close_file', '0x05':'smb_flush_data', '0x06':'smb_delete_file', '0x07':'smb_rename', '0x10':'smb_check_directory', '0x24':'smb_locking', '0x25':'smb_transaction', '0x26':'smb_transaction_secondary', '0x2b':'smb_echo', '0x2e':'smb_read_file', '0x2f':'smb_write_file', '0x32':'smb_transaction2', '0x33':'smb_transaction2_secondary', '0x34':'smb_find_close', '0x71':'smb_tree_disconnect', '0x72':'smb_negotiation', '0x73':'smb_session_establishment', '0x74':'smb_logoff', '0x75':'smb_tree_connect', '0xa0':'smb_nt_transaction', '0xa1':'smb_nt_transaction_secondary', '0xa2':'smb_create_open_file', '0xa4':'smb_cancel', '0xc0':'smb_print_file', '0xfe':'smb_invalid', '0xff':'smb_NIL'}

# smb_trans2
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/a3f5183b-eedd-40e9-a13b-a4d80eec5d0b , https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/1cc40e02-aaea-4f33-b7b7-3a6b63906516
# 0xffffff -> no official code meaning unknown; example: request not in traffic, 
# smb_trans2 detailed parsing seems to be of limited use for timeline
smb_trans2_subcmd_dict = {'0x0000':'TRANS2_OPEN2 : open or create a file and set extended attributes','0x0001':'TRANS2_FIND_FIRST2 : search for file(s) within a directory or for a directory','0x0002':'TRANS2_FIND_NEXT2 : continues a search started by TRANS2_FIND_FIRST2','0x0003':'TRANS2_QUERY_FS_INFORMATION : request info about the object store underlying a share on the server','0x0004':'TRANS2_SET_FS_INFORMATION : cmd reserved but not implemented','0x0005':'TRANS2_QUERY_PATH_INFORMATION : request information about a specific file or directory via PATH','0x0006':'TRANS2_SET_PATH_INFORMATION : set the standard and extended attribute information of a specific file or directory on target via PATH string','0x0007':'TRANS2_QUERY_FILE_INFORMATION : request information about a specific file or directory via FID','0x0008':'TRANS2_SET_FILE_INFORMATION : set the standard and extended attribute information of a specific file or directory on the target via FID','0x0009':'TRANS2_FSCTL : cmd reserved but not implemented','0x000A':'TRANS2_IOCTL2 : cmd reserved but not implemented','0x000B':'TRANS2_FIND_NOTIFY_FIRST : cmd is obsolete','0x000C':'TRANS2_FIND_NOTIFY_NEXT : cmd is obsolete','0x000D':'TRANS2_CREATE_DIRECTORY : create a new directory and can be used to set extended attribute information','0x000E':'TRANS2_SESSION_SETUP : cmd is reserved but not implemented','0x0010':'TRANS2_GET_DFS_REFERRAL : identify the actual share on a server that has accessed the leaf component of the DFS path by getting a referral','0x0011':'TRANS2_REPORT_DFS_INCONSISTENCY : cmd is reserved but not implemented'}
# SMB Extended attributes: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/6008aa8f-d2d8-4366-b775-b81aece05bb1

# MACB lists for sub-protocols
opnum_samr_m_list = [2,9,21,22,23,24,26,29,30,31,32,35,37,38,45,52,53,54,55,58,66]
opnum_samr_a_list = [3,5,6,7,8,11,13,15,16,17,18,19,20,25,27,28,33,34,36,39,40,41,44,46,47,48,49,51,56,65]
opnum_samr_b_list = [10,12,14,50]

opnum_lsarpc_m_list = [4,8,19,20,24,27,29,34,37,38,40,41,42,47,49,54,74]
opnum_lsarpc_a_list = [2,3,6,7,11,13,17,18,23,25,26,28,30,31,32,33,35,36,39,43,44,46,48,50,53,55,73]
opnum_lsarpc_b_list = [10,12,16,51,59]

opnum_srvsvc_m_list = [17,18,19,22,25,27,37,38,40,41,45,46,49,50,51,53,54,56,57]
opnum_srvsvc_a_list = [8,9,10,12,15,16,20,21,23,24,26,28,30,31,32,33,34,35,36,39,43,52,55]
opnum_srvsvc_b_list = [14,44,48]

opnum_wkssvc_m_list = [1,6,7,22,23,24,27,28,29]
opnum_wkssvc_a_list = [0,2,5,9,11,13,20,25,26,30]
opnum_wkssvc_b_list = ['NO','CREATION/BIRTH','AT','THE','MOMENT']

opnum_winreg_m_list = [7,8,11,18,19,21,22,23,35]
opnum_winreg_a_list = [0,1,2,3,4,9,10,12,15,16,17,26,27,29,32,33,34]
opnum_winreg_b_list = [6,13,20,31]

opnum_svcctl_m_list = [1,2,5,7,11,19,23,31,36,37,47,49,50,51]
opnum_svcctl_a_list = [4,6,9,13,14,16,17,18,20,21,25,26,28,29,30,32,33,35,38,39,40,41,42,48,56]
opnum_svcctl_b_list = [12,24,44,45,60]

opnum_atsvc_m_list = [1]
opnum_atsvc_a_list = [2,3]
opnum_atsvc_b_list = [0]


#########################################################################################################################################################################
#																			open TODOS																					#
#########################################################################################################################################################################

#this version:

# TODO next version:
## TODO: implement parse at parameter.. which will be forwarded to tshark
### tshark -d tcp.port==8888,http Decodes tcp port 8888 as http traffic
## TODO: smb1
### smb.old_file -> filled when files are renamed.. new file name in smb.file => 0x07
# TODO: check timesketch export https://github.com/google/timesketch/blob/master/docs/CreateTimelineFromJSONorCSV.md
# TODO: samr traffic capture RID to names, for enrichment?
# TODO: visualization
# TODO: smb_pipe, use cases
# TODO: continue smb2_ioctl_function_dict research and adding Name: explanation form => might be not useful at the given time.
# TODO: extended output, just smb2 openfile responses, not their requests
#-> yes only done on packets with characteristics in responses... think about how to extend to request packet.

#maybe:
#TODO:
## maybe: reduce read & write requests to a single line?
## smb2.cmd == 0x10 -> smb2.class and smb2.file_info.infolevel could it enable us to find out which infos were requested and do we want to know that? -> not really interesting in a specific meaning, as filename will be included.
## if smb2.cmd == 0x11 is interesting, same files as smb2.cmd == 0x10, 0x11 is setInfo
## smb2.file_info.infolevel -> https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4718fc40-e539-4014-8e33-b675af74e3e1 # wireshark shows hex, site shows dec
## smb2.class -> https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ee9614c4-be54-4a3c-98f1-769a7032a0e4 -> InfoType 0x01:SMB2_0_INFO_FILE, 0x02:SMB2_0_INFO_FILESYSTEM, 0x03:SMB2_0_INFO_SECURITY, 0x04:SMB2_0_INFO_QUOTA

# TODO: smb2.fsctl.wait.name for FSCTL_PIPE_WAIT includes name to the pipe... like psexecsvc..?

#########################################################################################################################################################################
#																			imports																						#
#########################################################################################################################################################################

# imports
try:
	import subprocess
	import csv
	from sys import platform
	import time,datetime
	import getopt,sys,os
	import re
	from collections import defaultdict
	import copy
	import json
	import traceback
	#import time
except Exception as e:
	print("missing module: ")
	print(e)
	exit(1)

#version string
smbtimelineversion = '0.1000'

# define os we are running on; if false we are running on Windows, else we are running Linux
os_linux = True

user_dict = {}
domain_dict = {}
host_dict = {}
fname_packet_dict = {}
fname_fid_dict = {}
packet_to_fid_dict = {}
service_info_dict = {} # format: frame.number + service_info string -> used to extend service_info string from request to response
registry_info_dict = {} # format: frame.number + registry_info string -> used to extend registry_info string from request to response
wsInfoColumnDict = {}


# control parameter:
smb1 = False
smb2 = False
strip = False
clean = True
use_json = True
defaults = False
remove_striped = False
wsInfoColumn = False
l2toutput_file = ''
wp = ''
inputfile = ''
inputfile_o = ''
l2tputput = ''

# smb filter definition:
smb_filter = "smb and ( (smb.cmd == 0x72) or (smb.cmd == 0x73) or (smb.cmd == 0x75) or (smb.cmd == 0xa2) or (smb.cmd == 0x24) or (smb.cmd == 0x2e) or (smb.cmd == 0x04) or  (smb.cmd == 0x71) or (smb.cmd == 0x74) or (smb.cmd == 0x2f) or (smb.cmd == 0x01) or (smb.cmd == 0x06) or (smb.cmd == 0x07) or (smb.cmd == 0x25) or (smb.cmd == 0x26) or (smb.cmd == 0x32) or (smb.cmd == 0x33) or (smb.cmd == 0xa0)  or (smb.cmd == 0xa1) or (smb.cmd == 0x10))"
# smb commands: https://msdn.microsoft.com/en-us/library/ee441741.aspx, https://msdn.microsoft.com/en-us/library/ee441616.aspx
# only currently used commands were considered.
# commands not in thark filter: '0x05':'smb_flush_data','0x2b':'smb_echo', '0x34':'smb_find_close', '0xa4':'smb_cancel', '0xc0':'smb_print_file', '0xfe':'smb_invalid', '0xff':'smb_NIL' 

# smb2 filter definition:
# https://msdn.microsoft.com/en-us/library/cc246528.aspx, https://msdn.microsoft.com/en-us/library/cc246482.aspx
#smb2 will also cover smb3 
# https://wiki.wireshark.org/SMB2
## see section "SMB2 Opcodes"
#commands not in tshark filter:
# smb2.cmd == 0x0c SMB2/Cancel # smb2.cmd == 0x0d SMB2/KeepAlive # smb2.cmd == 0x0f SMB2/Notify # smb2.cmd == 0x12 SMB2/Break

smb2_filter = "smb2 and ( (smb2.cmd == 0x00) or (smb2.cmd == 0x01) or (smb2.cmd == 0x02) or (smb2.cmd == 0x03) or (smb2.cmd == 0x04) or (smb2.cmd == 0x05) or (smb2.cmd == 0x06) or (smb2.cmd == 0x07) or (smb2.cmd == 0x08) or (smb2.cmd == 0x09) or (smb2.cmd == 0x0a) or (smb2.cmd == 0x0b) or (smb2.cmd == 0x0e) or (smb2.cmd == 0x10) or (smb2.cmd == 0x11))"


#########################################################################################################################################################################
#																			Functions																					#
#########################################################################################################################################################################

#function to print usage info
def usage():
	print ("Usage: ")
	print ("-f, --file <PATH> \n\tPath to pcap file containing traffic to analyze, mandatory parameter")
	print ("-2, --smb2 \n\tSMB modus: create a timeline for SMB2 and SMB3 traffic, non mandatory parameter, default active if no parameter for SMB modus is given. Output will be stored in current working directory: timeline_smb2.csv")
	print ("-1, --smb1 \n\tSMB modus: create a timeline for SMB1 traffic, non mandatory parameter, default not active if no parameter for SMB modus is given. Output will be stored in current working directory: timeline_smb1.csv")
	print ("-p, --protocol <PATH> \n\tPath to protocol file, non mandatory parameter, if not given no protocol will be written.")
	print ("-e, --extended <PATH> \n\tPath to file, non mandatory parameter, if given a combined timeline in log2timeline format will be created")
	print ("-s, --strip \n\tstrip traffic and create a new pcap only containing smb traffic, see code or protocol in regards to used bpf (filter).\n\t\tThe resulting pcap file will not be deleted, frame.number values from timelines will not match the original pcap file if -s is used. If you want to lookup more details for frames, use the pcap \"pcap_stripped_TIMESTAMP.pcap\" (TIMESTAMP format: YearMonthDayHourMinute). In this file the frame.numbers will match with the timelines.")
	print ("-d, --deletestriped \n\tif -s is given the stripped pcap will be deleted. This will not allow you to match frame.number from the timelines in the original pcap file.")
	print ("-n, --noclean \n\tdo not clean created tmp files, exception: tmp pcap file written by option -s")
	print ("-i, --infoColumn \n\tAdds the wireshark info column to the timeline. This step needs some extra processing time.")
	print ("-c, --csv \n\tuse csv output of tshark instead of json. This mode is deprecated since version 0.1000 and will no longer be updated.")
	print ("-h, --help \n\tPrints this usage info and exits.")

#
# Function to check if system script is running on is Windows or not. function sets global os_linux variable to False if Windows, otherwise
# os_linux will be True
#
def checkos ():
	global os_linux
	global wp
	global writetoprotocol
	print("checking os")
	if platform == "win32":
		os_linux = False
	if wp:
		writetoprotocol('\n################# Platform identified by python to run smbtimeline ##################\n')
		writetoprotocol(platform + '\n')
		writetoprotocol('\n#####################################################################################\n')

#
# Function to check if tshark is in path, if not script will fail with exit code 1 and print out an error message
# checkos() needs to be run fist to determine OS script is running on
#
def checktshark ():
	print("checking for tshark")
	try:
		command = ['tshark', '-v']  # the shell command
		process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None)
		#output, error = process.communicate()
		if wp:
			# write complete output to protocol, it includes which windows and other tool versions are used/important
			writetoprotocol('\n########################## Tshark/Wireshark/OS Version used #########################\n')
			#writetoprotocol(output + '\n')
			writetoprotocol(process.stdout.read().decode('UTF-8') + '\n')
			writetoprotocol('\n#####################################################################################\n')
	except Exception as e:
		print ("error while testing for tshark in path:")
		print (e)
		print(traceback.format_exc())
		exit(1)
			
#
# Function to check if tcpdump or windump is in path, if not script will fail with exit code 1 and print out an error message
# checkos() needs to be run fist to determine OS script is running on
#
def checkdump ():
	print("checking for tcpdump/windump")
	global os_linux
	try:
		if os_linux:
			command = ['tcpdump', '-D']  # the shell command
		else:
			command = ['windump', '-D']  # the shell command
		process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None)
		output, error = process.communicate()
		if wp:
			writetoprotocol('\n################################## tcpdump/windump ##################################\n')
			writetoprotocol('found tcpdump or windump in path; execution successful \n')
			writetoprotocol('\n#####################################################################################\n')
		#print (output)
	except Exception as e:
		print ("error while testing for tcpdump or windump in path:")
		print (e)
		print(traceback.format_exc())
		exit(1)

#
# Function to strip traffic and create a new pcap only containing smb traffic
# Parameter pcap_source pcap file to be stripped down
# Return name of stripped pcap
#
def stripPCAP (pcap_source):
	print("stripping smb traffic from given pcap")
	start_time = time.time()
	global os_linux
	global wp
	newpcap = 'pcap_stripped' + datetime.datetime.now().strftime("%Y%m%d%I%M") + '.pcap'
	dumpfilter = '(port 445 or portrange 137-139)'
	# smb ports:
	# direct host smb TCP port 445
	# Via NetBIOS API UDP ports 137, 138 & TCP ports 137, 139 (NetBIOS over TCP/IP)
	if wp:
			writetoprotocol('\n############################## tcpdump/windump filter ###############################\n')
			writetoprotocol('Original pcap was filtered with the following filter: ' + dumpfilter + ' .\n')
			writetoprotocol('This should be a good enough filter to strip down a large pcap before running it \n')
			writetoprotocol('through tshark and do the heavy lifting and dissect the traffic.\n')
			writetoprotocol('pcap file written to: '+ newpcap +'\n')
			writetoprotocol('\n#####################################################################################\n')
	if os_linux:
		command = ['tcpdump', '-r', pcap_source, '-w', newpcap, '-s', '0', '-n', dumpfilter ]  # the shell command
	else:
		command = ['windump', '-r', pcap_source, '-w', newpcap, '-s', '0', '-n', dumpfilter ]  # the shell command
			
	#process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None)
	process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	output, error = process.communicate()	
	stop_time = time.time()
	elapsed = stop_time - start_time
	h = int(elapsed//3600)
	m = int((elapsed%3600) // 60)
	s = int((elapsed%3600)%60)
	temp_durations = "total time: %d:%d:%d (hh:mm:ss)" %(h,m,s)
	print(temp_durations)
	if wp:
		writetoprotocol('\n##################################### stripPCAP #####################################\n')
		writetoprotocol('\n############################ ' + temp_durations + ' ############################\n')
		
	return newpcap

#		
# function to run tshark filer, deprecated function -> replaced by tsharkfilter_json
# Parameter inputfile: input pcap 
# Parameter filter: the tshark filter which should be used with tshark
# 					example: tsharkfilter("smb.cmd == 0x73")
# Parameter filepath: the filepath where csv output will be written to
# Parameter filtername: the filtername decides which output fields will be used
#
def tsharkfilter (inputfile,filter,filepath,filtername):
	global wp
	print("running filter: " + filtername + " (this can take a while, be patient)")
	start_time = time.time()
	# '-E', 'separator=/t', '-E', 'quote=d', '-E', 'header=y'
	# we generate one csv file per filter, depenting on the filtername provides
	if filtername == "smb_filter":
		command = ['tshark', '-n', '-r', inputfile , '-E', 'separator=,', '-E', 'quote=d', '-E', 'header=y', '-Y', filter,  '-T', 'fields', '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'eth.src', '-e', 'eth.dst', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.srcport', '-e', 'tcp.dstport', '-e', 'udp.dstport', '-e', 'udp.srcport', '-e', 'smb.cmd', '-e', 'smb.mid', '-e', 'smb.uid', '-e', 'smb.pid', '-e', 'smb.tid', '-e', 'smb.account', '-e', 'ntlmssp.auth.username', '-e', 'ntlmssp.auth.domain' , '-e' , 'smb.primary_domain' , '-e', 'ntlmssp.auth.hostname' , '-e', 'smb.path', '-e', 'smb.file', '-e', 'smb.fid', '-e', 'smb.create.action', '-e', '_ws.col.Info', '-e', 'smb.response_to', '-e', 'tcp.stream', '-e', 'smb.dir_name', '-e', 'smb.search_pattern', '-e' , 'srvsvc.opnum', '-e' , 'wkssvc.opnum', '-e' , 'winreg.opnum', '-e' , 'svcctl.opnum', '-e' , 'atsvc.opnum', '-e','smb.trans2.cmd', '-e','svcctl.displayname', '-e', 'svcctl.servicename', '-e', 'atsvc.atsvc_JobInfo.command', '-e' , 'srvsvc.srvsvc_NetShareInfo2.name', '-e' , 'srvsvc.srvsvc_NetShareInfo2.path', '-e' , 'srvsvc.srvsvc_NetShareDel.share_name', '-e' , 'lsarpc.opnum', '-e' , 'samr.opnum', '-e','winreg.winreg_OpenKey.keyname', '-e','winreg.winreg_CreateKey.name', '-e','winreg.winreg_LoadKey.keyname', '-e','winreg.winreg_QueryValue.value_name', '-e','winreg.winreg_SetValue.name', '-e','winreg.winreg_DeleteValue.value','-e', 'smb_netlogon.user_name', '-e', 'smb_netlogon.unicode_computer_name', '-e', 'winreg.QueryMultipleValue.ve_valuename' , '-e', 'winreg.winreg_EnumKey.name' , '-e', 'winreg.winreg_EnumValue.name','-e', 'smb_netlogon.domain_name']  # the shell command
		if wp:
			writetoprotocol('\n######## SMB1: Tshark/Wireshark Filter -> SMB1 commands included in timeline ########\n')
			writetoprotocol(filter + '\n')
			writetoprotocol('\n#####################################################################################\n')
	elif filtername == "smb2_filter":
		command = ['tshark', '-n', '-r', inputfile , '-E', 'separator=,', '-E', 'quote=d', '-E', 'header=y', '-Y', filter, '-T', 'fields', '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'eth.src', '-e', 'eth.dst', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.srcport', '-e', 'tcp.dstport', '-e', 'udp.dstport', '-e', 'udp.srcport', '-e', 'smb2.cmd', '-e', '_ws.col.Info', '-e', 'ntlmssp.auth.username', '-e', 'ntlmssp.auth.domain' , '-e', 'ntlmssp.auth.hostname' , '-e', 'smb2.pid' , '-e', 'smb2.tid' , '-e', 'smb2.acct' , '-e', 'smb2.domain' , '-e', 'smb2.host' , '-e', 'smb2.sesid' , '-e', 'smb2.filename' , '-e', 'smb2.tree' , '-e', 'smb2.fid' , '-e', 'smb2.create.action' , '-e', 'smb2.share_type', '-e', 'smb2.response_to', '-e', 'tcp.stream', '-e', 'smb2.find.pattern', '-e' , 'srvsvc.opnum', '-e' , 'wkssvc.opnum', '-e' , 'winreg.opnum', '-e' , 'svcctl.opnum', '-e' , 'atsvc.opnum', '-e','svcctl.displayname', '-e', 'svcctl.servicename', '-e', 'atsvc.atsvc_JobInfo.command', '-e' , 'srvsvc.srvsvc_NetShareInfo2.name', '-e' , 'srvsvc.srvsvc_NetShareInfo2.path', '-e' , 'srvsvc.srvsvc_NetShareDel.share_name', '-e', 'smb2.ioctl.function', '-e' , 'lsarpc.opnum', '-e' , 'samr.opnum', '-e','winreg.winreg_OpenKey.keyname', '-e','winreg.winreg_CreateKey.name', '-e','winreg.winreg_LoadKey.keyname', '-e','winreg.winreg_QueryValue.value_name', '-e','winreg.winreg_SetValue.name', '-e','winreg.winreg_DeleteValue.value','-e', 'smb_netlogon.user_name', '-e', 'smb_netlogon.unicode_computer_name', '-e', 'winreg.QueryMultipleValue.ve_valuename' , '-e', 'winreg.winreg_EnumKey.name' , '-e', 'winreg.winreg_EnumValue.name','-e', 'smb_netlogon.domain_name']  # the shell command
		if wp:
			writetoprotocol('\n####### SMB2/3: Tshark/Wireshark Filter -> SMB2 and SMB3 commands included in timeline #######\n')
			writetoprotocol(filter + '\n')
			writetoprotocol('\n#####################################################################################\n')
	
	else:
		print ("UNKNOWN FILTERNAME")
		exit(1)

	process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	#04.11 FIX
	f = open(filepath,"w",encoding='UTF-8')
	#output, error = process.communicate()
	#for aline in output:
	#	f.write(aline)
	while True:
		line = process.stdout.readline().decode('UTF-8')
		if line != '':
			f.write(line)
		else:
			break
	f.close()
	stop_time = time.time()
	elapsed = stop_time - start_time
	h = int(elapsed//3600)
	m = int((elapsed%3600) // 60)
	s = int((elapsed%3600)%60)
	temp_durations = "total time: %d:%d:%d (hh:mm:ss)" %(h,m,s)
	print(temp_durations)
	if wp:
		writetoprotocol('\n##################################### tsharkfilter #####################################\n')
		writetoprotocol('\n############################ ' + temp_durations + ' ############################\n')
	# TODO: read process.stderr.readline().decode('UTF-8') and write to protocol

#
# function to run tshark filer using json output of tshark
# json output can be combined with -e fieldnames -> this output loses the capability to exactly match commands and parameters in case of two smb commands in one frame
# Parameter inputfile: input pcap 
# Parameter filter: the tshark filter which should be used with tshark
# 					example: tsharkfilter("smb.cmd == 0x73")
# Parameter filepath: the filepath where json output will be written to
# Parameter filtername: will be used to write current processed filter to the protocol. Can be either smb_filter oder smb2_filter.
#
def tsharkfilter_json(inputfile,filter,filepath,filtername):
	global wp
	print("running filter: " + filtername + " (this can take a while, be patient)")
	start_time = time.time()
	if filtername == "smb_filter":
		if wp:
			writetoprotocol('\n######## SMB1: Tshark/Wireshark Filter -> SMB1 commands included in timeline ########\n')
			writetoprotocol(filter + '\n')
			writetoprotocol('\n#####################################################################################\n')	
	elif filtername == "smb2_filter":
		if wp:
			writetoprotocol('\n####### SMB2/3: Tshark/Wireshark Filter -> SMB2 and SMB3 commands included in timeline #######\n')
			writetoprotocol(filter + '\n')
			writetoprotocol('\n#####################################################################################\n')
	else:
		print('UNKNOWN FILTERNAME')
		exit(1)
	
	# run tshark command and write output to filepath
	command = ['tshark', '-n', '-r', inputfile , '-Y', filter , '-T', 'json']
	process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	f = open(filepath,"w", encoding="utf-8")
	while True:
		line = process.stdout.readline().decode('UTF-8')
		if line !='':
			f.write(line)
		else:
			break
		
	f.close()
	
	stop_time = time.time()
	elapsed = stop_time - start_time
	h = int(elapsed//3600)
	m = int((elapsed%3600) // 60)
	s = int((elapsed%3600)%60)
	temp_durations = "total time: %d:%d:%d (hh:mm:ss)" %(h,m,s)
	print(temp_durations)
	if wp:
		writetoprotocol('\n################################## tsharkfilter_json ##################################\n')
		writetoprotocol('\n############################ ' + temp_durations + ' ############################\n')

#
# helper method used as object_pairs_hook for native json.load method
# usualy all json entries are parsed to a dict. the problem in this case is, a python dict can not have duplicate keys.
# the json given by tshark contains duplicate keys in case of multiple smb commands. without this helper function only on header and one smb command will be present in the parsed json dicts.
# this functions solves this issue by putting dublicate keys into a list 
# the result is that the smb section in now a list of dicts containing the headers and smb command sections.
# array_on_duplicate_keys
# probs to: https://stackoverflow.com/questions/14902299/json-loads-allows-duplicate-keys-in-a-dictionary-overwriting-the-first-value
# Parameter ordered_pairs: given by native json library
## example:
## >>> print (p[0].get('_source').get('layers').keys())
## dict_keys(['nbss', 'tcp', 'frame', 'eth', 'ip', 'smb2'])
## print (p[0].get('_source').get('layers').get('smb2')[0])
## {'SMB2 Header': {'smb2.credits.requested': '1', ...'smb2.tid': '0x00000005'}, 'Create Request (0x05)': {'smb2.filename_tree': {'smb2.olb.length':..., 'smb2.create.chain_offset': '0x00000000'}}}}
## >>> print (p[0].get('_source').get('layers').get('smb2')[0].keys())
## dict_keys(['SMB2 Header', 'Create Request (0x05)'])
## >>> print (p[0].get('_source').get('layers').get('smb2')[1])
def aodk(ordered_pairs):
	d = {}
	for k,v in ordered_pairs:
		if k in d:
			if type(d[k]) is list:
				d[k].append(v)
			else:
				d[k] = [d[k],v]
		else:
			d[k] = v
	return d
		
#
# function to read json file and write csv timeline output file, this functions also ensures that smb packets carrying multiple smb commands are treated in the correct way.
# for each smb command, the method handle_packet will be called, this will result in one timeline row per smb command, even if it was send in one single frame. Only the smb part is split, the rest of the packet data, like
# frame.number etc will still be present in packet object. In oder to parse multiple smb commands to a list instead of a dict (with missing values) the help function aodk is key.
# Parameter infile: the filepath where json input will be read from
# Parameter timelinewriter: csv Dictwriter object to write output to
# Parameter filtername: will be added to csv to help identify filter used to get data
def parseJSON (infile,timelinewriter,filtername):
	global wp
	print("parsing tshark json to timeline for " + filtername)
	start_time = time.time()
	if filtername == "smb_filter" or filtername == "smb2_filter":
				
		try:
			fp = open(infile,'r',encoding='utf-8')
			packets = json.load(fp,object_pairs_hook=aodk)
			#packets are in order of their appearance in the json file. This order represents the occurrence in the pcap aka ordered by frame.number
			# in case of any sorting problems the following line sorts the packets based on frame.number
			#packets.sort(key= lambda x:int(x['_source']['layers']['frame']['frame.number']))
			##for DEBUUGING: check sorting and exit
			##for pkt in packets:
			##	print(pkt['_source']['layers']['frame']['frame.number'])
			##exit(0)
			
			#packets = json.load(fp,object_pairs_hook=aodk)
			for pkt in packets:
				# each pkt is a dict containing the packet, if duplicate entries are present (like multiple smb commands) they are stored as list (see method aodk)
				# we need to check if the smb section is a list or a dict
				# check for smb2:
				if ('smb2' in pkt.get('_source').get('layers')):
					if isinstance(pkt.get('_source').get('layers').get('smb2'),list):
						#multiple smb commands because smb2 is of type list, we need to get get the list from the dict, loop over all entries and put a single entry back into the pkt object and call handle packet
						# removes the smb command list from packet dict
						smbcmd_list = pkt.get('_source').get('layers').pop('smb2')
						# loop over smbcmd_list entries and set one single entry (smb cmd + header) at key "smb2" and call handle packet
						# for every entry in smbcmd_list the handle packet function will be called. 
						for smbc in smbcmd_list:
							pkt.get('_source').get('layers').__setitem__('smb2',smbc)
							# DEBUG
							#print(type(pkt.get('_source').get('layers').get('smb2')))
							#print(pkt.get('_source').get('layers').get('smb2').keys())
							#print(pkt.get('_source').get('layers').get('frame').get('frame.number'))
							handle_packet(pkt,filtername,timelinewriter)
							del pkt.get('_source').get('layers')['smb2'] # clean for next entry in the loop
					else:
						handle_packet(pkt,filtername,timelinewriter)
				# check for smb1:
				elif ('smb' in pkt.get('_source').get('layers')):
					if isinstance(pkt.get('_source').get('layers').get('smb'),list):
						#multiple smb commands because smb is of type list, we need to get get the list from the dict, loop over all entries and put a single entry back into the pkt object and call handle packet
						# removes the list from packet dict
						smbcmd_list = pkt.get('_source').get('layers').pop('smb')
						# loop over smbcmd_list entries and set one single entry (smb cmd + header) at key "smb" and call handle packet
						for smbc in smbcmd_list:
							pkt.get('_source').get('layers').__setitem__('smb',smbc)
							handle_packet(pkt,filtername,timelinewriter)
							del pkt.get('_source').get('layers')['smb'] # clean for next entry in the loop
					else:
						handle_packet(pkt,filtername,timelinewriter)
				else:
					# nothing to do should not be the case.
					print("Error unable to determine smb type of packet")
					print("frame number:" + pkt.get('_source',{}).get('layers',{}).get('frame',{}).get('frame.number', ''))
					exit(1)

		except Exception as e:
			print ("error parsing json input file " + infile + " , make sure it is formatted correctly")
			print(e)	
			print(traceback.format_exc())
	else:
		print("Unknown filter_name in normalizeCSV function")
		print("Exiting without cleanup")
		exit(1)
	stop_time = time.time()
	elapsed = stop_time - start_time
	h = int(elapsed//3600)
	m = int((elapsed%3600) // 60)
	s = int((elapsed%3600)%60)
	temp_durations = "total time: %d:%d:%d (hh:mm:ss)" %(h,m,s)
	print(temp_durations)
	if wp:
		writetoprotocol('\n##################################### parseJSON #####################################\n')
		writetoprotocol('\n############################ ' + temp_durations + ' ############################\n')
		

#
# function to create a dict containing framenumber and wireshark info field
# Parameter infile: pcap
# Return: dict containing frame.number and wireshark's info field
def createInfoFieldDict (infile):
	from collections import OrderedDict
	global wp
	print("Generating tmp wireshark info column dict")
	start_time = time.time()
	infofieldDict = {}
	command = ['tshark', '-n', '-r', infile , '-E', 'separator=,', '-E', 'quote=d', '-T', 'fields', '-e', 'frame.number', '-e', '_ws.col.Info']  # the shell command
	process2 = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	while True:
		line = process2.stdout.readline().decode('UTF-8')
		if line != '':
			# splint line on first occurance of , into frame.number as key and info cloumn as valuse
			list_line = line.split(',',1)
			# remove starting and trailing " from key
			key = list_line[0][+1:-1]
			# remove starting and trailing "linefeed from key
			infofieldDict[key] = list_line[1][+1:-2]
		else:
			break
	stop_time = time.time()
	elapsed = stop_time - start_time
	h = int(elapsed//3600)
	m = int((elapsed%3600) // 60)
	s = int((elapsed%3600)%60)
	temp_durations = "total time: %d:%d:%d (hh:mm:ss)" %(h,m,s)
	print(temp_durations)
	if wp:
		writetoprotocol('\n########################### create wireshark info colomn ###########################\n')
		writetoprotocol('\n_ws.col.Info Field will be matched by frame.number and added to timeline \n')
		writetoprotocol('\n############################ ' + temp_durations + ' ############################\n')

	return infofieldDict

#
# function handles on parsed packet (dict) from json output and writes up to n rows to timeline csv file
# Parameter packet: the packet dict object
# Parameter filtername: current running filter
# Parameter timelinewriter: csv writer object, will be used to write parsed rows into timeline
def handle_packet(packet,filtername,timelinewriter):
	global wp
	global wsInfoColumn
	global wsInfoColumnDict
	# for each packet we initialize the row object, no values left from previous packet (execpt via specific *_dicts (like user_dict etc.)
	row = {}
	
	smbv = 1
	# get packet data 
	p = packet.get('_source','')
	# get frame dict
	pf = p.get('layers',{}).get('frame','')
	# get ip dict
	pi = p.get('layers',{}).get('ip','')
	# get ethernet dict
	pe = p.get('layers',{}).get('eth','')
	# get transport (tcp or udp dict)
	## get protocol (tcp/udp) dict
	if('tcp'in p['layers']):
		pp = p['layers']['tcp']
	elif('udp'in p['layers']):
		pp = p['layers']['udp']
	else:
		pp = {}
		if wp:
			writetoprotocol('unable to determine transport protocol for packet: ' + pf.get('frame.number','') + ' setting empty source and destination port')

	# get smb or smb2 dict
	if('smb2' in p['layers']):
		#smb version 2 or3
		smbv = 2
		# ps object is normal dict if no duplicate entries (multiple smb commands per packet) were found while parsing.
		# if multiple commands where present, it is a list object!
		ps = p['layers']['smb2']
	if('smb' in p['layers']):
		smbv = 1
		ps = p['layers']['smb']
		
	#set data in row dict
	row['frame.number'] = pf.get('frame.number', '')
	tmp_time = pf.get('frame.time_epoch','')
	if(len(tmp_time) > 0):
		tmp_datetime = datetime.datetime.utcfromtimestamp(float(pf['frame.time_epoch']))
		row['frame.date_epoch'] = tmp_datetime.strftime('%Y-%m-%d')
		row['frame.time_epoch'] = tmp_datetime.strftime('%H:%M:%S.%f')
	else:
		row['frame.date_epoch'] = ''
		row['frame.time_epoch'] = ''
	
	row['eth.src'] = pe.get('eth.src','')
	row['eth.dst'] = pe.get('eth.dst','')
	
	row['timezone'] = 'UTC'
	row['ip.src'] = pi.get('ip.src','')
	row['ip.dst'] = pi.get('ip.dst','')
	# either tcp or udp.*port will return nothing
	row['srcport'] = pp.get('tcp.srcport','') + pp.get('udp.srcport','')
	row['dstport'] = pp.get('tcp.dstport','') + pp.get('udp.dstport','')
	row['tcp.stream'] = pp.get('tcp.stream','')
	
	if wsInfoColumn:
		row['_ws.col.Info'] = wsInfoColumnDict.get(row['frame.number'],'')
	
	# End dealing with data which is related to the packet independent of potentially multiple smb commands per packet
	
	##### FIXME: doublecheck if this should be in the loop for smb commands
	
	# deal with winreg, 
	if('winreg' in p['layers']):
		# new row object per packet, keys will not contain values from packet before
		row['winreg.opnum'] = p.get('layers',{}).get('winreg',{}).get('winreg.opnum','')
		#loop needed
		for winreg_key,winreg_val in p.get('layers',{}).get('winreg','').items(): 
			if 'Keyname:' in winreg_key:
				for t_winreg_key,t_winreg_val in winreg_val.items():
					if 'Keyname:' in t_winreg_key:
						row['winreg.winreg_OpenKey.keyname'] = t_winreg_val.get('winreg.winreg_OpenKey.keyname','')
			if 'Name:' in winreg_key:
				for t_winreg_key,t_winreg_val in winreg_val.items():
					if 'Name:' in t_winreg_key:
						row['winreg.winreg_CreateKey.name'] = t_winreg_val.get('winreg.winreg_CreateKey.name','') # -> in Wireshark sample
						row['winreg.winreg_SetValue.name'] = t_winreg_val.get('winreg.winreg_SetValue.name','') # -> in wireshark sample
			if 'Value:' in winreg_key:
				for t_winreg_key,t_winreg_val in winreg_val.items():
					if 'Value:' in t_winreg_key:
						row['winreg.winreg_DeleteValue.value'] = t_winreg_val.get('winreg.winreg_DeleteValue.value','') # -> in Wireshark sample
			if 'Key:' in winreg_key:
				for t_winreg_key,t_winreg_val in winreg_val.items():
					if 'Key:' in t_winreg_key:
						row['winreg.winreg_DeleteKey.key'] = t_winreg_cal.get('winreg.winreg_DeleteKey.key','') # -> in Wireshark sample
			if 'Pointer to Value Name' in winreg_key:
				for t_winreg_key,t_winreg_val in winreg_val.items():
					if 'Value Name:' in t_winreg_key:
						for tt_winreg_key,tt_winreg_val in t_winreg_val.items():
							if 'Value Name' in tt_winreg_key:
								row['winreg.winreg_QueryValue.value_name'] = tt_winreg_val.get('winreg.winreg_QueryValue.value_name','') # -> smb.json
		
		
		# FIXME: no sample currently, if found set the corresponding value in row from packet, rest will be done in enrich opnum
		#row['winreg.QueryMultipleValue.ve_valuename'] = ''
		#row['winreg.winreg_LoadKey.keyname'] = ''
		#row['winreg.winreg_EnumKey.name'] = '' -> # in wireshark sample but no name...
		#row['winreg.winreg_EnumValue.name'] = '' # -> in wireshark sample but no name
		
	# deal with svcctl, 
	if('svcctl' in p['layers']):
		row['svcctl.opnum'] = p.get('layers',{}).get('svcctl',{}).get('svcctl.opnum','')
		# loop needed to extract displayname and servicename
		for svcctl_key,svcctl_val in p.get('layers',{}).get('svcctl','').items():
			if 'Service Name:' in svcctl_key:
				row['svcctl.servicename'] = svcctl_val.get('svcctl.servicename','')
			if 'Display Name:' in svcctl_key:
				row['svcctl.displayname'] = svcctl_val.get('svcctl.displayname','')

	# deal with atsvc
	if('atsvc' in p['layers']):
		row['atsvc.opnum'] = p.get('layers',{}).get('atsvc',{}).get('atsvc.opnum','')
		# jobInfo.command
		for atsvc_key,atsvc_val in p.get('layers',{}).get('atsvc','').items():
			if 'Pointer to Job Info' in atsvc_key:
				for t_atsvc_key,t_atsvc_val in atsvc_val.items():
					if 'Pointer to Command' in t_atsvc_key:
						row['atsvc.atsvc_JobInfo.command'] = t_atsvc_val.get('atsvc.atsvc_JobInfo.command','')

	# deal with srvsvc
	if('srvsvc' in p['layers']):
		row['srvsvc.opnum'] = p.get('layers',{}).get('srvsvc',{}).get('srvsvc.opnum','')
		netshareInfo2 = p.get('layers',{}).get('srvsvc',{}).get('srvsvc_NetShareInfo',{}).get('Pointer to Info2 (srvsvc_NetShareInfo2)',{}).get('srvsvc.srvsvc_NetShareInfo.info2',{})
		for t_netshareInfo2_key,t_netshareInfo2_val in netshareInfo2.items():
			if 'Pointer to Name' in t_netshareInfo2_key:
				row['srvsvc.srvsvc_NetShareInfo2.name'] = t_netshareInfo2_val.get('srvsvc.srvsvc_NetShareInfo2.name','')
			if 'Pointer to Path' in t_netshareInfo2_key:
				row['srvsvc.srvsvc_NetShareInfo2.path'] = t_netshareInfo2_val.get('srvsvc.srvsvc_NetShareInfo2.path','')
		row['srvsvc.srvsvc_NetShareDel.share_name'] = p.get('layers',{}).get('srvsvc',{}).get('srvsvc.srvsvc_NetShareDel.share_name', '')
		
		
		
	# deal with wkssvc
	if('wkssvc' in p['layers']):
		row['wkssvc.opnum'] = p.get('layers',{}).get('wkssvc',{}).get('wkssvc.opnum','')
		
	# deal with lsarpc
	if('lsarpc' in p['layers']):
		row['lsarpc.opnum'] = p.get('layers',{}).get('lsarpc',{}).get('lsarpc.opnum','')
		
	# deal with samr
	if('samr' in p['layers']):
		row['samr.opnum'] = p.get('layers',{}).get('samr',{}).get('samr.opnum','')
		
				
	##### END FIXME: doublecheck if this should be in the loop for smb commands
		
		
	# START dealing with smb specific data 
	
# if a packet carries more than 1 smb comment, it contains the corresponding amounts of header and smb command json entries. example: 2 smb commands -> {header1};{smb command1};{header2};{smb_sommand2}

	if(smbv == 1):
		# get header by name, header will be removed, so it does no longer need to be considered within the loop
		ps_header = ps.pop('SMB Header')
		# get values from header	
		# take 'smb.mid','smb.uid','smb.pid','smb.tid','smb.fid', from header
		row['smb.cmd'] = ps_header.get('smb.cmd','')
		row['smb_action'] = smb_cmd_dict.get(format(int(row['smb.cmd']),'#04x'),'Error parsing smb command')	
		row['smb.mid'] = ps_header.get('smb.mid','')
		row['smb.uid'] = ps_header.get('smb.uid','')
		row['smb.pid'] = ps_header.get('smb.pid','')
		row['smb.tid'] = ps_header.get('smb.tid','')
		# smb.tid_tree can contain empty string, need to test before
		if len(ps_header.get('smb.tid_tree','')) > 0:
			row['smb.path'] = ps_header.get('smb.tid_tree','').get('smb.path','')
		row['account'] = ps_header.get('smb2.sesid_tree',{}).get('smb2.acct','')
		row['smb.response_to'] = ps_header.get('smb.response_to','') 
		if len(row['smb.response_to']) > 0:
			row['status'] = "Response"
		else:
			row['status']  = "Request"
		
		#deal with smb_pipe 
		if('smb_pipe' in p['layers']):
			t_pipe = p.get('layers',{}).get('smb_pipe',{})
			if isinstance(t_pipe,dict):
				# smb_pipe can also be an empty string with will case an error as string object has no get Method...
				row['smb.file'] = t_pipe.get('smb.fid_tree',{}).get('smb.file','')
		
		for ps_entry_name, ps_entry in ps.items():
			# ps just carries stuff included in the smb part, header already processed and removed
			# non header entries -> values taken from header still are present in row object
			
			tmp_trans2_cmd = ''
			tmp_trans2_actionList = []
			tmp_trans2_cmd = ps_entry.get('smb.trans2.cmd','')
			# use tmp_trans2_cmd in smbtimeline field, if it is a smb_trans2 request
			if format(int(row['smb.cmd']),'#04x') == '0x32' and len(tmp_trans2_cmd) > 0:
				tmp_trans2_actionList = smb_trans2_subcmd_dict.get(format(int(tmp_trans2_cmd),'#06x'),format(int(tmp_trans2_cmd),'#06x')).split(':')
				if len(tmp_trans2_actionList) > 1:
					row['info'] = row.get('info','') + ' ' + tmp_trans2_actionList[1]
				row['smb_action'] = row['smb_action'] + ' ' + tmp_trans2_actionList[0]
			
			if len(row.get('smb.file',''))==0:
				row['smb.file'] = setsmbfilename(ps_entry,row)
			row['smb.create.action'] = create_action_dict.get(ps_entry.get('smb.create.action',''),'')
			row['smb.fid'] = ps_entry.get('smb.fid','')
			row['account'] = ps_entry.get('smb.account','')
			if len(ps_entry.get('smb.path','')) > 0:
				# if no sm.path is given, we do not want to overwrite if already set within the header
				row['smb.path'] = ps_entry.get('smb.path','')
			
			row['smb.search_pattern'] = ps_entry.get('FIND_FIRST2 Parameters',{}).get('smb.search_pattern','') + ps_entry.get('smb.search_pattern','')
			#requestingHostname and domain
			row['domain'] = ps_entry.get('smb.primary_domain','') + ps_entry.get('smb_netlogon',{}).get('smb_netlogon.domain_name','')
			if len(row['domain']) == 0:
				if isinstance(ps_entry.get('GET_DFS_REFERRAL Data',{}).get('Referrals',{}).get('Referral',{}),list):
					# Referral is list.
					for ri in ps_entry.get('GET_DFS_REFERRAL Data',{}).get('Referrals',{}).get('Referral',{}):
						ri_domain_name = ri.get('smb_netlogon.domain_name','')
						if len(ri_domain_name) >0:
							row['domain'] = ri_domain_name
							break
				else:
					row['domain'] = ps_entry.get('GET_DFS_REFERRAL Data',{}).get('Referrals',{}).get('Referral',{}).get('smb.dfs.referral.domain_name','')
			if len(row['domain']) == 0:
				row['domain'] = ps_entry.get('smb.security_blob_tree',{}).get('gss-api',{}).get('spnego',{}).get('spnego.negTokenInit_element',{}).get('ntlmssp',{}).get('ntlmssp.negotiate.domain','')
			row['requestingHostname'] = ps_entry.get('browser',{}).get('browser.response_computer_name','')
			# as of today only spnego.negTokenTarg_element seems to be interesting, other items containing ntlmssp: spnego.negTokenInit_element
			tmp_ntlmssp = ps_entry.get('smb.security_blob_tree',{}).get('gss-api',{}).get('spnego',{}).get('spnego.negTokenTarg_element',{}).get('ntlmssp',{})
			if len(row['requestingHostname']) == 0: 
				row['requestingHostname'] = tmp_ntlmssp.get('ntlmssp.auth.hostname','')
			if len(row['domain']) == 0:
				row['domain'] = tmp_ntlmssp.get('ntlmssp.auth.domain','')
			if len(row['account']) == 0:
				row['account'] = tmp_ntlmssp.get('ntlmssp.auth.username','')
			# probably just session setup, TODO: check weather it is only needed for session setup and response, if so add check.
			for tmp_ntlmssp_entry_name,tmp_ntlmssp_entry in tmp_ntlmssp.get('ntlmssp.challenge.target_info',{}).items():
				if 'Attribute: NetBIOS computer name:' in tmp_ntlmssp_entry_name and len(row['requestingHostname']) == 0 :
					row['requestingHostname'] = tmp_ntlmssp_entry.get('ntlmssp.challenge.target_info.nb_computer_name','')
				if 'Attribute: NetBIOS domain name:' in tmp_ntlmssp_entry_name and len(row['domain']) == 0:
					row['domain'] = tmp_ntlmssp_entry.get('ntlmssp.challenge.target_info.nb_domain_name','')
			for tmp_ntlmssp_entry_name,tmp_ntlmssp_entry in tmp_ntlmssp.get('ntlmssp.auth.ntresponse_tree',{}).get('ntlmssp.ntlmv2_response_tree',{}).items():
				if 'Attribute: NetBIOS computer name:' in tmp_ntlmssp_entry_name and len(row['requestingHostname']) == 0:
					row['requestingHostname'] = tmp_ntlmssp_entry.get('ntlmssp.ntlmv2_response.nb_computer_name','')
				if 'Attribute: NetBIOS domain name:' in tmp_ntlmssp_entry_name and len(row['domain']) == 0:
					row['domain'] = tmp_ntlmssp_entry.get('ntlmssp.ntlmv2_response.nb_domain_name','')			

			if ps_entry_name == 'smb_netlogon':
				if len(row['requestingHostname']) == 0:
					row['requestingHostname'] = ps_entry.get('smb_netlogon.unicode_computer_name','')
				if len(row['account']) == 0:
					row['account'] = pw.entry.get('smb_netlogon.user_name','')
					
			#place account at index uid into user_dict,
			# if so far the user account field is empty we try to find the uid in the user_dict
			account = row.get('account','')
			if len(account) > 0: 
				if len(row.get('smb.uid','')) > 0:
					user_dict[row['smb.uid']] = account
			else:
				if row.get('smb.uid','0') in user_dict.keys():
					row['account'] = user_dict[row['smb.uid']]
			
			#place domain at index uid into domain_dict
			# if so far the domain field is emtpy, we try to find the uid in the domain_dict
			domain = row.get('domain','')
			if len(domain) > 0:
				if len(row.get('smb.uid','')) > 0:
					domain_dict[row['smb.uid']] = domain
			else:
				if row.get('smb.uid','0') in domain_dict.keys():
					row['domain'] = domain_dict[row['smb.uid']]
			
			enrich_opnum(row)
			# ALWAYS AFTER setting smb.file from smb level, as Netshare needs to overwrite value!!!
			srvsvc_Netshare(row,filtername)
					
##########################
#			#this is the end for the packet and smb specifics.
			timelinewriter.writerow(row)

		#for loop ends here, code below this line is not included in for loop but still in elif for smbv == 1
		
	elif(smbv == 2):
		# get header by name, header will be removed, so it does no longer need to be considered within the loop
		#ps_header = ps['SMB2 Header']
		ps_header = ps.pop('SMB2 Header')
		# get values from header
		row['smb2.cmd'] = ps_header.get('smb2.cmd','')
		row['smb_action'] = smb2_cmd_dict.get(format(int(row['smb2.cmd']),'#04x'),'Error parsing smb command')
		#row['smb.mid'] = ps_header.get('','')
		#row['smb.uid'] = ps_header.get('','')
		row['smb2.pid'] = ps_header.get('smb2.pid','')
		row['smb2.tid'] = ps_header.get('smb2.tid','')
		tmp_tid_tree = ps_header.get('smb2.tid_tree',{})
		row['smb2.tree'] = tmp_tid_tree.get('smb2.tree','')
		row['smb2.share_type'] = smb2_share_type_dict.get(tmp_tid_tree.get('smb2.share_type',''),'')
		row['requestingHostname'] = tmp_tid_tree.get('smb2.host','')
		row['domain'] = tmp_tid_tree.get('smb2.domain','')
		row['account'] = tmp_tid_tree.get('smb2.acct','')
		row['smb2.response_to'] = ps_header.get('smb2.response_to','')
		row['smb2.sesid'] = ps_header.get('smb2.sesid','')
		if len(row['smb2.response_to']) > 0:
			row['status'] = "Response"
		else:
			row['status']  = "Request"
		# done with a header enter loop
		# in loop skip entry if header
		# with the change to native json and and the clean up in parseJSON method this loop is no longer needed, but is does not break things, FIXME: remove loop FIXME: remove loop for smb1 as well
		for ps_entry_name, ps_entry in ps.items():
			# non header values taken from header are present in row object
			# this is why this is not in an else and executed for every iteration, we accept that the header iteration always will overwrite the fields below.
			# needs some time, but also initializes the values for the keys
			row['smb2.filename'] = ps_entry.get('smb2.filename','')
			# smb2.ioctl.in can also contain an empty string. strings does not have a .get method. we need to check content of smb2.ioctl.out first 
			if len(ps_entry.get('smb2.ioctl.in',{})) > 0 and len(row['smb2.filename']) == 0:
				row['smb2.filename'] = ps_entry.get('smb2.ioctl.in',{}).get('smb.file','')
			if len(ps_entry.get('smb2.tree', '')) > 0:
				row['smb2.tree'] = ps_entry.get('smb2.tree', '')
			# smb.dfs.referral.path only seen in responses, in the corresponding request it is set as filename, that is why we also set it as filename for the response
			if row.get('status','') == 'Response' and len(ps_entry.get('smb2.ioctl.out',{})) > 0 and len(row['smb2.filename']) == 0:
				# we can we have multiple referrals
				t_ref = ps_entry.get('smb2.ioctl.out',{}).get('Referrals',{}).get('Referral','')
				if type(t_ref) is list:
					for t_ref_a in t_ref:
						if len(t_ref_a.get('smb.dfs.referral.path','')) > 0:
							row['smb2.filename'] = t_ref_a.get('smb.dfs.referral.path','')
							break
				else:
					if len(t_ref) > 0:
						# t_ref can be empty string, not having a .get method, we need to check first.
						row['smb2.filename'] = t_ref.get('smb.dfs.referral.path','')
			if int(row['smb2.cmd']) == 14 and len(row.get('smb2.filename',''))==0:
				#find Response, smb2.filename needs special treetment
				#print(ps_entry.get('smb2.find.info_blob_tree',{}))
				temp_id_both_info = ps_entry.get('smb2.find.info_blob_tree',{}).get('smb2.find.id_both_directory_info','')
				if len(temp_id_both_info)>0:
					if isinstance(temp_id_both_info,list):
						#list
						concat_filenames = []
						for tr in temp_id_both_info:
							if len(tr.get('smb2.filename',''))>0:
								concat_filenames.append(tr.get('smb2.filename',''))
						concat_filenames.sort()
						row['smb2.filename'] = str(concat_filenames).strip('[]')
					else:
						#dict
						row['smb2.filename'] = temp_id_both_info.get('smb2.filename','')
				temp_full_dir_info = ps_entry.get('smb2.find.info_blob_tree',{}).get('smb2.find.full_directory_info','')
				if len(temp_full_dir_info)>0 and len(row.get('smb2.filename',''))==0:
					# if we set smb2.filename above, we do not overwrite here
					if isinstance(temp_full_dir_info,list):
						#list
						concat_filenames = []
						for tr in temp_full_dir_info:
							if len(tr.get('smb2.filename',''))>0:
								concat_filenames.append(tr.get('smb2.filename',''))
						concat_filenames.sort()
						row['smb2.filename'] = str(concat_filenames).strip('[]')
					else:
						#dict
						row['smb2.filename'] = temp_full_dir_info.get('smb2.filename','')
					
			row['smb2.create.action'] = create_action_dict.get(ps_entry.get('smb2.create.action',''),'')
			if len(row.get('smb2.share_type','')) == 0:
				# can already be set by smb header
				row['smb2.share_type'] = smb2_share_type_dict.get(ps_entry.get('smb2.share_type',''),'')
			row['smb2.find.pattern'] = ps_entry.get('smb2.find.pattern','')
			if len(row.get('domain','')) == 0:
				# smb2.ioctl.out can also contain an empty string. strings does not have a .get method. we need to check content of smb2.ioctl.out first  
				tmp_ioctl_out = ps_entry.get('smb2.ioctl.out',{})
				if len(tmp_ioctl_out) > 0:
					if isinstance(ps_entry.get('smb2.ioctl.out',{}).get('Referrals',{}).get('Referral',{}),list):
						# Referral is list.
						for ri in ps_entry.get('smb2.ioctl.out',{}).get('Referrals',{}).get('Referral',{}):
							ri_domain_name = ri.get('smb.dfs.referral.domain_name','')
							if len(ri_domain_name) >0:
								row['domain'] = ri_domain_name
								break
					else:
						row['domain'] = ps_entry.get('smb2.ioctl.out',{}).get('Referrals',{}).get('Referral',{}).get('smb.dfs.referral.domain_name','')
			if len(row.get('domain','')) == 0:
				row['domain'] = ps_entry.get('smb2.security_blob_tree',{}).get('gss-api',{}).get('spnego',{}).get('spnego.negTokenInit_element',{}).get('ntlmssp',{}).get('ntlmssp.negotiate.domain','')
			if ps_entry_name == 'rpc_netlogon':
				if len(row.get('domain','') == 0):
					tmp_rpc_controller_info = ps_entry.get('rpc_netlogon',{}).get('DOMAIN_CONTROLLER_INFO',{})
					for tmp_rcp_ci_entry_name,rmp_rcp_ci_entry in tmp_rpc_controller_info.items() :
						if 'Logon Domain:' in tmp_rcp_ci_entry_name:
							row['domain'] = tmp_tcp_ci_entry.get('netlogon.domain','')
			
			# as of today only snego.negTokenTarg_element seems to be intersting, other items containing ntlmssp: spnego.negTokenInit_element
			tmp_ntlmssp = ps_entry.get('smb2.security_blob_tree',{}).get('gss-api',{}).get('spnego',{}).get('spnego.negTokenTarg_element',{}).get('ntlmssp',{})
			if len(row.get('requestingHostname','')) == 0:
				row['requestingHostname'] = tmp_ntlmssp.get('ntlmssp.auth.hostname','')
			if len(row.get('domain','')) == 0:
				row['domain'] = tmp_ntlmssp.get('ntlmssp.auth.domain','')
			if len(row.get('account','')) == 0:
				row['account'] = tmp_ntlmssp.get('ntlmssp.auth.username','')
			# probably just session setup, TODO: check weather it is only needed for session setup and response, if so add check.
			for tmp_ntlmssp_entry_name,tmp_ntlmssp_entry in tmp_ntlmssp.get('ntlmssp.challenge.target_info',{}).items():
				if 'Attribute: NetBIOS computer name:' in tmp_ntlmssp_entry_name and len(row['requestingHostname']) == 0:
					row['requestingHostname'] = tmp_ntlmssp_entry.get('ntlmssp.challenge.target_info.nb_computer_name','')
				if 'Attribute: NetBIOS domain name:' in tmp_ntlmssp_entry_name and len(row['domain']) == 0:
					row['domain'] = tmp_ntlmssp_entry.get('ntlmssp.challenge.target_info.nb_domain_name','')
			for tmp_ntlmssp_entry_name,tmp_ntlmssp_entry in tmp_ntlmssp.get('ntlmssp.auth.ntresponse_tree',{}).get('ntlmssp.ntlmv2_response_tree',{}).items():
				if 'Attribute: NetBIOS computer name:' in tmp_ntlmssp_entry_name and len(row['requestingHostname']) == 0:
					row['requestingHostname'] = tmp_ntlmssp_entry.get('ntlmssp.ntlmv2_response.nb_computer_name','')
				if 'Attribute: NetBIOS domain name:' in tmp_ntlmssp_entry_name and len(row['domain']) == 0:
					row['domain'] = tmp_ntlmssp_entry.get('ntlmssp.ntlmv2_response.nb_domain_name','')
					
			#get smb2.fid from guid handle entriesFile:*
			for k,v in ps_entry.items():
				if 'GUID handle File:' in k:
					row['smb2.fid'] = v.get('smb2.fid','')
				#only if GUID handle File not present	
				elif k == 'GUID handle':
					row['smb2.fid'] = v.get('smb2.fid','')
				else:
					#do nothing
					continue
			if len(row.get('smb2.fid','')) == 0:
				tt_fid = ps_entry.get('smb2.create.extrainfo',{})
				#sometimes an empty string is returned
				if len(tt_fid)>0:
					for k,v in tt_fid.items():
						if 'SMB2_CREATE_DURABLE_HANDLE_REQUEST' in k:
							row['smb2.fid'] = v.get('smb2.create.chain_data',{}).get('GUID handle',{}).get('smb2.fid','')
			sub_proto = False
			
			# place account at index sesid into user_dict,
			# if so far the user account field is empty we try to find the sesid in the user_dict
			account = row.get('account','')
			if len(account) > 0:
				if len(row.get('smb2.sesid','')) > 0:
					user_dict[row['smb2.sesid']] = account
			else:
				if row.get('smb2.sesid','') in user_dict.keys():
					row['account'] = user_dict[row['smb2.sesid']]
			
			# place domain at index sesid into domain_dict
			# if so far the domain field is emtpy, we try to find the sesid in the domain_dict
			domain = row.get('domain','')
			if len(domain) > 0:
				if len(row.get('smb2.sesid','')) > 0:
					domain_dict[row['smb2.sesid']] = domain
			else:
				if row.get('smb2.sesid','') in domain_dict.keys():
					row['domain'] = domain_dict[row['smb2.sesid']]

			# place requestingHostname at index sesid into host_dict
			# if so far the requestingHostname field is emtpy, we try to find the sesid in the host_dict
			requestingHostname = row.get('requestingHostname','')
			if len(requestingHostname) > 0: 
				if len(row.get('smb2.sesid','')) > 0:
					host_dict[row['smb2.sesid']] = requestingHostname
			else:
				if row.get('smb2.sesid','') in host_dict.keys():
					row['requestingHostname'] = host_dict[row['smb2.sesid']]
					
			row = smb2setfilename(row)
			enrich_opnum(row)


			# deal with 'smb2.ioctl.function' only do this if non of the carried sub-protocols are already given more specific infos
			tmp_smb2_ioctl_function = ps_entry.get('smb2.ioctl.function','')
			if len(tmp_smb2_ioctl_function) > 0 and sub_proto == False :
				tmp_smb2_ioctl_function = format(int(tmp_smb2_ioctl_function),'#010x')
				ioctl_ext = smb2_ioctl_function_dict.get(tmp_smb2_ioctl_function,'')
				if len(ioctl_ext):
					# found something to extend
					row['smb_action'] = row.get('smb_action','') + ' ' + smb2_ioctl_function_dict.get(tmp_smb2_ioctl_function).split(':')[0]
					row['info'] = row.get('info','') + ' ' + smb2_ioctl_function_dict.get(tmp_smb2_ioctl_function).split(':')[1]
				else:
					# found nothing to extend
					row['smb_action'] = row['smb_action'] + ' unknown IOCTL function code: ' + tmp_smb2_ioctl_function

			# ALWAYS AFTER calling smb2setfilename, as Netshare needs to overwrite value!!!
			srvsvc_Netshare(row,filtername)

##########################
#			#this is the end for the packet and smb specifics.
			timelinewriter.writerow(row)
		#for loop ends here, code below this line is not included in for loop but still in elif for smbv == 2
	
	# if we reach this point, smbv is neither 1 nor 2
	else:
		print('DEBUG,UNKNOWN SMB VERSION... TODO how to handle')
######################################3
#	# we are done with the packet and all smd subcommands
		

# function to set smb.filename in row
# Parameter ps_entry: json to extract filename from
# Parameter row: dict of current row
# Return: filename
def setsmbfilename(ps_entry,row):
	r_filename = ''
	r_filename = ps_entry.get('smb.file','') + ps_entry.get('GET_DFS_REFERRAL Parameters',{}).get('smb.file','')
	# smb.dfs.referral.path only seen in responses, in the corresponding request it is set as filename, that is why we also set it as filename for the response
	if row.get('status','') == 'Response' and len(ps_entry.get('GET_DFS_REFERRAL Data',{})) > 0 and len(r_filename) == 0:
	# we can we have multiple referrals
		t_ref = ps_entry.get('GET_DFS_REFERRAL Data',{}).get('Referrals',{}).get('Referral','')
		if type(t_ref) is list:
			for t_ref_a in t_ref:
				if len(t_ref_a.get('smb.dfs.referral.path','')) > 0:
					r_filename = t_ref_a.get('smb.dfs.referral.path','')
					break
		else:
			if len(t_ref) > 0:
				# t_ref can be empty string, not having a .get method, we need to check first.
				r_filename = t_ref.get('smb.dfs.referral.path','')
	if len(r_filename) == 0:
		for k,v in ps_entry.items():
			if 'QUERY_PATH' in k:
				r_filename = v.get('smb.file','')
			elif 'QUERY_FILE_INFO' in k or 'SET_FILE_INFO' in k and len(r_filename) == 0: 
				r_filename = v.get('smb.fid_tree',{}).get('smb.file','')
			elif 'FIND_FIRST2 Data' in k and len(r_filename) == 0:
				# loop needed for find file both
				#f = True
				concat_filenames = []
				for kk,vv in v.items():
					if 'Find File' in kk:
						if len(vv.get('smb.file',''))>0:
							concat_filenames.append(vv.get('smb.file',''))
				concat_filenames.sort()
				r_filename = str(concat_filenames).strip('[]')
			elif 'FIND_NEXT2 Parameters' in k and len(r_filename) == 0:
				r_filename = v.get('smb.file','')
			elif 'FIND_NEXT2 Data' in k and len(r_filename) == 0:
				# loop needed
				#f = True
				concat_filenames = []
				for kk,vv in v.items():
					if 'Find File' in kk:
						if len(vv.get('smb.file',''))>0:
							concat_filenames.append(vv.get('smb.file',''))
				concat_filenames.sort()
				r_filename = str(concat_filenames).strip('[]')	
			else:
				continue 
	if len(r_filename) == 0:
		r_filename = ps_entry.get('smb.fid_tree',{}).get('smb.file','')
		
	# deal with smb.dir_name if set, usually only in 0x10 and 0x01 requests
	# as the directory name in the corresponding response is put into smb.file, do it same way for the request 
	directory = ps_entry.get('smb.dir_name','')
	if len(directory) > 0 and len(r_filename)==0:
		if format(int(row['smb.cmd']),'#04x') == '0x01' or format(int(row['smb.cmd']),'#04x') == '0x10':
			r_filename = directory
	
	
	return r_filename
	
#
# deprecated function, csv is replace by json		
# function to parse temp csv file and write it to normalized csv output file
# Parameter infile: the filepath where csv input will be read from
# Parameter timelinewriter: csv Dictwriter object to write output to
# Parameter filtername: will be added to csv to help identify filter used to get data
#
def normalizeCSV (infile,timelinewriter,filtername):
	global wp
	print("parsing tshark output to timeline for " + filtername)
	start_time = time.time()
	try:
		with open(infile,'r') as csvfile:
			dataDict = csv.DictReader(csvfile, delimiter=',', quotechar='\"',)
			#read header
			#csvHeaderDict = dataDict.next()
			csvHeaderDict = next(dataDict)
			
			if filtername == "smb_filter":
				# if protocol is enabled write to protocol about stripping smb1 -> smb.cmd 0xff
				if wp:
					writetoprotocol('\n############################## SMB1: smb command 0xff ##############################\n')
					writetoprotocol('The smb command 0xff, indicating no further command will be send, will be stripped while normalizing the timeline for smb1 traffic\n')
					writetoprotocol('\n#####################################################################################\n')
			
			# read fields in smb1 modus
				for row in dataDict:
					# standard fields
					row['timezone'] ='UTC'
					#'frame.date_epoch','frame.time_epoch'
					# datetime.datetime.utcfromtimestamp(float(timestamp)).strftime('%H:%M:%S.%f')
					tmp_datetime = datetime.datetime.utcfromtimestamp(float(row['frame.time_epoch']))
					row['frame.date_epoch'] = tmp_datetime.strftime('%Y-%m-%d')
					row['frame.time_epoch'] = tmp_datetime.strftime('%H:%M:%S.%f')
					#row['frame.date_epoch'] = time.strftime('%Y-%m-%d', time.gmtime(float(row['frame.time_epoch'])))
					#row['frame.time_epoch'] = time.strftime('%H:%M:%S', time.gmtime(float(row['frame.time_epoch'])))
					row['requestingHostname'] = row.pop('ntlmssp.auth.hostname','') + row.pop('smb_netlogon.unicode_computer_name','')# no smb. field carries the requesting hostname
					row['srcport'] = row.pop('tcp.srcport','') + row.pop('udp.srcport','')
					row['dstport'] = row.pop('tcp.dstport','') + row.pop('udp.dstport','')
							
					#parse smb.create.action from numeric into readable string
					if len(row['smb.create.action']) > 0:
						row['smb.create.action'] = create_action_dict[row.get('smb.create.action','')]

							
					# one network packet can carry multiple smb commands,
					# remove 255 as it indicates no further command
					t_smbcmd = row['smb.cmd'].split(',')
					i = 0
					while i<=0:
						try:
							t_smbcmd.remove('255')
						except ValueError as e:
							i=1
					if len(t_smbcmd) > 1:
						# account and domain and smb.path see to be showing up only once.. 
						# smb.file,smb.mid,smb.pid,smb.tid,smb.fid,smb.uid needs to be extended,
						c = 0
						tmp_row = row
						
						# split all fields which could be present multiple times and ensure result lists are the same length as t_smbcmd list
						# when we iterate over commands we can use the count for all dicts, no addition ifs etc. in case a list is shorter then t_smbcmd
						tmp_file = row.get('smb.file','').split(',')
						while (len(tmp_file) < len(t_smbcmd)):
							tmp_file.append('')
						tmp_col_Info = row.get('_ws.col.Info','').split(';') ## split by ;
						while (len(tmp_col_Info) < len(t_smbcmd)):
							tmp_col_Info.append('')
						tmp_mid = row.get('smb.mid','').split(',')
						while (len(tmp_mid) < len(t_smbcmd)):
							tmp_mid.append('')
						tmp_pid = row.get('smb.pid','').split(',')
						while (len(tmp_pid) < len(t_smbcmd)):
							tmp_pid.append('')
						tmp_tid = row.get('smb.tid','').split(',')
						while (len(tmp_tid) < len(t_smbcmd)):
							tmp_tid.append('')
						tmp_fid = row.get('smb.fid','').split(',')
						while (len(tmp_fid) < len(t_smbcmd)):
							tmp_fid.append('')
						tmp_uid = row.get('smb.uid','').split(',')
						while (len(tmp_uid) < len(t_smbcmd)):
							tmp_uid.append('')
						tmp_srvsvc = tmp_row.pop('srvsvc.opnum','').split(',')
						while (len(tmp_srvsvc) < len(t_smbcmd)):
							tmp_srvsvc.append('')
						tmp_wkssvc = tmp_row.pop('wkssvc.opnum','').split(',')
						while (len(tmp_wkssvc) < len(t_smbcmd)):
							tmp_wkssvc.append('')
						tmp_winreg = tmp_row.pop('winreg.opnum','').split(',')
						while (len(tmp_winreg) < len(t_smbcmd)):
							tmp_winreg.append('')
						tmp_svcctl = tmp_row.pop('svcctl.opnum','').split(',')
						while (len(tmp_svcctl) < len(t_smbcmd)):
							tmp_svcctl.append('')
						tmp_atsvc = tmp_row.pop('atsvc.opnum','').split(',')
						while (len(tmp_atsvc) < len(t_smbcmd)):
							tmp_atsvc.append('')
						tmp_lsarpc = tmp_row.pop('lsarpc.opnum','').split(',')
						while (len(tmp_lsarpc) < len(t_smbcmd)):
							tmp_lsarpc.append('')
						tmp_samr = tmp_row.pop('samr.opnum','').split(',')
						while (len(tmp_samr) < len(t_smbcmd)):
							tmp_samr.append('')
							
						tmp_trans2_sub = row.pop('smb.trans2.cmd','').split(',')
						while (len(tmp_trans2_sub) < len(t_smbcmd)):
							tmp_trans2_sub.append('')
						tmp_smb_search_pattern = row.get('smb.search_pattern','').split(',')
						while (len(tmp_smb_search_pattern) < len(t_smbcmd)):
							tmp_smb_search_pattern.append('')
						#svcctl.displayname,svcctl.servicename
						tmp_svcctl_displayname = row.get('svcctl.displayname','').split(',')
						while (len(tmp_svcctl_displayname) < len(t_smbcmd)):
							tmp_svcctl_displayname.append('')
						tmp_svcctl_servicename = row.get('svcctl.servicename','').split(',')
						while (len(tmp_svcctl_servicename) < len(t_smbcmd)):
							tmp_svcctl_servicename.append('')
						#winreg key and value names, if multiple of them they will not be extended as other protocol parts, all off them will show up in smb.file or smb2.filename 
						
							
						tmp_request_frameID = row.get('smb.response_to','').split(',')
						while (len(tmp_request_frameID) < len(t_smbcmd)):
							tmp_request_frameID.append(tmp_request_frameID[0])
						
						
						while (c < len(t_smbcmd)):
							tmp_row['smb.cmd'] = t_smbcmd[c]
							# one smb command, one match for smb_action, try to get a descriptive wording form smb_cmd_dict, if for any reason nothing is found, hex representation of command is set to filed
							tmp_row['smb_action'] = smb_cmd_dict.get(format(int(tmp_row['smb.cmd']),'#04x'),format(int(tmp_row['smb.cmd']),'#04x')) #smb_cmd_dict[format(int(tmp_row['smb.cmd']),'#04x')]
							tmp_row['smb.file'] = tmp_file[c]
							tmp_row['_ws.col.Info'] = tmp_col_Info[c]
							tmp_row['smb.mid'] = tmp_mid[c]
							tmp_row['smb.pid'] = tmp_pid[c]
							tmp_row['smb.tid'] = tmp_tid[c]
							tmp_row['smb.fid'] = tmp_fid[c]
							tmp_row['smb.uid'] = tmp_uid[c]
							tmp_row['smb.search_pattern'] = tmp_smb_search_pattern[c]
							tmp_row['smb.response_to'] = tmp_request_frameID[c]
						
							#use tmp_trans2_sub in smbtimeline field, if it is a smb_trans2 request
							if format(int(tmp_row['smb.cmd']),'#04x') == "0x32" and len(tmp_trans2_sub[c]) > 0 :
								# tmp_row['smb_action'] = tmp_row['smb_action'] + ' ' + smb_trans2_subcmd_dict.get(format(int(tmp_trans2_sub[c]),'#06x'),format(int(tmp_trans2_sub[c]),'#06x'))
								tmp_trans2_actionList = smb_trans2_subcmd_dict.get(format(int(tmp_trans2_sub[c]),'#06x'),format(int(tmp_trans2_sub[c]),'#06x')).split(':')
								if len(tmp_trans2_actionList) > 1:
									tmp_row['info'] = tmp_row.get('info','') + ' ' + tmp_trans2_actionList[1] 
								tmp_row['smb_action'] = tmp_row['smb_action'] + ' ' + tmp_trans2_actionList[0]

							#set srvsvc,wkssvc,winreg etc, opnum accoring to counter in tmp_row
							tmp_d = {'srvsvc.opnum':tmp_srvsvc[c],'wkssvc.opnum':tmp_wkssvc[c],'winreg.opnum':tmp_winreg[c],'svcctl.opnum':tmp_svcctl[c],'atsvc.opnum':tmp_atsvc[c],'lsarpc.opnum':tmp_lsarpc[c],'samr.opnum':tmp_samr[c],'svcctl.displayname':tmp_svcctl_displayname[c],'svcctl.servicename':tmp_svcctl_servicename[c]}
							tmp_row.update(tmp_d)
							# deals with sub-protocol opnum enrichment, like srvsvc,wkssvc,winreg,svcctl,atsvc, etc..
							enrich_opnum(tmp_row)
						
							# deal with smb.dir_name is set, usually only in 0x10 and 0x01 requests
							# as the directory name in the corresponding response is put into smb.file, do it same way for the request 
							directory = tmp_row.pop('smb.dir_name', '')
							if len(directory) > 0 :
								if format(int(tmp_row['smb.cmd']),'#04x') == '0x01' or format(int(tmp_row['smb.cmd']),'#04x') == '0x10':
									tmp_row['smb.file'] = directory
							
							# ALWAYS AFTER calling smb2setfilename, as Netshare needs to overwrite value!!!
							srvsvc_Netshare(tmp_row,filtername)
							
							# deal with account 
							account = tmp_row.pop('smb.account', '') + tmp_row.pop('ntlmssp.auth.username','') + tmp_row.pop('smb_netlogon.user_name','') 
							if len(account) > 0:
								tmp_row['account'] = account
								#setting uid 0 leads to false positives
								if int(row['smb.uid']) > 0:
									user_dict[row['smb.uid']] = account
							else:
								if tmp_row['smb.uid'] in user_dict.keys():
									tmp_row['account'] = user_dict[tmp_row['smb.uid']]
							account = ''	
							# deal with domain 
							domain = tmp_row.pop('smb.primary_domain', '') + tmp_row.pop('ntlmssp.auth.domain','') + tmp_row.pop('smb_netlogon.domain_name','')
							if len(domain) > 0:
								tmp_row['domain'] = domain
								#setting uid 0 leads to false positives
								if int(row['smb.uid']) > 0:
									domain_dict[row['smb.uid']] = domain
							else:
								if tmp_row['smb.uid'] in domain_dict.keys():
									tmp_row['domain'] = domain_dict[tmp_row['smb.uid']]
									
							if len(tmp_row['smb.response_to']) > 0:
								tmp_row['status'] = "Response"
							else:
								tmp_row['status']  = "Request"
									
							timelinewriter.writerow(tmp_row)
							c += 1
					else:
					
						row['smb.cmd'] = t_smbcmd[0]
						# one smb command, one match for smb_action, try to get a descriptive wording form smb_cmd_dict, if for any reason nothing is found, hex representation of command is set to filed
						row['smb_action'] = smb_cmd_dict.get(format(int(row['smb.cmd']),'#04x'),format(int(row['smb.cmd']),'#04x'))
										
						tmp_trans2_cmd = row.pop('smb.trans2.cmd','')
						# use tmp_trans2_cmd in smbtimeline field, if it is a smb_trans2 request
						if format(int(row['smb.cmd']),'#04x') == '0x32' and len(tmp_trans2_cmd) > 0:
							#row['smb_action'] = row['smb_action'] + ' ' + smb_trans2_subcmd_dict.get(format(int(tmp_trans2_cmd),'#06x'),format(int(tmp_trans2_cmd),'#06x'))
							tmp_trans2_actionList = smb_trans2_subcmd_dict.get(format(int(tmp_trans2_cmd),'#06x'),format(int(tmp_trans2_cmd),'#06x')).split(':')
							if len(tmp_trans2_actionList) > 1:
								row['info'] = row.get('info','') + ' ' + tmp_trans2_actionList[1]
							row['smb_action'] = row['smb_action'] + ' ' + tmp_trans2_actionList[0]
						
						# deal with smb.dir_name is set, usually only in 0x10 and 0x01 requests
						# as the directory name in the corresponding response is put into smb.file, do it same way for the request 
						directory = row.pop('smb.dir_name', '')
						if len(directory) > 0 :
							if format(int(row['smb.cmd']),'#04x') == '0x01' or format(int(row['smb.cmd']),'#04x') == '0x10':
								row['smb.file'] = directory
						
						# deals with sub-protocol opnum enrichment, like srvsvc,wkssvc,winreg,svcctl,atsvc, etc..
						enrich_opnum(row)
						# ALWAYS AFTER setting smb.file from smb level, as Netshare needs to overwrite value!!!
						srvsvc_Netshare(row,filtername)

						
						# deal with account 
						account = row.pop('smb.account', '') + row.pop('ntlmssp.auth.username','') + row.pop('smb_netlogon.user_name','')
						if len(account) > 0:
							row['account'] = account
							#user_dict[row['smb.uid']] = account
							#setting uid 0 leads to false positives
							if int(row['smb.uid']) > 0:
								user_dict[row['smb.uid']] = account
						else:
							if row['smb.uid'] in user_dict.keys():
								row['account'] = user_dict[row['smb.uid']]
						account = ''	
						# deal with domain 
						domain = row.pop('smb.primary_domain', '') + row.pop('ntlmssp.auth.domain','') + row.pop('smb_netlogon.domain_name','')
						if len(domain) > 0:
							row['domain'] = domain
							#domain_dict[row['smb.uid']] = domain
							#setting uid 0 leads to false positives
							if int(row['smb.uid']) > 0:
								domain_dict[row['smb.uid']] = domain
						else:
							if row['smb.uid'] in domain_dict.keys():
								row['domain'] = domain_dict[row['smb.uid']]

						# if smb.response_to is filled with a value, the packet/row is a response, otherwise it is a request
						if len(row['smb.response_to']) > 0:
							row['status'] = "Response"
						else:
							row['status']  = "Request"
								
								
								
						# write normalized row, keys which does not exist in target dict needs to be removed first!
						timelinewriter.writerow(row)					
						
			elif filtername == "smb2_filter":
			# read fields in smb2/smb3 modus
				#reg_FileNameFromInfo = re.compile("File: (.*?)$")
				for row in dataDict:
					# standard fields
					row['timezone'] ='UTC'
					#'frame.date_epoch','frame.time_epoch'
					tmp_datetime = datetime.datetime.utcfromtimestamp(float(row['frame.time_epoch']))
					row['frame.date_epoch'] = tmp_datetime.strftime('%Y-%m-%d')
					row['frame.time_epoch'] = tmp_datetime.strftime('%H:%M:%S.%f')
					#row['frame.date_epoch'] = time.strftime('%Y-%m-%d', time.gmtime(float(row['frame.time_epoch'])))
					#row['frame.time_epoch'] = time.strftime('%H:%M:%S', time.gmtime(float(row['frame.time_epoch'])))
					row['srcport'] = row.pop('tcp.srcport','') + row.pop('udp.srcport','')
					row['dstport'] = row.pop('tcp.dstport','') + row.pop('udp.dstport','')
					
					# deal with account 
					account = row.pop('smb2.acct', None) + row.pop('ntlmssp.auth.username',None) + row.pop('smb_netlogon.user_name','')
					if len(account) > 0:
						row['account'] = account
						user_dict[row['smb2.sesid']] = account
					else:
						if row['smb2.sesid'] in user_dict.keys():
							row['account'] = user_dict[row['smb2.sesid']]
					# deal with domain 
					domain = row.pop('smb2.domain', None) + row.pop('ntlmssp.auth.domain',None) + row.pop('smb_netlogon.domain_name','')
					if len(domain) > 0:
						row['domain'] = domain
						domain_dict[row['smb2.sesid']] = domain
					else:
						if row['smb2.sesid'] in domain_dict.keys():
							row['domain'] = domain_dict[row['smb2.sesid']]
					# deal with requesting hostname
					requestingHostname = row.pop('smb2.host', None) + row.pop('ntlmssp.auth.hostname',None) + row.pop('smb_netlogon.unicode_computer_name','')
					if len(requestingHostname) > 0:
						row['requestingHostname'] = requestingHostname
						host_dict[row['smb2.sesid']] = requestingHostname
					else:
						if row['smb2.sesid'] in host_dict.keys():
							row['requestingHostname'] = host_dict[row['smb2.sesid']]
							
							
					#parse smb2.create.action from numeric into readable string
					if len(row['smb2.create.action']) > 0:
						row['smb2.create.action'] = create_action_dict[row.get('smb2.create.action','')]
					
					#parse smb2.share_type from numeric into readable string, like 1 == physical device, 2 == namped pipe etc.
					# TODO: why does we need to do it again for tmp_row loop?
					if row['smb2.share_type'] in smb2_share_type_dict:
						row['smb2.share_type'] = smb2_share_type_dict[row['smb2.share_type']]

					

					# one network packet can carry multiple smb commands,
					# following code normalizes these packets to lines carrying only one smb command per line
					# infos which are extended in tshark export, like account,account,account (in case of three smb commands) will also be processed and extended to the corresponding line
					# if infos show up only once (like a filename) they are set in the line for the first command, other lines will be filled with empty strings
					# Example: if a packet carries 3 smb commands, it will result in three lines, same frame number etc. but only one smb command
					# original line: frame.number: 3 account: a,a,a filename: evil.exe, smb.command: 4,5
					#result:
					# line1: frame.number: 3 account: a filename: evil.exe, smb.command: 4
					# line2: frame.number: 3 account: a filename: '', smb.command: 5
					t_smbcmd = row['smb2.cmd'].split(',')
					if len(t_smbcmd) > 1:
						# more then one smb2.cmd per packet
						c = 0

						# remove 'smb2.ioctl.function', it should not show up more than once in a smb2 packet
						tmp_smb2_ioctl_function = row.pop('smb2.ioctl.function','')

						tmp_row = row
						# split all fields which could be present multiple times and ensure result lists are the same length as t_smbcmd list
						# when we iterate over commands we can use the count for all dicts, no addition ifs etc. in case a list is shorter then t_smbcmd
						tmp_share_type = row.get('smb2.share_type','').split(',')
						while (len(tmp_share_type) < len(t_smbcmd)):
							tmp_share_type.append('')
						tmp_col_Info = row.get('_ws.col.Info','').split(';') ## split by ;
						while (len(tmp_col_Info) < len(t_smbcmd)):
							tmp_col_Info.append('')
						tmp_fid = row.get('smb2.fid','').split(',') ## eventuell
						while (len(tmp_fid) < len(t_smbcmd)):
							tmp_fid.append('')
						tmp_tid = row.get('smb2.tid','').split(',')
						while (len(tmp_tid) < len(t_smbcmd)):
							tmp_tid.append('')
						tmp_pid = row.get('smb2.pid','').split(',')
						while (len(tmp_pid) < len(t_smbcmd)):
							tmp_pid.append('')
						tmp_sesid = row.get('smb2.sesid','').split(',')
						while (len(tmp_sesid) < len(t_smbcmd)):
							tmp_sesid.append('')						
						tmp_host = row.get('requestingHostname','').split(',')
						while (len(tmp_host) < len(t_smbcmd)):
							tmp_host.append('')						
						tmp_domain = row.get('domain','').split(',')
						while (len(tmp_domain) < len(t_smbcmd)):
							tmp_domain.append('')						
						tmp_account = row.get('account','').split(',')
						while (len(tmp_account) < len(t_smbcmd)):
							tmp_account.append('')						
						tmp_tree = row.get('smb2.tree', '').split(',')
						while (len(tmp_tree) < len(t_smbcmd)):
							tmp_tree.append('')
						tmp_smb2_find_pattern = row.get('smb2.find.pattern','').split(',')
						while (len(tmp_smb2_find_pattern) < len(t_smbcmd)):
							tmp_smb2_find_pattern.append('')
						
						tmp_srvsvc = tmp_row.pop('srvsvc.opnum','').split(',')
						while (len(tmp_srvsvc) < len(t_smbcmd)):
							tmp_srvsvc.append('')
						tmp_wkssvc = tmp_row.pop('wkssvc.opnum','').split(',')
						while (len(tmp_wkssvc) < len(t_smbcmd)):
							tmp_wkssvc.append('')
						tmp_winreg = tmp_row.pop('winreg.opnum','').split(',')
						while (len(tmp_winreg) < len(t_smbcmd)):
							tmp_winreg.append('')
						tmp_svcctl = tmp_row.pop('svcctl.opnum','').split(',')
						while (len(tmp_svcctl) < len(t_smbcmd)):
							tmp_svcctl.append('')
						tmp_atsvc = tmp_row.pop('atsvc.opnum','').split(',')
						while (len(tmp_atsvc) < len(t_smbcmd)):
							tmp_atsvc.append('')
						tmp_lsarpc = tmp_row.pop('lsarpc.opnum','').split(',')
						while (len(tmp_lsarpc) < len(t_smbcmd)):
							tmp_lsarpc.append('')
						tmp_samr = tmp_row.pop('samr.opnum','').split(',')
						while (len(tmp_samr) < len(t_smbcmd)):
							tmp_samr.append('')
						tmp_svcctl_displayname = row.get('svcctl.displayname','').split(',')
						while (len(tmp_svcctl_displayname) < len(t_smbcmd)):
							tmp_svcctl_displayname.append('')
						tmp_svcctl_servicename = row.get('svcctl.servicename','').split(',')
						while (len(tmp_svcctl_servicename) < len(t_smbcmd)):
							tmp_svcctl_servicename.append('')
						#winreg key and value names, if multiple of them they will not be extended as other protocol parts, all off them will show up in smb.file or smb2.filename 
						
						tmp_request_frameID = row.get('smb2.response_to','').split(',')
						while (len(tmp_request_frameID) < len(t_smbcmd)):
							tmp_request_frameID.append(tmp_request_frameID[0])

						while (c < len(t_smbcmd)):
							tmp_row['smb2.cmd'] = t_smbcmd[c]
							# one smb command, one match for smb_action, try to get a descriptive wording form smb2_cmd_dict, if for any reason nothing is found, hex representation of command is set to filed
							tmp_row['smb_action'] = smb2_cmd_dict.get(format(int(row['smb2.cmd']),'#04x'),format(int(row['smb2.cmd']),'#04x'))
							
							tmp_row['smb2.share_type'] = tmp_share_type[c]
							tmp_row['_ws.col.Info'] = tmp_col_Info[c]
							tmp_row['smb2.fid'] = tmp_fid[c]
							tmp_row['smb2.tid'] = tmp_tid[c]
							tmp_row['smb2.pid'] = tmp_pid[c]
							tmp_row['smb2.sesid'] = tmp_sesid[c]
							tmp_row['requestingHostname'] = tmp_host[c]
							tmp_row['domain'] = tmp_domain[c]
							tmp_row['account'] = tmp_account[c]
							tmp_row['smb2.tree'] = tmp_tree[c]
							tmp_row['smb2.response_to'] = tmp_request_frameID[c]
							tmp_row['smb2.find.pattern'] = tmp_smb2_find_pattern[c]
							
							#set srvsvc,wkssvc,winreg etc, opnum accoring to counter in tmp_row
							tmp_d = {'srvsvc.opnum':tmp_srvsvc[c],'wkssvc.opnum':tmp_wkssvc[c],'winreg.opnum':tmp_winreg[c],'svcctl.opnum':tmp_svcctl[c],'atsvc.opnum':tmp_atsvc[c],'lsarpc.opnum':tmp_lsarpc[c],'samr.opnum':tmp_samr[c],'svcctl.displayname':tmp_svcctl_displayname[c],'svcctl.servicename':tmp_svcctl_servicename[c]}
							tmp_row.update(tmp_d)
							# deals with sub-protocol opnum enrichment, like srvsvc,wkssvc,winreg,svcctl,atsvc, etc..
							enrich_opnum(tmp_row)
							
							#first check if it returns something, if so get [0]
							#res = reg_FileNameFromInfo.findall(tmp_row['_ws.col.Info'])
							#if len(res) > 0:
							#	tmp_row['smb2.filename'] = res[0]
							
							
							tmp_row = smb2setfilename(tmp_row)

							# ALWAYS AFTER calling smb2setfilename, as Netshare needs to overwrite value!!!
							srvsvc_Netshare(tmp_row,filtername)
							
							#parse smb2.share_type from numeric into readable string, like 1 == physical device, 2 == namped pipe etc.
							if tmp_row['smb2.share_type'] in smb2_share_type_dict:
								tmp_row['smb2.share_type'] = smb2_share_type_dict[tmp_row['smb2.share_type']]
							
							if len(tmp_row['smb2.response_to']) > 0:
								tmp_row['status'] = "Response"
							else:
								tmp_row['status']  = "Request"
								
							timelinewriter.writerow(tmp_row)
							c += 1
					else:
						# write normalized row, keys which does not exist in target dict needs to be removed first!		
							
						# one smb command, one match for smb_action, try to get a descriptive wording form smb2_cmd_dict, if for any reason nothing is found, hex representation of command is set to filed
						#row['smb_action'] = smb2_cmd_dict[format(int(row['smb2.cmd']),'#04x')]
						row['smb_action'] = smb2_cmd_dict.get(format(int(row['smb2.cmd']),'#04x'),format(int(row['smb2.cmd']),'#04x'))						
						

						# initialize sub-protocol indicator, used later for smb2.ioctl.function as any sub-protocol enrichment counts more than the potenial carrier protocol
						# sub-protocols so far are: srvsvc,wkssvc,winreg,svcctl,atsvc
						sub_proto = False
						row = smb2setfilename(row)
						# deals with sub-protocol opnum enrichment, like srvsvc,wkssvc,winreg,svcctl,atsvc, etc..
						enrich_opnum(row)

						# deal with 'smb2.ioctl.function' only do this if non of the carried sub-protocols are already given more specific infos
						tmp_smb2_ioctl_function = row.pop('smb2.ioctl.function','')
						if len(tmp_smb2_ioctl_function) > 0 and sub_proto == False :
							tmp_smb2_ioctl_function = format(int(tmp_smb2_ioctl_function),'#010x')
							ioctl_ext = smb2_ioctl_function_dict.get(tmp_smb2_ioctl_function,'')
							if len(ioctl_ext):
							# found something to extend
								row['smb_action'] = row['smb_action'] + ' ' + smb2_ioctl_function_dict.get(tmp_smb2_ioctl_function).split(':')[0]
								row['info'] = row.get('info','') + ' ' + smb2_ioctl_function_dict.get(tmp_smb2_ioctl_function).split(':')[1]
							else:
							# found nothing to extend
								row['smb_action'] = row['smb_action'] + ' unknown IOCTL function code: ' + tmp_smb2_ioctl_function

						# ALWAYS AFTER calling smb2setfilename, as Netshare needs to overwrite value!!!
						srvsvc_Netshare(row,filtername)
						
						# if smb2.response_to is filled with a value, the packet/row is a response, otherwise it is a request
						if len(row['smb2.response_to']) > 0:
							row['status'] = "Response"
						else:
							row['status']  = "Request"
				
						timelinewriter.writerow(row)
					
			else:
				print("Unknown filter_name in normalizeCSV function")
				print("Exiting without cleanup")
				exit(1)
						
	except Exception as e:
		print ("error parsing csv input file " + infile + " , make sure it is formatted correctly")
		print(e)
		print(traceback.format_exc())
		
	stop_time = time.time()
	elapsed = stop_time - start_time
	h = int(elapsed//3600)
	m = int((elapsed%3600) // 60)
	s = int((elapsed%3600)%60)
	temp_durations = "total time: %d:%d:%d (hh:mm:ss)" %(h,m,s)
	print(temp_durations)
	if wp:
		writetoprotocol('\n##################################### normalizeCSV #####################################\n')
		writetoprotocol('\n############################ ' + temp_durations + ' ############################\n')


# method tries to write a catalog of filenames seen in smb2 traffic an enrich packets not carrying smb2.filename attribute in the export with the corresponding filename
# filenames are taken if possible via the response_to relation, or via the fid (file-id) (either direct or via the fid from the originating request via response_to relation
# Parameter row: the row to operate on, dictionary
# Return: row after trying to set the filename, dictionary
def smb2setfilename (row):
	global fname_packet_dict
	global packet_to_fid_dict
	global fname_fid_dict

	#deal with filename
	request_frameID = row.get('smb2.response_to','')
	# if packet has filename, store it in fname_packet_dict, key is the current packet id
	#request_frameID = row.pop('smb2.response_to',None)
	#fname = row['smb2.filename']
	fname = row.get('smb2.filename','')
	if len(fname) > 0:
	# if a filename exist, it exist in the request packet, we save the filename to a dict with the frame.number of the request as key
		fname_packet_dict[row['frame.number']] = fname
						
	fid = row.get('smb2.fid', '')
	if len(fid) > 0 and fid != '00000000-0000-0000-0000-000000000000' and fid != 'ffffffff-ffff-ffff-ffff-ffffffffffff':
	#if packet has a fid, the fid is not "00000000-0000-0000-0000-000000000000" (fid send by client in creat requests, which we do not need, as server replies with the assigned fid)
	# fid ffffffff-ffff-ffff-ffff-ffffffffffff is for named pipes (FIXME: validate) which do not have a smb2.filename
	# fill packet to fid dict, to solve read request with fid where filename is not in fname_packet_dict, as read reply is response to (smb2.response_to) read request only haveing an existing fid 
		packet_to_fid_dict[row['frame.number']] = fid
						
	# if the packet is a reply (request_frameID is filled AND the ID is in the fname_packet_dict we can set the filename from the fname_packet_dict 
	# AND the response carries the FID( file id), which we use to store the filename in the 
	if request_frameID in fname_packet_dict and len(row.get('smb2.filename',''))==0:
		row['smb2.filename'] = fname_packet_dict[request_frameID]
		if len(fid) > 0:
			fname_fid_dict[row['smb2.fid']] = fname_packet_dict[request_frameID]
							
	else:
	# check if the packet contains a fid and if we already have it stored in the fname_fid_dict, if so we set the filename from the fname_fid_dict
		fid = row.get('smb2.fid', '')
		if len(fid) > 0 and row['smb2.fid'] in fname_fid_dict and len(row.get('smb2.filename',''))==0:
			row['smb2.filename'] = fname_fid_dict[row['smb2.fid']]
		else:
			#check if we find something in packet_to_fid via smb2.resonse_to in packet_to_fid and use the result to check if we have a filename in fname_fid_dict
			if request_frameID in packet_to_fid_dict and len(row.get('smb2.filename',''))==0:
				fid = packet_to_fid_dict[request_frameID]
				# there are cases were fid is present but we do not have a filename, so better avoid exceptions and errors and use get with default empty
				row['smb2.filename'] = fname_fid_dict.get(fid,'')

	return row

# method deals with sub-protocol opnum enrichment, like srvsvc,wkssvc,winreg,svcctl,atsvc, etc..
# Parameter row: the row to operate on, dictionary
# Return: not needed, we directly manipulate the object referenced
def enrich_opnum(row):
	# just needed for smb2/3 but does not hurt smb1, no need for more parameter or return value
	global sub_proto
	# deal with srvsvc.opnum
	tmp_srvsvc = row.pop('srvsvc.opnum','')
	if len(tmp_srvsvc) > 0:
		#if int(tmp_srvsvc) in smb_srvsvc_extendList:
		row['smb_action'] = row['smb_action'] + ' ' + smb_srvsvc_dict.get(tmp_srvsvc).split(':')[0]
		row['info'] = row.get('info','') + ' ' + smb_srvsvc_dict.get(tmp_srvsvc).split(':')[1]
		row['subProto_opnum'] = 'SRVSVC:' + tmp_srvsvc
		sub_proto = True
	#deal with 'wkssvc.opnum'
	tmp_wkssvc = row.pop('wkssvc.opnum','')
	if len(tmp_wkssvc) > 0:
		#if int(tmp_wkssvc) in smb_wkssvc_extendList:
		row['smb_action'] = row['smb_action'] + ' ' + smb_wkssvc_dict.get(tmp_wkssvc).split(':')[0]
		row['info'] = row.get('info','') + ' ' + smb_wkssvc_dict.get(tmp_wkssvc).split(':')[1]
		row['subProto_opnum'] = 'WKSSVC:' + tmp_wkssvc
		sub_proto = True
	#deal with 'winreg.opnum'
	tmp_winreg = row.pop('winreg.opnum','')
	if len(tmp_winreg) > 0:
		#if int(tmp_winreg) in smb_winreg_extendList:
		row['smb_action'] = row['smb_action'] + ' ' + smb_winreg_dict.get(tmp_winreg).split(':')[0]
		row['info'] = row.get('info','') + ' ' + smb_winreg_dict.get(tmp_winreg).split(':')[1]
		row['subProto_opnum'] = 'WINREG:' + tmp_winreg
		sub_proto = True
	# deal with winreg key and value names for specific opcodes, as fields are different per opcode, not a single filed for key name or valuename
	# only works with smb1 as traffic is no longer clear text in smb2/3
	tmp_winregKey = ''
	tmp_winregValue = ''
	if tmp_winreg == '15':
		tmp_winregKey = row.get('winreg.winreg_OpenKey.keyname','')
	if tmp_winreg == '6':
		tmp_winregKey = row.get('winreg.winreg_CreateKey.name','')
	if tmp_winreg == '13':
		tmp_winregKey = row.get('winreg.winreg_LoadKey.keyname','')
	if tmp_winreg == '17':
		tmp_winregValue = row.get('winreg.winreg_QueryValue.value_name','')
	if tmp_winreg == '22':
		tmp_winregValue = row.get('winreg.winreg_SetValue.name','')
	if tmp_winreg == '8':
		tmp_winregValue = row.get('winreg.winreg_DeleteValue.value','')
	if tmp_winreg == '9':
		tmp_winregValue = row.get('winreg.winreg_EnumKey.name','')
	if tmp_winreg == '10':
		tmp_winregValue = row.get('winreg.winreg_EnumValue.name','')
	if tmp_winreg == '29':
		tmp_winregValue = row.get('winreg.QueryMultipleValue.ve_valuename','')
	if tmp_winreg == '7' or '35':
		tmp_winregValue = row.get('winreg.winreg_DeleteKey.key','')
	#remove fields from row, value will be stored somewhere else, if they are not removed, they will break later parsing
	row.pop('winreg.winreg_OpenKey.keyname','')
	row.pop('winreg.winreg_CreateKey.name','')
	row.pop('winreg.winreg_LoadKey.keyname','')
	row.pop('winreg.winreg_QueryValue.value_name','')
	row.pop('winreg.winreg_SetValue.name','')
	row.pop('winreg.winreg_DeleteValue.value','')
	row.pop('winreg.winreg_EnumKey.name','')
	row.pop('winreg.winreg_EnumValue.name','')
	row.pop('winreg.QueryMultipleValue.ve_valuename','')
	row.pop('winreg.winreg_DeleteKey.key','')
	if len(tmp_winregKey) > 0 or len(tmp_winregValue) > 0:
		row['registry_info'] = 'Registry Key: ' + tmp_winregKey + ' Value: ' + tmp_winregValue
		# set entry for enrichment of response
		registry_info_dict[row['frame.number']] = row['registry_info']
	# try to enrich registry_info if packet is a response
	# shows only up in smb1 traffic, if it is smb2/3 we will get an empty string and no match in the registry_info_dict
	tmp_response = row.get('smb.response_to', '') + row.get('smb2.response_to', '')
	if tmp_response in registry_info_dict.keys():
		row['registry_info'] = registry_info_dict[row['smb.response_to']]
	
	#deal with 'svcctl.opnum'
	tmp_svcctl = row.pop('svcctl.opnum','')
	if len(tmp_svcctl) > 0:
		#if int(tmp_svcctl) in smb_svcctl_extendList:
		# all service contoll events are important
		row['smb_action'] = row['smb_action'] + ' ' + smb_svcctl_dict.get(tmp_svcctl).split(':')[0]
		row['info'] = row.get('info','') + ' ' + smb_svcctl_dict.get(tmp_svcctl).split(':')[1]
		row['subProto_opnum'] = 'SVCCTL:' + tmp_svcctl
		sub_proto = True
	# deal which servicename and displayname if they are set
	tmp_svcctl_servicename = row.pop('svcctl.servicename','')
	tmp_svcctl_displayname = row.pop('svcctl.displayname','')
	if len(tmp_svcctl_servicename) > 0 or len(tmp_svcctl_displayname) > 0:
		row['service_info'] = ' Servicename:' + tmp_svcctl_servicename + ' Displayname:' + tmp_svcctl_displayname
		service_info_dict[row['frame.number']] = ' Servicename:' + tmp_svcctl_servicename + ' Displayname:' + tmp_svcctl_displayname
	else:
		if len(row.get('smb.response_to','')) > 0:
			#smb1, check if corresponding request has service_info string
			if row['smb.response_to'] in service_info_dict.keys():
				row['service_info'] = service_info_dict[row['smb.response_to']]
		if len(row.get('smb2.response_to','')) > 0:
			#smb2, check if corresponding request has service_info string
			if row['smb2.response_to'] in service_info_dict.keys():
				row['service_info'] = service_info_dict[row['smb2.response_to']]
		
	#deal with 'atsvc.opnum'
	tmp_atsvc = row.pop('atsvc.opnum','')
	if len(tmp_atsvc) > 0:
		#if int(tmp_atsvc) in smb_atsvc_extendList:
		# all service control events are important
		row['smb_action'] = row['smb_action'] + ' ' + smb_atsvc_dict.get(tmp_atsvc).split(':')[0]
		row['info'] = row.get('info','') + ' ' + smb_atsvc_dict.get(tmp_atsvc).split(':')[1]
		row['subProto_opnum'] = 'ATSVC:' + tmp_atsvc
		sub_proto = True
	# deal with 'atsvc.atsvc_JobInfo.command'
	tmp_atsvc_command = row.pop('atsvc.atsvc_JobInfo.command','')
	if len(tmp_atsvc_command) > 0:
		row['service_info'] = ' at_svc command: ' + tmp_atsvc_command
		#FIXME: ??? additional info needed for MACB?
	#deal with 'lsarpc.opnum'
	tmp_lsarpc = row.pop('lsarpc.opnum','')
	if len(tmp_lsarpc) > 0:
		#if int(tmp_lsarpc) in smb_lsarpc_extendList:
		row['smb_action'] = row['smb_action'] + ' ' + smb_lsarpc_dict.get(tmp_lsarpc).split(':')[0]
		row['info'] = row.get('info','') + ' ' + smb_lsarpc_dict.get(tmp_lsarpc).split(':')[1]
		row['subProto_opnum'] = 'LSARPC:' + tmp_lsarpc
		sub_proto = True
	#deal with 'samr.opnum'
	tmp_samr = row.pop('samr.opnum','')
	if len(tmp_samr) > 0:
		#if int(tmp_samr) in smb_samr_extendList:
		row['smb_action'] = row['smb_action'] + ' ' + smb_samr_dict.get(tmp_samr).split(':')[0]
		row['info'] = row.get('info','') + ' ' + smb_samr_dict.get(tmp_samr).split(':')[1]
		row['subProto_opnum'] = 'SAMR:' + tmp_samr
		sub_proto = True

# method deals with NetShare* fields from srvsvc traffic
# ALWAYS AFTER calling smb2setfilename or setting smb.file from smb level traffic, as Netshare needs to overwrite value!!!
# Parameter row: the row to operate on, dictionary
# Parameter filtern: "smb_filter" for smb1 traffic, "smb2_filter" for smb2/3 traffic, relevant as different row structure 
# Return: not needed, we directly manipulate the object referenced
def srvsvc_Netshare(row,filtern):
	if filtern == "smb_filter":
		# deal with srvsvc.srvsvc_NetShare* fields
		# NetShareInfo2.name & Path and NetShareDel.share_name does not interfer with each other, fine to do it this way.
		# if fields interfer change to check srvsvc.opnum before setting fields
		tmp_srvsvc_NetShareInfo2_name = row.pop('srvsvc.srvsvc_NetShareInfo2.name','')
		if len(tmp_srvsvc_NetShareInfo2_name) > 0:
			row['smb.file'] = tmp_srvsvc_NetShareInfo2_name
			row['info'] = row.get('info','') + ' smb.file overwritten by srvsvc share info'
		tmp_srvsvc_NetShareInfo2_path = row.pop('srvsvc.srvsvc_NetShareInfo2.path','')
		if len(tmp_srvsvc_NetShareInfo2_path) > 0:
			row['smb.path'] = tmp_srvsvc_NetShareInfo2_path
			row['info'] = row.get('info','') + ' smb.path overwritten by srvsvc share info'
		tmp_srvsvc_NetShareDel_share_name = row.pop('srvsvc.srvsvc_NetShareDel.share_name','') 
		if len(tmp_srvsvc_NetShareDel_share_name) > 0:
			row['smb.file'] = tmp_srvsvc_NetShareDel_share_name
			row['smb.path'] = '' # we do not have it in the NetShareDel cmd.
			row['info'] = row.get('info','') + ' smb.file and smb.path overwritten by srvsvc share info'
	else:
		# deal with srvsvc.srvsvc_NetShare* fields AFTER smb2setfilename call -> srvsvc beats filename $IPC
		# NetShareInfo2.name & Path and NetShareDel.share_name does not interfer with each other, fine to do it this way.
		# if fields interfer change to check srvsvc.opnum before setting fields
		tmp_srvsvc_NetShareInfo2_name = row.pop('srvsvc.srvsvc_NetShareInfo2.name','')
		if len(tmp_srvsvc_NetShareInfo2_name) > 0:
			row['smb2.filename'] = tmp_srvsvc_NetShareInfo2_name
			row['info'] = row.get('info','') + ' smb2.filename overwritten by srvsvc share info'
		tmp_srvsvc_NetShareInfo2_path = row.pop('srvsvc.srvsvc_NetShareInfo2.path','')
		if len(tmp_srvsvc_NetShareInfo2_path) > 0:
			row['smb2.tree'] = tmp_srvsvc_NetShareInfo2_path
			row['info'] = row.get('info','') + ' smb2.tree overwritten by srvsvc share info'
		tmp_srvsvc_NetShareDel_share_name = row.pop('srvsvc.srvsvc_NetShareDel.share_name','') 
		if len(tmp_srvsvc_NetShareDel_share_name) > 0:
			row['smb2.filename'] = tmp_srvsvc_NetShareDel_share_name
			row['smb2.tree'] = '' # we do not have it in the NetShareDel cmd.
			row['info'] = row.get('info','') + ' smb2.filename and smb2.tree overwritten by srvsvc share info'

		
# function write given text to protocol file
# Parameter: text (text which should be written to file)	
def writetoprotocol(text):
	global protocolwriter
	protocolwriter.write(text)
	protocolwriter.flush()

	
# function get all fields that are included into desc file of extended output
def extenedOutout_desc(info_field,user,domain,path,file,smb_create,smb_search,service_info,registry_info,requestingHostname):
	des = ''
	if len(info_field) > 0:
		des += 'Info:' + info_field + ' '
	if len(user) > 0:
		des += 'User: ' + user + ' '
	if len(domain) > 0:
		des += 'Domain: ' + domain + ' '
	if len(path) > 0:
		des += 'Path: ' + path + ' '
	if len(smb_create) > 0:
		des += 'SMB create action: ' + smb_create + ' '
	if len(smb_search) > 0:
		des += 'SMB search pattern: ' + smb_search + ' '
	if len(service_info) > 0:
		des += 'service info: ' + service_info + ' '
	if len(registry_info) > 0:
		des += 'registy info: ' + registry_info + ' '
	if len(requestingHostname) > 0:
		des += 'Hostname(request): ' + requestingHostname + ' ' 
	return des

# function anticipates MACB string for log2timeline output
# MACB (Modification, Access, Changed ($MFT modified), and Birth) 
# Parameter: smbCmd (hex smb command from packet)
# Parameter: smbCreateAction (smb[2].create.action)
# Paramter: smbV SMB Version, some command strings have different meanings in smb1 or in smb2/3 (1 -> SMB Version 1, 2 -> SMB Version 2 or 3)
# Parameter: subproto_opnum, content of the filed subproto_opnum taken from row object. Used to define MACB for subprotocols
# Return: MACB String
def MACBString(smbCmd,smbCreateAction,smbV,subproto_opnum):
	global wb
	global create_action_dict
	global opnum_samr_m_list , opnum_samr_a_list , opnum_samr_b_list , opnum_lsarpc_m_list , opnum_lsarpc_a_list , opnum_lsarpc_b_list , opnum_srvsvc_m_list , opnum_srvsvc_a_list , opnum_srvsvc_b_list , opnum_wkssvc_m_list , opnum_wkssvc_a_list , opnum_wkssvc_b_list , opnum_winreg_m_list , opnum_winreg_a_list , opnum_winreg_b_list , opnum_svcctl_m_list , opnum_svcctl_a_list , opnum_svcctl_b_list , opnum_atsvc_m_list , opnum_svcctl_a_list , opnum_svcctl_b_list 
	smacb = '....'
	try:
		#MACB = ''
		if (smbCmd == '0x2e' and smbV == '1') or (smbCmd == '0x08' and smbV == '2'):
		# smb1 or smb2/3 read command
			smacb = '.A..'
		elif (smbCmd == '0x2f' and smbV == '1') or (smbCmd == '0x09' and smbV == '2'):
		# smb1 or smb2/3 write command
			smacb = 'M...'
		elif smbV == '1' and (smbCmd == '0x06' or smbCmd == '0x01'):
		#smb1 delete file or smb1 delete directory command	
			smacb = 'M.C.'
		elif smbV == '1' and smbCmd == '0x07' :
		#smb1 rename file command	
			smacb = '..C.'
		elif smbV == '2' and smbCmd == '0x11' :
		#smb2/3 set info command	
			smacb = '..C.'
		elif (smbV == '1' and smbCmd == '0xa2') or (smbV == '2' and smbCmd == '0x05'):
		# smb1 or smb2/3 open file
			c=[k for k,v in create_action_dict.items() if v == smbCreateAction]
			if len(c) > 0:
			# found key value in create_action_dict for given smbCreateAction
				createActionInt = int(c[0])
				if createActionInt == 2 :
				# file did not exist before and was created
					smacb = '...B'
				elif createActionInt == 0 or createActionInt == 3 :
				# file existed and was overwritten
					smacb = 'M.C.'
				elif createActionInt == 1 :
					smacb = '.A..' #file exists and is opened
#				else:
#					return '....'
		# for smb2/3 and smbCmd 0x09,0x08,0x0b and for smb1 and smbCmd 0x25 we overwrite MACB string accroding to subprotocol
		# yes this will handel one line multiple times, but it is way more easier to handle all subporocol stuff at one place than doing it in the specific if/elif above
		if (smbCmd == '0x08' and smbV == '2') or (smbCmd == '0x09' and smbV == '2') or (smbCmd == '0x0b' and smbV == '2') or (smbCmd == '0x25' and smbV == '1'):
			if len(subproto_opnum)>0:
				tmp_split = subproto_opnum.split(':')
				tmp_opnum = int(tmp_split[1])
				# SAMR section
				if tmp_split[0] == 'SAMR':
					if tmp_opnum in opnum_samr_m_list:
						#modification
						smacb = 'M...'
					elif tmp_opnum in opnum_samr_a_list:
						#access
						smacb = '.A..'
					elif tmp_opnum in opnum_samr_b_list:
						#creation
						smacb = '...B'
					else:
						#do not overwrite
						smacb = smacb
				# LSARPC section
				elif tmp_split[0] == 'LSARPC':
					if tmp_opnum in opnum_lsarpc_m_list:
						#modification
						smacb = 'M...'
					elif tmp_opnum in opnum_lsarpc_a_list:
						#access
						smacb = '.A..'
					elif tmp_opnum in opnum_lsarpc_b_list:
						#creation
						smacb = '...B'
					else:
						#do not overwrite
						smacb = smacb
				# SRVSVC section
				elif tmp_split[0] == 'SRVSVC':
					if tmp_opnum in opnum_srvsvc_m_list:
						#modification
						smacb = 'M...'
					elif tmp_opnum in opnum_srvsvc_a_list:
						#access
						smacb = '.A..'
					elif tmp_opnum in opnum_srvsvc_b_list:
						#creation
						smacb = '...B'
					else:
						#do not overwrite
						smacb = smacb
				# WKSSVC section
				elif tmp_split[0] == 'WKSSVC':
					if tmp_opnum in opnum_wkssvc_m_list:
						#modification
						smacb = 'M...'
					elif tmp_opnum in opnum_wkssvc_a_list:
						#access
						smacb = '.A..'
					#elif tmp_opnum in opnum_wkssvc_b_list:
						#creation , not used at the moment
					#	smacb = '...B'
					else:
						#do not overwrite
						smacb = smacb
				# WINREG section
				elif tmp_split[0] == 'WINREG':
					if tmp_opnum in opnum_winreg_m_list:
						#modification
						smacb = 'M...'
					elif tmp_opnum in opnum_winreg_a_list:
						#access
						smacb = '.A..'
					elif tmp_opnum in opnum_winreg_b_list:
						#creation
						smacb = '...B'
					else:
						#do not overwrite
						smacb = smacb
				# SVCCTL section
				elif tmp_split[0] == 'SVCCTL':
					if tmp_opnum in opnum_svcctl_m_list:
						#modification
						smacb = 'M...'
					elif tmp_opnum in opnum_svcctl_a_list:
						#access
						smacb = '.A..'
					elif tmp_opnum in opnum_svcctl_b_list:
						#creation
						smacb = '...B'
					else:
						#do not overwrite
						smacb = smacb
				# ATSVC section
				elif tmp_split[0] == 'ATSVC':
					if tmp_opnum in opnum_atsvc_m_list:
						#modification
						smacb = 'M...'
					elif tmp_opnum in opnum_atsvc_a_list:
						#access
						smacb = '.A..'
					elif tmp_opnum in opnum_atsvc_b_list:
						#creation
						smacb = '...B'
					else:
						#do not overwrite
						smacb = smacb
				else:
					#do not overwrite
					smacb = smacb
			#else:
			#don't overwrite, do nothing
		
		return smacb
	
	except Exception as e:
		if wp:
			writetoprotocol('Error determining MACB String, setting default ----')
			writetoprotocol(str(e))
			print(traceback.format_exc())
		return '....'
	
# function parses and writes log2timeline (axa extended output)
# Parameter: l2toutput (path to log2timeline output target)
# Parameter: smb1timeline (path to smb1 timeline as input, empty if smb1 timeline was not produced)
# Parameter: smb2timeline (path to smb2/3 timeline as input, empty if smb2/3 timeline was not produced)
# Parameter: delimiterChar (-e option: ',' ; -b option: '|')
def l2toutput(l2toutput_file,smb1timeline,smb2timeline,delimiterChar):
	print("parsing timeline output to extended output file")
	start_time = time.time()
	global wp
	global inputfile
	l2tdict = defaultdict(list)
	new_row = ({'date': '', 'time' : '', 'timezone': '', 'MACB':'', 'source':'', 'sourcetype':'', 'type':'', 'user':'', 'host':'', 'short':'', 'desc':'', 'version':'', 'filename':'', 'inode':'', 'notes':'', 'format':'', 'extra':''})
	print("starting extended output")
	if wp:
		writetoprotocol('\n######################### log2timeline export ########################\n')
		if delimiterChar == ",":
			writetoprotocol('Output format: csv \n')
		else:
			#delimiter: |
			writetoprotocol('Output format: body file \n')
		writetoprotocol(l2toutput_file + '\n')
		writetoprotocol('\n#####################################################################################\n')
		
	try:	
		# create timeline write object
		l2twriter = open(l2toutput_file,'w')
		lt2Headerlist = ['date','time','timezone','MACB','source','sourcetype','type','user','host','short','desc','version','filename','inode','notes','format','extra']
		l2twriter = csv.DictWriter(l2twriter, delimiter=delimiterChar, quotechar='\"', fieldnames=lt2Headerlist)
		#l2twriter = csv.DictWriter(l2twriter, delimiter=',', quotechar='\"', fieldnames=lt2Headerlist)
		l2twriter.writeheader()
	except Exception as e:
		print ('unable to open or write to specified extended output file ' + l2toutput_file + '\n')
		print (e)
		print(traceback.format_exc())

	if len(smb1timeline) > 0:
	# process smb1 timeline
		smb1_data = csv.DictReader(open(smb1timeline),delimiter=',',quotechar='\"')
		#for row in smb1_data, parse to l2tHeader + sortfield is frame.number
		for row in smb1_data:
			new_row['date'] = row['frame.date_epoch']
			new_row['time'] = row['frame.time_epoch']
			new_row['timezone'] = row['timezone']
			new_row['MACB'] = MACBString(format(int(row['smb.cmd']),'#04x'),row.get('smb.create.action',''),'1',row.get('subProto_opnum','')) # if smb write: M, if read and smb.create 1: A, if read and smb.create C,
			new_row['source'] = 'pcap'
			new_row['sourcetype'] = 'pcap ' + inputfile + ' parsed by smbtimeline'
			new_row['type'] = row.get('smb_action','') + ' ' + row.get('status','')
			new_row['user'] = row.get('account','')
			new_row['host'] = row.get('ip.src','') 
			new_row['short'] = row.get('smb_action','') + ' ' + row.get('status','') + ' ' + row.get('ip.src','') + ':' + row.get('srcport','') + ' -> ' + row.get('ip.dst','') + ':' + row.get('dstport','')
			#new_row['desc'] = new_row.get('short', '') + ' User: ' + row.get('account','') + ' Domain: ' + row.get('domain','') + ' Path: ' + row.get('smb.path','') + ' File: ' + row.get('smb.file','') + ' SMB create action: ' + row.get('smb.create.action','') + ' SMB search pattern: ' + row.get('smb.search_pattern','') + row.get('service_info','')
			#new_row['desc'] = 'User: ' + row.get('account','') + ' Domain: ' + row.get('domain','') + ' Path: ' + row.get('smb.path','') + ' File: ' + row.get('smb.file','') + ' SMB create action: ' + row.get('smb.create.action','') + ' SMB search pattern: ' + row.get('smb.search_pattern','') + ' service_info: ' + row.get('service_info','') + ' registry_info: ' + row.get('registry_info','')
			new_row['desc'] = extenedOutout_desc(row.get('info',''),row.get('account',''),row.get('domain',''),row.get('smb.path',''),row.get('smb.file',''),row.get('smb.create.action',''),row.get('smb.search_pattern',''),row.get('service_info',''),row.get('registry_info',''),row.get('requestingHostname',''))
			new_row['version'] = '2'
			new_row['filename'] = row.get('smb.file', '')
			new_row['inode'] = '-'
			new_row['notes'] = 'wireshark info column: ' + row.get('_ws.col.Info','')
			new_row['format'] = 'smbtimeline'
			new_row['extra'] = 'SMB MID: ' + row.get('smb.mid','-') + '; SMB UID: ' + row.get('smb.uid','-') + '; SMB PID: ' + row.get('smb.pid','-') + '; SMB TID: ' + row.get('smb.tid','-') + '; SMB FID: ' + row.get('smb.fid','-') + '; Frame nr: ' + row.get('frame.number','-') + '; TCP stream nr; ' + row.get('tcp.stream','-') + '; Response to frame nr: ' + row.get('smb.response_to','-')
			#we use frame.number als key for dict, we later sort the dict based on the key
			# as we initialized a defauldict with an empty list as default, we can use append to add an entry to the list item per key. If the key does not exist, append is called for the empty list (default), if the key exist,append is called
			# for the already existing list.
			# Reason: we can append and deal with multiple lines per frame.number (one frame => multiple smb commands -> multiple lines in timeline with same frame.number
			# we need to do a deepcopy of the object, which will be appended to the list, otherwise it is just a reference to the new_row object. Which will represent the last status of the new_row object for all keys.
			l2tdict[int(row['frame.number'])].append(copy.deepcopy(new_row))

	
	if len(smb2timeline) > 0:
	# process smb2 timeline
		smb2_data = csv.DictReader(open(smb2timeline),delimiter=',',quotechar='\"')
		#for row in smb2_data, parse to l2tHeader + sortfield is frame.number
		for row in smb2_data:
			new_row['date'] = row['frame.date_epoch']
			new_row['time'] = row['frame.time_epoch']
			new_row['timezone'] = row['timezone']
			new_row['MACB'] = MACBString(format(int(row['smb2.cmd']),'#04x'),row.get('smb2.create.action',''),'2',row.get('subProto_opnum','')) 
			new_row['source'] = 'pcap'
			new_row['sourcetype'] = 'pcap ' + inputfile + ' parsed by smbtimeline'
			new_row['type'] = row.get('smb_action','') + ' ' + row.get('status','')
			new_row['user'] = row.get('account','')
			new_row['host'] = row.get('ip.src','')
			new_row['short'] = row.get('smb_action','') + ' ' + row.get('status','') + ' ' + row.get('ip.src','') + ':' + row.get('srcport','') + ' -> ' + row.get('ip.dst','') + ':' + row.get('dstport','') 
			#new_row['desc'] = new_row.get('short', '') + ' User: ' + row.get('account','') + ' Domain: ' + row.get('domain','') + ' Path: ' + row.get('smb2.tree','') + ' File: ' + row.get('smb2.filename','') + ' SMB create action: ' + row.get('smb2.create.action','') + ' SMB search pattern: ' + row.get('smb2.find.pattern','') + row.get('service_info','')
			new_row['desc'] = extenedOutout_desc(row.get('info',''),row.get('account',''),row.get('domain',''),row.get('smb2.tree',''),row.get('smb2.filename',''),row.get('smb2.create.action',''),row.get('smb2.find.pattern',''),row.get('service_info',''),row.get('registry_info',''),row.get('requestingHostname',''))
			new_row['version'] = '2'
			new_row['filename'] = row.get('smb2.filename','')
			new_row['inode'] = '-'
			new_row['notes'] = 'wireshark info column: ' + row.get('_ws.col.Info','')
			new_row['format'] = 'smbtimeline'
			new_row['extra'] = 'SMB SESID: ' + row.get('smb2.sesid','-') + '; SMB PID: ' + row.get('smb2.pid','-') + '; SMB TID: ' + row.get('smb2.tid','-') + '; SMB FID: ' + row.get('smb2.fid','-') + '; Frame nr: ' + row.get('frame.number','-') + '; TCP stream nr: ' + row.get('tcp.stream','-') + '; Response to frame nr: ' + row.get('smb2.response_to','-')
			#we use frame.number als key for dict, we later sort the dict based on the key
			# as we initialized a defauldict with an empty list as default, we can use append to add an entry to the list item per key. If the key does not exist, append is called for the empty list (default), if the key exist,append is called
			# for the already existing list.
			# Reason: we can append and deal with multiple lines per frame.number (one frame => multiple smb commands -> multiple lines in timeline with same frame.number
			# we need to do a deepcopy of the object, which will be appended to the list, otherwise it is just a reference to the new_row object. Which will represent the last status of the new_row object for all keys.
			l2tdict[int(row['frame.number'])].append(copy.deepcopy(new_row))
	

	# sort l2tdict via key
	# for key in sorted(l2tdict.keys(),reverse=True):
	# key=lambda row:int(row['frame.number'])
	
	# sort l2tdict via key as integer
	#for k in sorted(l2tdict.iterkeys(),key=lambda k:int(k),reverse=True):
	#for k in sorted(l2tdict.iterkeys(),key=lambda k:int(k)):
	for k in sorted(l2tdict.keys(),key=lambda k:int(k)):
	# iterare through l2tdict
		t_rowlist = l2tdict[k]
		for t_row in t_rowlist:
		# for each entry iterate through list returned
			#print(t_row)
			# for each entry in list returned write to file
			l2twriter.writerow(t_row)
			
	stop_time = time.time()
	elapsed = stop_time - start_time
	h = int(elapsed//3600)
	m = int((elapsed%3600) // 60)
	s = int((elapsed%3600)%60)
	temp_durations = "total time: %d:%d:%d (hh:mm:ss)" %(h,m,s)
	print(temp_durations)
	if wp:
		writetoprotocol('\n##################################### l2toutput #####################################\n')
		writetoprotocol('\n############################ ' + temp_durations + ' ############################\n')
		

		
#########################################################################################################################################################################
#																			start some logic																			#
#########################################################################################################################################################################
try:
	opts, args = getopt.getopt(sys.argv[1:],"12f:p:ho:e:sncdi",["smb1","smb2","file=","protocol=","help","outputdir=","extended=","strip","noclean","csv","deletestriped","infoColumn"])
 
except getopt.GetoptError as err:
	print(err)
	usage()
	exit(1)
	
for opt, arg in opts:
	if opt in ("-1", "--smb1"):
		smb1 = True
	elif opt in ("-f", "--file"):
		inputfile_o = arg
		inputfile = inputfile_o
	elif opt in ("-2","--smb2"):
		smb2 = True
	elif opt in ("-p","--protocol"):
		wp = arg
	elif opt in ("-e","--extended"):
		l2toutput_file = arg
	elif opt in ("-s","--strip"):
		strip = True
	elif opt in ("-n","--noclean"):
		clean = False
	elif opt in ("-c","--csv"):
		use_json = False
	elif opt in ("-d", "--deletestriped"):	
		remove_striped = True
	elif opt in ("-i", "--infoColumn"):
		wsInfoColumn = True
	elif opt in ("-h","--help"):
		usage()
		exit(0)
	else:
		usage()
		assert False, "unknown option"

		
#IF no parameters given, except -f(--file) run default: smb2 and smb1 timeline, protocol yes, no quick filter, doing cleanup
if len(opts) == 1:
	if opts[0][0] == '-f' or opts[0][0] == '--file':
		print('just -f option given')
		smb1 = True
		smb2 = True
		wp = 'protocol.txt'
		defaults = True
				
		
# set variable for protocol status & initialize protocol file if requested
if len(wp) > 0:
	proto = True
	try:
		protocolwriter = open(wp,'w')
	except Exception as e:
		print("\nunable to open protocol file for writing\nProvided argument: " + wp)
else:
	proto = False

#write to protocol that defaults where used.
if defaults:
	if wp:
		writetoprotocol('\n################################ default options used ################################\n')
		writetoprotocol('it was just the -f (--file) option given; using defaults: --smb1 --smb2 -p protocol.txt \n')
		writetoprotocol('\n#####################################################################################\n')
	
#write version to protocol
if wp:
	writetoprotocol('\n################################ smbtimeline version ################################\n')
	writetoprotocol( 'Version: ' + smbtimelineversion +'\n')
	writetoprotocol('\n#####################################################################################\n')
		
# check with os script is running on; needs to be performed before any other methods, as they depend on os
checkos()
# check if tshark tool is in path
checktshark()

# if strip option is set, we take the provided pcap and strip traffic down to smb only
if strip:
	# check if we can execute tcpdump or windump
	checkdump()
	inputfile = stripPCAP(inputfile)

if wsInfoColumn:
	wsInfoColumnDict = createInfoFieldDict(inputfile)


if smb2:
	# section for smb2
	timelinefile = "timeline_smb2.csv"
	csvwriter = open(timelinefile,'w')
	csvHeaderlist = ['frame.number','frame.date_epoch','frame.time_epoch','timezone','ip.src','ip.dst','srcport','dstport','smb_action','info','status','smb2.tree','smb2.filename','account','domain','smb2.find.pattern','requestingHostname','service_info','registry_info','smb2.share_type','smb2.create.action','_ws.col.Info','smb2.sesid' ,'smb2.pid' ,'smb2.tid' ,'smb2.fid','eth.src','eth.dst','smb2.cmd', 'tcp.stream', 'smb2.response_to', 'subProto_opnum']
	timelinewriter = csv.DictWriter(csvwriter, delimiter=',', quotechar='\"', fieldnames=csvHeaderlist)
	timelinewriter.writeheader()
	if use_json: 
		#using json output is selected
		tsharkfilter_json(inputfile,smb2_filter,"smb2_filter.json","smb2_filter")
		parseJSON ("smb2_filter.json",timelinewriter,"smb2_filter")
	else:
		# use deprecated csv method
		tsharkfilter(inputfile,smb2_filter,"smb2_filter.csv","smb2_filter")
		normalizeCSV ("smb2_filter.csv",timelinewriter,"smb2_filter")
		if wp:
			writetoprotocol('\n############################ SMB2/3 legacy csv mode used ############################\n')
			writetoprotocol( 'with option -c --csv you have used a deprecated function.\n')
			writetoprotocol('\n#####################################################################################\n')
	csvwriter.close()
	# clean up all smb2 tmp csv files
	if clean:
		if use_json:
			#using json output is selected:
			os.remove('smb2_filter.json')
			if wp:
				writetoprotocol('\n###################################### Clean up #####################################\n')
				writetoprotocol( 'removed tmp file: smb2_filter.json\n')
				writetoprotocol('\n#####################################################################################\n')
		else:
			#remove csv file
			os.remove('smb2_filter.csv')
			if wp:
				writetoprotocol('\n###################################### Clean up #####################################\n')
				writetoprotocol( 'removed tmp file: smb2_filter.csv\n')
				writetoprotocol('\n#####################################################################################\n')

if smb1:
	# section for smb
	timelinefile = "timeline_smb1.csv"
	csvwriter = open(timelinefile,'w')
	csvHeaderlist = ['frame.number','frame.date_epoch','frame.time_epoch','timezone','ip.src','ip.dst','srcport','dstport','smb_action','info','status','smb.path','smb.file','account','domain','smb.search_pattern','requestingHostname','service_info','registry_info','smb.mid','smb.uid','smb.pid','smb.tid','smb.fid','smb.create.action','_ws.col.Info','eth.src','eth.dst','smb.cmd','tcp.stream', 'smb.response_to', 'subProto_opnum']
	timelinewriter = csv.DictWriter(csvwriter, delimiter=',', quotechar='\"', fieldnames=csvHeaderlist)
	timelinewriter.writeheader()
	if use_json:
		#using json output is selected:
		tsharkfilter_json(inputfile,smb_filter,"smb_filter.json","smb_filter")
		parseJSON ("smb_filter.json",timelinewriter,"smb_filter")
	else:
		# use deprecated csv method
		tsharkfilter(inputfile,smb_filter,"smb_filter.csv","smb_filter")
		normalizeCSV ("smb_filter.csv",timelinewriter,"smb_filter")
		if wp:
			writetoprotocol('\n############################# SMB1 legacy csv mode used #############################\n')
			writetoprotocol( 'with option -c --csv you have used a deprecated function.\n')
			writetoprotocol('\n#####################################################################################\n')
	csvwriter.close()
	# clean up all smb tmp csv files
	if clean:
		if use_json:
			#using json output is selected:
			os.remove('smb_filter.json')
			if wp:
				writetoprotocol('\n###################################### Clean up #####################################\n')
				writetoprotocol( 'removed tmp file: smb_filter.json\n')
				writetoprotocol('\n#####################################################################################\n')
		else:
			#remove csv file
			os.remove('smb_filter.csv')
			if wp:
				writetoprotocol('\n###################################### Clean up #####################################\n')
				writetoprotocol( 'removed tmp file: smb_filter.csv\n')
				writetoprotocol('\n#####################################################################################\n')

if strip:
	# clean stripped pcap, but only if inputfile !+ inputfile_o, as we do not want to delete the original file/evidence
	if clean and inputfile != inputfile_o and remove_striped:
		os.remove(inputfile)	
		if wp:
			writetoprotocol('\n###################################### Clean up #####################################\n')
			writetoprotocol( 'removed tmp file: ' + inputfile + '\n')
			writetoprotocol('\n#####################################################################################\n')


if len(l2toutput_file):
	# option to write log2timeline output given
	tmp_smb1_timelinefile = tmp_smb2_timelinefile = ''
	if smb1:
		tmp_smb1_timelinefile = "timeline_smb1.csv"
	if smb2:
		tmp_smb2_timelinefile = "timeline_smb2.csv"
		
	l2toutput(l2toutput_file,tmp_smb1_timelinefile,tmp_smb2_timelinefile,',')
		
#write smbtimeline limitations and further infos to protocol if protocol is enables
if wp:
	writetoprotocol('\n############################## smbtimeline intention ###############################\n')
	writetoprotocol('smbtimeline is designed to produce a timeline out of smb network traffic. A timeline is a timeline and not a listing of every less or more important detail. Therefore smbtimeline provides an overview and a timeline, it is not, an will not, be a tool for doing deep dive analysis of single network packets. If you want to see any little detail of a packet use tools like wirkshark or a hexeditor.\n')
	writetoprotocol('\n#####################################################################################\n')
	writetoprotocol('\n##################### smbtimeline limitations and explanations ######################\n')
	writetoprotocol('\nsmbtimeline depends on the parsing capabilities of wireshark/tshark. If wireshark/tshark is not capable of identifying and parsing traffic as smb, the traffic will also not be processed by smbtimeline.\n')
	writetoprotocol('\nONLY if deprecated csv output is used: SMB traffic an carry one or more smb commands, if this is the case smbtimeline produces one entry into the timeline per smb command.\nIf data-fields in this case show up multiple times in the export of tshark, they have to be split between smb commands. This will be done in the order of appearance.\n\tExample: Packet contains 3 smb commands (a,b,c) and the export has there values (y,x,z) for the data-field "examplefield". \n\tResult:\n\ttimelineNR\tsmb command\texamplefield\n\t1\t\ta\t\ty\n\t2\t\tb\t\tx\n\t3\t\tc\t\tz\nIf a packet carries more than one smb command, but the data-field just carries one value it will be assigned to the first row, for the remaining rows a blank value will be used.')
	writetoprotocol('If SMB traffic contains srvsvc.NetShareInfo2.name,srvsvc.srvsvc_NetShareInfo2.path,srvsvc.srvsvc_NetShareDel.share_name: file & path and tree & filename (for smb2/3) will be overwritten with the aforementioned values.')
	writetoprotocol('\nSMB Traffic can carry a sub-protocol in Remote Procedure Calls, like srvsvc or wkssvc. If a sub-protocol is addressed by smbtimeline, additional info will be added.')
	writetoprotocol('\nCurrently addressed sub-protocols: samr,lsarpc,srvsvc,wkssvc,winreg,svcctl,atsvc')
	writetoprotocol('\n\tNot all IOCTL ctlcodes will be decoded, if the code is missing in the extention dict, its ctlcode will be shown as hex.')
	writetoprotocol('\n\tONLY if deprecated csv output is used: winreg protocol ONLY SMB1: registrykey names are extracted from winreg.opnum in {15 6 13}, value names from winreg.opnum in {17 22 8} and stored in registry_info field')
	writetoprotocol('\n\tCurrent mode for winreg protocol: Keys and Values are extracted where found.')
	writetoprotocol('\n\tIt appears that some fields in the json output of tshark are not always at the same place in the json structure of a frame. It is possible that a field is missed, especially in deeper levels of the frames. If you find a situation where this is the case, please get in touch and provided a sample pcap.')
	writetoprotocol('\nMACB String limitations:')
	writetoprotocol('\n\tMACB Strings are not a perfect match for network protocols, for DCE/RPC aka sub-protocols it is even less of a match. Due to that sub-protocols just get "modification" (M...), "access" (.A..) and "brith" (...B) assigned.\n\tThe state "change", in regards of (file) metadata changes is not used.')
	writetoprotocol('\n\tIn sub-protocols some of the open commands (which will get an .A..) will only show in their response if the request was successful of not. No matter if the request was successful or not, they will get a .A.. .')
	writetoprotocol('\n#####################################################################################\n')
	# extended output l2t enabled
	if len(l2toutput_file):
		writetoprotocol('\n################################# extendet output  #################################\n')
		writetoprotocol('\nMACB String:')
		writetoprotocol('\nMatching smb traffic to MACB String not final yet, please consider it in beta status at the moment')
		writetoprotocol('\nFor MACB limitations see limitations section above.')
		writetoprotocol('\nSMB1-3 read requests are causing an .A.. MACB String')
		writetoprotocol('\nSMB1-3 write requests are causing an M... MACB String')
		writetoprotocol('\nSMB1-3 open requests are causing an ...B MACB String if the smbcreateaction returned is 2 (which indicates file did not existed befor and was createde')
		writetoprotocol('\nSMB1-3 open requests are causing an M.C. MACB String if the smbcreateaction returned is 0 or 3 (which indicates file did existed before and was overwritten')
		writetoprotocol('\nSMB1-3 open requests are causing an .A.. MACB String if the smbcreateaction returned is 1 (which indicates file did existed before and was opened')
		writetoprotocol('\nSMB1 delete file or delete directory requests are causing an M.C. MACB String')
		writetoprotocol('\nSMB1 rename file requests are causing an ..C. MACB String')
		writetoprotocol('\nSMB2/3 set_info requests are causing an ..C. MACB String')
		writetoprotocol('\nMACB String is overwritten if a sub-protocol is present and opnums of the protocol are included in List for modicication,access,change,brith. See lists per subprotocol above:\n')
		writetoprotocol('samr:\n\tModification: ' + str(opnum_samr_m_list) + '\n\tAccess: ' + str(opnum_samr_a_list) + '\n\tBirth: ' + str(opnum_samr_b_list) + '\n')
		writetoprotocol('lsarpc:\n\tModification: ' + str(opnum_lsarpc_m_list) + '\n\tAccess: ' + str(opnum_lsarpc_a_list) + '\n\tBirth: ' + str(opnum_lsarpc_b_list) + '\n')
		writetoprotocol('srvsvc:\n\tModification: ' + str(opnum_srvsvc_m_list) + '\n\tAccess: ' + str(opnum_srvsvc_a_list) + '\n\tBirth: ' + str(opnum_srvsvc_b_list) + '\n')
		writetoprotocol('wkssvc:\n\tModification: ' + str(opnum_wkssvc_m_list) + '\n\tAccess: ' + str(opnum_wkssvc_a_list) + '\n\tBirth: ' + str(opnum_wkssvc_b_list) + '\n')
		writetoprotocol('winreg:\n\tModification: ' + str(opnum_winreg_m_list) + '\n\tAccess: ' + str(opnum_winreg_a_list) + '\n\tBirth: ' + str(opnum_winreg_b_list) + '\n')
		writetoprotocol('svcctl:\n\tModification: ' + str(opnum_svcctl_m_list) + '\n\tAccess: ' + str(opnum_svcctl_a_list) + '\n\tBirth: ' + str(opnum_svcctl_b_list) + '\n')
		writetoprotocol('atsvc:\n\tModification: ' + str(opnum_atsvc_m_list) + '\n\tAccess: ' + str(opnum_atsvc_a_list) + '\n\tBirth: ' + str(opnum_atsvc_b_list) + '\n')
		writetoprotocol('\nField definitions log2timeline format -> smbtimeline:\n')
		writetoprotocol('date: frame.date_epoch\n')
		writetoprotocol('time: frame.time_epoch\n') 
		writetoprotocol('timezone: timezone\n') 
		writetoprotocol('MACB: see above for definition how MACB string is set\n') 
		writetoprotocol('source: pcap (hardcoded value)\n') 
		writetoprotocol('sourcetype: pcap INPUTFILENAME parsed by smbtimeline\n') 
		writetoprotocol('type: smb_action + status\n') 
		writetoprotocol('user: account\n') 
		writetoprotocol('host: ip.src\n') 
		writetoprotocol('short: smb_action + status + ip.src : srcport -> ip.dst : dstport\n') 
		writetoprotocol('desc (for SMB1): extended output field (if present): info_field + account + domain + smb.path + smb.file + smb.create.action + smb.search_pattern + service_info + registry_info + requestingHostname\n')
		writetoprotocol('desc (for SMB2/3): extended output field (if present): info_field + account + domain + smb2.tree + smb2.filename + smb2.create.action + smb2.find.pattern + service_info + registry_info + requestingHostname\n')		
		writetoprotocol('version: 2 (hardcoded value)\n') 
		writetoprotocol('filename (for SMB1): smb.file\n')
		writetoprotocol('filename (for SMB2/3): smb2.filename\n')		
		writetoprotocol('inode: - (hardcoded value)\n') 
		writetoprotocol('notes: contains wireshark info column\n') 
		writetoprotocol('format: smbtimeline (hardcoded value)\n') 
		writetoprotocol('extra (for SMB1): smb.mid + smb.uid + smb.pid + smb.tid + smb.fid + frame.number + tcp.stream + smb.response_to\n')
		writetoprotocol('extra (for SMB2/3): smb2.sesid + smb2.pid + smb2.tid + smb2.fid + frame.number + tcp.stream + smb2.response_to\n')
		writetoprotocol('\n#####################################################################################\n')
	
