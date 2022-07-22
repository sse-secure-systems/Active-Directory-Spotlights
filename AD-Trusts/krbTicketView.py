#!/usr/bin/env python3
# 
###
#### Build on the works of
##### https://github.com/SecureAuthCorp/impacket; AND
##### https://github.com/dirkjanm/forest-trust-tools/blob/master/getftST.py
###
##
#

import argparse
import binascii
import datetime
from pyasn1.codec.der import decoder

from impacket.krb5.ccache import CCache
from impacket.krb5.types import Ticket
from impacket.krb5.crypto import  _enctype_table, Key
from impacket.krb5.asn1 import EncTicketPart, AD_IF_RELEVANT
from impacket.krb5.pac import PACTYPE, PAC_INFO_BUFFER, KERB_VALIDATION_INFO, PAC_CLIENT_INFO_TYPE, PAC_CLIENT_INFO, \
    PAC_SERVER_CHECKSUM, PAC_SIGNATURE_DATA, PAC_PRIVSVR_CHECKSUM, PAC_UPN_DNS_INFO, UPN_DNS_INFO, PAC_CREDENTIALS_INFO, PAC_LOGON_INFO
from impacket.dcerpc.v5.rpcrt import TypeSerialization1
from impacket.krb5.crypto import InvalidChecksum



TICKET_ENC_TABLE = {
    0: 'reserved [RFC6448]',
    1: 'des-cbc-crc [RFC6649]',
    2: 'des-cbc-md4 [RFC6649]',
    3: 'des-cbc-md5 [RFC6649]',
    4: 'Reserved [RFC3961]',
    5: 'des3-cbc-md5 [RFC8429]',
    6: 'Reserved [RFC3961]',
    7: 'des3-cbc-sha1 [RFC8429]',
    8: 'Unassigned',
    9: 'dsaWithSHA1-CmsOID [RFC4556]',
    10: 'md5WithRSAEncryption-CmsOID [RFC4556]',
    11: 'sha1WithRSAEncryption-CmsOID [RFC4556]',
    12: 'rc2CBC-EnvOID 	[RFC4556]',
    13: 'rsaEncryption-EnvOID [RFC4556][rom PKCS#1 v1.5]]',
    14: 'rsaES-OAEP-ENV-OID [RFC4556][rom PKCS#1 v2.0]]',
    15: 'des-ede3-cbc-Env-OID [RFC4556]',
    16: 'des3-cbc-sha1-kd [RFC8429]',
    17: 'aes128-cts-hmac-sha1-96 [RFC3962]',
    18: 'aes256-cts-hmac-sha1-96 [RFC3962]',
    19: 'aes128-cts-hmac-sha256-128 [RFC8009]',
    20: 'aes256-cts-hmac-sha384-192 [RFC8009]',
    21: 'Unassigned',
    22: 'Unassigned',
    23: 'rc4-hmac [RFC8429]',
    24: 'rc4-hmac-exp [RFC6649]',
    25: 'camellia128-cts-cmac [RFC6803]',
    26: 'camellia256-cts-cmac [RFC6803]'
}

TICKET_FLAG_BITSIZE = 32
TICKET_FLAG_BITS = {
    1: 'reserved',
    2: 'forwardable',
    4: 'forwarded',
    8: 'proxiable',
    16: 'proxy',
    32: 'may-postdate',
    64: 'postdated',
    128: 'invalid',
    256: 'renewable',
    512: 'initial',
    1024: 'pre-authent',
    2048: 'hw-authent',
    4096: 'transited-policy-checked',
    8192: 'ok-as-delegate',
    16384: 'unkown',
    32768: 'name-canonicalize'
}

## https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.4
TICKET_AUTHORIZATION_DATA_TYPES = {
    'AD-IF-RELEVANT': 1,
    'AD-WIN2K-PAC': 128 
}

IDENT_LEVEL_1 = ""
IDENT_LEVEL_2 = " "*2
IDENT_LEVEL_3 = " "*4
IDENT_LEVEL_4 = " "*6
IDENT_LEVEL_5 = " "*8
IDENT_LEVEL_6 = " "*10
IDENT_LEVEL_7 = " "*12

MSG_TYPE_DEFAULT = ""
MSG_TYPE_HEADER = "\033[1m"
MSG_TYPE_SUBHEADER = "\033[38;5;102m"
MSG_TYPE_FIELD = "\033[38;5;65m"
MSG_TYPE_FIELD_VALUE = "\033[38;5;146m"
MSG_TYPE_ERROR = "\033[38;5;196m"
MSG_TYPE_END = "\033[0m"

def log(msg, msgType=MSG_TYPE_DEFAULT, identLevel=IDENT_LEVEL_1):
    if( msgType == MSG_TYPE_FIELD and (':' in msg) ):
        msgSplit = msg.split(':')
        print("%s%s%s%s:%s%s%s" %(
            identLevel,
            MSG_TYPE_FIELD,
            msgSplit[0],
            MSG_TYPE_END,
            MSG_TYPE_FIELD_VALUE,
            msgSplit[1],
            MSG_TYPE_END
        ))
    else:
        print("%s%s%s%s" %(
            msgType,
            identLevel,
            msg,
            MSG_TYPE_END  
        ))

def get_ticket_enc_type(enctype):
    try:
        enct = TICKET_ENC_TABLE[enctype]
        return enct.upper()
    except:
        return "UNKNOWN ENC TYPE '%s'" %(enctype)

def reverse_bit_flags(num,bitSize):
    binary = bin(num)
    reverse = binary[-1:1:-1]
    reverse = reverse + (bitSize - len(reverse))*'0'
    return int(reverse,2)

def enumerate_ticket_flags(intFlagSum):
    flags = []
    flagval = reverse_bit_flags(intFlagSum, TICKET_FLAG_BITSIZE)
    for fbit in sorted( TICKET_FLAG_BITS.keys(), reverse=True):
        if( fbit & flagval ):
            sflag = TICKET_FLAG_BITS[fbit].upper()
            flags.append( sflag )
    return flags

def datetime_from_timestmp(timestamp):
    return datetime.date.fromtimestamp(timestamp)

def datetime_from_kerberos_time(timestring):
    return datetime.datetime.strptime(timestring, '%Y%m%d%H%M%SZ')

def timestring_from_datetim(dt):
    return dt.strftime('%a, %B %d %H-%M-%S %Y')

def print_ticket_flags(ticketFlags, identLevel):
    ticket_flags = enumerate_ticket_flags(ticketFlags)
    sticket_flags = ' '.join(ticket_flags)
    log("Flags: %s" %(sticket_flags), MSG_TYPE_FIELD, identLevel)

def print_ticket_lifetimes(ticket_valid_from, ticket_valid_until,ticket_renew_till, identLevel):
    log("Valid From: %s" %(timestring_from_datetim(ticket_valid_from)), MSG_TYPE_FIELD, identLevel )
    log("Valid Until: %s" %(timestring_from_datetim(ticket_valid_until)), MSG_TYPE_FIELD, identLevel )
    log("Max. End-Time (absolute expiration): %s" %(timestring_from_datetim(ticket_renew_till)), MSG_TYPE_FIELD, identLevel )

def print_encrypted_ticket_parts(encTicketPart):
    log("--- EncryptedTicket ---", MSG_TYPE_SUBHEADER, IDENT_LEVEL_4)
    ### Client Name
    try:
        client_name = ''
        cnameSequence = encTicketPart['cname']
        for cname_component in cnameSequence['name-string']._componentValues:
            client_name += '/%s' %cname_component.prettyPrint()
        client_name = client_name.lstrip('/')
        ### Client Realm
        crealmComponent = encTicketPart['crealm']
        client_realm = crealmComponent.prettyPrint()
        log("Client: %s@%s" %( client_name, client_realm ), MSG_TYPE_FIELD, IDENT_LEVEL_5 )
    except Exception as error:
        ## If you don't see a Client name feel free to investigate what's wrong
        pass
    ## Print flags
    ticket_flags = encTicketPart['flags']._value
    print_ticket_flags(ticket_flags, IDENT_LEVEL_5)
    ## Print Lifetimes
    ticket_valid_from = encTicketPart['starttime']._value
    dticket_valid_from = datetime_from_kerberos_time(ticket_valid_from)
    ticket_valid_until = encTicketPart['endtime']._value
    ddticket_valid_from = datetime_from_kerberos_time(ticket_valid_until)
    ticket_renew_till = encTicketPart['renew-till']._value
    dticket_renew_till = datetime_from_kerberos_time(ticket_renew_till)
    print_ticket_lifetimes(
        dticket_valid_from,
        ddticket_valid_from,
        dticket_renew_till,
        IDENT_LEVEL_5
    )
    ## Print PAC
    print_encrypted_ticket_pac(encTicketPart)

def print_encrypted_ticket_pac(encTicketPart):
    adIfRelevant = decoder.decode(encTicketPart['authorization-data'][0]['ad-data'], asn1Spec=AD_IF_RELEVANT())[0]
    if( adIfRelevant[0]['ad-type']._value == TICKET_AUTHORIZATION_DATA_TYPES['AD-WIN2K-PAC'] ):
        log("--- PAC ---", MSG_TYPE_SUBHEADER, IDENT_LEVEL_5)
        pacType = PACTYPE(bytes(adIfRelevant[0]['ad-data']))
        buff = pacType['Buffers']
        for bufferN in range(pacType['cBuffers']):
            infoBuffer = PAC_INFO_BUFFER(buff)
            data = pacType['Buffers'][infoBuffer['Offset']-8:][:infoBuffer['cbBufferSize']]
            if infoBuffer['ulType'] == PAC_LOGON_INFO:
                log("## KERB_VALIDATION_INFO [MS-PAC] section 2.5 ##", MSG_TYPE_SUBHEADER, IDENT_LEVEL_6)
                type1 = TypeSerialization1(data)
                # I'm skipping here 4 bytes with its the ReferentID for the pointer
                newdata = data[len(type1)+4:]
                kerbdata = KERB_VALIDATION_INFO()
                kerbdata.fromString(newdata)
                kerbdata.fromStringReferents(newdata[len(kerbdata.getData()):])
                log('Username: %s' %(kerbdata['EffectiveName']), MSG_TYPE_FIELD, IDENT_LEVEL_6)
                log('Domain SID: %s' %(kerbdata['LogonDomainId'].formatCanonical()), MSG_TYPE_FIELD, IDENT_LEVEL_6)
                log('UserId: %s' %(kerbdata['UserId']), MSG_TYPE_FIELD, IDENT_LEVEL_6)
                log('PrimaryGroupId: %s' %(kerbdata['PrimaryGroupId']), MSG_TYPE_FIELD, IDENT_LEVEL_6)
                log('Member of groups:', MSG_TYPE_SUBHEADER, IDENT_LEVEL_6)
                for group in kerbdata['GroupIds']:
                    log('- %d (attributes: %d)' %(group['RelativeId'],  group['Attributes']), MSG_TYPE_FIELD_VALUE, IDENT_LEVEL_7)
                log('LogonServer: %s' %(kerbdata['LogonServer']), MSG_TYPE_FIELD, IDENT_LEVEL_6)
                log('LogonDomainName: %s' %(kerbdata['LogonDomainName']), MSG_TYPE_FIELD, IDENT_LEVEL_6)
                
                log('Extra SIDS:', MSG_TYPE_SUBHEADER, IDENT_LEVEL_6)
                for sid in kerbdata['ExtraSids']:
                    log('-  %s' %(sid['Sid'].formatCanonical()), MSG_TYPE_FIELD_VALUE, IDENT_LEVEL_7)
                if kerbdata['ResourceGroupDomainSid']:
                    log('Extra domain groups found! Domain SID:', MSG_TYPE_FIELD, IDENT_LEVEL_6)
                    log(kerbdata['ResourceGroupDomainSid'].formatCanonical(), MSG_TYPE_FIELD, IDENT_LEVEL_6)
                    log('Relative groups:', IDENT_LEVEL_6)
                    for group in kerbdata['ResourceGroupIds']:
                        log('- %d (attributes: %d)' % (group['RelativeId'],  group['Attributes']), MSG_TYPE_FIELD, IDENT_LEVEL_7)
                    
            # TYPE 0x02
            elif infoBuffer['ulType'] == PAC_CREDENTIALS_INFO:
                print("## PAC_CREDENTIAL_INFO [MS-PAC] section 2.6.1 ##")
                pacCredInfo = PAC_CREDENTIAL_INFO(data)
                pacCredInfo.dump()
                print()
            
            # TYPE 0x06
            elif infoBuffer['ulType'] == PAC_SERVER_CHECKSUM:
                pass
                #print("## Server Checksum [MS-PAC] section 2.8 ##")
                ## NOT IMPLEMENTED YET
                #print("[Currently not implemented or intentionally omitted]")
                # signatureData = PAC_SIGNATURE_DATA(data)
                # if logging.getLogger().level == logging.DEBUG:
                #     signatureData.dump()
            
            # TYPE 0x07
            elif infoBuffer['ulType'] == PAC_PRIVSVR_CHECKSUM:
                pass
                #print("## KDC Checksum [MS-PAC] section 2.8 ##")
                ## NOT IMPLEMENTED YET
                #print("[Currently not implemented or intentionally omitted]")
                # signatureData = PAC_SIGNATURE_DATA(data)
                # if logging.getLogger().level == logging.DEBUG:
                #     signatureData.dump()

            # TYPE 0x0A
            elif infoBuffer['ulType'] == PAC_CLIENT_INFO_TYPE:
                pass
                #print("## PAC_CLIENT_INFO [MS-PAC] section 2.7 ##")
                ## NOT IMPLEMENTED YET
                #print("[Currently not implemented or intentionally omitted]")

            # TYPE 0x0B
            elif infoBuffer['ulType'] == PAC_DELEGATION_INFO:
                pass
                #print("## S4U_DELEGATION_INFO [MS-PAC] section 2.9 ##")
                #S4UDelegationInfo = S4U_DELEGATION_INFO(data)
                ## NOT IMPLEMENTED YET
                #print("[Currently not implemented or intentionally omitted]")
                
            # TYPE 0x0C
            elif infoBuffer['ulType'] == PAC_DELEGATION_INFO:
                print("## UPN_DNS_INFO [MS-PAC] section 2.10 ##")
                upnDNSInfo = UPN_DNS_INFO(data)
                upnDNSInfo.dump()

            # TYPE 0x0D
            elif infoBuffer['ulType'] == 0x0D:
                pass
                #print("## PAC_CLIENT_CLAIMS_INFO [MS-PAC] section 2.11 ##")
                ## NOT IMPLEMENTED YET
                #print("[Currently not implemented or intentionally omitted]")
                
            # TYPE 0x0E
            elif infoBuffer['ulType'] == 0x0E:
                pass
                #print("## PAC_DEVICE_INFO [MS-PAC] section 2.12 ##")
                ## NOT IMPLEMENTED YET
                #print("[Currently not implemented or intentionally omitted]")

            # TYPE 0x0F
            elif infoBuffer['ulType'] == 0x0F:
                pass
                #print("## PAC_DEVICE_CLAIMS_INFO [MS-PAC] section 2.13 ##")
                ## NOT IMPLEMENTED YET
                #print("[Currently not implemented or intentionally omitted]")

            # TYPE 0x10
            elif infoBuffer['ulType'] == 0x10:
                pass
                #print("## Ticket Checksum [MS-PAC] section 2.8 ##")
                #signatureData = PAC_SIGNATURE_DATA(data)
                #if logging.getLogger().level == logging.DEBUG:
                #    signatureData.dump()
                #    print()
           
            else:
                print("ulType: %s" %infoBuffer['ulType'] )
   

            # elif infoBuffer['ulType'] == PAC_UPN_DNS_INFO:
            #     upn = UPN_DNS_INFO(data)
            #     if logging.getLogger().level == logging.DEBUG:
            #         upn.dump()
            #         print(data[upn['DnsDomainNameOffset']:])
            #         # print
            # else:
            #     hexdump(data)

            # if logging.getLogger().level == logging.DEBUG:
            #     print("#"*80)

            buff = buff[len(infoBuffer):]


def viewCCacheFile(ticketPath=None, ticketKey=None):
    #log("[*] Reading CCachefile at '%s'" %(filePath), IDENT_LEVEL_1 )
    ## Try loading as .kirbi file first
    ccache = None
    try:
        ccache = CCache.loadKirbiFile(ticketPath)
    except Exception as e:
        ccache = CCache.loadFile(ticketPath)
    if( not ccache ):
        log("[-] Failed to parse to ticket :/ ", MSG_TYPE_ERROR, IDENT_LEVEL_1)
        return
    ## Get Principal and realm of ccache file
    #### Defined in section 6.2 of https://www.ietf.org/rfc/rfc4120.txt
    log("## CCache File ##", MSG_TYPE_HEADER, IDENT_LEVEL_1)
    principal_name_type = ccache.principal.header.fields['name_type']
    for principal_component in ccache.principal.components:
        principal_component_data = principal_component.fields['data']
        if( principal_name_type == 0x1 ):
            log("NT-PRINCIPAL: %s" %(principal_component_data), MSG_TYPE_FIELD, IDENT_LEVEL_2) ## NT-PRINCIPAL 
        else:
            log("Principal (type '%s'): %s [Check section 6.2 of https://www.ietf.org/rfc/rfc4120.txt for details on this type of principal]" %(principal_name_type, principal_component_data), MSG_TYPE_FIELD, IDENT_LEVEL_2)
    principal_realm = ccache.principal.realm.fields['data']
    log("REALM: %s" %(principal_realm), MSG_TYPE_FIELD, IDENT_LEVEL_2)

    ## Extract tickets from ccache file
    log("## Credentials ##", MSG_TYPE_HEADER, IDENT_LEVEL_1)
    credcount = 0
    for credential in ccache.credentials:
        credcount += 1
        ## Print information contained in cached credential file
        log("Credential #%s" %(credcount), MSG_TYPE_SUBHEADER, IDENT_LEVEL_2)
        ### Get client and server - skipping the server part to not confuse people
        ticket_client = credential.header['client']
        sticket_client = ticket_client.prettyPrint() ## the client name is encrypted in the ticket
        ticket_server = credential.header['server']
        sticket_server = ticket_server.prettyPrint()
        log("Client: %s" %( sticket_client ), MSG_TYPE_FIELD, IDENT_LEVEL_3 )
        log("Server: %s" %( sticket_server ), MSG_TYPE_FIELD, IDENT_LEVEL_3 )
        ### Get ticket flags
        ticket_flags = credential.header.fields['tktflags']
        print_ticket_flags(ticket_flags, IDENT_LEVEL_3)
        ## Get encryption key type - skipped here as i will extract it from the ticket, EncType will be the same, but this way it's less confusing
        #ticket_enc_type = credential.header.fields['key'].fields['keytype']
        #log("Encryption Type: %s" %(get_ticket_enc_type(ticket_enc_type)), MSG_TYPE_FIELD, IDENT_LEVEL_3 )
        ## Get Lifetime stats
        ticket_valid_from = credential.header.fields['time'].fields['starttime']
        dticket_valid_from = datetime_from_timestmp(ticket_valid_from)
        ticket_valid_until = credential.header.fields['time'].fields['endtime']
        dticket_valid_until = datetime_from_timestmp(ticket_valid_until)
        ticket_renew_till = credential.header.fields['time'].fields['renew_till']
        dticket_renew_till = datetime_from_timestmp(ticket_renew_till)
        print_ticket_lifetimes(
            dticket_valid_from,
            dticket_valid_until,
            dticket_renew_till,
            IDENT_LEVEL_3
        )
        ## Print information contained in ticket
        log("Ticket #%s" %(credcount), MSG_TYPE_SUBHEADER, IDENT_LEVEL_2)
        ## Build Ticket
        enc_ticket = Ticket()
        enc_ticket.from_asn1( credential.ticket['data'] )
        enc_ticket_etype = enc_ticket.encrypted_part.etype
        ticket_ciphertext = enc_ticket.encrypted_part.ciphertext.encode('iso-8859-1')
        ticket_cipher = _enctype_table[ enc_ticket_etype ]
        ## Get Client and Server
        # ticket_client = credential.header['client']
        # sticket_client = ticket_client.prettyPrint() ## the client name is encrypted in the ticket
        ticket_server = enc_ticket.service_principal
        sticket_server = ticket_server.__str__()
        #log("Client: %s" %( sticket_client ), MSG_TYPE_FIELD, IDENT_LEVEL_3 )
        log("Server: %s" %( sticket_server ), MSG_TYPE_FIELD, IDENT_LEVEL_3 )
        ## Get Encryption Type
        log("Encryption Type: %s" %(get_ticket_enc_type(enc_ticket_etype)), MSG_TYPE_FIELD, IDENT_LEVEL_3 )
        
        if( ticketKey ):
            plainTextTicket = None
            ## Decrypt ticket
            try:
                ticket_key = Key(ticket_cipher.enctype, binascii.unhexlify( ticketKey ))
                plainTextTicket = ticket_cipher.decrypt(ticket_key, 2, ticket_ciphertext)
            except Exception as error:
                if( type(error) == InvalidChecksum ):
                    log(
                        "Error: %s. Possibly this is due to a wrong ticket key. Are you sure the supplied key is correct for this ticket?" %(error),
                        MSG_TYPE_ERROR,
                        IDENT_LEVEL_1
                    )
                elif( 'Wrong key length' in str(error) ):
                    log(
                        "Error: %s. The length of the supplied key doesn't match the encryption algorithm, which is '%s' for this ticket." %(error, TICKET_ENC_TABLE[ticket_cipher.enctype]),
                        MSG_TYPE_ERROR,
                        IDENT_LEVEL_1
                    )
                else:
                    log(
                        "We got an error while trying to decrypt the ticket: %s." %error,
                        MSG_TYPE_ERROR,
                        IDENT_LEVEL_1
                    )
            ## Print encrypted Part
            if(plainTextTicket):
                try:
                    encTicketPart = decoder.decode(plainTextTicket, asn1Spec=EncTicketPart())[0]
                    print_encrypted_ticket_parts(encTicketPart)
                except Exception as error:
                    log(
                            "We got an error while print the encrypted parts of the ticket: %s." %error,
                            MSG_TYPE_ERROR,
                            IDENT_LEVEL_1
                        )
        else:
            log(
                "\nNo key was supplied, so can't decrypt ticket.",
                MSG_TYPE_DEFAULT,
                IDENT_LEVEL_1
            )

if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=True, description="")
    parser.add_argument('-t', '--ticket', dest='ticket', action='store', help='--ticket /path/to/ticket[.kirbi|.ccache]')
    parser.add_argument('-k', '--key', dest='key', action='store', help='--key 09c024da4139e98b77b2c20d1bd6a28ac5610e6982ab47c8e5b578b1ba58bd5b')
    options = parser.parse_args()
    
    if( options.ticket ):
        viewCCacheFile(ticketPath=options.ticket, ticketKey=options.key)
    else:
        log(
            "A path to a Kerberos ticket must be supplied\n",
            MSG_TYPE_ERROR,
            IDENT_LEVEL_1
        )
        parser.print_help()
