package gokrb5

// #include <krb5.h>
import "C"

const (
	NT_UNKNOWN              = C.KRB5_NT_UNKNOWN
	NT_PRINCIPAL            = C.KRB5_NT_PRINCIPAL
	NT_SRV_INST             = C.KRB5_NT_SRV_INST
	NT_SRV_HST              = C.KRB5_NT_SRV_HST
	NT_SRV_XHST             = C.KRB5_NT_SRV_XHST
	NT_UID                  = C.KRB5_NT_UID
	NT_X500_PRINCIPAL       = C.KRB5_NT_X500_PRINCIPAL
	NT_SMTP_NAME            = C.KRB5_NT_SMTP_NAME
	NT_ENTERPRISE_PRINCIPAL = C.KRB5_NT_ENTERPRISE_PRINCIPAL
	NT_WELLKNOWN            = C.KRB5_NT_WELLKNOWN
	NT_MS_PRINCIPAL         = C.KRB5_NT_MS_PRINCIPAL
	NT_MS_PRINCIPAL_AND_ID  = C.KRB5_NT_MS_PRINCIPAL_AND_ID
	NT_ENT_PRINCIPAL_AND_ID = C.KRB5_NT_ENT_PRINCIPAL_AND_ID
)

const (
	KRB5KDC_ERR_NONE                 = C.KRB5KDC_ERR_NONE                 //		"No error"
	KRB5KDC_ERR_NAME_EXP             = C.KRB5KDC_ERR_NAME_EXP             //	"Client's entry in database has expired"
	KRB5KDC_ERR_SERVICE_EXP          = C.KRB5KDC_ERR_SERVICE_EXP          //	"Server's entry in database has expired"
	KRB5KDC_ERR_BAD_PVNO             = C.KRB5KDC_ERR_BAD_PVNO             //	"Requested protocol version not supported"
	KRB5KDC_ERR_C_OLD_MAST_KVNO      = C.KRB5KDC_ERR_C_OLD_MAST_KVNO      //	"Client's key is encrypted in an old master key"
	KRB5KDC_ERR_S_OLD_MAST_KVNO      = C.KRB5KDC_ERR_S_OLD_MAST_KVNO      //	"Server's key is encrypted in an old master key"
	KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN  = C.KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN  // "Client not found in Kerberos database"
	KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN  = C.KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN  // "Server not found in Kerberos database"
	KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE = C.KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE // "Principal has multiple entries in Kerberos database"
	KRB5KDC_ERR_NULL_KEY             = C.KRB5KDC_ERR_NULL_KEY             //	"Client or server has a null key"
	KRB5KDC_ERR_CANNOT_POSTDATE      = C.KRB5KDC_ERR_CANNOT_POSTDATE      //	"Ticket is ineligible for postdating"
	KRB5KDC_ERR_NEVER_VALID          = C.KRB5KDC_ERR_NEVER_VALID          //	"Requested effective lifetime is negative or too short"
	KRB5KDC_ERR_POLICY               = C.KRB5KDC_ERR_POLICY               //		"KDC policy rejects request"
	KRB5KDC_ERR_BADOPTION            = C.KRB5KDC_ERR_BADOPTION            //	"KDC can't fulfill requested option"
	KRB5KDC_ERR_ETYPE_NOSUPP         = C.KRB5KDC_ERR_ETYPE_NOSUPP         //	"KDC has no support for encryption type"
	KRB5KDC_ERR_SUMTYPE_NOSUPP       = C.KRB5KDC_ERR_SUMTYPE_NOSUPP       //	"KDC has no support for checksum type"
	KRB5KDC_ERR_PADATA_TYPE_NOSUPP   = C.KRB5KDC_ERR_PADATA_TYPE_NOSUPP   // "KDC has no support for padata type"
	KRB5KDC_ERR_TRTYPE_NOSUPP        = C.KRB5KDC_ERR_TRTYPE_NOSUPP        //	"KDC has no support for transited type"
	KRB5KDC_ERR_CLIENT_REVOKED       = C.KRB5KDC_ERR_CLIENT_REVOKED       //	"Clients credentials have been revoked"
	KRB5KDC_ERR_SERVICE_REVOKED      = C.KRB5KDC_ERR_SERVICE_REVOKED      //	"Credentials for server have been revoked"
	KRB5KDC_ERR_TGT_REVOKED          = C.KRB5KDC_ERR_TGT_REVOKED          //	"TGT has been revoked"
	KRB5KDC_ERR_CLIENT_NOTYET        = C.KRB5KDC_ERR_CLIENT_NOTYET        //	"Client not yet valid - try again later"
	KRB5KDC_ERR_SERVICE_NOTYET       = C.KRB5KDC_ERR_SERVICE_NOTYET       //	"Server not yet valid - try again later"
	KRB5KDC_ERR_KEY_EXP              = C.KRB5KDC_ERR_KEY_EXP              //  	"Password has expired"
	KRB5KDC_ERR_PREAUTH_FAILED       = C.KRB5KDC_ERR_PREAUTH_FAILED       //  "Preauthentication failed"

	KRB5KDC_ERR_PREAUTH_REQUIRED   = C.KRB5KDC_ERR_PREAUTH_REQUIRED   // "Additional pre-authentication required"
	KRB5KDC_ERR_SERVER_NOMATCH     = C.KRB5KDC_ERR_SERVER_NOMATCH     //	"Requested server and ticket don't match"
	KRB5KDC_ERR_MUST_USE_USER2USER = C.KRB5KDC_ERR_MUST_USE_USER2USER //  "Server principal valid for user2user only"
	KRB5KDC_ERR_PATH_NOT_ACCEPTED  = C.KRB5KDC_ERR_PATH_NOT_ACCEPTED  //   "KDC policy rejects transited path"
	KRB5KDC_ERR_SVC_UNAVAILABLE    = C.KRB5KDC_ERR_SVC_UNAVAILABLE    // "A service is not available that is required to process the request"
	KRB5PLACEHOLD_30               = C.KRB5PLACEHOLD_30               //		"KRB5 error code 30"

	KRB5KRB_AP_ERR_BAD_INTEGRITY = C.KRB5KRB_AP_ERR_BAD_INTEGRITY // "Decrypt integrity check failed"
	KRB5KRB_AP_ERR_TKT_EXPIRED   = C.KRB5KRB_AP_ERR_TKT_EXPIRED   //	"Ticket expired"
	KRB5KRB_AP_ERR_TKT_NYV       = C.KRB5KRB_AP_ERR_TKT_NYV       //	"Ticket not yet valid"
	KRB5KRB_AP_ERR_REPEAT        = C.KRB5KRB_AP_ERR_REPEAT        //	"Request is a replay"
	KRB5KRB_AP_ERR_NOT_US        = C.KRB5KRB_AP_ERR_NOT_US        //	"The ticket isn't for us"
	KRB5KRB_AP_ERR_BADMATCH      = C.KRB5KRB_AP_ERR_BADMATCH      //	"Ticket/authenticator don't match"
	KRB5KRB_AP_ERR_SKEW          = C.KRB5KRB_AP_ERR_SKEW          //	"Clock skew too great"
	KRB5KRB_AP_ERR_BADADDR       = C.KRB5KRB_AP_ERR_BADADDR       //	"Incorrect net address"
	KRB5KRB_AP_ERR_BADVERSION    = C.KRB5KRB_AP_ERR_BADVERSION    //	"Protocol version mismatch"
	KRB5KRB_AP_ERR_MSG_TYPE      = C.KRB5KRB_AP_ERR_MSG_TYPE      //	"Invalid message type"
	KRB5KRB_AP_ERR_MODIFIED      = C.KRB5KRB_AP_ERR_MODIFIED      //	"Message stream modified"
	KRB5KRB_AP_ERR_BADORDER      = C.KRB5KRB_AP_ERR_BADORDER      //	"Message out of order"
	KRB5KRB_AP_ERR_ILL_CR_TKT    = C.KRB5KRB_AP_ERR_ILL_CR_TKT    // "Illegal cross-realm ticket"
	KRB5KRB_AP_ERR_BADKEYVER     = C.KRB5KRB_AP_ERR_BADKEYVER     //	"Key version is not available"
	KRB5KRB_AP_ERR_NOKEY         = C.KRB5KRB_AP_ERR_NOKEY         //	"Service key not available"
	KRB5KRB_AP_ERR_MUT_FAIL      = C.KRB5KRB_AP_ERR_MUT_FAIL      //	"Mutual authentication failed"
	KRB5KRB_AP_ERR_BADDIRECTION  = C.KRB5KRB_AP_ERR_BADDIRECTION  //	"Incorrect message direction"
	KRB5KRB_AP_ERR_METHOD        = C.KRB5KRB_AP_ERR_METHOD        //	"Alternative authentication method required"
	KRB5KRB_AP_ERR_BADSEQ        = C.KRB5KRB_AP_ERR_BADSEQ        //	"Incorrect sequence number in message"
	KRB5KRB_AP_ERR_INAPP_CKSUM   = C.KRB5KRB_AP_ERR_INAPP_CKSUM   //	"Inappropriate type of checksum in message"

	KRB5KRB_AP_PATH_NOT_ACCEPTED                    = C.KRB5KRB_AP_PATH_NOT_ACCEPTED                    //	"Policy rejects transited path"
	KRB5KRB_ERR_RESPONSE_TOO_BIG                    = C.KRB5KRB_ERR_RESPONSE_TOO_BIG                    //	"Response too big for UDP, retry with TCP"
	KRB5PLACEHOLD_53                                = C.KRB5PLACEHOLD_53                                //	"KRB5 error code 53"
	KRB5PLACEHOLD_54                                = C.KRB5PLACEHOLD_54                                //	"KRB5 error code 54"
	KRB5PLACEHOLD_55                                = C.KRB5PLACEHOLD_55                                //	"KRB5 error code 55"
	KRB5PLACEHOLD_56                                = C.KRB5PLACEHOLD_56                                //	"KRB5 error code 56"
	KRB5PLACEHOLD_57                                = C.KRB5PLACEHOLD_57                                //	"KRB5 error code 57"
	KRB5PLACEHOLD_58                                = C.KRB5PLACEHOLD_58                                //	"KRB5 error code 58"
	KRB5PLACEHOLD_59                                = C.KRB5PLACEHOLD_59                                //	"KRB5 error code 59"
	KRB5KRB_ERR_GENERIC                             = C.KRB5KRB_ERR_GENERIC                             //	"Generic error (see e-text)"
	KRB5KRB_ERR_FIELD_TOOLONG                       = C.KRB5KRB_ERR_FIELD_TOOLONG                       //	"Field is too long for this implementation"
	KRB5KDC_ERR_CLIENT_NOT_TRUSTED                  = C.KRB5KDC_ERR_CLIENT_NOT_TRUSTED                  //		"Client not trusted"
	KRB5KDC_ERR_KDC_NOT_TRUSTED                     = C.KRB5KDC_ERR_KDC_NOT_TRUSTED                     //			"KDC not trusted"
	KRB5KDC_ERR_INVALID_SIG                         = C.KRB5KDC_ERR_INVALID_SIG                         //			"Invalid signature"
	KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED      = C.KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED      //	"Key parameters not accepted"
	KRB5KDC_ERR_CERTIFICATE_MISMATCH                = C.KRB5KDC_ERR_CERTIFICATE_MISMATCH                //		"Certificate mismatch"
	KRB5KRB_AP_ERR_NO_TGT                           = C.KRB5KRB_AP_ERR_NO_TGT                           //			"No ticket granting ticket"
	KRB5KDC_ERR_WRONG_REALM                         = C.KRB5KDC_ERR_WRONG_REALM                         //			"Realm not local to KDC"
	KRB5KRB_AP_ERR_USER_TO_USER_REQUIRED            = C.KRB5KRB_AP_ERR_USER_TO_USER_REQUIRED            //	"User to user required"
	KRB5KDC_ERR_CANT_VERIFY_CERTIFICATE             = C.KRB5KDC_ERR_CANT_VERIFY_CERTIFICATE             //		"Can't verify certificate"
	KRB5KDC_ERR_INVALID_CERTIFICATE                 = C.KRB5KDC_ERR_INVALID_CERTIFICATE                 //		"Invalid certificate"
	KRB5KDC_ERR_REVOKED_CERTIFICATE                 = C.KRB5KDC_ERR_REVOKED_CERTIFICATE                 //		"Revoked certificate"
	KRB5KDC_ERR_REVOCATION_STATUS_UNKNOWN           = C.KRB5KDC_ERR_REVOCATION_STATUS_UNKNOWN           //	"Revocation status unknown"
	KRB5KDC_ERR_REVOCATION_STATUS_UNAVAILABLE       = C.KRB5KDC_ERR_REVOCATION_STATUS_UNAVAILABLE       //	"Revocation status unavailable"
	KRB5KDC_ERR_CLIENT_NAME_MISMATCH                = C.KRB5KDC_ERR_CLIENT_NAME_MISMATCH                //		"Client name mismatch"
	KRB5KDC_ERR_KDC_NAME_MISMATCH                   = C.KRB5KDC_ERR_KDC_NAME_MISMATCH                   //		"KDC name mismatch"
	KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE            = C.KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE            //	"Inconsistent key purpose"
	KRB5KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED         = C.KRB5KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED         //	"Digest in certificate not accepted"
	KRB5KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED        = C.KRB5KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED        //	"Checksum must be included"
	KRB5KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED  = C.KRB5KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED  //	"Digest in signed-data not accepted"
	KRB5KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED = C.KRB5KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED //	"Public key encryption not supported"
	//	KRB5PLACEHOLD_82                                = C.KRB5PLACEHOLD_82                                //	"KRB5 error code 82"
	KRB5PLACEHOLD_83                      = C.KRB5PLACEHOLD_83                      //	"KRB5 error code 83"
	KRB5PLACEHOLD_84                      = C.KRB5PLACEHOLD_84                      //	"KRB5 error code 84"
	KRB5KRB_AP_ERR_IAKERB_KDC_NOT_FOUND   = C.KRB5KRB_AP_ERR_IAKERB_KDC_NOT_FOUND   //         "The IAKERB proxy could not find a KDC"
	KRB5KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE = C.KRB5KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE //	"The KDC did not respond to the IAKERB proxy"
	KRB5PLACEHOLD_87                      = C.KRB5PLACEHOLD_87                      //	"KRB5 error code 87"
	KRB5PLACEHOLD_88                      = C.KRB5PLACEHOLD_88                      //	"KRB5 error code 88"
	KRB5PLACEHOLD_89                      = C.KRB5PLACEHOLD_89                      //	"KRB5 error code 89"
	//	KRB5KDC_ERR_PREAUTH_EXPIRED                     = C.KRB5KDC_ERR_PREAUTH_EXPIRED                     //	"KRB5 error code 90"
	//	KRB5KDC_ERR_MORE_PREAUTH_DATA_REQUIRED          = C.KRB5KDC_ERR_MORE_PREAUTH_DATA_REQUIRED          //	"KRB5 error code 91"
	KRB5PLACEHOLD_92                         = C.KRB5PLACEHOLD_92                         //	"KRB5 error code 92"
	KRB5KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTION = C.KRB5KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTION // "An unsupported critical FAST option was requested"
	KRB5PLACEHOLD_94                         = C.KRB5PLACEHOLD_94                         //	"KRB5 error code 94"
	KRB5PLACEHOLD_95                         = C.KRB5PLACEHOLD_95                         //	"KRB5 error code 95"
	KRB5PLACEHOLD_96                         = C.KRB5PLACEHOLD_96                         //	"KRB5 error code 96"
	KRB5PLACEHOLD_97                         = C.KRB5PLACEHOLD_97                         //	"KRB5 error code 97"
	KRB5PLACEHOLD_98                         = C.KRB5PLACEHOLD_98                         //	"KRB5 error code 98"
	KRB5PLACEHOLD_99                         = C.KRB5PLACEHOLD_99                         //	"KRB5 error code 99"
	KRB5KDC_ERR_NO_ACCEPTABLE_KDF            = C.KRB5KDC_ERR_NO_ACCEPTABLE_KDF            //		"No acceptable KDF offered"
	KRB5PLACEHOLD_101                        = C.KRB5PLACEHOLD_101                        //	"KRB5 error code 101"
	KRB5PLACEHOLD_102                        = C.KRB5PLACEHOLD_102                        //	"KRB5 error code 102"
	KRB5PLACEHOLD_103                        = C.KRB5PLACEHOLD_103                        //	"KRB5 error code 103"
	KRB5PLACEHOLD_104                        = C.KRB5PLACEHOLD_104                        //	"KRB5 error code 104"
	KRB5PLACEHOLD_105                        = C.KRB5PLACEHOLD_105                        //	"KRB5 error code 105"
	KRB5PLACEHOLD_106                        = C.KRB5PLACEHOLD_106                        //	"KRB5 error code 106"
	KRB5PLACEHOLD_107                        = C.KRB5PLACEHOLD_107                        //	"KRB5 error code 107"
	KRB5PLACEHOLD_108                        = C.KRB5PLACEHOLD_108                        //	"KRB5 error code 108"
	KRB5PLACEHOLD_109                        = C.KRB5PLACEHOLD_109                        //	"KRB5 error code 109"
	KRB5PLACEHOLD_110                        = C.KRB5PLACEHOLD_110                        //	"KRB5 error code 110"
	KRB5PLACEHOLD_111                        = C.KRB5PLACEHOLD_111                        //	"KRB5 error code 111"
	KRB5PLACEHOLD_112                        = C.KRB5PLACEHOLD_112                        //	"KRB5 error code 112"
	KRB5PLACEHOLD_113                        = C.KRB5PLACEHOLD_113                        //	"KRB5 error code 113"
	KRB5PLACEHOLD_114                        = C.KRB5PLACEHOLD_114                        //	"KRB5 error code 114"
	KRB5PLACEHOLD_115                        = C.KRB5PLACEHOLD_115                        //	"KRB5 error code 115"
	KRB5PLACEHOLD_116                        = C.KRB5PLACEHOLD_116                        //	"KRB5 error code 116"
	KRB5PLACEHOLD_117                        = C.KRB5PLACEHOLD_117                        //	"KRB5 error code 117"
	KRB5PLACEHOLD_118                        = C.KRB5PLACEHOLD_118                        //	"KRB5 error code 118"
	KRB5PLACEHOLD_119                        = C.KRB5PLACEHOLD_119                        //	"KRB5 error code 119"
	KRB5PLACEHOLD_120                        = C.KRB5PLACEHOLD_120                        //	"KRB5 error code 120"
	KRB5PLACEHOLD_121                        = C.KRB5PLACEHOLD_121                        //	"KRB5 error code 121"
	KRB5PLACEHOLD_122                        = C.KRB5PLACEHOLD_122                        //	"KRB5 error code 122"
	KRB5PLACEHOLD_123                        = C.KRB5PLACEHOLD_123                        //	"KRB5 error code 123"
	KRB5PLACEHOLD_124                        = C.KRB5PLACEHOLD_124                        //	"KRB5 error code 124"
	KRB5PLACEHOLD_125                        = C.KRB5PLACEHOLD_125                        //	"KRB5 error code 125"
	KRB5PLACEHOLD_126                        = C.KRB5PLACEHOLD_126                        //	"KRB5 error code 126"
	KRB5PLACEHOLD_127                        = C.KRB5PLACEHOLD_127                        //	"KRB5 error code 127"

	KRB5_ERR_RCSID = C.KRB5_ERR_RCSID //	"$Id$"

	KRB5_LIBOS_BADLOCKFLAG = C.KRB5_LIBOS_BADLOCKFLAG //	"Invalid flag for file lock mode"
	KRB5_LIBOS_CANTREADPWD = C.KRB5_LIBOS_CANTREADPWD //	"Cannot read password"
	KRB5_LIBOS_BADPWDMATCH = C.KRB5_LIBOS_BADPWDMATCH //	"Password mismatch"
	KRB5_LIBOS_PWDINTR     = C.KRB5_LIBOS_PWDINTR     //		"Password read interrupted"

	KRB5_PARSE_ILLCHAR   = C.KRB5_PARSE_ILLCHAR   //		"Illegal character in component name"
	KRB5_PARSE_MALFORMED = C.KRB5_PARSE_MALFORMED //	"Malformed representation of principal"

	KRB5_CONFIG_CANTOPEN     = C.KRB5_CONFIG_CANTOPEN     //	"Can't open/find Kerberos configuration file"
	KRB5_CONFIG_BADFORMAT    = C.KRB5_CONFIG_BADFORMAT    //	"Improper format of Kerberos configuration file"
	KRB5_CONFIG_NOTENUFSPACE = C.KRB5_CONFIG_NOTENUFSPACE //	"Insufficient space to return complete information"

	KRB5_BADMSGTYPE = C.KRB5_BADMSGTYPE //		"Invalid message type specified for encoding"

	KRB5_CC_BADNAME      = C.KRB5_CC_BADNAME      //		"Credential cache name malformed"
	KRB5_CC_UNKNOWN_TYPE = C.KRB5_CC_UNKNOWN_TYPE //	"Unknown credential cache type"
	KRB5_CC_NOTFOUND     = C.KRB5_CC_NOTFOUND     //		"Matching credential not found"
	KRB5_CC_END          = C.KRB5_CC_END          //			"End of credential cache reached"

	KRB5_NO_TKT_SUPPLIED = C.KRB5_NO_TKT_SUPPLIED //	"Request did not supply a ticket"

	KRB5KRB_AP_WRONG_PRINC     = C.KRB5KRB_AP_WRONG_PRINC     //		"Wrong principal in request"
	KRB5KRB_AP_ERR_TKT_INVALID = C.KRB5KRB_AP_ERR_TKT_INVALID //	"Ticket has invalid flag set"

	KRB5_PRINC_NOMATCH         = C.KRB5_PRINC_NOMATCH         //		"Requested principal and ticket don't match"
	KRB5_KDCREP_MODIFIED       = C.KRB5_KDCREP_MODIFIED       //	"KDC reply did not match expectations"
	KRB5_KDCREP_SKEW           = C.KRB5_KDCREP_SKEW           //		"Clock skew too great in KDC reply"
	KRB5_IN_TKT_REALM_MISMATCH = C.KRB5_IN_TKT_REALM_MISMATCH //	"Client/server realm mismatch in initial ticket request"

	KRB5_PROG_ETYPE_NOSUPP   = C.KRB5_PROG_ETYPE_NOSUPP   //	"Program lacks support for encryption type"
	KRB5_PROG_KEYTYPE_NOSUPP = C.KRB5_PROG_KEYTYPE_NOSUPP //	"Program lacks support for key type"
	KRB5_WRONG_ETYPE         = C.KRB5_WRONG_ETYPE         //		"Requested encryption type not used in message"
	KRB5_PROG_SUMTYPE_NOSUPP = C.KRB5_PROG_SUMTYPE_NOSUPP //	"Program lacks support for checksum type"

	KRB5_REALM_UNKNOWN   = C.KRB5_REALM_UNKNOWN   //		"Cannot find KDC for requested realm"
	KRB5_SERVICE_UNKNOWN = C.KRB5_SERVICE_UNKNOWN //	"Kerberos service unknown"
	KRB5_KDC_UNREACH     = C.KRB5_KDC_UNREACH     //		"Cannot contact any KDC for requested realm"
	KRB5_NO_LOCALNAME    = C.KRB5_NO_LOCALNAME    //		"No local name found for principal name"

	KRB5_MUTUAL_FAILED = C.KRB5_MUTUAL_FAILED //		"Mutual authentication failed"

	KRB5_RC_TYPE_EXISTS   = C.KRB5_RC_TYPE_EXISTS   //		"Replay cache type is already registered"
	KRB5_RC_MALLOC        = C.KRB5_RC_MALLOC        //		"No more memory to allocate (in replay cache code)"
	KRB5_RC_TYPE_NOTFOUND = C.KRB5_RC_TYPE_NOTFOUND //	"Replay cache type is unknown"
	KRB5_RC_UNKNOWN       = C.KRB5_RC_UNKNOWN       //		"Generic unknown RC error"
	KRB5_RC_REPLAY        = C.KRB5_RC_REPLAY        //		"Message is a replay"
	KRB5_RC_IO            = C.KRB5_RC_IO            //			"Replay cache I/O operation failed"
	KRB5_RC_NOIO          = C.KRB5_RC_NOIO          //		"Replay cache type does not support non-volatile storage"
	KRB5_RC_PARSE         = C.KRB5_RC_PARSE         //		"Replay cache name parse/format error"

	KRB5_RC_IO_EOF     = C.KRB5_RC_IO_EOF     //		"End-of-file on replay cache I/O"
	KRB5_RC_IO_MALLOC  = C.KRB5_RC_IO_MALLOC  //		"No more memory to allocate (in replay cache I/O code)"
	KRB5_RC_IO_PERM    = C.KRB5_RC_IO_PERM    //		"Permission denied in replay cache code"
	KRB5_RC_IO_IO      = C.KRB5_RC_IO_IO      //		"I/O error in replay cache i/o code"
	KRB5_RC_IO_UNKNOWN = C.KRB5_RC_IO_UNKNOWN //		"Generic unknown RC/IO error"
	KRB5_RC_IO_SPACE   = C.KRB5_RC_IO_SPACE   //		"Insufficient system space to store replay information"

	KRB5_TRANS_CANTOPEN  = C.KRB5_TRANS_CANTOPEN  //		"Can't open/find realm translation file"
	KRB5_TRANS_BADFORMAT = C.KRB5_TRANS_BADFORMAT //	"Improper format of realm translation file"

	KRB5_LNAME_CANTOPEN  = C.KRB5_LNAME_CANTOPEN  //		"Can't open/find lname translation database"
	KRB5_LNAME_NOTRANS   = C.KRB5_LNAME_NOTRANS   //		"No translation available for requested principal"
	KRB5_LNAME_BADFORMAT = C.KRB5_LNAME_BADFORMAT //	"Improper format of translation database entry"

	KRB5_CRYPTO_INTERNAL = C.KRB5_CRYPTO_INTERNAL //	"Cryptosystem internal error"

	KRB5_KT_BADNAME      = C.KRB5_KT_BADNAME      //		"Key table name malformed"
	KRB5_KT_UNKNOWN_TYPE = C.KRB5_KT_UNKNOWN_TYPE //	"Unknown Key table type"
	KRB5_KT_NOTFOUND     = C.KRB5_KT_NOTFOUND     //		"Key table entry not found"
	KRB5_KT_END          = C.KRB5_KT_END          //			"End of key table reached"
	KRB5_KT_NOWRITE      = C.KRB5_KT_NOWRITE      //		"Cannot write to specified key table"
	KRB5_KT_IOERR        = C.KRB5_KT_IOERR        //		"Error writing to key table"

	KRB5_NO_TKT_IN_RLM = C.KRB5_NO_TKT_IN_RLM //		"Cannot find ticket for requested realm"
	KRB5DES_BAD_KEYPAR = C.KRB5DES_BAD_KEYPAR //		"DES key has bad parity"
	KRB5DES_WEAK_KEY   = C.KRB5DES_WEAK_KEY   //		"DES key is a weak key"

	KRB5_BAD_ENCTYPE = C.KRB5_BAD_ENCTYPE //		"Bad encryption type"
	KRB5_BAD_KEYSIZE = C.KRB5_BAD_KEYSIZE //		"Key size is incompatible with encryption type"
	KRB5_BAD_MSIZE   = C.KRB5_BAD_MSIZE   //		"Message size is incompatible with encryption type"

	KRB5_CC_TYPE_EXISTS = C.KRB5_CC_TYPE_EXISTS //		"Credentials cache type is already registered."
	KRB5_KT_TYPE_EXISTS = C.KRB5_KT_TYPE_EXISTS //		"Key table type is already registered."

	KRB5_CC_IO        = C.KRB5_CC_IO        //			"Credentials cache I/O operation failed XXX"
	KRB5_FCC_PERM     = C.KRB5_FCC_PERM     //		"Credentials cache permissions incorrect"
	KRB5_FCC_NOFILE   = C.KRB5_FCC_NOFILE   //		"No credentials cache found"
	KRB5_FCC_INTERNAL = C.KRB5_FCC_INTERNAL //		"Internal credentials cache error"
	KRB5_CC_WRITE     = C.KRB5_CC_WRITE     //		"Error writing to credentials cache"
	KRB5_CC_NOMEM     = C.KRB5_CC_NOMEM     //		"No more memory to allocate (in credentials cache code)"
	KRB5_CC_FORMAT    = C.KRB5_CC_FORMAT    //		"Bad format in credentials cache"
	KRB5_CC_NOT_KTYPE = C.KRB5_CC_NOT_KTYPE //		"No credentials found with supported encryption types"

	KRB5_INVALID_FLAGS = C.KRB5_INVALID_FLAGS //		"Invalid KDC option combination (library internal error)"
	KRB5_NO_2ND_TKT    = C.KRB5_NO_2ND_TKT    //		"Request missing second ticket"

	KRB5_NOCREDS_SUPPLIED = C.KRB5_NOCREDS_SUPPLIED //	"No credentials supplied to library routine"

	KRB5_SENDAUTH_BADAUTHVERS = C.KRB5_SENDAUTH_BADAUTHVERS //	"Bad sendauth version was sent"
	KRB5_SENDAUTH_BADAPPLVERS = C.KRB5_SENDAUTH_BADAPPLVERS //	"Bad application version was sent (via sendauth)"
	KRB5_SENDAUTH_BADRESPONSE = C.KRB5_SENDAUTH_BADRESPONSE //	"Bad response (during sendauth exchange)"
	KRB5_SENDAUTH_REJECTED    = C.KRB5_SENDAUTH_REJECTED    //	"Server rejected authentication (during sendauth exchange)"

	KRB5_PREAUTH_BAD_TYPE = C.KRB5_PREAUTH_BAD_TYPE //	"Unsupported preauthentication type"
	KRB5_PREAUTH_NO_KEY   = C.KRB5_PREAUTH_NO_KEY   //		"Required preauthentication key not supplied"
	KRB5_PREAUTH_FAILED   = C.KRB5_PREAUTH_FAILED   //		"Generic preauthentication failure"

	KRB5_RCACHE_BADVNO = C.KRB5_RCACHE_BADVNO //	"Unsupported replay cache format version number"
	KRB5_CCACHE_BADVNO = C.KRB5_CCACHE_BADVNO //	"Unsupported credentials cache format version number"
	KRB5_KEYTAB_BADVNO = C.KRB5_KEYTAB_BADVNO //	"Unsupported key table format version number"

	KRB5_PROG_ATYPE_NOSUPP      = C.KRB5_PROG_ATYPE_NOSUPP      //	"Program lacks support for address type"
	KRB5_RC_REQUIRED            = C.KRB5_RC_REQUIRED            //	"Message replay detection requires rcache parameter"
	KRB5_ERR_BAD_HOSTNAME       = C.KRB5_ERR_BAD_HOSTNAME       //	"Hostname cannot be canonicalized"
	KRB5_ERR_HOST_REALM_UNKNOWN = C.KRB5_ERR_HOST_REALM_UNKNOWN //	"Cannot determine realm for host"
	KRB5_SNAME_UNSUPP_NAMETYPE  = C.KRB5_SNAME_UNSUPP_NAMETYPE  //	"Conversion to service principal undefined for name type"

	KRB5KRB_AP_ERR_V4_REPLY  = C.KRB5KRB_AP_ERR_V4_REPLY  // "Initial Ticket response appears to be Version 4 error"
	KRB5_REALM_CANT_RESOLVE  = C.KRB5_REALM_CANT_RESOLVE  //	"Cannot resolve network address for KDC in requested realm"
	KRB5_TKT_NOT_FORWARDABLE = C.KRB5_TKT_NOT_FORWARDABLE //	"Requesting ticket can't get forwardable tickets"
	KRB5_FWD_BAD_PRINCIPAL   = C.KRB5_FWD_BAD_PRINCIPAL   // "Bad principal name while trying to forward credentials"

	KRB5_GET_IN_TKT_LOOP   = C.KRB5_GET_IN_TKT_LOOP   //  "Looping detected inside krb5_get_in_tkt"
	KRB5_CONFIG_NODEFREALM = C.KRB5_CONFIG_NODEFREALM //	"Configuration file does not specify default realm"

	KRB5_SAM_UNSUPPORTED   = C.KRB5_SAM_UNSUPPORTED   //  "Bad SAM flags in obtain_sam_padata"
	KRB5_SAM_INVALID_ETYPE = C.KRB5_SAM_INVALID_ETYPE //	"Invalid encryption type in SAM challenge"
	KRB5_SAM_NO_CHECKSUM   = C.KRB5_SAM_NO_CHECKSUM   //	"Missing checksum in SAM challenge"
	KRB5_SAM_BAD_CHECKSUM  = C.KRB5_SAM_BAD_CHECKSUM  //	"Bad checksum in SAM challenge"
	KRB5_KT_NAME_TOOLONG   = C.KRB5_KT_NAME_TOOLONG   //	"Keytab name too long"
	KRB5_KT_KVNONOTFOUND   = C.KRB5_KT_KVNONOTFOUND   //	"Key version number for principal in key table is incorrect"
	KRB5_APPL_EXPIRED      = C.KRB5_APPL_EXPIRED      //	"This application has expired"
	KRB5_LIB_EXPIRED       = C.KRB5_LIB_EXPIRED       //	"This Krb5 library has expired"

	KRB5_CHPW_PWDNULL = C.KRB5_CHPW_PWDNULL //		"New password cannot be zero length"
	KRB5_CHPW_FAIL    = C.KRB5_CHPW_FAIL    //		"Password change failed"
	KRB5_KT_FORMAT    = C.KRB5_KT_FORMAT    //		"Bad format in keytab"

	KRB5_NOPERM_ETYPE        = C.KRB5_NOPERM_ETYPE        //	"Encryption type not permitted"
	KRB5_CONFIG_ETYPE_NOSUPP = C.KRB5_CONFIG_ETYPE_NOSUPP //	"No supported encryption types (config file error?)"
	KRB5_OBSOLETE_FN         = C.KRB5_OBSOLETE_FN         //	"Program called an obsolete, deleted function"

	KRB5_EAI_FAIL    = C.KRB5_EAI_FAIL    //	"unknown getaddrinfo failure"
	KRB5_EAI_NODATA  = C.KRB5_EAI_NODATA  //	"no data available for host/domain name"
	KRB5_EAI_NONAME  = C.KRB5_EAI_NONAME  //	"host/domain name not found"
	KRB5_EAI_SERVICE = C.KRB5_EAI_SERVICE //	"service name unknown"

	KRB5_ERR_NUMERIC_REALM = C.KRB5_ERR_NUMERIC_REALM // "Cannot determine realm for numeric host address"

	KRB5_ERR_BAD_S2K_PARAMS = C.KRB5_ERR_BAD_S2K_PARAMS // "Invalid key generation parameters from KDC"

	KRB5_ERR_NO_SERVICE = C.KRB5_ERR_NO_SERVICE //	"service not available"

	KRB5_CC_READONLY = C.KRB5_CC_READONLY //    "Ccache function not supported: read-only ccache type"
	KRB5_CC_NOSUPP   = C.KRB5_CC_NOSUPP   //      "Ccache function not supported: not implemented"

	KRB5_DELTAT_BADFORMAT = C.KRB5_DELTAT_BADFORMAT //	"Invalid format of Kerberos lifetime or clock skew string"

	KRB5_PLUGIN_NO_HANDLE  = C.KRB5_PLUGIN_NO_HANDLE  //	"Supplied data not handled by this plugin"
	KRB5_PLUGIN_OP_NOTSUPP = C.KRB5_PLUGIN_OP_NOTSUPP //  "Plugin does not support the operation"

	KRB5_ERR_INVALID_UTF8  = C.KRB5_ERR_INVALID_UTF8  //	"Invalid UTF-8 string"
	KRB5_ERR_FAST_REQUIRED = C.KRB5_ERR_FAST_REQUIRED // "FAST protected pre-authentication required but not supported by KDC"

	KRB5_LOCAL_ADDR_REQUIRED  = C.KRB5_LOCAL_ADDR_REQUIRED  //  "Auth context must contain local address"
	KRB5_REMOTE_ADDR_REQUIRED = C.KRB5_REMOTE_ADDR_REQUIRED // "Auth context must contain remote address"

	KRB5_TRACE_NOSUPP = C.KRB5_TRACE_NOSUPP // "Tracing unsupported"
)
