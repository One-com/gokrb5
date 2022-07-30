package gokrb5

// #include <krb5.h>
/*
#include "./data.h"

krb5_error_code
helper_krb5_rd_req(krb5_context context, krb5_auth_context *auth_context, void *inbuf, unsigned int length, krb5_const_principal server, krb5_keytab keytab, krb5_flags *ap_req_options, krb5_ticket **ticket) {
  krb5_error_code code;
  krb5_data kdata;

  kdata = make_data(inbuf, length);
  code = krb5_rd_req(context, auth_context, &kdata, server, keytab, ap_req_options, ticket);
  return code;
}

krb5_error_code
helper_krb5_mk_req_extended(krb5_context context, krb5_auth_context *auth_context, krb5_flags ap_req_options, void *inbuf, unsigned int ilen, krb5_creds *creds, krb5_data *odata) {
  krb5_error_code code;
  krb5_data idata;

  idata = make_data(inbuf, ilen);

  code = krb5_mk_req_extended(context, auth_context, ap_req_options, &idata, creds, odata);

  return code;
}
*/
import "C"

import (
	"runtime"
	"unsafe"
)

type AuthContext struct {
	c *Context
	p C.krb5_auth_context // pointer type
}

type Authenticator struct {
	c *Context
	p *C.krb5_authenticator // NON pointer type
}

func newAuthContextFromC(c *Context, p C.krb5_auth_context) *AuthContext {
	cp := &AuthContext{c, p}
	runtime.SetFinalizer(cp, (*AuthContext).free)
	return cp
}

func newAuthenticatorFromC(c *Context, p *C.krb5_authenticator) *Authenticator {
	cp := &Authenticator{c, p}
	runtime.SetFinalizer(cp, (*Authenticator).free)
	return cp
}

func (p *AuthContext) free() {
	C.krb5_auth_con_free(p.c.toC(), p.p)
	p.p = nil
}

func (p *Authenticator) free() {
	C.krb5_free_authenticator(p.c.toC(), p.p)
	p.p = nil
}

func (kc *Context) NewAuthContext() (*AuthContext, error) {

	var ac C.krb5_auth_context
	code := C.krb5_auth_con_init(kc.toC(), &ac)
	if code != 0 {
		return nil, ErrorCode(code)
	}
	return newAuthContextFromC(kc, ac), nil
}

func (p *AuthContext) Authenticator() (*Authenticator, error) {
	var r *C.krb5_authenticator
	code := C.krb5_auth_con_getauthenticator(p.c.toC(), p.p, &r)
	if code != 0 {
		return nil, ErrorCode(code)
	}
	return newAuthenticatorFromC(p.c, r), nil
}

func (p *Authenticator) Client() (*Principal, error) {
	if p.p.client != nil {
		var cp C.krb5_principal
		code := C.krb5_copy_principal(p.c.toC(), p.p.client, &cp)
		if code != 0 {
			return nil, ErrorCode(code)
		}
		return newPrincipalFromC(p.c, cp), nil
	}
	return nil, nil
}

func (p *AuthContext) RdReq(request []byte, keytab *Keytab, server *Principal) (*Ticket, error) {
	var tp *C.krb5_ticket

	code := C.helper_krb5_rd_req(p.c.toC(), &p.p, unsafe.Pointer(&request[0]), C.uint(len(request)),
		server.p, keytab.p, nil, &tp)
	if code != 0 {
		return nil, ErrorCode(code)
	}
	return newTicketFromC(p.c, tp), nil
}

func (p *AuthContext) MkReq(creds *Creds, ap_req_options int32, in []byte) (request []byte, err error) {
	var out_data C.krb5_data

	var ibuf unsafe.Pointer
	var ilen int
	if in != nil {
		ibuf = unsafe.Pointer(&in[0])
		ilen = len(in)
	}

	code := C.helper_krb5_mk_req_extended(p.c.toC(), &p.p, C.krb5_flags(ap_req_options), ibuf, C.uint(ilen), creds.p, &out_data)
	if code != 0 {
		return nil, ErrorCode(code)
	}
	request = C.GoBytes(unsafe.Pointer(out_data.data), C.int(out_data.length))
	C.krb5_free_data_contents(p.c.toC(), &out_data)
	return

}
