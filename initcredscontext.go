package gokrb5

// #include <krb5.h>
/*
#include "./data.h"


krb5_error_code
helper_krb5_init_creds_step(krb5_context context, krb5_init_creds_context icreds_context, void *inbuf, unsigned int ilen, krb5_data *odata, krb5_data *orealm,  unsigned int *flags) {
  krb5_error_code code;
  krb5_data idata;

  idata = make_data(inbuf, ilen);

  code = krb5_init_creds_step(context, icreds_context, &idata, odata, orealm, flags);

  return code;
}

*/
import "C"

import (
	"runtime"
	"unsafe"
)

type InitCredsContext struct {
	c *Context
	p C.krb5_init_creds_context // pointer type
}

func newInitCredsContextFromC(c *Context, p C.krb5_init_creds_context) *InitCredsContext {
	cp := &InitCredsContext{c, p}
	runtime.SetFinalizer(cp, (*Keytab).Close)
	return cp
}

func (p *InitCredsContext) free() {
	C.krb5_init_creds_free(p.c.toC(), p.p)
	p.p = nil
}

func (kc *Context) NewInitCredsContext(client *Principal) (*InitCredsContext, error) {

	var cp C.krb5_init_creds_context
	code := C.krb5_init_creds_init(kc.toC(), client.p, nil, nil, 0, nil, &cp)
	if code != 0 {
		return nil, ErrorCode(code)
	}
	return newInitCredsContextFromC(kc, cp), nil
}

func (ic *InitCredsContext) SetPassword(password string) (err error) {

	pw := C.CString(password)
	defer C.free(unsafe.Pointer(pw))

	code := C.krb5_init_creds_set_password(ic.c.toC(), ic.p, pw)
	if code != 0 {
		return ErrorCode(code)
	}
	return nil

}

func (ic *InitCredsContext) GetCreds() (creds *Creds, err error) {
	var c C.krb5_creds
	code := C.krb5_init_creds_get_creds(ic.c.toC(), ic.p, &c)
	if code != 0 {
		return nil, ErrorCode(code)
	}
	creds = newCredsFromGo(ic.c, &c)
	return
}

func (ic *InitCredsContext) Step(in []byte) (out []byte, realm string, flags uint32, err error) {
	var out_data C.krb5_data
	var out_realm C.krb5_data

	var ibuf unsafe.Pointer
	var ilen int
	if in != nil {
		ibuf = unsafe.Pointer(&in[0])
		ilen = len(in)
	}

	code := C.helper_krb5_init_creds_step(ic.c.toC(), ic.p,
		ibuf, C.uint(ilen),
		&out_data, &out_realm, (*C.uint)(&flags))
	if code != 0 {
		err = ErrorCode(code)
		return
	}

	out = C.GoBytes(unsafe.Pointer(out_data.data), C.int(out_data.length))
	C.krb5_free_data_contents(ic.c.toC(), &out_data)

	realm = C.GoStringN(out_realm.data, C.int(out_realm.length))
	C.krb5_free_data_contents(ic.c.toC(), &out_realm)

	return
}
