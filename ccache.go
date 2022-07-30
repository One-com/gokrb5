package gokrb5

// #include <krb5.h>
import "C"

import (
	"runtime"
)

type CCacheCursor C.krb5_cc_cursor

type CCache struct {
	c *Context
	p C.krb5_ccache // Pointer type.
}

func newCCacheFromC(c *Context, p C.krb5_ccache) *CCache {
	cp := &CCache{c, p}
	runtime.SetFinalizer(cp, (*CCache).Close)
	return cp
}

func (p *CCache) Close() {
	C.krb5_cc_close(p.c.toC(), p.p)
	p.p = nil
}

func (kc *Context) CcDefault() (*CCache, error) {
	var cp C.krb5_ccache
	code := C.krb5_cc_default(kc.toC(), &cp)
	if code != 0 {
		return nil, ErrorCode(code)
	}
	return newCCacheFromC(kc, cp), nil
}

func (kc *Context) CcResolve(name string) (*CCache, error) {

	var cp C.krb5_ccache
	cname := C.CString(name)
	code := C.krb5_cc_resolve(kc.toC(), cname, &cp)
	if code != 0 {
		return nil, ErrorCode(code)
	}
	return newCCacheFromC(kc, cp), nil

}

func (p *CCache) GetPrincipal() (*Principal, error) {
	var cp C.krb5_principal
	code := C.krb5_cc_get_principal(p.c.toC(), p.p, &cp)
	if code != 0 {
		return nil, ErrorCode(code)
	}

	return newPrincipalFromC(p.c, cp), nil
}

func (p *CCache) StartSeqGet() (*CCacheCursor, error) {
	var cursor C.krb5_cc_cursor
	code := C.krb5_cc_start_seq_get(p.c.toC(), p.p, &cursor)
	if code != 0 {
		return nil, ErrorCode(code)
	}
	return (*CCacheCursor)(&cursor), nil

}

func (p *CCache) NextCred(cursor *CCacheCursor) (creds *Creds, err error) {
	c := &C.krb5_creds{}

	code := C.krb5_cc_next_cred(p.c.toC(), p.p, (*C.krb5_cc_cursor)(cursor), c)
	if code != 0 {
		if code == C.KRB5_CC_END {
			return
		}
		err = ErrorCode(code)
		return
	}
	creds = newCredsFromGo(p.c, c)
	return
}

func (p *CCache) EndSeqGet(cursor *CCacheCursor) (err error) {
	code := C.krb5_cc_end_seq_get(p.c.toC(), p.p, (*C.krb5_cc_cursor)(cursor))
	if code != 0 {
		err = ErrorCode(code)
	}
	return
}
