package gokrb5

// #include <krb5.h>
import "C"

import (
	"runtime"
)

type Creds struct {
	c *Context
	p *C.krb5_creds // NOT a pointer type.
}

func newCredsFromC(c *Context, p *C.krb5_creds) *Creds {
	cp := &Creds{c, p}
	runtime.SetFinalizer(cp, (*Creds).free)
	return cp
}

func newCredsFromGo(c *Context, p *C.krb5_creds) *Creds {
	cp := &Creds{c, p}
	runtime.SetFinalizer(cp, (*Creds).freeContents)
	return cp
}

func (c *Creds) freeContents() {
	C.krb5_free_cred_contents(c.c.toC(), c.p)
}

func (c *Creds) free() {
	C.krb5_free_creds(c.c.toC(), c.p)
	c.p = nil
}

func (c *Creds) StartTime() int32 {
	return int32(c.p.times.starttime)
}

func (c *Creds) Server() (*Principal, error) {
	var cp C.krb5_principal
	code := C.krb5_copy_principal(c.c.toC(), c.p.server, &cp)
	if code != 0 {
		return nil, ErrorCode(code)
	}
	return newPrincipalFromC(c.c, cp), nil
}

func (c *Creds) Client() (*Principal, error) {
	var cp C.krb5_principal
	code := C.krb5_copy_principal(c.c.toC(), c.p.client, &cp)
	if code != 0 {
		return nil, ErrorCode(code)
	}
	return newPrincipalFromC(c.c, cp), nil
}
