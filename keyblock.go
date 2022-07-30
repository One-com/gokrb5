package gokrb5

// #include <krb5.h>
import "C"

import (
	"runtime"
)

type Keyblock struct {
	c *Context
	p *C.krb5_keyblock // NOT pointer type
}

func newKeyblockFromC(c *Context, p *C.krb5_keyblock) *Keyblock {
	cp := &Keyblock{c, p}
	runtime.SetFinalizer(cp, (*Keyblock).free)
	return cp
}

func (p *Keyblock) free() {
	C.krb5_free_keyblock(p.c.toC(), p.p)
	p.p = nil
}

func (p *Keyblock) Copy() (*Keyblock, error) {
	var k2 *C.krb5_keyblock
	code := C.krb5_copy_keyblock(p.c.toC(), p.p, &k2)
	if code != 0 {
		return nil, ErrorCode(code)
	}
	return newKeyblockFromC(p.c, k2), nil
}
