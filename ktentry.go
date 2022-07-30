package gokrb5

// #include <krb5.h>
import "C"

import (
	"runtime"
	"unsafe"
)

type KeytabEntry struct {
	c *Context
	p *C.krb5_keytab_entry // NOT pointer type
}

func newKeytabEntryFromC(c *Context, p *C.krb5_keytab_entry) *KeytabEntry {
	cp := &KeytabEntry{c, p}
	runtime.SetFinalizer(cp, (*KeytabEntry).free)
	return cp
}

func newKeytabEntryFromGo(c *Context, p *C.krb5_keytab_entry) *KeytabEntry {
	cp := &KeytabEntry{c, p}
	runtime.SetFinalizer(cp, (*KeytabEntry).freeContents)
	return cp
}

func (p *KeytabEntry) free() {
	C.krb5_free_keytab_entry_contents(p.c.toC(), p.p)
	C.free(unsafe.Pointer(p.p))
	p.p = nil
}

func (p *KeytabEntry) freeContents() {
	C.krb5_free_keytab_entry_contents(p.c.toC(), p.p)
}

func (p *KeytabEntry) Principal() (*Principal, error) {
	var p2 C.krb5_principal
	code := C.krb5_copy_principal(p.c.toC(), p.p.principal, &p2)
	if code != 0 {
		return nil, ErrorCode(code)
	}
	return newPrincipalFromC(p.c, p2), nil
}

func (p *KeytabEntry) Kvno() uint {
	return uint(p.p.vno)
}

func (p *KeytabEntry) Key() (*Keyblock, error) {
	var k *C.krb5_keyblock
	code := C.krb5_copy_keyblock(p.c.toC(), &p.p.key, &k)
	if code != 0 {
		return nil, ErrorCode(code)
	}
	return newKeyblockFromC(p.c, k), nil
}

func (p *KeytabEntry) Timestamp() int32 {
	return int32(p.p.timestamp)
}
