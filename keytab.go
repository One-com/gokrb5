package gokrb5

// #include <krb5.h>
import "C"

import (
	"runtime"
	"unsafe"
)

type KeytabCursor C.krb5_kt_cursor

type Keytab struct {
	c *Context
	p C.krb5_keytab // pointer type
}

func newKeytabFromC(c *Context, p C.krb5_keytab) *Keytab {
	cp := &Keytab{c, p}
	runtime.SetFinalizer(cp, (*Keytab).Close)
	return cp
}

func (p *Keytab) Close() {
	C.krb5_kt_close(p.c.toC(), p.p)
	p.p = nil
}

func (kc *Context) KtResolve(name string) (*Keytab, error) {

	var cp C.krb5_keytab
	cname := C.CString(name)
	code := C.krb5_kt_resolve(kc.toC(), cname, &cp)
	if code != 0 {
		return nil, ErrorCode(code)
	}
	return newKeytabFromC(kc, cp), nil

}

func (p *Keytab) HaveContent() bool {
	code := C.krb5_kt_have_content(p.c.toC(), p.p)
	if code != 0 {
		return false
	}
	return true

}

func (p *Keytab) GetName(maxlength uint) (name string, err error) {
	var cstring *C.char
	cstring = (*C.char)(C.malloc(C.size_t(maxlength)))
	code := C.krb5_kt_get_name(p.c.toC(), p.p, cstring, C.uint(maxlength))
	if code != 0 {
		return "", ErrorCode(code)
	}
	name = C.GoString(cstring)
	C.free(unsafe.Pointer(cstring))
	return
}

func (p *Keytab) GetEntry(princ *Principal, vno uint, enctype int32) (*KeytabEntry, error) {
	var entry *C.krb5_keytab_entry
	entry = (*C.krb5_keytab_entry)(C.malloc(C.size_t(unsafe.Sizeof(*entry))))
	code := C.krb5_kt_get_entry(p.c.toC(), p.p, princ.p, C.krb5_kvno(vno), C.krb5_enctype(enctype), entry)
	if code != 0 {
		return nil, ErrorCode(code)
	}
	return newKeytabEntryFromC(p.c, entry), nil

}

func (p *Keytab) AddEntry(entry *KeytabEntry) error {
	code := C.krb5_kt_add_entry(p.c.toC(), p.p, entry.p)
	if code != 0 {
		return ErrorCode(code)
	}
	return nil
}

func (p *Keytab) RemoveEntry(entry *KeytabEntry) error {
	code := C.krb5_kt_remove_entry(p.c.toC(), p.p, entry.p)
	if code != 0 {
		return ErrorCode(code)
	}
	return nil
}

func (p *Keytab) StartSeqGet() (*KeytabCursor, error) {
	var cursor C.krb5_kt_cursor
	code := C.krb5_kt_start_seq_get(p.c.toC(), p.p, &cursor)
	if code != 0 {
		return nil, ErrorCode(code)
	}
	return (*KeytabCursor)(&cursor), nil

}

func (p *Keytab) NextEntry(cursor *KeytabCursor) (entry *KeytabEntry, err error) {
	c := &C.krb5_keytab_entry{}

	code := C.krb5_kt_next_entry(p.c.toC(), p.p, c, (*C.krb5_kt_cursor)(cursor))
	if code != 0 {
		if code == C.KRB5_KT_END {
			return
		}
		err = ErrorCode(code)
		return
	}
	entry = newKeytabEntryFromGo(p.c, c)
	return
}

func (p *Keytab) EndSeqGet(cursor *KeytabCursor) (err error) {
	code := C.krb5_kt_end_seq_get(p.c.toC(), p.p, (*C.krb5_kt_cursor)(cursor))
	if code != 0 {
		err = ErrorCode(code)
	}
	return
}
