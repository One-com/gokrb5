package gokrb5

/*
#cgo LDFLAGS: -lkrb5

#include <krb5.h>

*/
import "C"

import (
	"runtime"
	"unsafe"
)

// MIT libkrb5 krb5_error_code.
type ErrorCode C.krb5_error_code

func (e ErrorCode) Code() int32 {
	return int32(e)
}

func (e ErrorCode) Error() string {
	var cmsg *C.char
	cmsg = C.krb5_get_error_message(nil, C.krb5_error_code(e))
	gostr := C.GoString(cmsg)
	C.krb5_free_error_message(nil, cmsg) // seems like a NOOP
	return gostr
}

// Context is libkrb5 krb5_context and has all global operations a methods
// No method on Context or any returned objects are go-routine safe.

type Context struct {
	kctx unsafe.Pointer // a krb5_context
}

func (kc *Context) ErrorMessage(e ErrorCode) string {
	var cmsg *C.char
	cmsg = C.krb5_get_error_message(kc.toC(), C.krb5_error_code(e))
	gostr := C.GoString(cmsg)
	C.krb5_free_error_message(kc.toC(), cmsg)
	return gostr
}

func (kc *Context) toC() C.krb5_context {
	return C.krb5_context(kc.kctx)
}

// InitContext must be called to use Kerberos. It provides access to all global methods.
func InitContext() (ctx *Context, err error) {
	var kc C.krb5_context
	code := C.krb5_init_secure_context(&kc)
	if code != 0 {
		err = ErrorCode(code)
		return
	}
	ctx = &Context{kctx: unsafe.Pointer(kc)}
	runtime.SetFinalizer(ctx, freeContext)
	return
}

// libkrb5 seems to make all free operations safe to call twice by
// making them a NOP if the pointer is nil.
func freeContext(kc *Context) {
	if kc.kctx != nil {
		C.krb5_free_context(C.krb5_context(kc.kctx))
	}
	kc.kctx = nil
}

func (kc *Context) Timeofday() (seconds, microseconds int32, err error) {
	var cs C.krb5_timestamp
	var cms C.krb5_int32

	code := C.krb5_us_timeofday(kc.toC(), &cs, &cms)
	if code != 0 {
		err = ErrorCode(code)
		return
	}
	return int32(cs), int32(cms), nil
}

func (kc *Context) GetDefaultRealm() (realm string, err error) {
	var cstring *C.char
	code := C.krb5_get_default_realm(kc.toC(), &cstring)
	if code != 0 {
		err = ErrorCode(code)
		return
	}
	realm = C.GoString(cstring)
	C.krb5_free_default_realm(kc.toC(), cstring)
	return
}

func (kc *Context) SetDefaultRealm(realm string) (err error) {
	var cstring *C.char

	cstring = C.CString(realm)

	code := C.krb5_set_default_realm(kc.toC(), cstring)
	if code != 0 {
		err = ErrorCode(code)
		return
	}
	C.free(unsafe.Pointer(cstring))
	return
}
