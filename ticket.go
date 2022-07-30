package gokrb5

// #include <krb5.h>
/*

#include "./data.h"

// We need to create the krb5_data in C, to not pass Go-pointer to Go-pointer
krb5_error_code
helper_decode_ticket(void *gobuf, unsigned int length, krb5_ticket **ticket) {
  krb5_error_code code;
  krb5_data kdata;

  kdata = make_data(gobuf, length);
  code = krb5_decode_ticket(&kdata, ticket);
  return code;
}
*/
import "C"

import (
	"runtime"
	"unsafe"
)

type Ticket struct {
	c *Context
	p *C.krb5_ticket // NOT a pointer type
}

func newTicketFromC(c *Context, p *C.krb5_ticket) *Ticket {
	cp := &Ticket{c, p}
	runtime.SetFinalizer(cp, (*Ticket).free)
	return cp
}

func (p *Ticket) free() {
	C.krb5_free_ticket(p.c.toC(), p.p)
	p.p = nil
}

func (kc *Context) DecodeTicket(data []byte) (*Ticket, error) {

	var tp *C.krb5_ticket

	code := C.helper_decode_ticket(unsafe.Pointer(&data[0]), C.uint(len(data)), &tp)
	if code != 0 {
		return nil, ErrorCode(code)
	}

	return newTicketFromC(kc, tp), nil

}

func (p *Ticket) Server() (*Principal, error) {
	if p.p.server != nil {
		var cp C.krb5_principal
		code := C.krb5_copy_principal(p.c.toC(), p.p.server, &cp)
		if code != 0 {
			return nil, ErrorCode(code)
		}
		return newPrincipalFromC(p.c, cp), nil
	}
	return nil, nil
}

func (p *Ticket) Client() (*Principal, error) {
	if p.p.enc_part2 != nil && p.p.enc_part2.client != nil {
		var cp C.krb5_principal
		code := C.krb5_copy_principal(p.c.toC(), p.p.enc_part2.client, &cp)
		if code != 0 {
			return nil, ErrorCode(code)
		}
		return newPrincipalFromC(p.c, cp), nil
	}
	return nil, nil
}
