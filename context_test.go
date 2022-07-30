package gokrb5

import (
	"testing"
)

// go test -v -exec 'faketime "2008-12-24 08:15:42"'
const (
	testTimeofday = 1230102942
	testRealm     = "LOCALHOST"
)

func TestFaketime(t *testing.T) {
	krb, e := InitContext()
	if e != nil {
		t.Fatal(e)
	}

	s, _, e := krb.Timeofday()
	if e != nil {
		t.Fatal(e)
	}

	if s != testTimeofday && s != testTimeofday+1 {
		t.Errorf("%d != %d", s, testTimeofday)
	}
}

func TestDefaultRealm(t *testing.T) {
	krb, e := InitContext()
	if e != nil {
		t.Fatal(e)
	}

	e = krb.SetDefaultRealm("FOOBAR")
	if e != nil {
		t.Fatal(e)
	}

	var r string
	r, e = krb.GetDefaultRealm()
	if e != nil {
		t.Fatal(e)
	}
	if r != "FOOBAR" {
		t.Error("Setting and getting default realm failed")
	}
}
