package gokrb5

import (
	"testing"
)

func TestPrincipal(t *testing.T) {
	kctx, e := InitContext()
	if e != nil {
		t.Fatal(e)
	}

	var realm = "REALM"
	var components = []string{"some", "random", "principal"}
	var pnamestr = "some/random/principal@REALM"

	p1, err := kctx.BuildPrincipal(NT_PRINCIPAL, realm, components...)
	if err != nil {
		t.Fatal(err)
	}

	if p1.String() != pnamestr {
		t.Errorf("Principal build failed, %s != %s\n", p1, pnamestr)
	}

	str, err := p1.UnparseName()
	if err != nil {
		t.Fatal(err)
	}

	p2, err := kctx.ParseName(str)
	if err != nil {
		t.Fatal(err)
	}

	nt, comp, r := p2.NameType(), p2.Name(), p2.Realm()

	var fail bool
	for i, c := range comp {
		if c != components[i] {
			fail = true
		}
	}

	if nt != NT_PRINCIPAL || r != realm || fail {
		t.Error("Principal ParseName failed\n")
	}
}
