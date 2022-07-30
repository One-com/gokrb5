package gokrb5

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"testing"
)

const (
	testClientPrinc = "client@LOCALHOST"
	testCCache      = `BQQADAABAAgAAAAAAAAAAAAAAAEAAAABAAAACUxPQ0FMSE9TVAAAAAZjbGllbnQAAAABAAAAAQAA
AAlMT0NBTEhPU1QAAAAGY2xpZW50AAAAAgAAAAIAAAAJTE9DQUxIT1NUAAAABmtyYnRndAAAAAlM
T0NBTEhPU1QAEgAAACBSFkmqlKEDZdIJbz1xB2fezfoAkiuMPk8i3BiJvA4p4lggZRJYIGUSWCG2
kgAAAAAAUEEAAAAAAAAAAAAAAAABOmGCATYwggEyoAMCAQWhCxsJTE9DQUxIT1NUoh4wHKADAgEC
oRUwExsGa3JidGd0GwlMT0NBTEhPU1Sjgf0wgfqgAwIBEqEDAgEBooHtBIHq2IE9lkSCtONr0n72
ZCvF5GeDOMLXI7OzL7CJh3rNQ62QKTixmgPvJpOPwNiz7v3pZE0ABQ3jADMNTh9kwO8zYGToqzC2
MlVUBolKmlebwA+Q1XDG1cMnVB9Xnuu0UxLx7eDRkILGxJxkqsVtfT8F9GIf5GqqMDpMJRMGMO6J
e73SCk98QCiCRtfDq7ix+4CL1CgYpZruOvR7S6UDmQFZJE6VdVrU0jPU7hLrHzs+JEGCjRaLeeYD
CmVbRqdPMB2kYL07sKtGxUzs5uRVWfXXWo/rlI4J0BfwUtWWFziS4M36Iz6hMgX/STucAAAAAAAA
AAEAAAABAAAACUxPQ0FMSE9TVAAAAAZjbGllbnQAAAAAAAAAAwAAAAxYLUNBQ0hFQ09ORjoAAAAV
a3JiNV9jY2FjaGVfY29uZl9kYXRhAAAACmZhc3RfYXZhaWwAAAAaa3JidGd0L0xPQ0FMSE9TVEBM
T0NBTEhPU1QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAN5ZXMAAAAA`
)

var _ = fmt.Println

func TestCCache(t *testing.T) {
	kctx, e := InitContext()
	if e != nil {
		t.Fatal(e)
	}

	file, err := ioutil.TempFile("", "test_ccache_")
	if err != nil {
		t.Fatal(err)
	}

	data, err := base64.StdEncoding.DecodeString(testCCache)
	if err != nil {
		t.Fatal(err)
	}

	_, err = file.Write(data)
	if err != nil {
		t.Fatal(err)
	}

	cc, err := kctx.CcResolve("FILE:" + file.Name())
	if err != nil {
		t.Fatal(err)
	}

	p, _ := cc.GetPrincipal()
	if p.String() != testClientPrinc {
		t.Fatalf("Failed reading CC principal. %s != %s", p.String(), testClientPrinc)
	}

	cursor, err := cc.StartSeqGet()
	if err != nil {
		t.Fatal(err)
	}

	for {
		cred, err := cc.NextCred(cursor)
		if err != nil {
			if kerr, ok := err.(ErrorCode); ok && kerr.Code() == KRB5_CC_END {
				break
			}
			t.Fatal(err)
		}
		if cred == nil {
			break
		}
		client, err := cred.Client()
		if err != nil {
			t.Fatal(err)
		}
		server, err := cred.Server()
		if err != nil {
			t.Fatal(err)
		}

		if server.Realm() == "X-CACHECONF:" {
			continue
		}

		if client.String() != testClientPrinc || server.String() != "krbtgt/LOCALHOST@LOCALHOST" {
			t.Fatal("Didn't find TGT in CCache")
		}
	}

}
