package gokrb5

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"testing"
)

const (
	testServicePrinc = "http/localhost@LOCALHOST"
	testKeytab       = `BQIAAABLAAIACUxPQ0FMSE9TVAAEaHR0cAAJbG9jYWxob3N0AAAAAVggQiYEABIAIMkX5Jau//Xz
SwWZAlOucx0ROMl3BP6TVGD08H3CUbSOAAAAOwACAAlMT0NBTEhPU1QABGh0dHAACWxvY2FsaG9z
dAAAAAFYIEImBAARABBHkETIIzVpt/S7ZPdwiyJtAAAAQwACAAlMT0NBTEhPU1QABGh0dHAACWxv
Y2FsaG9zdAAAAAFYIEImBAAQABiAsIM4imsxpMhbjDgZbiDcRtV200ZdwiwAAAA7AAIACUxPQ0FM
SE9TVAAEaHR0cAAJbG9jYWxob3N0AAAAAVggQiYEABcAEDsDb3W9J7J8lXYcOwU3tHM=`
)

var _ = fmt.Println

func TestKeytab(t *testing.T) {
	kctx, e := InitContext()
	if e != nil {
		t.Fatal(e)
	}

	file, err := ioutil.TempFile("", "test_keytab_")
	if err != nil {
		t.Fatal(err)
	}

	data, err := base64.StdEncoding.DecodeString(testKeytab)
	if err != nil {
		t.Fatal(err)
	}

	_, err = file.Write(data)
	if err != nil {
		t.Fatal(err)
	}

	kt, err := kctx.KtResolve("FILE:" + file.Name())
	if err != nil {
		t.Fatal(err)
	}

	cursor, err := kt.StartSeqGet()
	if err != nil {
		t.Fatal(err)
	}

	for {
		entry, err := kt.NextEntry(cursor)
		if err != nil {
			if kerr, ok := err.(ErrorCode); ok && kerr.Code() == KRB5_KT_END {
				break
			}
			t.Fatal(err)
		}
		if entry == nil {
			break
		}
		princ, err := entry.Principal()
		if err != nil {
			t.Fatal(err)
		}
		pstr := princ.String()

		if pstr != testServicePrinc && entry.Kvno() != 4 {
			t.Fatalf("Unexpected principal keys in keytab: (kvno:%d) %s", entry.Kvno(), pstr)
		}
	}

}
