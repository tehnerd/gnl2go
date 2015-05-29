package gnl2go

import (
	"fmt"
	"syscall"
	"testing"
)

func TestAttrListSerDes(t *testing.T) {
	al := CreateAttrListType(CtrlAttrList)
	testMap := make(map[string]SerDes)
	familyId := U16Type(1)
	familyName := NulStringType("testFamily")
	version := U32Type(1)
	hdrSize := U32Type(100)
	maxAttr := U32Type(14)
	testMap["FAMILY_ID"] = &familyId
	testMap["FAMILY_NAME"] = &familyName
	testMap["VERSION"] = &version
	testMap["HDRSIZE"] = &hdrSize
	testMap["MAXATTR"] = &maxAttr
	al.Set(testMap)
	serializedList := al.Serialize()
	fmt.Println(serializedList)
	al.Deserialize(serializedList)
	for k, v := range testMap {
		if data, exist := al.Amap[k]; !exist {
			t.Errorf("deserialized map not equal to original\n key %v doesnt exist\n", k)
		} else {
			data.Val()
			v.Val()
		}
	}
	var sd SerDes
	sd = &al
	sd.Val()
}

func TestToFromAFUnion(t *testing.T) {
	fmt.Println("starting to test to/from af union")
	v4addr := "1.4.2.1"
	v6addr := "2a02:1::1"
	if !validateIp(v4addr) || !validateIp(v6addr) {
		t.Errorf("validation failed!\n")
		return
	}
	af, addr := toAFUnion(v4addr)
	if af != syscall.AF_INET {
		t.Errorf("to af failed")
		return
	}
	v4dec := fromAFUnion(af, addr)
	fmt.Println(v4dec)
	af, addr = toAFUnion(v6addr)
	if af != syscall.AF_INET6 {
		t.Errorf("to af failed")
		return
	}
	v6dec := fromAFUnion(af, addr)
	fmt.Println(v6dec)

}
