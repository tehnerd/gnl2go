package gnl2go

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
)

var (
	IpvsStatsAttrList = CreateAttrListDefinition("IpvsStatsAttrList",
		[]AttrTuple{
			AttrTuple{Name: "CONNS", Type: "U32Type"},
			AttrTuple{Name: "INPKTS", Type: "U32Type"},
			AttrTuple{Name: "OUTPKTS", Type: "U32Type"},
			AttrTuple{Name: "INBYTES", Type: "U64Type"},
			AttrTuple{Name: "OUTBYTES", Type: "U64Type"},
			AttrTuple{Name: "CPS", Type: "U32Type"},
			AttrTuple{Name: "INPPS", Type: "U32Type"},
			AttrTuple{Name: "OUTPPS", Type: "U32Type"},
			AttrTuple{Name: "INBPS", Type: "U32Type"},
			AttrTuple{Name: "OUTBPS", Type: "U32Type"},
		})

	IpvsServiceAttrList = CreateAttrListDefinition("IpvsServiceAttrList",
		[]AttrTuple{
			AttrTuple{Name: "AF", Type: "U16Type"},
			AttrTuple{Name: "PROTOCOL", Type: "U16Type"},
			AttrTuple{Name: "ADDR", Type: "BinaryType"},
			AttrTuple{Name: "PORT", Type: "Net16Type"},
			AttrTuple{Name: "FWMARK", Type: "U32Type"},
			AttrTuple{Name: "SCHED_NAME", Type: "NulStringType"},
			AttrTuple{Name: "FLAGS", Type: "BinaryType"},
			AttrTuple{Name: "TIMEOUT", Type: "U32Type"},
			AttrTuple{Name: "NETMASK", Type: "U32Type"},
			AttrTuple{Name: "STATS", Type: "IpvsStatsAttrList"},
			AttrTuple{Name: "PE_NAME", Type: "NulStringType"},
		})

	IpvsDestAttrList = CreateAttrListDefinition("IpvsDestAttrList",
		[]AttrTuple{
			AttrTuple{Name: "ADDR", Type: "BinaryType"},
			AttrTuple{Name: "PORT", Type: "Net16Type"},
			AttrTuple{Name: "FWD_METHOD", Type: "U32Type"},
			AttrTuple{Name: "WEIGHT", Type: "I32Type"},
			AttrTuple{Name: "U_THRESH", Type: "U32Type"},
			AttrTuple{Name: "L_THRESH", Type: "U32Type"},
			AttrTuple{Name: "ACTIVE_CONNS", Type: "U32Type"},
			AttrTuple{Name: "INACT_CONNS", Type: "U32Type"},
			AttrTuple{Name: "PERSIST_CONNS", Type: "U32Type"},
			AttrTuple{Name: "STATS", Type: "IpvsStatsAttrList"},
			AttrTuple{Name: "ADDR_FAMILY", Type: "U16Type"},
		})

	IpvsDaemonAttrList = CreateAttrListDefinition("IpvsDaemonAttrList",
		[]AttrTuple{
			AttrTuple{Name: "STATE", Type: "U32Type"},
			AttrTuple{Name: "MCAST_IFN", Type: "NulStringType"},
			AttrTuple{Name: "SYNC_ID", Type: "U32Type"},
		})

	IpvsInfoAttrList = CreateAttrListDefinition("IpvsInfoAttrList",
		[]AttrTuple{
			AttrTuple{Name: "VERSION", Type: "U32Type"},
			AttrTuple{Name: "CONN_TAB_SIZE", Type: "U32Type"},
		})

	IpvsCmdAttrList = CreateAttrListDefinition("IpvsCmdAttrList",
		[]AttrTuple{
			AttrTuple{Name: "SERVICE", Type: "IpvsServiceAttrList"},
			AttrTuple{Name: "DEST", Type: "IpvsDestAttrList"},
			AttrTuple{Name: "DAEMON", Type: "IpvsDaemonAttrList"},
			AttrTuple{Name: "TIMEOUT_TCP", Type: "U32Type"},
			AttrTuple{Name: "TIMEOUT_TCP_FIN", Type: "U32Type"},
			AttrTuple{Name: "TIMEOUT_UDP", Type: "U32Type"},
		})

	IpvsMessageInitList = []AttrListTuple{
		AttrListTuple{Name: "NEW_SERVICE", AttrList: CreateAttrListType(IpvsCmdAttrList)},
		AttrListTuple{Name: "SET_SERVICE", AttrList: CreateAttrListType(IpvsCmdAttrList)},
		AttrListTuple{Name: "DEL_SERVICE", AttrList: CreateAttrListType(IpvsCmdAttrList)},
		AttrListTuple{Name: "GET_SERVICE", AttrList: CreateAttrListType(IpvsCmdAttrList)},
		AttrListTuple{Name: "NEW_DEST", AttrList: CreateAttrListType(IpvsCmdAttrList)},
		AttrListTuple{Name: "SET_DEST", AttrList: CreateAttrListType(IpvsCmdAttrList)},
		AttrListTuple{Name: "DEL_DEST", AttrList: CreateAttrListType(IpvsCmdAttrList)},
		AttrListTuple{Name: "GET_DEST", AttrList: CreateAttrListType(IpvsCmdAttrList)},
		AttrListTuple{Name: "NEW_DAEMON", AttrList: CreateAttrListType(IpvsCmdAttrList)},
		AttrListTuple{Name: "DEL_DAEMON", AttrList: CreateAttrListType(IpvsCmdAttrList)},
		AttrListTuple{Name: "GET_DAEMON", AttrList: CreateAttrListType(IpvsCmdAttrList)},
		AttrListTuple{Name: "SET_CONFIG", AttrList: CreateAttrListType(IpvsCmdAttrList)},
		AttrListTuple{Name: "GET_CONFIG", AttrList: CreateAttrListType(IpvsCmdAttrList)},
		AttrListTuple{Name: "SET_INFO", AttrList: CreateAttrListType(IpvsCmdAttrList)},
		AttrListTuple{Name: "GET_INFO", AttrList: CreateAttrListType(IpvsCmdAttrList)},
		AttrListTuple{Name: "ZERO", AttrList: CreateAttrListType(IpvsCmdAttrList)},
		AttrListTuple{Name: "FLUSH", AttrList: CreateAttrListType(IpvsCmdAttrList)},
	}
)

func validateIp(ip string) bool {
	for _, c := range ip {
		if c == ':' {
			_, err := IPv6StringToAddr(ip)
			if err != nil {
				return false
			}
			return true
		}
	}
	_, err := IPv4ToUint32(ip)
	if err != nil {
		return false
	}
	return true
}

func toAFUnion(ip string) (uint16, []byte) {
	buf := new(bytes.Buffer)
	for _, c := range ip {
		if c == ':' {
			addr, _ := IPv6StringToAddr(ip)
			err := binary.Write(buf, binary.BigEndian, addr)
			if err != nil {
				panic("cant encode ipv6 addr to net format")
			}
			encAddr := buf.Bytes()
			if len(encAddr) != 16 {
				panic("length not equal to 16")
			}
			return syscall.AF_INET6, encAddr
		}
	}
	addr, _ := IPv4ToUint32(ip)
	err := binary.Write(buf, binary.BigEndian, addr)
	if err != nil {
		panic("cant encode ipv4 addr to net format")
	}
	encAddr := buf.Bytes()
	for len(encAddr) != 16 {
		encAddr = append(encAddr, byte(0))
	}
	return syscall.AF_INET, encAddr
}

func fromAFUnion(af uint16, addr []byte) string {
	if af == syscall.AF_INET6 {
		var v6addr IPv6Addr
		err := binary.Read(bytes.NewReader(addr), binary.BigEndian, &v6addr)
		if err != nil {
			panic("cant decode ipv6 addr from net repr")
		}
		addrStr := IPv6AddrToString(v6addr)
		return addrStr
	}
	var v4addr uint32
	//we leftpadded addr to len 16 above,so our v4 addr in addr[12:]
	err := binary.Read(bytes.NewReader(addr[:4]), binary.BigEndian, &v4addr)
	if err != nil {
		panic("cant decode v4 addr from net rep")
	}
	addrStr := Uint32IPv4ToString(v4addr)
	return addrStr
}

func ToProtoNum(proto NulStringType) U16Type {
	p := string(proto)
	switch strings.ToLower(p) {
	case "tcp":
		return U16Type(syscall.IPPROTO_TCP)
	case "udp":
		return U16Type(syscall.IPPROTO_UDP)
	}
	return U16Type(0)
}

func FromProtoNum(pnum U16Type) NulStringType {
	switch uint16(pnum) {
	case syscall.IPPROTO_TCP:
		return NulStringType("TCP")
	case syscall.IPPROTO_UDP:
		return NulStringType("UDP")
	}
	return NulStringType("UNKNOWN")
}

type Dest struct {
	IP     string
	Weight int32
	Port   uint16
	AF     uint16
}

func (d *Dest) IsEqual(od *Dest) bool {
	return d.IP == od.IP && d.Weight == od.Weight && d.Port == od.Port
}

func (d *Dest) InitFromAttrList(list map[string]SerDes) {
	//lots of casts from interface w/o checks; so we are going to panic if something goes wrong
	af, ok := list["ADDR_FAMILY"].(*U16Type)
	if !ok {
		//OLD kernel (3.18-), which doesnt support addr_family in dest definition
		dAF := U16Type(d.AF)
		af = &dAF
	} else {
		d.AF = uint16(*af)
	}
	addr, ok := list["ADDR"].(*BinaryType)
	if !ok {
		fmt.Printf("attr list: %#v\n", list)
		panic("no dst ADDR in attr list")
	}
	d.IP = fromAFUnion(uint16(*af), []byte(*addr))
	w, ok := list["WEIGHT"].(*I32Type)
	if !ok {
		fmt.Printf("attr list: %#v\n", list)
		panic("no dst WEIGHT in attr list")
	}
	d.Weight = int32(*w)
	p, ok := list["PORT"].(*Net16Type)
	if !ok {
		fmt.Printf("attr list: %#v\n", list)
		panic("no dst PORT in attr list")
	}
	d.Port = uint16(*p)
}

type Service struct {
	Proto  uint16
	VIP    string
	Port   uint16
	Sched  string
	FWMark uint32
	AF     uint16
}

func (s *Service) IsEqual(os Service) bool {
	return s.Proto == os.Proto && s.VIP == os.VIP &&
		s.Port == os.Port && s.Sched == os.Sched && s.FWMark == os.FWMark
}

func (s *Service) InitFromAttrList(list map[string]SerDes) {
	if _, exists := list["ADDR"]; exists {
		af := list["AF"].(*U16Type)
		s.AF = uint16(*af)
		addr := list["ADDR"].(*BinaryType)
		s.VIP = fromAFUnion(uint16(*af), []byte(*addr))
		proto := list["PROTOCOL"].(*U16Type)
		s.Proto = uint16(*proto)
		p := list["PORT"].(*Net16Type)
		s.Port = uint16(*p)
	} else {
		fw := list["FWMARK"].(*U32Type)
		s.FWMark = uint32(*fw)

	}
	sched := list["SCHED_NAME"].(*NulStringType)
	s.Sched = string(*sched)
}

type Pool struct {
	Service Service
	Dests   []Dest
}

func (p *Pool) InitFromAttrList(list map[string]SerDes) {
	//TODO(tehnerd):...
}

type IpvsClient struct {
	Sock NLSocket
	mt   *MessageType
}

func (ipvs *IpvsClient) Init() {
	LookupTypeOnStartup(IpvsMessageInitList, "IPVS")
	ipvs.Sock.Init()
	ipvs.mt = Family2MT[MT2Family["IPVS"]]
}

func (ipvs *IpvsClient) Flush() {
	msg := ipvs.mt.InitGNLMessageStr("FLUSH", ACK_REQUEST)
	ipvs.Sock.Execute(msg)
}

func (ipvs *IpvsClient) GetPools() []Pool {
	var pools []Pool
	msg := ipvs.mt.InitGNLMessageStr("GET_SERVICE", MATCH_ROOT_REQUEST)
	resps := ipvs.Sock.Query(msg)
	for _, resp := range resps {
		var pool Pool
		svcAttrList := resp.GetAttrList("SERVICE")
		pool.Service.InitFromAttrList(svcAttrList.(*AttrListType).Amap)
		destReq := ipvs.mt.InitGNLMessageStr("GET_DEST", MATCH_ROOT_REQUEST)
		destReq.AttrMap["SERVICE"] = svcAttrList.(*AttrListType)
		destResps := ipvs.Sock.Query(destReq)
		for _, destResp := range destResps {
			var d Dest
			dstAttrList := destResp.GetAttrList("DEST")
			d.AF = pool.Service.AF
			if dstAttrList != nil {
				d.InitFromAttrList(dstAttrList.(*AttrListType).Amap)
				pool.Dests = append(pool.Dests, d)
			}
		}
		pools = append(pools, pool)
	}
	return pools
}

func (ipvs *IpvsClient) modifyService(method string, vip string,
	port uint16, protocol uint16, amap map[string]SerDes) {
	af, addr := toAFUnion(vip)
	//1<<32-1
	netmask := uint32(4294967295)
	if af == syscall.AF_INET6 {
		netmask = 128
	}
	msg := ipvs.mt.InitGNLMessageStr(method, ACK_REQUEST)
	AF := U16Type(af)
	Port := Net16Type(port)
	Netmask := U32Type(netmask)
	Addr := BinaryType(addr)
	Proto := U16Type(protocol)
	Flags := BinaryType([]byte{0, 0, 0, 0, 0, 0, 0, 0})
	atl, _ := ATLName2ATL["IpvsServiceAttrList"]
	sattr := CreateAttrListType(atl)
	sattr.Amap["AF"] = &AF
	sattr.Amap["PORT"] = &Port
	sattr.Amap["PROTOCOL"] = &Proto
	sattr.Amap["ADDR"] = &Addr
	sattr.Amap["NETMASK"] = &Netmask
	sattr.Amap["FLAGS"] = &Flags
	for k, v := range amap {
		sattr.Amap[k] = v
	}
	msg.AttrMap["SERVICE"] = &sattr
	ipvs.Sock.Execute(msg)
}

func (ipvs *IpvsClient) AddService(vip string,
	port uint16, protocol uint16, sched string) {
	paramsMap := make(map[string]SerDes)
	Sched := NulStringType(sched)
	Timeout := U32Type(0)
	paramsMap["SCHED_NAME"] = &Sched
	paramsMap["TIMEOUT"] = &Timeout
	ipvs.modifyService("NEW_SERVICE", vip, port,
		protocol, paramsMap)
}

func (ipvs *IpvsClient) DelService(vip string,
	port uint16, protocol uint16) {
	ipvs.modifyService("DEL_SERVICE", vip, port,
		protocol, nil)
}

func (ipvs *IpvsClient) modifyFWMService(method string, fwmark uint32,
	af uint16, amap map[string]SerDes) {
	AF := U16Type(af)
	FWMark := U32Type(fwmark)
	netmask := uint32(4294967295)
	if af == syscall.AF_INET6 {
		netmask = 128
	}
	msg := ipvs.mt.InitGNLMessageStr(method, ACK_REQUEST)
	Netmask := U32Type(netmask)
	Flags := BinaryType([]byte{0, 0, 0, 0, 0, 0, 0, 0})
	atl, _ := ATLName2ATL["IpvsServiceAttrList"]
	sattr := CreateAttrListType(atl)
	sattr.Amap["FWMARK"] = &FWMark
	sattr.Amap["FLAGS"] = &Flags
	sattr.Amap["AF"] = &AF
	sattr.Amap["NETMASK"] = &Netmask
	for k, v := range amap {
		sattr.Amap[k] = v
	}
	msg.AttrMap["SERVICE"] = &sattr
	ipvs.Sock.Execute(msg)
}

func (ipvs *IpvsClient) AddFWMService(fwmark uint32,
	sched string, af uint16) {
	paramsMap := make(map[string]SerDes)
	Sched := NulStringType(sched)
	Timeout := U32Type(0)
	paramsMap["SCHED_NAME"] = &Sched
	paramsMap["TIMEOUT"] = &Timeout
	ipvs.modifyFWMService("NEW_SERVICE", fwmark,
		af, paramsMap)
}

func (ipvs *IpvsClient) DelFWMService(fwmark uint32, af uint16) {
	ipvs.modifyFWMService("DEL_SERVICE", fwmark, af, nil)
}

func (ipvs *IpvsClient) modifyDest(method string, vip string, port uint16,
	rip string, protocol uint16, amap map[string]SerDes) {
	//starts with r - for real's related, v - for vip's
	vaf, vaddr := toAFUnion(vip)
	raf, raddr := toAFUnion(rip)
	msg := ipvs.mt.InitGNLMessageStr(method, ACK_REQUEST)

	vAF := U16Type(vaf)
	vAddr := BinaryType(vaddr)
	rAF := U16Type(raf)
	rAddr := BinaryType(raddr)

	Port := Net16Type(port)
	Proto := U16Type(protocol)

	vatl, _ := ATLName2ATL["IpvsServiceAttrList"]
	ratl, _ := ATLName2ATL["IpvsDestAttrList"]
	sattr := CreateAttrListType(vatl)
	rattr := CreateAttrListType(ratl)

	sattr.Amap["AF"] = &vAF
	sattr.Amap["PORT"] = &Port
	sattr.Amap["PROTOCOL"] = &Proto
	sattr.Amap["ADDR"] = &vAddr

	/*
		XXX(tehnerd): real's port right now is equal to vip's but again it's trivial to fix
		for example in param map you could override amap["PORT"]
	*/
	rattr.Amap["ADDR_FAMILY"] = &rAF
	rattr.Amap["PORT"] = &Port
	rattr.Amap["ADDR"] = &rAddr

	for k, v := range amap {
		rattr.Amap[k] = v
	}
	msg.AttrMap["SERVICE"] = &sattr
	msg.AttrMap["DEST"] = &rattr
	ipvs.Sock.Execute(msg)

}

func (ipvs *IpvsClient) AddDest(vip string, port uint16, rip string,
	protocol uint16, weight int32) {
	paramsMap := make(map[string]SerDes)
	Weight := I32Type(weight)
	//XXX(tehnerd): hardcode, but easy to fix; 2 - tunneling
	FWDMethod := U32Type(2)
	LThresh := U32Type(0)
	UThresh := U32Type(0)
	paramsMap["WEIGHT"] = &Weight
	paramsMap["FWD_METHOD"] = &FWDMethod
	paramsMap["L_THRESH"] = &LThresh
	paramsMap["U_THRESH"] = &UThresh
	ipvs.modifyDest("NEW_DEST", vip, port, rip, protocol, paramsMap)
}

func (ipvs *IpvsClient) UpdateDest(vip string, port uint16, rip string,
	protocol uint16, weight int32) {
	paramsMap := make(map[string]SerDes)
	Weight := I32Type(weight)
	//XXX(tehnerd): hardcode, but easy to fix; 2 - tunneling
	FWDMethod := U32Type(2)
	LThresh := U32Type(0)
	UThresh := U32Type(0)
	paramsMap["WEIGHT"] = &Weight
	paramsMap["FWD_METHOD"] = &FWDMethod
	paramsMap["L_THRESH"] = &LThresh
	paramsMap["U_THRESH"] = &UThresh
	ipvs.modifyDest("SET_DEST", vip, port, rip, protocol, paramsMap)
}

func (ipvs *IpvsClient) DelDest(vip string, port uint16, rip string,
	protocol uint16) {
	ipvs.modifyDest("DEL_DEST", vip, port, rip, protocol, nil)
}

func (ipvs *IpvsClient) modifyFWMDest(method string, fwmark uint32,
	rip string, vaf uint16, port uint16, amap map[string]SerDes) {
	//starts with r - for real's related, v - for vip's
	raf, raddr := toAFUnion(rip)
	msg := ipvs.mt.InitGNLMessageStr(method, ACK_REQUEST)

	vAF := U16Type(vaf)

	rAF := U16Type(raf)
	rAddr := BinaryType(raddr)
	Port := Net16Type(port)

	FWMark := U32Type(fwmark)

	vatl, _ := ATLName2ATL["IpvsServiceAttrList"]
	ratl, _ := ATLName2ATL["IpvsDestAttrList"]

	sattr := CreateAttrListType(vatl)
	rattr := CreateAttrListType(ratl)

	sattr.Amap["FWMARK"] = &FWMark
	sattr.Amap["AF"] = &vAF

	rattr.Amap["ADDR_FAMILY"] = &rAF
	rattr.Amap["ADDR"] = &rAddr
	rattr.Amap["PORT"] = &Port

	for k, v := range amap {
		rattr.Amap[k] = v
	}
	msg.AttrMap["SERVICE"] = &sattr
	msg.AttrMap["DEST"] = &rattr
	ipvs.Sock.Execute(msg)

}

/*
func (ipvs *IpvsClient) modifyFWMDest(method string, fwmark uint32,
	rip string, vaf uint16, port uint16, amap map[string]SerDes) {

*/
func (ipvs *IpvsClient) AddFWMDest(fwmark uint32, rip string, vaf uint16,
	port uint16, weight int32) {
	paramsMap := make(map[string]SerDes)
	Weight := I32Type(weight)
	//XXX(tehnerd): hardcode, but easy to fix; 2 - tunneling
	FWDMethod := U32Type(2)
	LThresh := U32Type(0)
	UThresh := U32Type(0)
	paramsMap["WEIGHT"] = &Weight
	paramsMap["FWD_METHOD"] = &FWDMethod
	paramsMap["L_THRESH"] = &LThresh
	paramsMap["U_THRESH"] = &UThresh
	ipvs.modifyFWMDest("NEW_DEST", fwmark, rip, vaf, port, paramsMap)
}

func (ipvs *IpvsClient) UpdateFWMDest(fwmark uint32, rip string, vaf uint16,
	port uint16, weight int32) {
	paramsMap := make(map[string]SerDes)
	Weight := I32Type(weight)
	//XXX(tehnerd): hardcode, but easy to fix; 2 - tunneling
	FWDMethod := U32Type(2)
	LThresh := U32Type(0)
	UThresh := U32Type(0)
	paramsMap["WEIGHT"] = &Weight
	paramsMap["FWD_METHOD"] = &FWDMethod
	paramsMap["L_THRESH"] = &LThresh
	paramsMap["U_THRESH"] = &UThresh
	ipvs.modifyFWMDest("SET_DEST", fwmark, rip, vaf, port, paramsMap)
}

func (ipvs *IpvsClient) DelFWMDest(fwmark uint32, rip string, vaf uint16,
	port uint16) {
	ipvs.modifyFWMDest("DEL_DEST", fwmark, rip, vaf, port, nil)
}

func (ipvs *IpvsClient) Exit() {
	ipvs.Sock.Close()
}
