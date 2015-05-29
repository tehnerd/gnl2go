package gnl2go

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"syscall"
)

const (
	REQUEST   = 1
	MULTI     = 2
	ACK       = 4
	ECHO      = 8
	DUMP_INTR = 16

	ROOT   = 0x100
	MATCH  = 0x200
	ATOMIC = 0x400
	DUMP   = (ROOT | MATCH)

	REPLACE = 0x100
	EXCL    = 0x200
	CREATE  = 0x400
	APPEND  = 0x800

	ACK_REQUEST        = (REQUEST | ACK)
	MATCH_ROOT_REQUEST = (MATCH | ROOT | REQUEST)
)

/* from gnlpy:
# In order to discover family IDs, we'll need to exchange some Ctrl
# messages with the kernel.  We declare these message types and attribute
# list types below.
*/

var (
	CtrlOpsAttrList = CreateAttrListDefinition("CtrlOpsAttrList",
		[]AttrTuple{
			AttrTuple{Name: "ID", Type: "U32Type"},
			AttrTuple{Name: "FLAGS", Type: "U32Type"},
		})

	CtrlMcastGroupAttrList = CreateAttrListDefinition("CtrlMcastGroupAttrList",
		[]AttrTuple{
			AttrTuple{Name: "NAME", Type: "NulStringType"},
			AttrTuple{Name: "ID", Type: "U32Type"},
		})

	CtrlAttrList = CreateAttrListDefinition("CtrlAttrList",
		[]AttrTuple{
			AttrTuple{Name: "FAMILY_ID", Type: "U16Type"},
			AttrTuple{Name: "FAMILY_NAME", Type: "NulStringType"},
			AttrTuple{Name: "VERSION", Type: "U32Type"},
			AttrTuple{Name: "HDRSIZE", Type: "U32Type"},
			AttrTuple{Name: "MAXATTR", Type: "U32Type"},
			AttrTuple{Name: "OPS", Type: "IgnoreType"},
			AttrTuple{Name: "MCAST_GROUPS", Type: "CtrlMcastGroupAttrList"},
		})

	NoneAttrList = []AttrTuple{}

	CtrlMessageInitList = []AttrListTuple{
		AttrListTuple{Name: "NEWFAMILY", AttrList: CreateAttrListType(CtrlAttrList)},
		AttrListTuple{Name: "DELFAMILY", AttrList: CreateAttrListType(NoneAttrList)},
		AttrListTuple{Name: "GETFAMILY", AttrList: CreateAttrListType(CtrlAttrList)},
		AttrListTuple{Name: "NEWOPS", AttrList: CreateAttrListType(NoneAttrList)},
		AttrListTuple{Name: "DELOPS", AttrList: CreateAttrListType(NoneAttrList)},
		AttrListTuple{Name: "GETOPS", AttrList: CreateAttrListType(NoneAttrList)},
		AttrListTuple{Name: "NEWMCAST_GRP", AttrList: CreateAttrListType(NoneAttrList)},
		AttrListTuple{Name: "DELMCAST_GRP", AttrList: CreateAttrListType(NoneAttrList)},
		AttrListTuple{Name: "GETMCAST_GRP", AttrList: CreateAttrListType(NoneAttrList)},
	}
	ErrorMessageInitList = []AttrListTuple{}
	DoneMessageInitList  = []AttrListTuple{}
	CtrlMessage          = CreateMsgType(CtrlMessageInitList, 16)
	ErrorMessage         = CreateMsgType(ErrorMessageInitList, 2)
	DoneMessage          = CreateMsgType(DoneMessageInitList, 3)
)

const (
	ControlMessageType = 16
	ErrorMessageType   = 2
	DoneMessageType    = 3
)

/*
Global map witch maps family_id to MessageType
Used for decoding/deserializing of incoming nl msgs
*/

var (
	Family2MT       = make(map[uint16]*MessageType)
	LookupOnStartup = make(map[string][]AttrListTuple)
	MT2Family       = make(map[string]uint16)
	ATLName2ATL     = make(map[string][]AttrTuple)
)

type SerDes interface {
	Serialize() []byte
	Deserialize([]byte)
	Val()
}

type U8Type uint8

func (u8 *U8Type) Serialize() []byte {
	writer := new(bytes.Buffer)
	err := binary.Write(writer, binary.LittleEndian, u8)
	if err != nil {
		return nil
	}
	return writer.Bytes()
}

func (u8 *U8Type) Deserialize(buf []byte) {
	reader := bytes.NewReader(buf)
	err := binary.Read(reader, binary.LittleEndian, u8)
	if err != nil {
		panic("error during binary reading")
	}
}

func (u8 *U8Type) Val() {
	fmt.Println(uint8(*u8))
}

type U16Type uint16

func (u16 *U16Type) Serialize() []byte {
	writer := new(bytes.Buffer)
	err := binary.Write(writer, binary.LittleEndian, u16)
	if err != nil {
		return nil
	}
	return writer.Bytes()
}
func (u16 *U16Type) Deserialize(buf []byte) {
	reader := bytes.NewReader(buf)
	err := binary.Read(reader, binary.LittleEndian, u16)
	if err != nil {
		panic("error during binary reading")
	}
}

func (u16 *U16Type) Val() {
	fmt.Println(uint16(*u16))
}

type U32Type uint32

func (u32 *U32Type) Serialize() []byte {
	writer := new(bytes.Buffer)
	err := binary.Write(writer, binary.LittleEndian, u32)
	if err != nil {
		return nil
	}
	return writer.Bytes()
}

func (u32 *U32Type) Deserialize(buf []byte) {
	reader := bytes.NewReader(buf)
	err := binary.Read(reader, binary.LittleEndian, u32)
	if err != nil {
		panic("error during binary reading")
	}
}

func (u32 *U32Type) Val() {
	fmt.Println(uint32(*u32))
}

type I32Type int32

func (i32 *I32Type) Serialize() []byte {
	writer := new(bytes.Buffer)
	err := binary.Write(writer, binary.LittleEndian, i32)
	if err != nil {
		return nil
	}
	return writer.Bytes()
}

func (i32 *I32Type) Deserialize(buf []byte) {
	reader := bytes.NewReader(buf)
	err := binary.Read(reader, binary.LittleEndian, i32)
	if err != nil {
		panic("error during binary reading")
	}
}

func (i32 *I32Type) Val() {
	fmt.Println(int32(*i32))
}

type U64Type uint64

func (u64 *U64Type) Serialize() []byte {
	writer := new(bytes.Buffer)
	err := binary.Write(writer, binary.LittleEndian, u64)
	if err != nil {
		return nil
	}
	return writer.Bytes()
}

func (u64 *U64Type) Deserialize(buf []byte) {
	reader := bytes.NewReader(buf)
	err := binary.Read(reader, binary.LittleEndian, u64)
	if err != nil {
		panic("error during binary reading")
	}
}

func (u64 *U64Type) Val() {
	fmt.Println(uint64(*u64))
}

type Net16Type uint16

func (n16 *Net16Type) Serialize() []byte {
	writer := new(bytes.Buffer)
	err := binary.Write(writer, binary.BigEndian, n16)
	if err != nil {
		return nil
	}
	return writer.Bytes()
}

func (n16 *Net16Type) Deserialize(buf []byte) {
	reader := bytes.NewReader(buf)
	err := binary.Read(reader, binary.BigEndian, n16)
	if err != nil {
		panic("error during binary reading")
	}
}

func (n16 *Net16Type) Val() {
	fmt.Println(uint16(*n16))
}

type Net32Type uint32

func (n32 *Net32Type) Serialize() []byte {
	writer := new(bytes.Buffer)
	err := binary.Write(writer, binary.BigEndian, n32)
	if err != nil {
		return nil
	}
	return writer.Bytes()
}

func (n32 *Net32Type) Deserialize(buf []byte) {
	reader := bytes.NewReader(buf)
	err := binary.Read(reader, binary.BigEndian, n32)
	if err != nil {
		panic("error during binary reading")
	}
}

func (n32 *Net32Type) Val() {
	fmt.Println(uint32(*n32))
}

type NulStringType string

func (ns NulStringType) Serialize() []byte {
	return append([]byte(ns), 0)
}

func (ns *NulStringType) Deserialize(buf []byte) {
	if buf[len(buf)-1] != 0 {
		panic("non 0 terminated string")
	}
	s := string(buf[:len(buf)-1])
	*ns = NulStringType(s)
}

func (ns *NulStringType) Val() {
	fmt.Println(string(*ns))
}

type IgnoreType bool

func (it *IgnoreType) Serialize() []byte {
	return nil
}

func (it *IgnoreType) Deserialize(buf []byte) {
}

func (it *IgnoreType) Val() {
	fmt.Println("ignore type")
}

type BinaryType []byte

func (bt *BinaryType) Serialize() []byte {
	return []byte(*bt)
}

func (bt *BinaryType) Deserialize(buf []byte) {
	*bt = BinaryType(buf)
}

func (bt *BinaryType) Val() {
	fmt.Println(*bt)
}

type AttrTuple struct {
	Name string
	Type string
}

type AttrHdr struct {
	Len uint16
	Num uint16
}

type AttrListType struct {
	Key2name map[int]string
	Name2key map[string]int
	Key2Type map[int]string
	Amap     map[string]SerDes
}

func CreateAttrListDefinition(listName string, atl []AttrTuple) []AttrTuple {
	ATLName2ATL[listName] = atl
	return atl
}

func CreateAttrListType(attrListMap []AttrTuple) AttrListType {
	al := new(AttrListType)
	al.Key2name = make(map[int]string)
	al.Name2key = make(map[string]int)
	al.Key2Type = make(map[int]string)
	al.Amap = make(map[string]SerDes)
	for i, attr := range attrListMap {
		key := i + 1
		al.Key2name[key] = attr.Name
		al.Key2Type[key] = attr.Type
		al.Name2key[attr.Name] = key
	}
	return *al
}

func (al *AttrListType) Set(amap map[string]SerDes) {
	al.Amap = amap
}

func (al *AttrListType) Serialize() []byte {
	buf := make([]byte, 0)
	pad := make([]byte, 4)
	for attrType, attrData := range al.Amap {
		if attrNum, exists := al.Name2key[attrType]; !exists {
			fmt.Printf("name2key: %#v\n", al.Name2key)
			fmt.Println("attr type which doesnt  exist: ", attrType)
			panic("err. amap and attrList are incompatible. No type in name2key")
		} else {
			data := attrData.Serialize()
			attrLen := AttrHdr{Len: uint16(len(data) + 4), Num: uint16(attrNum)}
			attrBuf := new(bytes.Buffer)
			err := binary.Write(attrBuf, binary.LittleEndian, attrLen)
			if err != nil {
				panic("cant encode attr len")
			}
			/*
				TODO(tehnerd): lots of padding hack's translated from gnlpy as is.
				prob one day gonna read more about it.
			*/
			buf = append(buf, attrBuf.Bytes()...)
			buf = append(buf, data...)
			padLen := (4 - (len(data) % 4)) & 0x3
			if padLen > 4 {
				panic("error in pad len calc")
			}
			buf = append(buf, pad[:padLen]...)
		}
	}
	return buf
}

func DeserializeSerDes(serdesType string, list []byte) SerDes {
	switch serdesType {
	case "U8Type":
		attr := new(U8Type)
		attr.Deserialize(list)
		return attr
	case "U16Type":
		attr := new(U16Type)
		attr.Deserialize(list)
		return attr
	case "U32Type":
		attr := new(U32Type)
		attr.Deserialize(list)
		return attr
	case "U64Type":
		attr := new(U64Type)
		attr.Deserialize(list)
		return attr
	case "I32Type":
		attr := new(I32Type)
		attr.Deserialize(list)
		return attr
	case "Net16Type":
		attr := new(Net16Type)
		attr.Deserialize(list)
		return attr
	case "Net32Type":
		attr := new(Net32Type)
		attr.Deserialize(list)
		return attr
	case "NulStringType":
		attr := new(NulStringType)
		attr.Deserialize(list)
		return attr
	case "IgnoreType":
		attr := new(IgnoreType)
		return attr
	case "BinaryType":
		attr := new(BinaryType)
		attr.Deserialize(list)
		return attr
	/*
		XXX(tehnerd): dangerous assumption that we either have basic types (above) or it's
		a nested attribute's list. havent tested in prod yet
	*/
	default:
		atl, exists := ATLName2ATL[serdesType]
		if !exists {
			fmt.Println("serdes doesnt exists. type: ", serdesType)
		}
		attr := CreateAttrListType(atl)
		attr.Deserialize(list)
		return &attr
	}
	return nil
}

func (al *AttrListType) Deserialize(list []byte) {
	al.Amap = make(map[string]SerDes)
	var attrHdr AttrHdr
	for len(list) > 0 {
		err := binary.Read(bytes.NewReader(list), binary.LittleEndian, &attrHdr)
		if err != nil {
			fmt.Println(err)
			panic("cant read attr header for deserialization")
		}
		//XXX(tehnerd): again fb's hacks
		attrHdr.Len = attrHdr.Len & 0x7fff
		//TODO(tehnerd): no support for "RecursiveSelf" as for now
		fieldType, exists := al.Key2Type[int(attrHdr.Num)]
		if !exists {
			list = list[(int(attrHdr.Len+3) & (^3)):]
			//TODO(tehnerd): hack. had panics on ipvs's PE_NAME
			continue
			fmt.Printf("attr hdr is: %#v\n", attrHdr)
			fmt.Printf("Key2Type is: %#v\n", al.Key2Type)
			panic("msg and attrList incompatible")
		}
		fieldName := al.Key2name[int(attrHdr.Num)]
		al.Amap[fieldName] = DeserializeSerDes(fieldType, list[4:attrHdr.Len])
		list = list[(int(attrHdr.Len+3) & (^3)):]
	}
}

func (al *AttrListType) Val() {
	for k, v := range al.Amap {
		fmt.Println(k)
		v.Val()
	}
}

type MessageType struct {
	Name2key         map[string]int
	Key2name         map[int]string
	Key2attrListType map[int]AttrListType
	Family           uint16
}

type AttrListTuple struct {
	Name     string
	AttrList AttrListType
}

func CreateMsgType(alist []AttrListTuple, familyId uint16) MessageType {
	if v, exists := Family2MT[familyId]; exists {
		return *v
	}
	var mt MessageType
	mt.InitMessageType(alist, familyId)
	Family2MT[familyId] = &mt
	return mt
}

func LookupTypeOnStartup(alist []AttrListTuple, familyName string) {
	LookupOnStartup[familyName] = alist
}

func (mt *MessageType) InitMessageType(alist []AttrListTuple, familyId uint16) {
	mt.Name2key = make(map[string]int)
	mt.Key2name = make(map[int]string)
	mt.Key2attrListType = make(map[int]AttrListType)
	mt.Family = familyId
	for i, attrTyple := range alist {
		key := i + 1
		mt.Name2key[attrTyple.Name] = key
		mt.Key2name[key] = attrTyple.Name
		mt.Key2attrListType[key] = attrTyple.AttrList
	}

}

//GNL - generic netlink msg. NL msg contains NLmsgHdr + GNLMsg

type GNLMsgHdr struct {
	Cmnd    uint8
	Version uint8
}

type GNLMessage struct {
	Hdr     GNLMsgHdr
	AttrMap map[string]SerDes
	Family  uint16
	Flags   uint16
	MT      *MessageType
}

func (msg *GNLMessage) Init(hdr GNLMsgHdr, amap map[string]SerDes,
	family, flags uint16) {
	msg.Hdr = hdr
	msg.AttrMap = amap
	msg.Family = family
	msg.Flags = flags
}

func (mt *MessageType) InitGNLMessageStr(cmnd string, flags uint16) GNLMessage {
	var gnlMsg GNLMessage
	cmndId, exists := mt.Name2key[cmnd]
	if !exists {
		fmt.Printf("cmnd with name %s doesnt exists\n", cmnd)
		panic("no such cmnd")
	}
	amap := make(map[string]SerDes)
	gnlMsg.Init(GNLMsgHdr{Cmnd: uint8(cmndId), Version: 1},
		amap,
		mt.Family,
		flags)
	gnlMsg.MT = mt
	return gnlMsg
}

func (msg *GNLMessage) GetAttrList(name string) SerDes {
	return msg.AttrMap[name]
}

func (msg *GNLMessage) SetAttrList(name string, val SerDes) {
	msg.AttrMap[name] = val
}

func (mt *MessageType) SerializeGNLMsg(msg GNLMessage) []byte {
	sMsg := make([]byte, 0)
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, msg.Hdr)
	if err != nil {
		fmt.Println(err)
		panic("cant serialize msg hdr")
	}
	sMsg = append(sMsg, buf.Bytes()...)
	//padding
	sMsg = append(sMsg, []byte{0, 0}...)
	if v, exists := mt.Key2attrListType[int(msg.Hdr.Cmnd)]; !exists {
		fmt.Printf("no existing cmnd in %#v\n", msg.Hdr)
		panic("no such cmnd in key2attrlist dict")
	} else {
		v.Set(msg.AttrMap)
		sMsg = append(sMsg, v.Serialize()...)
	}
	return sMsg
}

func (mt *MessageType) DeserializeGNLMsg(sMsg []byte) GNLMessage {
	var msgHdr GNLMsgHdr
	err := binary.Read(bytes.NewReader(sMsg), binary.LittleEndian, &msgHdr)
	if err != nil {
		fmt.Println(err)
		panic("cant read(deserialize) msg hdr")
	}
	v, exists := mt.Key2attrListType[int(msgHdr.Cmnd)]
	if !exists {
		fmt.Printf("messageType is : %#v\n", mt)
		fmt.Printf("non existing cmnd: %#v\n", msgHdr)
		fmt.Printf("key2attr list: %#v\n", mt.Key2attrListType)
		panic("no such cmnd in key2attrlist dict")
	}
	v.Deserialize(sMsg[4:])
	var msg GNLMessage
	msg.Init(msgHdr, v.Amap, 1, ACK_REQUEST)
	return msg
}

type NLMsgHdr struct {
	TotalLen uint32
	Family   uint16
	Flags    uint16
	Seq      uint32
	PortID   uint32
}

func SerializeNLMsg(mt *MessageType, msg GNLMessage, portId, Seq uint32) []byte {
	nlMsg := make([]byte, 0)
	payload := mt.SerializeGNLMsg(msg)
	nlHdr := NLMsgHdr{
		TotalLen: uint32(len(payload) + 16),
		Family:   msg.Family,
		Flags:    msg.Flags,
		Seq:      Seq,
		PortID:   portId}
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, nlHdr)
	if err != nil {
		fmt.Println(err)
		panic("cant serialize nl msg hdr")
	}
	nlMsg = append(nlMsg, buf.Bytes()...)
	nlMsg = append(nlMsg, payload...)
	return nlMsg
}

func DeserializeNLMsg(sMsg []byte) (GNLMessage, []byte) {
	var nlHdr NLMsgHdr
	err := binary.Read(bytes.NewReader(sMsg), binary.LittleEndian, &nlHdr)
	if err != nil {
		fmt.Println(err)
		panic("cant deserialize nl msg hdr")
	}
	mt, exists := Family2MT[nlHdr.Family]
	if !exists {
		fmt.Printf("hdr is: %#v\n", nlHdr)
		panic("msg with such family doesn exist in mType dict")
	}
	if nlHdr.Family == ErrorMessageType {
		var ErrorCode int32
		binary.Read(bytes.NewReader(sMsg[16:]), binary.LittleEndian, &ErrorCode)
		if ErrorCode != 0 {
			fmt.Println("ErrorCode is: ", -ErrorCode)
			if len(sMsg) > 20 {
				emsg, _ := DeserializeNLMsg(sMsg[20:])
				fmt.Printf("%#v\n", emsg)
			}
			panic("recved error msg")
		} else {
			return GNLMessage{}, nil
		}
	} else if nlHdr.Family == DoneMessageType {
		var msg GNLMessage
		msg.Family = nlHdr.Family
		msg.Flags = nlHdr.Flags
		return msg, nil
	}
	msg := mt.DeserializeGNLMsg(sMsg[16:])
	msg.Family = nlHdr.Family
	msg.Flags = nlHdr.Flags
	return msg, sMsg[nlHdr.TotalLen:]

}

type NLSocket struct {
	Sd      int
	Seq     uint32
	PortID  uint32
	Lock    *sync.Mutex
	Verbose bool
}

func (nlSock *NLSocket) Init() {
	//16 - NETLINK_GENERIC
	sd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, 16)
	if err != nil {
		panic("cant create netlink socket")
	}
	pid := uint32(syscall.Getpid())
	sa := &syscall.SockaddrNetlink{
		Pid:    pid,
		Groups: 0,
		Family: syscall.AF_NETLINK}
	if err = syscall.Bind(sd, sa); err != nil {
		panic("cant bind to netlink socket")
	}
	nlSock.Lock = new(sync.Mutex)
	nlSock.Sd = sd
	nlSock.Seq = 0
	nlSock.PortID = pid
	for k, v := range LookupOnStartup {
		familyId := nlSock.ResolveFamily(NulStringType(k))
		CreateMsgType(v, uint16(*familyId))
		MT2Family[k] = uint16(*familyId)
	}
}

func (nlSock *NLSocket) Close() {
	syscall.Close(nlSock.Sd)
}

func (nlSock *NLSocket) ResolveFamily(family NulStringType) *U16Type {
	gnlMsg := CtrlMessage.InitGNLMessageStr("GETFAMILY", REQUEST)
	gnlMsg.SetAttrList("FAMILY_NAME", &family)
	reply := nlSock.Query(gnlMsg)
	familyId := reply[0].GetAttrList("FAMILY_ID")
	//wea re going to panic if it's  not U16Type
	return familyId.(*U16Type)
}

func (nlSock *NLSocket) Query(msg GNLMessage) []GNLMessage {
	nlSock.Lock.Lock()
	defer nlSock.Lock.Unlock()
	nlSock.send(msg)
	resp := nlSock.recv()
	return resp
}

func (nlSock *NLSocket) send(msg GNLMessage) {
	data := SerializeNLMsg(msg.MT, msg, nlSock.PortID, nlSock.Seq)
	nlSock.Seq += 1
	lsa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	err := syscall.Sendto(nlSock.Sd, data, 0, lsa)
	if err != nil {
		fmt.Println(err)
		panic("cant send to netlink socket")
	}
}

func (nlSock *NLSocket) recv() []GNLMessage {
	buff := make([]byte, 16384)
	var msgsList []GNLMessage
	for {
		//TODO(tehnerd): nonblocking(so we could loop around it), if 16384 wont be enough
		n, _, err := syscall.Recvfrom(nlSock.Sd, buff, 0)
		if err != nil {
			fmt.Println(err)
			panic("cand read from socket")
		}
		resp := buff[:n]
		for len(resp) > 0 {
			rmsg, data := DeserializeNLMsg(resp)
			if len(msgsList) == 0 && rmsg.Flags&0x2 == 0 {
				return []GNLMessage{rmsg}
			} else if rmsg.Family == DoneMessageType {
				return msgsList
			}
			msgsList = append(msgsList, rmsg)
			resp = data
		}

	}
	return msgsList
}

func (nlSock *NLSocket) Execute(msg GNLMessage) {
	nlSock.Lock.Lock()
	defer nlSock.Lock.Unlock()
	nlSock.send(msg)
	resp := nlSock.recv()
	if len(resp) != 1 {
		panic("we dont expect more than one msg in response")
	}
	if resp[0].Family == ErrorMessageType {
		panic("error in response of execution")
	}
}
