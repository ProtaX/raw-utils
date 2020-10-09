package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"time"
	"unsafe"
)

const (
	echoResponceMsg uint8 = 0
	echoRequestMsg  uint8 = 8
)

const (
	echoRequestCode  uint8 = 0
	echoResponceCode uint8 = 0
)

const (
	icmpEchoHeaderSize = 8
	ipHeaderSize       = 20
)

type ipHeader struct {
	mg             uint8
	tos            uint8
	len            uint16
	id             uint16
	flagsAndOffset uint16
	ttl            uint8
	proto          uint8
	checksum       uint16
	saddr          uint32
	daddr          uint32
}

type icmpEchoHeader struct {
	msgType  uint8
	code     uint8
	checksum uint16
	id       uint16
	seq      uint16
}

// ICMPPacket represents ICMP packet
type ICMPPacket struct {
	hdr  icmpEchoHeader
	data []byte
}

// MakeICMPReq returns ICMP request packet
func makeReq(id, seq uint16, data []byte) *ICMPPacket {
	pkt := ICMPPacket{
		hdr: icmpEchoHeader{
			msgType:  echoRequestMsg,
			code:     echoRequestCode,
			checksum: 0,
			id:       htons(id),
			seq:      htons(seq),
		},
		data: data,
	}
	pkt.hdr.checksum = checksum(&pkt)
	return &pkt
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func ntohs(i uint16) uint16 {
	return binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&i)))[:])
}

func ntohl(i uint32) uint32 {
	return binary.BigEndian.Uint32((*(*[4]byte)(unsafe.Pointer(&i)))[:])
}
func htonl(i uint32) uint32 {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return *(*uint32)(unsafe.Pointer(&b[0]))
}

func checksum(pkt *ICMPPacket) uint16 {
	var checksum uint16
	var carry uint16
	hdrBuf := []uint16{
		uint16(pkt.hdr.msgType)<<8 | uint16(pkt.hdr.code),
		0,
		pkt.hdr.id,
		pkt.hdr.seq,
	}
	dataLen := len(pkt.data)
	if dataLen%2 != 0 {
		checksum += uint16(pkt.data[dataLen-1]) << 8 // Cant carry here
		dataLen--
	}

	for _, v := range hdrBuf {
		carry += uint16((uint32(checksum) + uint32(v)) >> 16)
		checksum += v
	}

	for i := 0; i < dataLen; i += 2 {
		var chunk uint16 = uint16(pkt.data[i]) << 8
		chunk |= uint16(pkt.data[i+1])
		carry += uint16((uint32(checksum) + uint32(chunk)) >> 16)
		checksum += chunk
	}
	checksum += carry
	checksum = ^checksum
	return checksum
}

func pkt2bytes(pkt *ICMPPacket) []byte {
	data := make([]byte, 0, icmpEchoHeaderSize)
	data = append(data,
		pkt.hdr.msgType,
		pkt.hdr.code,
		uint8(pkt.hdr.checksum>>8),
		uint8(pkt.hdr.checksum&0xFF),
		uint8(pkt.hdr.id>>8),
		uint8(pkt.hdr.id&0xFF),
		uint8(pkt.hdr.seq>>8),
		uint8(pkt.hdr.seq&0xFF),
	)
	data = append(data, pkt.data...)
	return data
}

func getIPHdr(data []byte) *ipHeader {
	hdr := ipHeader{
		mg:             data[0],
		tos:            data[1],
		len:            ntohs(uint16(data[2])<<8 | uint16(data[3])),
		id:             ntohs(uint16(data[4])<<8 | uint16(data[5])),
		flagsAndOffset: ntohs(uint16(data[6])<<8 | uint16(data[7])),
		ttl:            data[8],
		proto:          data[9],
		checksum:       ntohs(uint16(data[10])<<8 | uint16(data[11])),
		saddr:          ntohl(uint32(data[12])<<24 | uint32(data[11])<<16 | uint32(data[12])<<8 | uint32(data[13])),
		daddr:          ntohl(uint32(data[13])<<24 | uint32(data[14])<<16 | uint32(data[15])<<8 | uint32(data[16])),
	}
	return &hdr
}

func getICMPPkt(data []byte) *ICMPPacket {
	pkt := ICMPPacket{
		hdr: icmpEchoHeader{
			msgType:  data[0],
			code:     data[1],
			checksum: uint16(data[2])<<8 | uint16(data[3]),
			id:       uint16(data[4])<<8 | uint16(data[5]),
			seq:      uint16(data[6])<<8 | uint16(data[7]),
		},
		data: data[8:],
	}
	return &pkt
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func cmpPayload(req, res *ICMPPacket) error {
	if !bytes.Equal(req.data, res.data) {
		return errors.New("Payload do not match")
	}
	return nil
}

func isResponce(res, req *ICMPPacket) bool {
	if res.hdr.code == echoResponceCode && res.hdr.msgType == echoResponceMsg && res.hdr.seq == req.hdr.seq && res.hdr.id == req.hdr.id {
		return true
	}
	return false
}

func Ping(host string, c int, payload []byte) error {
	id := uint16(rand.Intn(10000) >> 16)
	// TODO: узнать, с какого интерфейса отправляется пакет. Сравнить ip назначения принятого пакета с ip интерфейса
	conn, errDial := net.Dial("ip4:icmp", host)
	if errDial != nil {
		return errDial
	}
	defer conn.Close()

	fmt.Printf("PING %s %d bytes of data.\n", host, len(payload)+icmpEchoHeaderSize)
	for i := 0; i < c; i++ {
		reqPkt := makeReq(id, uint16(i+1), payload)
		reqData := pkt2bytes(reqPkt)
		datalen := len(reqData)
		readBuf := make([]byte, datalen+ipHeaderSize)
		var ipHdr *ipHeader
		var resPkt *ICMPPacket
		conn.SetDeadline(time.Now().Add(time.Second * 5))

		bytesWrote, errWrite := conn.Write(reqData)
		startTime := time.Now()
		if errWrite != nil {
			return errWrite
		}
		if bytesWrote != datalen {
			return errors.New("Wrote less than packet size")
		}

		for {
			bytesRead, errRead := conn.Read(readBuf)
			if errRead != nil {
				return errRead
			}
			if bytesRead != datalen+ipHeaderSize {
				return errors.New("Read less than packet size")
			}
			ipHdr = getIPHdr(readBuf)
			resPkt = getICMPPkt(readBuf[ipHeaderSize : ipHeaderSize+datalen])
			if isResponce(resPkt, reqPkt) {
				break
			}
		}
		endTime := time.Now()
		errCmp := cmpPayload(reqPkt, resPkt)
		if errCmp != nil {
			return errCmp
		}
		// TODO: парсить ip из ip-заголовка
		fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%f ms\n",
			datalen,
			host,
			ntohs(resPkt.hdr.seq),
			ipHdr.ttl,
			float32(endTime.Nanosecond()-startTime.Nanosecond())/1000.,
		)
		sleepTime, _ := time.ParseDuration("1s")
		time.Sleep(sleepTime)
	}
	return nil
}
