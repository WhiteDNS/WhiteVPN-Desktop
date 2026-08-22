package helper

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestDeleteLinkRequestIsWellFormed(t *testing.T) {
	msg := BuildDeleteLinkRequest(7, 0xFEED)
	if got := binary.LittleEndian.Uint32(msg[0:4]); got != uint32(len(msg)) {
		t.Fatalf("length field %d does not match message size %d", got, len(msg))
	}
	if type_ := binary.LittleEndian.Uint16(msg[4:6]); type_ != 17 {
		t.Fatalf("message type %d is not RTM_DELLINK", type_)
	}
	flags := binary.LittleEndian.Uint16(msg[6:8])
	if flags != nlmFRequest|nlmFAck {
		t.Fatalf("flags %#x must request an acknowledgement so failure is visible", flags)
	}
	if index := binary.LittleEndian.Uint32(msg[20:24]); index != 7 {
		t.Fatalf("interface index %d is not the one asked for", index)
	}
	if seq := binary.LittleEndian.Uint32(msg[8:12]); seq != 0xFEED {
		t.Fatalf("sequence %d is not echoed for matching replies", seq)
	}
}

func TestNetlinkAckParsing(t *testing.T) {
	ok := make([]byte, nlMsgHeaderSize+4)
	binary.LittleEndian.PutUint16(ok[4:6], 2)
	binary.LittleEndian.PutUint32(ok[16:20], 0)
	if err := NetlinkAckError(ok); err != nil {
		t.Fatalf("a zero errno ack means success, got %v", err)
	}

	failure := make([]byte, nlMsgHeaderSize+4)
	binary.LittleEndian.PutUint16(failure[4:6], 2)
	binary.LittleEndian.PutUint32(failure[16:20], 19) // ENODEV
	var errno *Errno
	err := NetlinkAckError(failure)
	if !errors.As(err, &errno) || errno.Code != 19 {
		t.Fatalf("a non-zero errno must surface its code, got %v", err)
	}

	if err := NetlinkAckError([]byte{1, 2, 3}); !errors.Is(err, ErrShortNetlinkReply) {
		t.Fatalf("short garbage must be refused, got %v", err)
	}

	notAck := make([]byte, nlMsgHeaderSize+4)
	binary.LittleEndian.PutUint16(notAck[4:6], 16) // some other message type
	if err := NetlinkAckError(notAck); !errors.Is(err, ErrUnexpectedNetlinkReply) {
		t.Fatalf("non-error replies are not acks, got %v", err)
	}
}

func TestBytesAreStable(t *testing.T) {
	want := []byte{
		32, 0, 0, 0, // length
		17, 0, // RTM_DELLINK
		5, 0, // REQUEST|ACK
		1, 0, 0, 0, // sequence 1
		0, 0, 0, 0, // kernel pid
		// ifinfomsg: family, pad, type
		0, 0, 0, 0,
		9, 0, 0, 0, // interface index 9
		0, 0, 0, 0, // flags
		0, 0, 0, 0, // change mask
	}
	got := BuildDeleteLinkRequest(9, 1)
	if !bytes.Equal(got, want) {
		t.Fatalf("the wire format moved:\n got %x\nwant %x", got, want)
	}
}
