package helper

import (
	"encoding/binary"
	"strconv"
)

// The one netlink message this app ever needs to build: RTM_DELLINK. Kept in a
// portable file so its bytes can be asserted from any development machine,
// while the socket that sends it stays on Linux.

const (
	rtmDeleteLink = 17 // unix.RTM_DELLINK
	nlmFRequest   = 1
	nlmFAck       = 4
)

// ifinfomsg is 16 bytes: family, pad, type, index, then four flag words.
const ifInfoMsgSize = 16

// nlMsgHeaderSize is sizeof(struct nlmsghdr).
const nlMsgHeaderSize = 16

// BuildDeleteLinkRequest marshals an RTM_DELLINK for one interface index.
//
// Little-endian is not universal for netlink (the kernel follows the host's
// byte order), but every architecture Go ships that runs systemd user sessions
// is little-endian; a big-endian builder would be dead code nobody can test.
func BuildDeleteLinkRequest(interfaceIndex int, sequence uint32) []byte {
	total := nlMsgHeaderSize + ifInfoMsgSize
	msg := make([]byte, total)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(total))
	binary.LittleEndian.PutUint16(msg[4:6], rtmDeleteLink)
	binary.LittleEndian.PutUint16(msg[6:8], nlmFRequest|nlmFAck)
	binary.LittleEndian.PutUint32(msg[8:12], sequence)
	// Kernel pid: 0 means "from userspace".
	binary.LittleEndian.PutUint32(msg[12:16], 0)

	// ifinfomsg: family AF_UNSPEC(0), pad 0, type 0, index, change mask 0.
	binary.LittleEndian.PutUint32(msg[nlMsgHeaderSize+4:nlMsgHeaderSize+8], uint32(interfaceIndex))
	return msg
}

// NetlinkError parses the errno out of an NLMSG_ERROR reply. Zero means the
// deletion was acknowledged.
func NetlinkAckError(reply []byte) error {
	if len(reply) < nlMsgHeaderSize+4 {
		return ErrShortNetlinkReply
	}
	if binary.LittleEndian.Uint16(reply[4:6]) != 2 { // NLMSG_ERROR
		return ErrUnexpectedNetlinkReply
	}
	code := int32(binary.LittleEndian.Uint32(reply[nlMsgHeaderSize : nlMsgHeaderSize+4]))
	if code == 0 {
		return nil
	}
	return &Errno{Code: code}
}

type Errno struct{ Code int32 }

func (e *Errno) Error() string { return "netlink error " + strconv.Itoa(int(e.Code)) }

var (
	ErrShortNetlinkReply      = &fixedError{"netlink reply too short"}
	ErrUnexpectedNetlinkReply = &fixedError{"netlink replied with something other than an ack"}
)

type fixedError struct{ text string }

func (e *fixedError) Error() string { return e.text }
