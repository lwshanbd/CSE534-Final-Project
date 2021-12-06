package shadowsocks

import (
	"CSE534Project/logger"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	AddrMask byte = 0xf
)

type Reader struct {
	rc        *Cipher
	readBuf   []byte
	readNonce []byte
	leftover  []byte
}

type Writer struct {
	wc         *Cipher
	writeBuf   []byte
	writeNonce []byte
}

type Conn struct {
	net.Conn
	Reader
	Writer
}

func NewConn(c net.Conn, cipher *Cipher) *Conn {
	rc := cipher
	rcCopy := *rc
	wc := &rcCopy
	return &Conn{
		Conn: c,
		Reader: Reader{
			readBuf: leakyBuf.Get(),
			rc:      rc,
		},
		Writer: Writer{
			writeBuf: leakyBuf.Get(),
			wc:       wc,
		},
	}
}

func (c *Conn) Close() error {
	leakyBuf.Put(c.readBuf)
	leakyBuf.Put(c.writeBuf)
	return c.Conn.Close()
}

func RawAddr(addr string) (buf []byte, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: address error %s %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: invalid port %s", addr)
	}

	hostLen := len(host)
	l := 1 + 1 + hostLen + 2 // addrType + lenByte + address + port
	buf = make([]byte, l)
	buf[0] = 3             // 3 means the address is domain name
	buf[1] = byte(hostLen) // host address length  followed by host address
	copy(buf[2:], host)
	binary.BigEndian.PutUint16(buf[2+hostLen:2+hostLen+2], uint16(port))
	return
}

// DialWithRawAddr is intended for use by users implementing a local socks proxy.
// rawaddr shoud contain part of the data in socks request, starting from the
// ATYP field. (Refer to rfc1928 for more information.)
func DialWithRawAddr(rawaddr []byte, server string, cipher *Cipher) (c *Conn, err error) {
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return
	}
	c = NewConn(conn, cipher)
	if _, err = c.Write(rawaddr); err != nil {
		c.Close()
		return nil, err
	}
	return
}

// Dial: addr should be in the form of host:port
func Dial(addr, server string, cipher *Cipher) (c *Conn, err error) {
	ra, err := RawAddr(addr)
	if err != nil {
		return
	}
	return DialWithRawAddr(ra, server, cipher)
}

const payloadSizeMask = 0x3FFF

func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

func (c *Conn) InitReader() (err error) {
	salt := make([]byte, c.rc.SaltSize())
	if _, err = io.ReadFull(c.Conn, salt); err != nil {
		return
	}
	if CheckSalt(salt) {
		err = errors.New("repeated salt detected")
		logger.Info.Println("Fake IP:", c.RemoteAddr())
		return
	}

	if err = c.rc.InitCipher(salt); err != nil {
		return
	}
	//fmt.Printf("waiting for Payload sz= %d\n", salt)
	c.readNonce = make([]byte, c.rc.NonceSize())
	return
}

func (c *Conn) InitWriter() error {
	salt := make([]byte, c.wc.SaltSize())
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	if err := c.wc.InitCipher(salt); err != nil {
		return err
	}
	c.writeNonce = make([]byte, c.wc.NonceSize())
	_, err := c.Conn.Write(salt)
	AddSalt(salt)
	if err != nil {
		return err
	}

	return nil
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.rc.AEAD == nil {
		err = c.InitReader()
		if err != nil {
			return 0, err
		}
		// fmt.Println("Conn Initialized")
	}

	bufsz := len(b)
	if nleft := len(c.leftover); nleft > 0 {
		ncopy := min(nleft, bufsz)
		copy(b, c.leftover[:ncopy])
		c.leftover = c.leftover[ncopy:]
		return ncopy, nil
	}

	// decrypt payload size
	buf := c.readBuf[:2+c.rc.Overhead()+8]
	//fmt.Println("waiting for SZ")
	_, err = io.ReadFull(c.Conn, buf)
	if err != nil {
		return 0, err
	}

	_, err = c.rc.Open(buf[:0], c.readNonce, buf, nil)
	increment(c.readNonce)
	if err != nil {
		return 0, err
	}

	tmp_times := make([]byte, 8)
	for i := 0; i < 8; i++ {
		tmp_times[i] = buf[i]
	}
	time_stamps := int64(binary.LittleEndian.Uint64(tmp_times))

	if CheckTimestamp(time_stamps) {
		fmt.Printf("time stamp error%d\n", time_stamps)
		logger.Info.Println("Fake IP:", c.RemoteAddr())
		err = errors.New("time stamp error")
		return 0, err
	}

	size := (int(buf[8])<<8 + int(buf[9])) & payloadSizeMask
	// decrypt payload
	buf = c.readBuf[:size+c.rc.Overhead()]

	_, err = io.ReadFull(c.Conn, buf)
	if err != nil {
		return 0, err
	}
	_, err = c.rc.Open(buf[:0], c.readNonce, buf, nil)
	increment(c.readNonce)
	if err != nil {
		return 0, err
	}

	if size > len(b) {
		copy(b, buf[:len(b)])
		c.leftover = make([]byte, size-len(b))
		copy(c.leftover, buf[len(b):size])
		n = len(b)
	} else {
		copy(b, buf[:size])
		n = size
	}
	//fmt.Println("Done")
	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.wc.AEAD == nil {
		err = c.InitWriter()
		if err != nil {
			return
		}
	}
	total := len(b)
	offset := 0
	for total > 0 {
		nr := min(payloadSizeMask, total)
		ubuf := b[offset : offset+nr]

		currentTime := time.Now().UTC().Unix()
		tmp_time := make([]byte, 8)
		binary.LittleEndian.PutUint64(tmp_time, uint64(currentTime))
		offset += nr
		total -= nr
		encMsgSz := 2 + c.wc.Overhead() + nr + c.wc.Overhead() + 8
		buf := c.writeBuf[:encMsgSz]
		for i := 0; i < 8; i++ {
			buf[i] = tmp_time[i]
		}
		buf[8], buf[9] = byte(nr>>8), byte(nr) // big-endian payload size

		buf = c.wc.Seal(buf[:0], c.writeNonce, buf[:10], nil)

		buf = buf[8+2+c.wc.Overhead() : encMsgSz]

		copy(buf, ubuf)
		increment(c.writeNonce)
		c.wc.Seal(buf[:0], c.writeNonce, buf[:nr], nil)
		increment(c.writeNonce)

		n, err = c.Conn.Write(c.writeBuf[:encMsgSz])

		if err != nil {
			return
		}

	}

	return len(b), nil
}
