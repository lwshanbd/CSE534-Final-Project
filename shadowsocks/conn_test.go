package shadowsocks

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
)

func mustNewCipher(method string) *Cipher {
	const testPassword = "password"
	cipher, err := NewCipher(method, testPassword)

	if err != nil {
		panic(err)
	}
	return cipher
}

type transcriptConn struct {
	net.Conn
	ReadTranscript []byte
}

func (conn *transcriptConn) Read(p []byte) (int, error) {
	n, err := conn.Conn.Read(p)
	conn.ReadTranscript = append(conn.ReadTranscript, p[:n]...)
	return n, err
}

func connSalts(method string) (err error) {
	// underlying network connection
	clientConn, serverConn := net.Pipe()
	// make a transcript of bytes at the network level
	clientTranscriptConn := &transcriptConn{Conn: clientConn}
	serverTranscriptConn := &transcriptConn{Conn: serverConn}
	// connection at the ShadowSocks level
	clientSSConn := NewConn(clientTranscriptConn, mustNewCipher(method))
	serverSSConn := NewConn(serverTranscriptConn, mustNewCipher(method))

	clientToServerData := []byte("clientToServerData")
	serverToClientData := []byte("serverToClientData")

	go func() {
		defer serverSSConn.Close()
		for i := 0; i < 10; i++ {
			buf := make([]byte, len(clientToServerData))
			// read the client data
			sb := make([]byte, 5)
			nread := 0
			off := 0
			for nread < len(clientToServerData) {
				nn, err := serverSSConn.Read(sb)
				nread += nn
				copy(buf[off:off+nn], sb[:nn])
				off += nn
				if err != nil {
					fmt.Println("error reading client data")
					fmt.Println(err)
					return
				}
			}
			if !bytes.Equal(buf, clientToServerData) {
				fmt.Printf("unmatched c to s data %s\n", string(buf))
				return
			}
			// send the server data
			_, err = serverSSConn.Write(serverToClientData)
			if err != nil {
				fmt.Println("error writing server data")
				return
			}
		}
	}()

	for i := 0; i < 10; i++ {
		// send the client data
		_, err = clientSSConn.Write(clientToServerData)
		if err != nil {
			fmt.Println("error writing client data")
			return
		}
		// read the server data
		buf := make([]byte, len(serverToClientData))
		_, err = io.ReadFull(clientSSConn, buf)
		if err != nil {
			fmt.Println("error reading server data")
			fmt.Println(err)
			return
		}
		if !bytes.Equal(buf, serverToClientData) {
			fmt.Printf("unmatched s to c data %s\n", string(buf))
			return
		}
	}

	return
}

func TestMsgPassing(t *testing.T) {
	for method := range cipherMethod {
		fmt.Println("Testing Method " + method)
		err := connSalts(method)
		if err != nil {
			t.Errorf("%s connection error: %s", method, err)
			continue
		}

	}
}
