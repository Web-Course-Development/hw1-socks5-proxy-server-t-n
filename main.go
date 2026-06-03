package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
)

const (
	socksVersion = 0x05

	methodNoAuth        = 0x00
	methodUserPass      = 0x02
	methodNotAcceptable = 0xFF

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	method, err := negotiateAuth(conn)
	if err != nil {
		log.Printf("auth negotiation error: %v", err)
		return
	}

	if method == methodUserPass {
		if err := authenticateUserPass(conn); err != nil {
			log.Printf("authentication error: %v", err)
			return
		}
	}

	targetAddr, err := readConnectRequest(conn)
	if err != nil {
		log.Printf("connect request error: %v", err)
		sendReply(conn, 0x01)
		return
	}

	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("dial target error: %v", err)
		sendReply(conn, 0x05)
		return
	}
	defer target.Close()

	if err := sendReply(conn, 0x00); err != nil {
		log.Printf("send reply error: %v", err)
		return
	}

	relay(conn, target)
}

func negotiateAuth(conn net.Conn) (byte, error) {
	header := make([]byte, 2)

	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, err
	}

	if header[0] != socksVersion {
		return 0, fmt.Errorf("invalid SOCKS version")
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)

	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, err
	}

	requiredMethod := byte(methodNoAuth)

	if os.Getenv("PROXY_USER") != "" {
		requiredMethod = methodUserPass
	}

	for _, method := range methods {
		if method == requiredMethod {
			_, err := conn.Write([]byte{socksVersion, requiredMethod})
			return requiredMethod, err
		}
	}

	conn.Write([]byte{socksVersion, methodNotAcceptable})
	return 0, fmt.Errorf("no acceptable authentication method")
}

func authenticateUserPass(conn net.Conn) error {
	header := make([]byte, 2)

	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != 0x01 {
		return fmt.Errorf("invalid username/password auth version")
	}

	usernameLength := int(header[1])
	username := make([]byte, usernameLength)

	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}

	passwordLengthBuffer := make([]byte, 1)

	if _, err := io.ReadFull(conn, passwordLengthBuffer); err != nil {
		return err
	}

	passwordLength := int(passwordLengthBuffer[0])
	password := make([]byte, passwordLength)

	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	expectedUser := os.Getenv("PROXY_USER")
	expectedPass := os.Getenv("PROXY_PASS")

	if string(username) == expectedUser && string(password) == expectedPass {
		_, err := conn.Write([]byte{0x01, 0x00})
		return err
	}

	conn.Write([]byte{0x01, 0x01})
	return fmt.Errorf("invalid username or password")
}

func readConnectRequest(conn net.Conn) (string, error) {
	header := make([]byte, 4)

	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}

	if header[0] != socksVersion {
		return "", fmt.Errorf("invalid SOCKS version")
	}

	if header[1] != cmdConnect {
		sendReply(conn, 0x07)
		return "", fmt.Errorf("only CONNECT command is supported")
	}

	if header[2] != 0x00 {
		return "", fmt.Errorf("invalid reserved byte")
	}

	var host string

	switch header[3] {
	case atypIPv4:
		addr := make([]byte, 4)

		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}

		host = net.IP(addr).String()

	case atypDomain:
		lengthBuffer := make([]byte, 1)

		if _, err := io.ReadFull(conn, lengthBuffer); err != nil {
			return "", err
		}

		domainLength := int(lengthBuffer[0])
		domain := make([]byte, domainLength)

		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}

		host = string(domain)

	default:
		sendReply(conn, 0x08)
		return "", fmt.Errorf("unsupported address type")
	}

	portBuffer := make([]byte, 2)

	if _, err := io.ReadFull(conn, portBuffer); err != nil {
		return "", err
	}

	port := binary.BigEndian.Uint16(portBuffer)
	targetAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))

	return targetAddr, nil
}

func sendReply(conn net.Conn, rep byte) error {
	reply := []byte{
		socksVersion,
		rep,
		0x00,
		atypIPv4,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}

	_, err := conn.Write(reply)
	return err
}

func relay(client net.Conn, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(target, client)

		if tcpTarget, ok := target.(*net.TCPConn); ok {
			tcpTarget.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, target)

		if tcpClient, ok := client.(*net.TCPConn); ok {
			tcpClient.CloseWrite()
		}
	}()

	wg.Wait()
}