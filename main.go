package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"sync"

	//	"github.com/kr/pty"
	"golang.org/x/crypto/ssh"
)

func main() {

	// In the latest version of crypto/ssh (after Go 1.3), the SSH server type has been removed
	// in favour of an SSH connection type. A ssh.ServerConn is created by passing an existing
	// net.Conn and a ssh.ServerConfig to ssh.NewServerConn, in effect, upgrading the net.Conn
	// into an ssh.ServerConn

	config, err := generateConfig()
	if err != nil {
		log.Fatalf("generateConfig err: %s", err)
	}

	/*
		// You can generate a keypair with 'ssh-keygen -t rsa'
		privateBytes, err := ioutil.ReadFile("id_rsa")
		if err != nil {
			log.Fatal("Failed to load private key (./id_rsa)")
		}
	*/
	private, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:2200")
	if err != nil {
		log.Fatalf("Failed to listen on 2200 (%s)", err)
	}

	// Accept all connections
	log.Print("Listening on 2200...")
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}
		// Before use, a handshake must be performed on the incoming net.Conn.
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			log.Printf("Failed to handshake (%s)", err)
			continue
		}

		log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		// Discard all global out-of-band Requests
		go ssh.DiscardRequests(reqs)
		// Accept all channels
		go handleChannels(chans)
	}
}

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func handleChannel(newChannel ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}
	bash := exec.Command("bash")
	stdout, err := bash.StdoutPipe()
	if err != nil {
		log.Printf("Could not Open StdoutPipe (%s)", err)
		return
	}
	// Prepare teardown function
	close := func() {
		connection.Close()
		_, err := bash.Process.Wait()
		if err != nil {
			log.Printf("Failed to exit bash (%s)", err)
		}
		log.Printf("Session closed")
	}
	//pipe session to bash and visa-versa
	var once sync.Once
	go func() {
		io.Copy(connection, stdout)
		once.Do(close)
	}()
	/*
		go func() {
			io.Copy(bashf, connection)
			once.Do(close)
		}()
	*/
	/*
		// Fire up bash for this session
		bash := exec.Command("bash")

		// Prepare teardown function
		close := func() {
			connection.Close()
			_, err := bash.Process.Wait()
			if err != nil {
				log.Printf("Failed to exit bash (%s)", err)
			}
			log.Printf("Session closed")
		}

		// Allocate a terminal for this channel
		log.Print("Creating pty...")
		bashf, err := pty.Start(bash)
		if err != nil {
			log.Printf("Could not start pty (%s)", err)
			close()
			return
		}

		//pipe session to bash and visa-versa
		var once sync.Once
		go func() {
			io.Copy(connection, bashf)
			once.Do(close)
		}()
		go func() {
			io.Copy(bashf, connection)
			once.Do(close)
		}()
	*/

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range requests {
			switch req.Type {
			case "shell":
				// We only accept the default shell
				// (i.e. no command in the Payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)
				}
				/*
					case "pty-req":
						termLen := req.Payload[3]
						w, h := parseDims(req.Payload[termLen+4:])
						SetWinsize(bashf.Fd(), w, h)
						// Responding true (OK) here will let the client
						// know we have a pty ready for input
						req.Reply(true, nil)
					case "window-change":
						w, h := parseDims(req.Payload)
						SetWinsize(bashf.Fd(), w, h)
				*/
			}
		}
	}()
}

func generateConfig() (*ssh.ServerConfig, error) {
	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	certCheck := NewCertChecker()
	config := &ssh.ServerConfig{
		PublicKeyCallback: certCheck.Authenticate,
	}
	p, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		return nil, err
	}
	config.AddHostKey(p)
	return config, nil
}

func NewCertChecker() *ssh.CertChecker {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(Pubkey))
	if err != nil {
		log.Fatalf("ParseAuthorizedKey: %v", err)
	}
	/*
		validCert, ok := key.(*ssh.Certificate)
		if !ok {
			log.Fatalf("key is not *ssh.Certificate (%T)", key)
		}
	*/
	return &ssh.CertChecker{
		IsAuthority: func(auth ssh.PublicKey) bool {
			//return bytes.Equal(auth.Marshal(), validCert.SignatureKey.Marshal())
			return bytes.Equal(auth.Marshal(), key.Marshal())
		},
	}
}

var Pubkey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzW4xPbwHP3lNhiCzPG7JtB0/Muny7kx6X007UF3HW+Qfd09HsH1twncH+7Jp269rBOkVrqxSM1p/IdTQZSI8pW5cyyBXiTMmDTlUrorxGxCVooQA27RCyAv1DlAIOELIQIdzG1w9rtUR/4EkuFTAElfrLyD0ZvAc3d8f4XCl3TzrRNB8UulIPcLMNbPMvkHlzVLbLY8i3Lqznxp8BnCahqwrUDRS4uabisQ0HIqqA5azXa/ksWQpB4MNH67VxGPSYoV/QvE1rrqP0ckcJq0BL5yYRnMFoU+mQHw14l5wjnM6lgf+ePdLIFCZFt7B7uV+YVBMFalFtA3EoQZ5l040X`

const privateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAs1uMT28Bz95TYYgszxuybQdPzLp8u5Mel9NO1Bdx1vkH3dPR
7B9bcJ3B/uyaduvawTpFa6sUjNafyHU0GUiPKVuXMsgV4kzJg05VK6K8RsQlaKEA
Nu0QsgL9Q5QCDhCyECHcxtcPa7VEf+BJLhUwBJX6y8g9GbwHN3fH+Fwpd0860TQf
FLpSD3CzDWzzL5B5c1S2y2PIty6s58afAZwmoasK1A0UuLmm4rENByKqgOWs12v5
LFkKQeDDR+u1cRj0mKFf0LxNa66j9HJHCatAS+cmEZzBaFPpkB8NeJecI5zOpYH/
nj3SyBQmRbewe7lfmFQTBWpRbQNxKEGeZdONFwIDAQABAoIBAAFjNOusZSwxgR2h
Cw+zHCdBxjlEPBDLa5IrHVIAuG28UXZC3D3iZDez0LtjIzLGUlPqWn0hvq/0PRo0
5elIKWtdfQb0i07L30c3xOrogGJfxBZSIIlMPjPSWBk8vONU97uuN2IGaeUgat4+
YvKLUWrHqkAHVYmsbbXdJFvkgqGcpPebHOoOkISA+/4m4hapOB828K34d8ynJ93c
e+r8Ode/fvq197yaVUUxNisqjtDKQDb9CdOVxKlAH1y0avF19C/vhA/xbDh02Xs8
roShbWKO18vofrKShWDDiQw58VYfNKLvib32yJtsPBnU7GGXsvd5mUsVTiXe/mRS
K93TY8kCgYEA7XrrFbXy6lxCd9nRuiUDFbYFoZ8px1LJTn65hNqYbN21aMZZgX2m
uN8l47iRorr2IMsfWEEArCDmQQa6hUAvMIMsQqevvOBDMqq5wNForKNDxeoeUKWP
PZRHgC5QHXGacPnIdDRYuqR2g26HIj5O8fKbDgZGiyKReIIw3noAV80CgYEAwVhD
uYFgnTAmaBJX8hN8VOCfa4+fnNmQBos1m67EsjRjVzgkdCRRGa12Rug0Idqat1nu
TMk26v7AoymSUBAlBUaV73weJ5R5G2fvLjQ/ihKO/9aOzB6OKhKbj24iWc2BuwL9
Xjimswx4AbvpQLmWlHBrYIy5Hg9L9/wfzY5IjHMCgYBtdU1ryVx4tyOP2F75nFuq
oyY/U3xPOhI9Ut2xpYvCCgK2k03oCIFTDs+JAaZmyiPuA5Gj/PoRXGykpjRMfMQD
aUJ6So4O0ZNHhDdv71V+1RXE4F8urtCyAmleZHpax+T2k7rYDNSk2m8hr00r9Gow
zLC5Kx1SvhEs6V0a/kKwNQKBgEyAKxPcUCkB40BseaXL9fbzhcCebG44W1drf4Oh
DCzis6fQDAR0Vi6Nxu3ZdL8sauk/SR3Sw8sJj5k/mqfZK3zB6BOBDcFlauHgJvAm
Njngi/pIn+m98UxOXoTK9AaKXNltHmlIixTvSxCMlIdKp30GWkYyiBCPxuRROxgv
Qx9nAoGAYanyGJ9Jbyr/T5hunH/uymdLD9R/sgQG04r7qiPlXi47uOFW7k7h7M6M
NJg4Jn3vy07680dvZJCVdxfVq57SPESY3kcxj5hQWJ2WFKBuSKeg0k+8AsLy6oMp
QKFOuE95M2RA4x/B4AVy1sjo5VyZTnFK5VvlJfRsLiXYh4x7YvE=
-----END RSA PRIVATE KEY-----
`
