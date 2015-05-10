package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"sync"

	"golang.org/x/crypto/ssh"
)

func startServe() {

	config, err := generateConfig()
	if err != nil {
		log.Fatalf("generateConfig err: %s", err)
	}

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
	/*
		// You can generate a keypair with 'ssh-keygen -t rsa'
		privateBytes, err := ioutil.ReadFile("id_rsa")
		if err != nil {
			log.Fatal("Failed to load private key (./id_rsa)")
		}
		private, err := ssh.ParsePrivateKey([]byte(ServerPrivateKey))
		if err != nil {
			log.Fatal("Failed to parse private key")
		}
		config.AddHostKey(private)
	*/
	certCheck := NewCertChecker()
	config := &ssh.ServerConfig{
		PublicKeyCallback: certCheck.Authenticate,
	}
	p, err := ssh.ParsePrivateKey([]byte(ServerPrivateKey))
	if err != nil {
		return nil, err
	}
	config.AddHostKey(p)
	return config, nil
}

func NewCertChecker() *ssh.CertChecker {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ClientPubkey))
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
