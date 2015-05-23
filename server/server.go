package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"github.com/masahide/gosshd/key"
	"golang.org/x/crypto/ssh"
)

func StartServe() {

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
		log.Printf("Accept: %s", tcpConn.RemoteAddr())
		// Before use, a handshake must be performed on the incoming net.Conn.
		sshConn, chans, globalReqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			log.Printf("Failed to handshake (%s)", err)
			continue
		}
		log.Printf("ssh.NewServerConn: %s", tcpConn.RemoteAddr())

		log.Printf("New SSH connection from %s (%s), SessionID:%s, user:%s", sshConn.RemoteAddr(), sshConn.ClientVersion(), sshConn.SessionID(), sshConn.User())
		// Discard all global out-of-band Requests
		//go ssh.DiscardRequests(globalReqs)
		go printReq("globalReq", globalReqs)
		// Accept all channels
		go handleChannels(chans)
	}
}

func printReq(chtype string, reqs <-chan *ssh.Request) {
	noop := func(r *ssh.Request) {
		log.Printf("%s Type:%s WantReply:%v Payload:%s", chtype, r.Type, r.WantReply, r.Payload)
	}
	for req := range reqs {
		noop(req)
	}
}

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

type forwardedTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

// RFC 4254 7.2
type channelOpenDirectMsg struct {
	Raddr string
	Rport uint32
	Laddr string
	Lport uint32
}

func handleChannel(newChannel ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	/*
		if t := newChannel.ChannelType(); t != "session" {
			newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
			return
		}
	*/

	t := newChannel.ChannelType()
	switch t {
	case "forwarded-tcpip":
	case "direct-tcpip":
	}
	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		errMsg := fmt.Sprintf("Could not accept channel (%s)", err)
		log.Println(errMsg)
		newChannel.Reject(ssh.ConnectionFailed, errMsg)
		return
	}
	log.Printf("Accept channel type: %s", newChannel.ChannelType())
	var payload channelOpenDirectMsg
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		errMsg := fmt.Sprintf("could not parse direct-tcpip payload:%s ", err.Error())
		log.Println(errMsg)
		newChannel.Reject(ssh.ConnectionFailed, errMsg)
		return
	}
	log.Printf("%# v", payload)
	go printReq("reqs", requests)
	/*
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
	*/
	close := func() {
		connection.Close()
		os.Stdin.Close()
	}
	var once sync.Once
	go func() {
		io.Copy(connection, os.Stdin)
		once.Do(close)
	}()
	go func() {
		io.Copy(os.Stdout, connection)
		once.Do(close)
	}()
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
	okey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key.ClientPubkey))
	if err != nil {
		return nil, err
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil //TODO:test
			if bytes.Compare(okey.Marshal(), key.Marshal()) == 0 {
				perms := ssh.Permissions{}
				return &perms, nil
			} else {
				return nil, errors.New("Key does not match")
			}
		},
		AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
			log.Printf("user %q, method %q: %v", conn.User(), method, err)
		},
	}
	p, err := ssh.ParsePrivateKey([]byte(key.ServerPrivateKey))
	if err != nil {
		return nil, err
	}
	config.AddHostKey(p)
	return config, nil
}
