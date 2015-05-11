package client

import (
	"io"
	"log"
	"os"
	"sync"

	"github.com/masahide/gosshd/key"
	"golang.org/x/crypto/ssh"
)

func generateConfig(user string) (*ssh.ClientConfig, error) {
	certCheck := key.NewCertChecker([]byte(key.ServerPubkey))
	serverPubkey, err := ssh.ParsePrivateKey([]byte(key.ClientPrivateKey))
	if err != nil {
		return nil, err
	}
	config := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: certCheck.CheckHostKey,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(serverPubkey),
		},
	}
	return config, nil
}

func Dial() {
	config, err := generateConfig("test_user")
	if err != nil {
		panic("Failed to generateConfig: " + err.Error())
	}
	client, err := ssh.Dial("tcp", "localhost:2200", config)
	if err != nil {
		panic("Failed to dial: " + err.Error())
	}
	log.Printf("connect user:%s, SessionID:%s, ServerVersion:%s, RemoteAddr:%s", client.Conn.User(), client.Conn.SessionID, client.Conn.ServerVersion, client.Conn.RemoteAddr)
	ch, request, err := client.Conn.OpenChannel("test", nil)
	if err != nil {
		log.Fatalf("OpenChannel: %v", err)
	}
	log.Printf("Open channel")
	go ssh.DiscardRequests(request)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		//	io.Copy(connection, stdout)
		io.Copy(ch, os.Stdin)
		//once.Do(close)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(os.Stdout, ch)
		//once.Do(close)
	}()
	wg.Wait()

}
