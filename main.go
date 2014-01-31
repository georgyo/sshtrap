/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"code.google.com/p/go.crypto/ssh"
	"code.google.com/p/go.crypto/ssh/terminal"
	"flag"
	"github.com/golang/glog"
	"io/ioutil"
	"runtime"
	"strconv"
	"time"
)

var rsaPrivKeyFile = flag.String("rsa_key", "id_rsa", "The private rsa key for the ssh-server")
var dsaPrivKeyFile = flag.String("dsa_key", "id_dsa", "The private dsa key for the ssh-server")
var ecdsaPrivKeyFile = flag.String("ecdsa_key", "id_ecdsa", "The private ecdsa key for the ssh-server")
var bumpEvery = flag.Int("bump_every", 3600, "How offten to print general process stats, in seconds")
var port = flag.Int("port", 2022, "The port to listen on")

func init() {
}

func Bumper() {
	ticker := time.NewTicker(time.Duration(*bumpEvery) * time.Second)
	var mstats runtime.MemStats
	for {
		runtime.ReadMemStats(&mstats)
		off := (int(mstats.NumGC) + len(mstats.PauseNs) - 1) % len(mstats.PauseNs)
		glog.Infof("GoRoutines: %v Alloc: %vBytes LastGCPause: %v AvgGCPause: %v",
			runtime.NumGoroutine(), mstats.Alloc, time.Duration(mstats.PauseNs[off]),
			time.Duration(mstats.PauseTotalNs/uint64(mstats.NumGC)))

		<-ticker.C

	}
}

func ServeSSHConnection(sConn *ssh.ServerConn) {
	defer sConn.Close()
	defer glog.Infof("%-20v: Destroyed Connection", sConn.RemoteAddr())

	sCloseChan := make(chan struct{})
	defer close(sCloseChan)

	for {
		// Accept reads from the connection, demultiplexes packets
		// to their corresponding channels and returns when a new
		// channel request is seen. Some goroutine must always be
		// calling Accept; otherwise no messages will be forwarded
		// to the channels.
		channel, err := sConn.Accept()
		if err != nil {
			glog.Errorf("error from Accept from %v with error %v: ", sConn.RemoteAddr(), err)
			break
		}

		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if channelType := channel.ChannelType(); channelType != "session" {
			glog.Errorf("Rejected Channel from %v because of unknown channel type %q", sConn.RemoteAddr(), channelType)
			channel.Reject(ssh.UnknownChannelType, "unknown channel type "+channelType)
			continue
		}
		go func() {
			channel.Accept()
			defer channel.Close()
			defer glog.Infof("%-20v: Destroyed Channel", sConn.RemoteAddr())

			cCloseChan := make(chan struct{})
			defer close(cCloseChan)

			glog.Infof("%-20v: Created Channel Payload=%q", sConn.RemoteAddr(), channel.ExtraData())
			term := terminal.NewTerminal(channel, "> ")
			serverTerm := ServerTerminal{
				Term:    term,
				Channel: channel,
				Conn:    sConn,
			}
			for {
				line, err := serverTerm.ReadLine()
				if err != nil {
					glog.Infof("%-20v: ReadError=%q", sConn.RemoteAddr(), err)
					return
				}
				glog.Infof("%-20v: ReadLine=%q", sConn.RemoteAddr(), line)
				if line == "quit" {
					return
				}
			}

		}()
	}
}

func main() {
	flag.Parse()

	go Bumper()

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		NoClientAuth: false,
		PasswordCallback: func(conn *ssh.ServerConn, user, pass string) bool {
			glog.Warningf("Password auth - User=%q Password=%q Addr=%v ClientVersion=%q", user, pass, conn.RemoteAddr(), conn.ClientVersion)
			return true
		},
		PublicKeyCallback: func(conn *ssh.ServerConn, user, algo string, pubkey []byte) bool {
			glog.Warningf("Pubkey auth - User=%q Keyalgo=%q Addr=%v ClientVersion=%q", user, algo, conn.RemoteAddr(), conn.ClientVersion)
			return true
		},
		KeyboardInteractiveCallback: func(conn *ssh.ServerConn, user string, client ssh.ClientKeyboardInteractive) bool {
			glog.Warningf("Interactive auth - User=%q Addr=%v ClientVersion=%q", user, conn.RemoteAddr(), conn.ClientVersion)
			return true
		},
	}

	// Read all the key files, and add them to the ssh config if they check out
	for _, keyFile := range [3]*string{rsaPrivKeyFile, dsaPrivKeyFile, ecdsaPrivKeyFile} {
		pemBytes, err := ioutil.ReadFile(*keyFile)
		if err != nil {
			glog.Warning("Failed to load private key: ", err)
			continue
		}
		if signer, err := ssh.ParsePrivateKey(pemBytes); err != nil {
			glog.Fatal("Failed to parse private key: ", err)
		} else {
			glog.Info("Added private ", signer.PublicKey().PrivateKeyAlgo(), " key.")
			config.AddHostKey(signer)
		}
	}

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := ssh.Listen("tcp", "0.0.0.0:"+strconv.Itoa(*port), config)
	if err != nil {
		glog.Fatalf("failed to listen for connection: %v", err)
	}

	for {
		sConn, err := listener.Accept()
		if err != nil {
			glog.Errorf("failed to accept incoming connection from %v with error: %v", sConn.RemoteAddr(), err)
			continue
		}
		if err := sConn.Handshake(); err != nil {
			glog.Errorf("failed to handshake from %v with error: %v", sConn.RemoteAddr(), err)
			continue
		}

		// A ServerConn multiplexes several channels, which must
		// themselves be Accepted.
		go ServeSSHConnection(sConn)
	}

	glog.Fatal("How did I get here?")
}
