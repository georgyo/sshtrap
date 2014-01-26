//     Copyright (C) 2014  George Shammas
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"code.google.com/p/go.crypto/ssh"
	"code.google.com/p/go.crypto/ssh/terminal"
	"flag"
	"github.com/golang/glog"
	"io/ioutil"
	//"reflect"
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
	defer glog.Infof("Broke Down connection with %v", sConn.RemoteAddr())

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
			glog.Warningf("Rejected Channel from %v because of unknown channel type %q", sConn.RemoteAddr(), channelType)
			channel.Reject(ssh.UnknownChannelType, "unknown channel type "+channelType)
			continue
		}
		go func() {
			channel.Accept()
			defer channel.Close()
			defer glog.Infof("Broke Down Channel from %v", sConn.RemoteAddr())

			cCloseChan := make(chan struct{})
			defer close(cCloseChan)

			glog.Warningf("Creating Channel from %v with Payload: %q", sConn.RemoteAddr(), channel.ExtraData())

			term := terminal.NewTerminal(channel, "> ")
			serverTerm := &ssh.ServerTerminal{
				Term:    term,
				Channel: channel,
			}
			/*
				go func() {
					for {
						var data []byte
						length, err := channel.Read(data)
						if errT:= reflect.TypeOf(err); errT.String() == "ssh.ChannelRequest" {
							request := err.(ssh.ChannelRequest)
							glog.Warningf("Got a channel request from %v of %v: ", sConn.RemoteAddr(), request)
						} else if err != nil {
							glog.Errorf("Got a werid channel read from %v with error: %v", sConn.RemoteAddr(), err)
							break
						} else {
							glog.Warningf("Got a channel read from %v with data %q: ", sConn.RemoteAddr(), data[:length])
						}
					}
				}()
			*/
			for {
				line, err := serverTerm.ReadLine()
				if err != nil {
					return
				}
				glog.Info(line)
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
			glog.Warningf("Password auth - User=%q Addr=%v ClientVersion=%q", user, conn.RemoteAddr(), conn.ClientVersion)
			return true
		},
		PublicKeyCallback: func(conn *ssh.ServerConn, user, algo string, pubkey []byte) bool {
			glog.Warningf("Pubkey auth - User=%q Addr=%v ClientVersion=%q", user, conn.RemoteAddr(), conn.ClientVersion)
			return true
		},
		KeyboardInteractiveCallback: func(conn *ssh.ServerConn, user string, client ssh.ClientKeyboardInteractive) bool {
			glog.Warningf("Interactive auth - User=%q Addr=%v ClientVersion=%q", user, conn.RemoteAddr(), conn.ClientVersion)
			return true
		},
	}

	var keyFiles []*string
	keyFiles = append(keyFiles, rsaPrivKeyFile, dsaPrivKeyFile, ecdsaPrivKeyFile)
	for _, keyFile := range keyFiles {
		pemBytes, err := ioutil.ReadFile(*keyFile)
		if err != nil {
			glog.Warning("Failed to load private key: ", err)
			continue
		}
		if signer, err := ssh.ParsePrivateKey(pemBytes); err != nil {
			glog.Fatal("Failed to parse private key: ", err)
		} else {
			glog.Info("Added private key ", keyFile)
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
