/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"code.google.com/p/go.crypto/ssh"
	"encoding/binary"
	"github.com/golang/glog"
)

type ServerTerminal struct {
	Term    ssh.Terminal
	Channel ssh.Channel
	Conn    *ssh.ServerConn
}

func parseUint32(in []byte) (uint32, []byte, bool) {
	if len(in) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(in), in[4:], true
}

func parseString(in []byte) (out, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	if uint32(len(in)) < 4+length {
		return
	}
	out = in[4 : 4+length]
	rest = in[4+length:]
	ok = true
	return
}

// parsePtyRequest parses the payload of the pty-req message and extracts the
// dimensions of the terminal. See RFC 4254, section 6.2.
func parsePtyRequest(s []byte) (width, height int, ok bool) {
	_, s, ok = parseString(s)
	if !ok {
		return
	}
	width32, s, ok := parseUint32(s)
	if !ok {
		return
	}
	height32, _, ok := parseUint32(s)
	width = int(width32)
	height = int(height32)
	if width < 1 {
		ok = false
	}
	if height < 1 {
		ok = false
	}
	return
}

func (ss *ServerTerminal) Write(buf []byte) (n int, err error) {
	return ss.Term.Write(buf)
}

// ReadLine returns a line of input from the terminal.
func (ss *ServerTerminal) ReadLine() (line string, err error) {
	for {
		if line, err = ss.Term.ReadLine(); err == nil {
			return
		}

		req, ok := err.(ssh.ChannelRequest)
		if !ok {
			return
		}

		var payload []byte
		payload, _, ok = parseString(req.Payload)
		glog.Infof("%-20v: ChannelRequest Request=%q, WantReply=%t, Payload=%q",
			ss.Conn.RemoteAddr(), req.Request, req.WantReply, payload)

		err = nil // reset the error to nil for the return

		ok = false
		switch req.Request {
		case "pty-req":
			var width, height int
			width, height, ok = parsePtyRequest(req.Payload)
			ss.Term.SetSize(width, height)
		case "shell":
			ok = true
			if len(req.Payload) > 0 {
				// We don't accept any commands, only the default shell.
				ok = false
			}
		case "env":
			ok = true
		case "x11-req", "auth-agent-req@openssh.com":
			ok = false
		case "exec":
			var s []byte
			s, _, ok = parseString(req.Payload)
			line = string(s)
			ss.Channel.AckRequest(ok)
			return
		}
		if req.WantReply {
			ss.Channel.AckRequest(ok)
		}
	}
	panic("unreachable")
}
