// Copyright 2019-2022 go-pfcp authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Command hb-server sends a HeartbeatRequest and checks response.
//
// Heartbeat exchanging feature is planned be included in the go-pfcp package's
// built-in functions in the future.
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

const (
	// smfN4Addr = "11.11.11.3:8805"
	// upfN4Addr = "127.0.0.1:8805"
	// defaultN3Addr   = "193.168.1.3"
	UPLINK   = 1
	DOWNLINK = 2
)

type Pdr struct {
	pdrId               uint16
	fteid_teid          uint32
	fteid_ip            net.IP
	ueip                net.IP
	farId               uint32
	outer_header_remove uint8
	direction           int32
}

type Far struct {
	farId   uint32
	bFoward bool
	fwdParm *ie.OuterHeaderCreationFields
}

var teid2ueip map[uint32]net.IP

var g_farMap map[uint32]Far

var stdin io.WriteCloser

func main() {
	var (
		listen = flag.String("s", "11.11.11.1:8805", "addr/port to listen on")
	)
	flag.Parse()

	laddr, _ := net.ResolveUDPAddr("udp", *listen)

	conn, _ := net.ListenUDP("udp", laddr)

	buf := make([]byte, 1500)

	cmdStr := "python3 ~/0919-p4/behavioral-model/tools/runtime_CLI.py --thrift-port 9090"
	cmd := exec.Command("bash", "-c", cmdStr)
	cmdStdoutPipe, _ := cmd.StdoutPipe()
	stdin, _ = cmd.StdinPipe()

	err := cmd.Start()
	if err != nil {
		fmt.Println(err)
	}

	go syncLog(cmdStdoutPipe)

	go func() {
		err = cmd.Wait()
		if err != nil {
			fmt.Println(err)
		}
	}()

	for {
		fmt.Printf("waiting for messages to come on: %s", laddr)
		n, addr, _ := conn.ReadFrom(buf)

		msg, err := message.Parse(buf[:n])
		if err != nil {
			fmt.Printf("ignored undecodable message: %x, error: %s", buf[:n], err)
			continue
		}

		switch msg.MessageTypeName() {
		case "Heartbeat Request":
			fmt.Printf("\nmessage.HeartbeatRequest")
			// Timestamp shouldn't be the time message is sent in the real deployment but anyway :D
			var seq uint32 = 1
			hbres, _ := message.NewHeartbeatResponse(seq, ie.NewRecoveryTimeStamp(time.Now())).Marshal()
			conn.WriteTo(hbres, addr)
			fmt.Printf("\nsent Heartbeat Response to: %s", addr)
		case "Association Setup Request":
			fmt.Printf("\nmessage.AssociationSetupRequest")
			hbres, _ := pfcp_AssociationSetupRequest_parser(msg, addr)
			conn.WriteTo(hbres, addr)
			fmt.Printf("\nsent Association Setup Response to: %s", addr)
		case "Session Establishment Request":
			fmt.Printf("\nmessage.SessionEstablishmentRequest")
			hbres, _ := pfcp_SessionEstablish_parser(msg, addr)
			conn.WriteTo(hbres, addr)
			fmt.Printf("\nsent Session Establishment Response to: %s", addr)
		case "Session Modification Request":
			fmt.Printf("\nmessage.SessionModificationRequest")
			hbres, _ := pfcp_SessionModify_parser(msg, addr)
			conn.WriteTo(hbres, addr)
			fmt.Printf("\nsent Session Modification Response to: %s", addr)
		default:
			fmt.Printf("\ngot unexpected message: %s, from: %s", msg.MessageTypeName(), addr)
		}
	}
}

func syncLog(reader io.ReadCloser) {
	f, _ := os.OpenFile("file.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	defer f.Close()
	buf := make([]byte, 1024, 1024)
	for {
		strNum, err := reader.Read(buf)
		if strNum > 0 {
			outputByte := buf[:strNum]
			f.WriteString(string(outputByte))
		}
		if err != nil {
			//读到结尾
			if err == io.EOF || strings.Contains(err.Error(), "file already closed") {
				err = nil
			}
		}
	}
}

func pfcp_AssociationSetupRequest_parser(msg message.Message, addr net.Addr) ([]byte, error) {
	req := msg.(*message.AssociationSetupRequest)
	return message.NewAssociationSetupResponse(
		req.SequenceNumber,
		ie.NewNodeID("11.11.11.1", "", ""),
		ie.NewUserPlaneIPResourceInformation(0x25, 0, "11.11.11.1", "", "internet", 0),
		ie.NewCause(ie.CauseRequestAccepted)).Marshal()
}

func pfcp_SessionEstablish_parser(msg message.Message, addr net.Addr) ([]byte, error) {
	if g_farMap == nil {
		g_farMap = make(map[uint32]Far, 10)
	}
	if teid2ueip == nil {
		teid2ueip = make(map[uint32]net.IP, 200)
	}
	pdrs := make([]Pdr, 0)

	req := msg.(*message.SessionEstablishmentRequest)
	// if !ok {
	// 	fmt.Printf("got unexpected message: %s, from: %s", msg.MessageTypeName(), addr)
	// }

	/**session decode
	* f-seid
	 */
	// n3Ip = net.ParseIP(defaultN3Addr)

	fseid, _ := req.CPFSEID.FSEID()

	/*pdr decode
	* pdrId,pdi->sourceInterface,pdi->f-teid,pdi->ueip
	 */
	for _, crtPdrItem := range req.CreatePDR {
		var pdr Pdr
		pdrId, _ := crtPdrItem.PDRID()
		pdr.pdrId = pdrId

		farId, err := crtPdrItem.FARID()
		if err == nil {
			pdr.farId = farId
		}

		sourceInt, _ := crtPdrItem.SourceInterface()

		//"Access" interface value is 0
		if sourceInt == 0 {
			pdr.direction = UPLINK
		} else {
			pdr.direction = DOWNLINK
		}

		/*go-pfcp FTEID() has a bug ,need enumerate to find PDI*/
		crtIEs, _ := crtPdrItem.CreatePDR()
		for _, item := range crtIEs {
			if item.Type == ie.PDI {
				pdiIEs, _ := item.PDI()
				for _, pdiIe := range pdiIEs {
					if pdiIe.Type == ie.FTEID {
						fteid, _ := pdiIe.FTEID()
						if fteid != nil {
							// fmt.Println("fteid teid:", fteid.TEID, " fteid addr:", fteid.IPv4Address, " ueip:", pdr.fteid_ip)
							pdr.fteid_teid = fteid.TEID
							pdr.fteid_ip = fteid.IPv4Address
							// g_n3Ip = pdr.fteid_ip
						}
					}
				}
			}
		}

		ueip, err := crtPdrItem.UEIPAddress()
		pdr.ueip = ueip.IPv4Address

		outerRm, err := crtPdrItem.OuterHeaderRemovalDescription()
		pdr.outer_header_remove = outerRm
		pdrs = append(pdrs, pdr)
	}
	/*far decode*/
	for _, crtFarItem := range req.CreateFAR {
		var far Far
		farId, _ := crtFarItem.FARID()
		far.farId = farId

		bForw := crtFarItem.HasFORW()
		far.bFoward = bForw

		frIEs, _ := crtFarItem.ForwardingParameters()
		for _, frIe := range frIEs {
			if frIe.Type == ie.OuterHeaderCreation {
				outerHeaderField, _ := frIe.OuterHeaderCreation()
				if outerHeaderField != nil {
					far.fwdParm = outerHeaderField
					fmt.Println("!!!far.fwdParm.TEID", outerHeaderField.TEID)
					fmt.Println("!!!outerHeaderField", outerHeaderField)
				}
			}
		}
		g_farMap[far.farId] = far
	}

	// P4runtime
	// for _, pdr_item := range pdrs {
	// 	err = pfcp_rule_tran_p4table(p4RtC, &pdr_item)
	// 	if err != nil {
	// 		fmt.Error("pfcp_rule_tran_p4table error:", err)
	// 	}
	// }

	// return response
	return message.NewSessionEstablishmentResponse(0, 0,
		fseid.SEID, req.SequenceNumber,
		0, ie.NewNodeID("11.11.11.1", "", ""),
		ie.NewCause(ie.CauseRequestAccepted)).Marshal()
}

func pfcp_SessionModify_parser(msg message.Message, addr net.Addr) ([]byte, error) {
	var ueip, ranip net.IP
	var teid uint32

	req := msg.(*message.SessionModificationRequest)

	// decode
	fseid, _ := req.CPFSEID.FSEID()

	for _, crtPdrItem := range req.UpdatePDR {
		crtIEs, _ := crtPdrItem.UpdatePDR()
		for _, item := range crtIEs {
			if item.Type == ie.PDI {
				pdiIEs, _ := item.PDI()
				for _, pdiIe := range pdiIEs {
					if pdiIe.Type == ie.UEIPAddress {
						ueipIe, _ := pdiIe.UEIPAddress()
						ueip = ueipIe.IPv4Address
					}
				}
			}
		}

	}

	for _, crtFarItem := range req.UpdateFAR {
		farId, _ := crtFarItem.FARID()
		var far Far = g_farMap[farId]

		frIEs, _ := crtFarItem.UpdateForwardingParameters()
		for _, frIe := range frIEs {
			if frIe.Type == ie.OuterHeaderCreation {
				outerHeaderField, _ := frIe.OuterHeaderCreation()
				if outerHeaderField != nil {
					far.fwdParm = outerHeaderField
					teid = outerHeaderField.TEID
					ranip = outerHeaderField.IPv4Address
					// fmt.Println("\nmodification update TEID", outerHeaderField.TEID)
					// fmt.Println("modification update RANIP", outerHeaderField.IPv4Address)
				}
			}
		}
		g_farMap[far.farId] = far
	}

	// p4
	fmt.Println("\nrules to bmv2: ", ueip, " ", teid, " ", ranip)
	teid2ueip[teid] = ueip

	if teid != 1 {
		outstr := "table_add tognb gtpu_encap " + ueip.String() + " => " + fmt.Sprintf("%d", teid) + " 11.11.11.1 11.11.11.231\n"
		fmt.Println(outstr)
		io.WriteString(stdin, outstr)
		outstr = "table_add toupf gtpu_decap 11.11.11.231 11.11.11.1 " + fmt.Sprintf("%d", teid*2-1) + " " + ueip.String() + " =>\n"
		fmt.Println(outstr)
		io.WriteString(stdin, outstr)
		outstr = "table_add forarp arp_response " + ueip.String() + " => " + ueip.String() + "\n"
		fmt.Println(outstr)
		io.WriteString(stdin, outstr)

		// table_add toupf gtpu_decap 11.11.11.231 11.11.11.1 3 192.168.0.2 =>
		// table_add tognb gtpu_encap 192.168.0.2 => 2 11.11.11.1 11.11.11.231
		// table_add forarp arp_response 192.168.0.2 => 192.168.0.2")
	}

	// return response
	return message.NewSessionModificationResponse(0, 0, fseid.SEID, req.SequenceNumber,
		0, ie.NewCause(ie.CauseRequestAccepted)).Marshal()
}
