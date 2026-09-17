package extrojan

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/sagernet/sing-box/transport/trojan"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	CommandOpen byte = 0xE1
	CommandJoin byte = 0xE2
)

const (
	StatusOK byte = iota
	StatusUnsupportedVersion
	StatusUnauthorized
	StatusNotFound
	StatusResourceLimit
	StatusInvalidRequest
)

const (
	FrameStreamData   byte = 0x01
	FrameStreamACK    byte = 0x02
	FrameStreamFIN    byte = 0x03
	FrameStreamFINACK byte = 0x04

	FrameUDPOpen     byte = 0x10
	FrameUDPOpenACK  byte = 0x11
	FrameUDPData     byte = 0x12
	FrameUDPClose    byte = 0x13
	FrameUDPCloseACK byte = 0x14

	FramePing         byte = 0x20
	FramePong         byte = 0x21
	FrameSessionClose byte = 0x30
)

var responseMagic = [4]byte{'E', 'X', 'T', '1'}

type SessionID [16]byte
type ResumeToken [32]byte

type OpenRequest struct {
	Version        byte
	Flags          uint16
	RequestedLanes uint16
}

type OpenResponse struct {
	Status          byte
	Version         byte
	Message         string
	SessionID       SessionID
	ResumeToken     ResumeToken
	LaneID          uint32
	ResumeTimeoutMS uint32
	AcceptedLanes   uint16
}

type JoinRequest struct {
	Version     byte
	SessionID   SessionID
	ResumeToken ResumeToken
}

type JoinResponse struct {
	Status  byte
	Version byte
	Message string
	LaneID  uint32
}

func WriteOpenRequest(writer io.Writer, key [trojan.KeyLength]byte, request OpenRequest) error {
	if _, err := writer.Write(key[:]); err != nil {
		return err
	}
	if _, err := writer.Write(trojan.CRLF); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, CommandOpen); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, request.Version); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, request.Flags); err != nil {
		return err
	}
	return binary.Write(writer, binary.BigEndian, request.RequestedLanes)
}

func ReadOpenRequest(reader io.Reader) (OpenRequest, error) {
	var request OpenRequest
	if err := binary.Read(reader, binary.BigEndian, &request.Version); err != nil {
		return OpenRequest{}, err
	}
	if err := binary.Read(reader, binary.BigEndian, &request.Flags); err != nil {
		return OpenRequest{}, err
	}
	if err := binary.Read(reader, binary.BigEndian, &request.RequestedLanes); err != nil {
		return OpenRequest{}, err
	}
	return request, nil
}

func WriteOpenResponse(writer io.Writer, response OpenResponse) error {
	if _, err := writer.Write(responseMagic[:]); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, response.Status); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, response.Version); err != nil {
		return err
	}
	if response.Status != StatusOK {
		return writeMessage(writer, response.Message)
	}
	if _, err := writer.Write(response.SessionID[:]); err != nil {
		return err
	}
	if _, err := writer.Write(response.ResumeToken[:]); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, response.LaneID); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, response.ResumeTimeoutMS); err != nil {
		return err
	}
	return binary.Write(writer, binary.BigEndian, response.AcceptedLanes)
}

func ReadOpenResponse(reader io.Reader) (OpenResponse, error) {
	var magic [4]byte
	if _, err := io.ReadFull(reader, magic[:]); err != nil {
		return OpenResponse{}, err
	}
	if magic != responseMagic {
		return OpenResponse{}, errors.New("extrojan response magic mismatch")
	}
	var response OpenResponse
	if err := binary.Read(reader, binary.BigEndian, &response.Status); err != nil {
		return OpenResponse{}, err
	}
	if err := binary.Read(reader, binary.BigEndian, &response.Version); err != nil {
		return OpenResponse{}, err
	}
	if response.Status != StatusOK {
		message, err := readMessage(reader)
		if err != nil {
			return OpenResponse{}, err
		}
		response.Message = message
		return response, nil
	}
	if _, err := io.ReadFull(reader, response.SessionID[:]); err != nil {
		return OpenResponse{}, err
	}
	if _, err := io.ReadFull(reader, response.ResumeToken[:]); err != nil {
		return OpenResponse{}, err
	}
	if err := binary.Read(reader, binary.BigEndian, &response.LaneID); err != nil {
		return OpenResponse{}, err
	}
	if err := binary.Read(reader, binary.BigEndian, &response.ResumeTimeoutMS); err != nil {
		return OpenResponse{}, err
	}
	if err := binary.Read(reader, binary.BigEndian, &response.AcceptedLanes); err != nil {
		return OpenResponse{}, err
	}
	return response, nil
}

func WriteJoinRequest(writer io.Writer, key [trojan.KeyLength]byte, request JoinRequest) error {
	if _, err := writer.Write(key[:]); err != nil {
		return err
	}
	if _, err := writer.Write(trojan.CRLF); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, CommandJoin); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, request.Version); err != nil {
		return err
	}
	if _, err := writer.Write(request.SessionID[:]); err != nil {
		return err
	}
	_, err := writer.Write(request.ResumeToken[:])
	return err
}

func ReadJoinRequest(reader io.Reader) (JoinRequest, error) {
	var request JoinRequest
	if err := binary.Read(reader, binary.BigEndian, &request.Version); err != nil {
		return JoinRequest{}, err
	}
	if _, err := io.ReadFull(reader, request.SessionID[:]); err != nil {
		return JoinRequest{}, err
	}
	if _, err := io.ReadFull(reader, request.ResumeToken[:]); err != nil {
		return JoinRequest{}, err
	}
	return request, nil
}

func WriteJoinResponse(writer io.Writer, response JoinResponse) error {
	if _, err := writer.Write(responseMagic[:]); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, response.Status); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, response.Version); err != nil {
		return err
	}
	if response.Status != StatusOK {
		return writeMessage(writer, response.Message)
	}
	return binary.Write(writer, binary.BigEndian, response.LaneID)
}

func ReadJoinResponse(reader io.Reader) (JoinResponse, error) {
	var magic [4]byte
	if _, err := io.ReadFull(reader, magic[:]); err != nil {
		return JoinResponse{}, err
	}
	if magic != responseMagic {
		return JoinResponse{}, errors.New("extrojan response magic mismatch")
	}
	var response JoinResponse
	if err := binary.Read(reader, binary.BigEndian, &response.Status); err != nil {
		return JoinResponse{}, err
	}
	if err := binary.Read(reader, binary.BigEndian, &response.Version); err != nil {
		return JoinResponse{}, err
	}
	if response.Status != StatusOK {
		message, err := readMessage(reader)
		if err != nil {
			return JoinResponse{}, err
		}
		response.Message = message
		return response, nil
	}
	if err := binary.Read(reader, binary.BigEndian, &response.LaneID); err != nil {
		return JoinResponse{}, err
	}
	return response, nil
}

func writeMessage(writer io.Writer, message string) error {
	if len(message) > 1024 {
		message = message[:1024]
	}
	if err := binary.Write(writer, binary.BigEndian, uint16(len(message))); err != nil {
		return err
	}
	_, err := io.WriteString(writer, message)
	return err
}

func readMessage(reader io.Reader) (string, error) {
	var length uint16
	if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
		return "", err
	}
	if length > 1024 {
		return "", errors.New("extrojan response message too long")
	}
	message := make([]byte, length)
	if _, err := io.ReadFull(reader, message); err != nil {
		return "", err
	}
	return string(message), nil
}

func EncodeFrame(frameType byte, payload []byte, maxFrameSize int) ([]byte, error) {
	frameLength := 1 + len(payload)
	if frameLength < 1 || frameLength > maxFrameSize {
		return nil, fmt.Errorf("extrojan frame size %d exceeds limit %d", frameLength, maxFrameSize)
	}
	frame := make([]byte, 4+frameLength)
	binary.BigEndian.PutUint32(frame[:4], uint32(frameLength))
	frame[4] = frameType
	copy(frame[5:], payload)
	return frame, nil
}

func ReadFrame(reader io.Reader, maxFrameSize int) (byte, []byte, error) {
	var length uint32
	if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
		return 0, nil, err
	}
	if length < 1 || length > uint32(maxFrameSize) {
		return 0, nil, fmt.Errorf("invalid extrojan frame size %d", length)
	}
	frame := make([]byte, int(length))
	if _, err := io.ReadFull(reader, frame); err != nil {
		return 0, nil, err
	}
	return frame[0], frame[1:], nil
}

func EncodeStreamData(offset uint64, data []byte) []byte {
	payload := make([]byte, 8+len(data))
	binary.BigEndian.PutUint64(payload[:8], offset)
	copy(payload[8:], data)
	return payload
}

func DecodeStreamData(payload []byte) (uint64, []byte, error) {
	if len(payload) < 9 {
		return 0, nil, errors.New("short STREAM_DATA frame")
	}
	return binary.BigEndian.Uint64(payload[:8]), payload[8:], nil
}

func EncodeUint64(value uint64) []byte {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, value)
	return payload
}

func DecodeUint64(payload []byte) (uint64, error) {
	if len(payload) != 8 {
		return 0, errors.New("invalid uint64 frame payload")
	}
	return binary.BigEndian.Uint64(payload), nil
}

func EncodeUDPOpen(associationID uint64, destination M.Socksaddr) ([]byte, error) {
	var payload bytes.Buffer
	if err := binary.Write(&payload, binary.BigEndian, associationID); err != nil {
		return nil, err
	}
	if err := M.SocksaddrSerializer.WriteAddrPort(&payload, destination); err != nil {
		return nil, err
	}
	return payload.Bytes(), nil
}

func DecodeUDPOpen(payload []byte) (uint64, M.Socksaddr, error) {
	reader := bytes.NewReader(payload)
	var associationID uint64
	if err := binary.Read(reader, binary.BigEndian, &associationID); err != nil {
		return 0, M.Socksaddr{}, err
	}
	destination, err := M.SocksaddrSerializer.ReadAddrPort(reader)
	if err != nil {
		return 0, M.Socksaddr{}, err
	}
	if reader.Len() != 0 {
		return 0, M.Socksaddr{}, errors.New("trailing UDP_OPEN payload")
	}
	return associationID, destination, nil
}

func EncodeUDPOpenACK(associationID uint64, status byte) []byte {
	payload := make([]byte, 9)
	binary.BigEndian.PutUint64(payload[:8], associationID)
	payload[8] = status
	return payload
}

func DecodeUDPOpenACK(payload []byte) (uint64, byte, error) {
	if len(payload) != 9 {
		return 0, 0, errors.New("invalid UDP_OPEN_ACK payload")
	}
	return binary.BigEndian.Uint64(payload[:8]), payload[8], nil
}

func EncodeUDPData(associationID uint64, destination M.Socksaddr, data []byte) ([]byte, error) {
	var payload bytes.Buffer
	if err := binary.Write(&payload, binary.BigEndian, associationID); err != nil {
		return nil, err
	}
	if err := M.SocksaddrSerializer.WriteAddrPort(&payload, destination); err != nil {
		return nil, err
	}
	if _, err := payload.Write(data); err != nil {
		return nil, err
	}
	return payload.Bytes(), nil
}

func DecodeUDPData(payload []byte) (uint64, M.Socksaddr, []byte, error) {
	reader := bytes.NewReader(payload)
	var associationID uint64
	if err := binary.Read(reader, binary.BigEndian, &associationID); err != nil {
		return 0, M.Socksaddr{}, nil, err
	}
	destination, err := M.SocksaddrSerializer.ReadAddrPort(reader)
	if err != nil {
		return 0, M.Socksaddr{}, nil, err
	}
	if reader.Len() > DefaultMaxUDPPayload {
		return 0, M.Socksaddr{}, nil, errors.New("UDP payload too large")
	}
	data := make([]byte, reader.Len())
	if _, err := io.ReadFull(reader, data); err != nil {
		return 0, M.Socksaddr{}, nil, err
	}
	return associationID, destination, data, nil
}
