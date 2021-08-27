package main

import (
	"os"
	"io"
	"fmt"
	"net"
	"sync"
	"time"
	"errors"
	"strings"
	"strconv"
	
	"os/exec"
	"io/ioutil"
	"path/filepath"
)

var server string
var bucket string

func Log(message string) error {
	service := "inVirScan"
	loglevel := "info"
	logfilelocation := "/logs/inVirScan.log"

        file, err := os.OpenFile(logfilelocation, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
                return errors.New("Failed to open log file for writing: " + err.Error())
        }
        defer file.Close()

        current_time := time.Now().Local()
        t := current_time.Format("Jan 02 2006 03:04:05")
        _, err = file.WriteString(loglevel + " | " + t + " | " + service + " | " + message + "\n")

        if err != nil {
                return errors.New("Failed to write to log file: " + err.Error())
        }

        return nil
}

func virscan(filename string, wg *sync.WaitGroup) {
	var conn net.Conn
	var err error
	icapService := "avscan"

	defer wg.Done()

	recona := 0
	failedopen := false
	for {
		if recona >= 100 {
			failedopen = true
			break
		} 
		conn, err = net.DialTimeout("tcp", server, 5 * time.Second)
		if err != nil {
			Log("failed to connect to scanning engine (" + filename + ") (" + strconv.Itoa(recona) + "): " + err.Error())
			fmt.Println("failed to connect to scanning engine: " + err.Error())
			recona++
			continue
		}

		break
	}

	if failedopen {
		Log(filename + " Was *NOT* Scanned.  Failing Open.")
		fmt.Println(filename + " Was *NOT* Scanned.  Failing Open.")
		return
	}

	defer conn.Close()

	file, err := ioutil.ReadFile(filename)
	if err != nil {
		Log("failed to open file: " + err.Error())
		fmt.Println("failed to open file: " + err.Error())
		return
	}

	length := len(file)
	strlen := strconv.Itoa(length)
	hexval := fmt.Sprintf("%x", length)

	conn.Write([]byte("RESPMOD icap://127.0.0.1:1344/" + icapService + " ICAP/1.0\r\n"))
	conn.Write([]byte("Host: 127.0.0.1:1344\r\n"))
	conn.Write([]byte("User-Agent: CAC ICAP Client/1.1\r\n"))
	conn.Write([]byte("Allow: 204\r\n"))
	conn.Write([]byte("Connection: close\r\n"))
	conn.Write([]byte("Encapsulated: res-hdr=0, res-body=" + strlen + "\r\n"))
	conn.Write([]byte("\r\n"))
	conn.Write([]byte("Content-Length: " + strlen + "\r\n"))
	conn.Write([]byte("\r\n"))
	conn.Write([]byte(hexval + "\r\n"))
	conn.Write(file)
	conn.Write([]byte("\r\n"))
	conn.Write([]byte("0; ieof\r\n\r\n"))

	tmp := make([]byte, 256)
	output := ""

	for {
		_, err := conn.Read(tmp)
		if err != nil {
			if err != io.EOF {
			}
			break
		}

		output += string(tmp)
	}

	xthreat := ""
	infected := false
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "X-Infection-Found") {
			parts := strings.Split(line, ";")
			sthreat := strings.Split(parts[2], "=")
			xthreat = sthreat[1]
			infected = true
		}
	}

	if infected {
		Log("deleted file: " + filename + " - threat: " + xthreat)
		fmt.Println("deleted file: " + filename + " - threat: " + xthreat)
		os.Remove(filename)
	} else {
		Log(filename + " is clean")
		fmt.Println(filename + " is clean")
	}
}

func main() {
	var wg sync.WaitGroup
	var filelist []string

	if _, err := os.Stat("/var/run/virscan.run"); err == nil {
		Log("Run File Exists (/var/run/virscan.run).  Exiting.")
		return
	}

	t1 := []byte("running")
	err := ioutil.WriteFile("/var/run/virscan.run", t1, 0644)
	if err != nil {
		Log("Unable To Write /var/run/virscan.run.  Exiting.")
		return
	}

	server = os.Getenv("server")
	if len(server) == 0 {
		server = "capsscanprod.cac.com:1344"
	}

	bucket = os.Getenv("bucket")
	if len(bucket) == 0 {
		bucket = "cac-dealer-inventory-lz"
	}

	conn, err := net.DialTimeout("tcp", server, 5 * time.Second)
	if err != nil {
		Log("Can't Connect To Remote Scanner (invscanqa). Checking Prod...") 
		return
	}
	conn.Close()

	output, err := exec.Command("/usr/bin/aws", "s3", "sync", "s3://" + bucket, "/tmp/" + bucket).CombinedOutput()
	if err != nil {
		Log("Error Running AWS S3 Sync (output): " + string(output))
		Log("Error Running AWS S3 Sync (error): " + err.Error())
		fmt.Println(output)
		fmt.Println(err.Error())
		return
	}

	filepath.Walk("/tmp/" + bucket, func(path string, f os.FileInfo, err error) error {
		if ! f.IsDir() {
			filelist = append(filelist, path)
		}
		return nil
	})

	for _, file := range filelist {
		wg.Add(1)
		go virscan(file, &wg)
	}

	wg.Wait()

	output, err = exec.Command("/bin/tar", "cf", "/data/inv.tar", "-C", "/tmp/" + bucket, ".").CombinedOutput()
	if err != nil {
		Log("Error Taring Up Data (output): " + string(output))
		Log("Error Taring Up Data (error): " + err.Error())
		fmt.Println(output)
		fmt.Println(err.Error())
		return
	}

	output, err = exec.Command("/bin/tar", "xf", "/data/inv.tar", "-C", "/outbound/root/").CombinedOutput()
	if err != nil {
		Log("Error Extracting Tar Data (output): " + string(output))
		Log("Error Extracting Tar Data (error): " + err.Error())
		fmt.Println(output)
		fmt.Println(err.Error())
		return
	}

	output, err = exec.Command("/bin/tar", "xf", "/data/inv.tar", "-C", "/outbound/stored/").CombinedOutput()
	if err != nil {
		Log("Error Extracting Tar Data (output): " + string(output))
		Log("Error Extracting Tar Data (error): " + err.Error())
		fmt.Println(output)
		fmt.Println(err.Error())
		return
	}

	output, err = exec.Command("/usr/bin/aws", "s3", "rm", "s3://" + bucket, "--recursive").CombinedOutput()
	if err != nil {
		Log("Error Deleting Data In Bucket (output): " + string(output))
		Log("Error Deleting Data In Bucket (error): " + err.Error())
		fmt.Println(output)
		fmt.Println(err.Error())
		return
	}

	Log("Success")
	fmt.Println("Success!")

	err = os.Remove("/var/run/virscan.run")
	if err != nil {
		Log("Failed To Remove /var/run/virscan.run")
	}

	return
}
