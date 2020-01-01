/* SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Joyent, Inc.
 */
// +build solaris,amd64

package tun

import (
	"fmt"

	"unsafe"
	"syscall"

	"os"
//	"os/exec"
	"golang.org/x/sys/unix"
)

/*
 * ILLUMOS SYSTEM CALL HELPERS
 */

//go:cgo_import_dynamic libc_ioctl ioctl "libc.so"
//go:cgo_import_dynamic libc_putmsg putmsg "libc.so"
//go:cgo_import_dynamic libc_getmsg getmsg "libc.so"

//go:linkname f_ioctl libc_ioctl
//go:linkname f_putmsg libc_putmsg
//go:linkname f_getmsg libc_getmsg

var (
	f_ioctl uintptr
	f_putmsg uintptr
	f_getmsg uintptr
)

const (
	/*
	 * For use with "/dev/tun":
	 */
	TUNNEWPPA = 0x540001
	TUNSETPPA = 0x540002

	/*
	 * sys/stropts.h:
	 */
	I_STR = 0x5308
	I_POP = 0x5303
	I_PUSH = 0x5302
	I_PLINK = 0x5316
	I_PUNLINK = 0x5317

	/*
	 * sys/sockio.h:
	 */
	IF_UNITSEL = 0x80047336 /* set unit number */

	SIOCSLIFMUXID = 0x80786984
	SIOCGLIFMUXID = 0xc0786983
	SIOCGLIFINDEX = 0xc0786985
)

func sysvicall6(trap, nargs, a1, a2, a3, a4, a5, a6 uintptr) (
    r1, r2 uintptr, err syscall.Errno)

func ioctl(fd int, req uint, arg uintptr) (r int, err error) {
	r0, _, e0 := sysvicall6(uintptr(unsafe.Pointer(&f_ioctl)), 3,
	    uintptr(fd), uintptr(req), arg, 0, 0, 0)

	r = int(r0)
	if e0 != 0 {
		err = e0
	}

	return
}

func putmsg(fd int, ctlptr uintptr, dataptr uintptr, flags int) (
    r int, err error) {
	r0, _, e0 := sysvicall6(uintptr(unsafe.Pointer(&f_putmsg)), 4,
	    uintptr(fd), ctlptr, dataptr, uintptr(flags), 0, 0)

	r = int(r0)
	if e0 != 0 {
		err = e0
	}

	return
}

func getmsg(fd int, ctlptr uintptr, dataptr uintptr, flagsp uintptr) (
    r int, err error) {
	r0, _, e0 := sysvicall6(uintptr(unsafe.Pointer(&f_getmsg)), 4,
	    uintptr(fd), ctlptr, dataptr, flagsp, 0, 0)

	r = int(r0)
	if e0 != 0 {
		err = e0
	}

	return
}


/*
 * WIREGUARD/TUN INTERFACE
 */

type NativeTun struct {
	tunFile *os.File	/* TUN device file */
	ip_fd int		/* IP device fd */
	name string		/* Interface name */
	mtu int

	events chan Event
	errors chan error
}

// type Device interface {
// 	File() *os.File                 // returns the file descriptor of the device
// 	Read([]byte, int) (int, error)  // read a packet from the device (without any additional headers)
// 	Write([]byte, int) (int, error) // writes a packet to the device (without any additional headers)
// 	MTU() (int, error)              // returns the MTU of the device
// 	Name() (string, error)          // fetches and returns the current name
// 	Events() chan Event          // returns a constant channel of events related to the device
// 	Close() error                   // stops the device and closes the event channel
// }

func (tun *NativeTun) Name() (string, error) {
	return tun.name, nil
}

func (tun *NativeTun) Flush() error {
        // TODO: can flushing be implemented by buffering and using sendmmsg?
        return nil
}

func (tun *NativeTun) Read(buf []byte, offset int) (int, error) {
	select {
	case err := <-tun.errors:
		return 0, err

	default:
		return tun.read_tun(buf[offset:])
	}
}

func (tun *NativeTun) Write(buf []byte, offset int) (int, error) {
	return tun.write_tun(buf[offset:])
}

func (tun *NativeTun) File() *os.File {
	return tun.tunFile
}

func (tun *NativeTun) MTU() (int, error) {
	return tun.mtu, nil
}

func (tun *NativeTun) Events() chan Event {
	return tun.events
}

func (tun *NativeTun) Close() error {
	if tun.ip_fd >= 0 {
		ip_muxid, err := get_ip_muxid(tun.ip_fd, tun.name)
		if err != nil {
			return err
		}

		err = punlink(tun.ip_fd, ip_muxid)
		if err != nil {
			return err
		}

		unix.Close(tun.ip_fd)
		tun.ip_fd = -1
	}

	if tun.tunFile != nil {
		tun.tunFile.Close()
		tun.tunFile = nil
	}

	if tun.events != nil {
		close(tun.events)
	}

	return nil
}

func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	/*
	 * XXX It's not currently clear to me how to take a TUN file descriptor
	 * and determine the attached PPA.
	 *
	 * XXX Based on the current architecture of the daemon, we need to be
	 * able to reconstitute our NativeTun object from just a file
	 * descriptor number as the fd number is passed (with no other
	 * information) through the environment to the child.  For now, use the
	 * "-f" flag.
	 */
	return nil, fmt.Errorf("CreateTUNFromFile() not currently supported")
}

func CreateTUN(name string, mtu int) (Device, error) {
	if name != "tun" {
		return nil, fmt.Errorf("Interface name must be 'tun'")
	}

	/*
	 * To establish a "tun" interface, we need to open a few file
	 * descriptors.
	 */
	ip_node := "/dev/udp"
	dev_node := "/dev/tun"

	/*
	 * First, the IP driver:
	 */
	ip_fd, err := unix.Open(ip_node, unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("Could not open IP (%s)", ip_node)
	}

	/*
	 * Now, the TUN driver.  Note that we use "os.OpenFile()" instead of
	 * "unix.OpenFile()" so that we get the os.File object here.  The rest
	 * of the Wireguard API seems to depend on that functionality.
	 */
	tunFile, err := os.OpenFile(dev_node, unix.O_RDWR, 0)
	if err != nil {
		unix.Close(ip_fd)
		return nil, fmt.Errorf("Could not open TUN (%s)", dev_node)
	}
	fd := int(tunFile.Fd())

	/*
	 * Ask the TUN driver for a new PPA number:
	 */
	ppa, err := tun_new_ppa(fd)
	if err != nil {
		unix.Close(ip_fd)
		tunFile.Close()
		return nil, err
	}

	name = fmt.Sprintf("tun%d", ppa)
	fmt.Printf("device %v\n", name)

	/*
	 * Open another temporary file descriptor to the TUN driver.
	 * XXX It's not clear if this is actually needed, or if we could
	 * reuse the fd we got above...
	 */
	if_fd, err := unix.Open(dev_node, unix.O_RDWR, 0)
	if err != nil {
		unix.Close(ip_fd)
		tunFile.Close()
		return nil, fmt.Errorf("Could not open second TUN (%s)",
		    dev_node)
	}

	/*
	 * Push the IP module onto the new TUN device.
	 */
	if err = push_ip(if_fd); err != nil {
		unix.Close(if_fd)
		unix.Close(ip_fd)
		tunFile.Close()
		return nil, err
	}

	if err = unit_select(if_fd, ppa); err != nil {
		unix.Close(if_fd)
		unix.Close(ip_fd)
		tunFile.Close()
		return nil, err
	}

	ip_muxid, err := plink(ip_fd, if_fd)
	if err != nil {
		unix.Close(if_fd)
		unix.Close(ip_fd)
		tunFile.Close()
		return nil, err
	}

	/*
	 * XXX It would seem that we can now close this file descriptor,
	 * because of the persistent link established above.
	 */
	unix.Close(if_fd)
	if_fd = -1

	if err = set_ip_muxid(ip_fd, name, ip_muxid); err != nil {
		/*
		 * Attempt to disconnect the IP multiplexor before we close
		 * everything down.
		 */
		punlink(ip_fd, ip_muxid)

		unix.Close(ip_fd)
		tunFile.Close()
		return nil, err
	}

	tun := &NativeTun{
		events: make(chan Event, 10),
		errors: make(chan error, 1),
		mtu: mtu, /* XXX We should do something with the MTU! */
		name: name,
		tunFile: tunFile,
		ip_fd: ip_fd,
	}

	defer func () {
		/*
		 * XXX For now, we'll just send a link up event straight away.
		 */
		tun.events <- EventUp
	}()

	return tun, nil
}

func get_ip_muxid(fd int, name string) (int, error) {
	// struct lifreq { /* 0x178 bytes */
	//         char lifr_name[32]; /* offset: 0 bytes */
	//         union  lifr_lifru1; /* offset: 32 bytes */
	//         uint_t lifr_type; /* offset: 36 bytes */
	//         union  lifr_lifru; /* offset: 40 bytes */
	//                 - int lif_muxid[2];           /* mux id's for arp and ip */
	// };
	// #define lifr_ip_muxid   lifr_lifru.lif_muxid[0]
	ifr := make([]byte, 0x178)
	anb := []byte(name)
	for i := 0; i < len(anb); i++ {
		ifr[i] = anb[i]
	}

	_, err := ioctl(fd, SIOCGLIFMUXID, uintptr(unsafe.Pointer(&ifr[0])))
	if err != nil {
		return -1, fmt.Errorf("could not SIOCSLIFMUXID: %v", err)
	}

	/* ip_muxid = ifr.lifr_ip_muxid */
	var ip_muxid int = int(*(*int32)(unsafe.Pointer(&ifr[40 + 4 * 0])))

	fmt.Printf("got ip_muxid %v\n", ip_muxid)

	return ip_muxid, nil
}

func set_ip_muxid(fd int, name string, ip_muxid int) (error) {
	// struct lifreq { /* 0x178 bytes */
	//         char lifr_name[32]; /* offset: 0 bytes */
	//         union  lifr_lifru1; /* offset: 32 bytes */
	//         uint_t lifr_type; /* offset: 36 bytes */
	//         union  lifr_lifru; /* offset: 40 bytes */
	//                 - int lif_muxid[2];           /* mux id's for arp and ip */
	// };
	// #define lifr_ip_muxid   lifr_lifru.lif_muxid[0]
	ifr := make([]byte, 0x178)
	anb := []byte(name)
	for i := 0; i < len(anb); i++ {
		ifr[i] = anb[i]
	}
	/* ifr.lifr_ip_muxid  = ip_muxid */
	*(*int32)(unsafe.Pointer(&ifr[40 + 4 * 0])) = int32(ip_muxid)

	_, err := ioctl(fd, SIOCSLIFMUXID, uintptr(unsafe.Pointer(&ifr[0])))
	if err != nil {
		return fmt.Errorf("could not SIOCSLIFMUXID: %v", err)
	}

	return nil
}

func punlink(fd int, muxid int) (error) {
	_, err := ioctl(fd, I_PUNLINK, uintptr(muxid))
	if err != nil {
		return fmt.Errorf("could not I_PUNLINK: %v", err)
	}

	return  nil
}


func plink(fd int, other_fd int) (int, error) {
	ip_muxid, err := ioctl(fd, I_PLINK, uintptr(other_fd))
	if err != nil {
		return -1, fmt.Errorf("could not I_PLINK: %v", err)
	}

	fmt.Printf("ip_muxid %v\n", ip_muxid)

	return ip_muxid, nil
}

func unit_select(fd int, ppa int) (error) {
	int_ppa := make([]byte, 4) /* storage for the PPA number */
	*(*int32)(unsafe.Pointer(&int_ppa[0])) = int32(ppa)

	_, err := ioctl(fd, IF_UNITSEL, uintptr(unsafe.Pointer(&int_ppa[0])))
	if err != nil {
		return fmt.Errorf("could not select unit: %v", err)
	}

	return nil
}

func push_ip(fd int) (error) {
	/*
	 * We need a C string with the value "ip".
	 * XXX Is a Golang "string" implicitly NUL-terminated?
	 */
	modname := []byte{ 'i', 'p', 0 }

	_, err := ioctl(fd, I_PUSH, uintptr(unsafe.Pointer(&modname[0])))
	if err != nil {
		return fmt.Errorf("could not push IP module: %v\n", err)
	}

	return nil
}

/*
 * The "tun" device is a STREAMS module.  We need to make a STREAMS ioctl
 * request to that module using the TUNNEWPPA command.  Returns the newly
 * allocated PPA number.
 */
func tun_new_ppa(fd int) (int, error) {
	for try_ppa := 0; try_ppa < 128; try_ppa++ {
		/*
		 * The data pointer (ic_dp) for a TUNNEWPPA request must point to an
		 * int32_t value.  This value will be read to determine whether we want
		 * to allocate a specific PPA number, or if we want a dynamically
		 * assigned PPA number by passing -1.  If successful, the ioctl will
		 * return the allocated PPA number.
		 */
		int_ppa := make([]byte, 4) /* storage for the PPA number */
		*(*int32)(unsafe.Pointer(&int_ppa[0])) = int32(try_ppa)

		/*
		 * Construct a "struct strioctl" for use with the I_STR request
		 * we will make to the "tun" device.
		 */
		strioc := make([]byte, 0x18) /* struct strioctl */
		*(*int32)(unsafe.Pointer(&strioc[0])) = TUNNEWPPA /* int ic_cmd */
		*(*int32)(unsafe.Pointer(&strioc[4])) = 0 /* int ic_timout */
		*(*int32)(unsafe.Pointer(&strioc[8])) = 4 /* int ic_len */
		*(*uintptr)(unsafe.Pointer(&strioc[16])) = /* int ic_dp */
		    uintptr(unsafe.Pointer(&int_ppa[0]))

		new_ppa, err := ioctl(fd, I_STR, uintptr(unsafe.Pointer(&strioc[0])))
		if err == unix.EEXIST {
			/*
			 * This PPA appears to be in use; try the next one.
			 */
			continue
		} else if err != nil {
			return -1, fmt.Errorf("PPA allocation failure: %v", err)
		}

		return new_ppa, nil
	}

	return -1, fmt.Errorf("PPA allocation failure: all PPAs are busy")
}

/*
 * Read bytes from the TUN device into this slice, and return the number of
 * bytes we read.
 */
func (tun *NativeTun) read_tun(buf []byte) (int, error) {
	// struct strbuf { /* 0x10 bytes */
	//         int maxlen; /* offset: 0 bytes */
	//         int len; /* offset: 4 bytes */
	//         caddr_t buf; /* offset: 8 bytes */
	// };
	sbuf := make([]byte, 0x10) /* struct strbuf */
	*(*int32)(unsafe.Pointer(&sbuf[0])) = int32(len(buf)) /* int maxlen */
	*(*uintptr)(unsafe.Pointer(&sbuf[8])) = /* caddr_t buf */
	    uintptr(unsafe.Pointer(&buf[0]))

	var flags int32 = 0

	_, err := getmsg(int(tun.tunFile.Fd()), uintptr(0),
	    uintptr(unsafe.Pointer(&sbuf[0])),
	    uintptr(unsafe.Pointer(&flags)))
	if err != nil {
		return -1, fmt.Errorf("TUN read failure: %v", err)
	}

	return int(*(*int32)(unsafe.Pointer(&sbuf[4]))), /* int len */
	    nil
}

func (tun *NativeTun) write_tun(buf []byte) (int, error) {
	// struct strbuf { /* 0x10 bytes */
	//         int maxlen; /* offset: 0 bytes */
	//         int len; /* offset: 4 bytes */
	//         caddr_t buf; /* offset: 8 bytes */
	// };
	sbuf := make([]byte, 0x10) /* struct strbuf */
	*(*int32)(unsafe.Pointer(&sbuf[4])) = int32(len(buf)) /* int len */
	*(*uintptr)(unsafe.Pointer(&sbuf[8])) = /* caddr_t buf */
	    uintptr(unsafe.Pointer(&buf[0]))

	_, err := putmsg(int(tun.tunFile.Fd()), uintptr(0),
	    uintptr(unsafe.Pointer(&sbuf[0])), 0)
	if err != nil {
		return -1, fmt.Errorf("TUN write failure: %v", err)
	}

	return len(buf), nil
}
