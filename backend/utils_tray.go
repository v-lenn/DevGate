package main

import (
	"log"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

var (
	user32  = syscall.NewLazyDLL("user32.dll")
	shell32 = syscall.NewLazyDLL("shell32.dll")

	registerClass       = user32.NewProc("RegisterClassW")
	createWindowEx      = user32.NewProc("CreateWindowExW")
	defWindowProc       = user32.NewProc("DefWindowProcW")
	shellNotifyIcon     = shell32.NewProc("Shell_NotifyIconW")
	getMessage          = user32.NewProc("GetMessageW")
	translateMessage    = user32.NewProc("TranslateMessage")
	dispatchMessage     = user32.NewProc("DispatchMessageW")
	postQuitMessage     = user32.NewProc("PostQuitMessage")
	loadIcon            = user32.NewProc("LoadIconW")
	createPopupMenu     = user32.NewProc("CreatePopupMenu")
	appendMenu          = user32.NewProc("AppendMenuW")
	trackPopupMenu      = user32.NewProc("TrackPopupMenu")
	getCursorPos        = user32.NewProc("GetCursorPos")
	setForegroundWindow = user32.NewProc("SetForegroundWindow")
	findWindow          = user32.NewProc("FindWindowW")
	showWindow          = user32.NewProc("ShowWindow")
	destroyMenu         = user32.NewProc("DestroyMenu")
	shellExecute        = shell32.NewProc("ShellExecuteW")
)

const (
	NIM_ADD              = 0
	NIM_DELETE           = 2
	NIM_MODIFY           = 1
	NIF_MESSAGE          = 1
	NIF_ICON             = 2
	NIF_TIP              = 4
	NIF_INFO             = 0x00000010
	WM_USER              = 0x0400
	WM_TRAYICON          = WM_USER + 1
	WM_LBUTTONDBLCLK     = 0x0203
	WM_LBUTTONUP         = 0x0202
	WM_RBUTTONUP         = 0x0205
	NIN_BALLOONUSERCLICK = 0x0405
	IDI_APPLICATION      = 32512
	IDI_SHIELD           = 32518
	NIIF_WARNING         = 0x00000002

	MF_STRING       = 0x00000000
	MF_SEPARATOR    = 0x00000800
	TPM_RETURNCMD   = 0x0100
	TPM_RIGHTBUTTON = 0x0002
)

type WNDCLASSW struct {
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     syscall.Handle
	HIcon         syscall.Handle
	HCursor       syscall.Handle
	HbrBackground syscall.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
}

type NOTIFYICONDATAW struct {
	CbSize            uint32
	HWnd              syscall.Handle
	UID               uint32
	UFlags            uint32
	UCallbackMessage  uint32
	HIcon             syscall.Handle
	SzTip             [128]uint16
	DwState           uint32
	DwStateMask       uint32
	SzInfo            [256]uint16
	UTimeoutOrVersion uint32
	SzInfoTitle       [64]uint16
	DwInfoFlags       uint32
}

type POINT struct {
	X int32
	Y int32
}

type MSG struct {
	HWnd    syscall.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      [2]int32
}

var globalNid NOTIFYICONDATAW

func wndProc(hwnd syscall.Handle, msg uint32, wparam, lparam uintptr) uintptr {
	switch msg {
	case WM_TRAYICON:
		switch lparam {
		case WM_LBUTTONDBLCLK, NIN_BALLOONUSERCLICK:
			cfg := getSettings()
			if cfg.WebUIEnabled {
				openBrowser("http://localhost:8081")
			} else {
				titlePtr := syscall.StringToUTF16Ptr("DevGate Intercept")
				hwndCLI, _, _ := findWindow.Call(0, uintptr(unsafe.Pointer(titlePtr)))
				if hwndCLI != 0 {
					showWindow.Call(hwndCLI, 9) // SW_RESTORE
					setForegroundWindow.Call(hwndCLI)
				}
			}
		case WM_RBUTTONUP:
			// show context menu
			hMenu, _, _ := createPopupMenu.Call()
			if hMenu != 0 {
				appendMenu.Call(hMenu, MF_STRING, 1001, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Open Dashboard"))))
				appendMenu.Call(hMenu, MF_SEPARATOR, 0, 0)
				appendMenu.Call(hMenu, MF_STRING, 1002, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Exit"))))

				var pt POINT
				getCursorPos.Call(uintptr(unsafe.Pointer(&pt)))

				// set foreground window is required so that the menu closes when clicking elsewhere
				setForegroundWindow.Call(uintptr(hwnd))

				id, _, _ := trackPopupMenu.Call(
					hMenu,
					TPM_RETURNCMD|TPM_RIGHTBUTTON,
					uintptr(pt.X),
					uintptr(pt.Y),
					0,
					uintptr(hwnd),
					0,
				)

				// workaround: post a dummy WM_NULL message to force task switch,
				// allowing the context menu to disappear when clicking elsewhere.
				postMessage := user32.NewProc("PostMessageW")
				postMessage.Call(uintptr(hwnd), 0, 0, 0) // 0 is WM_NULL

				destroyMenu.Call(hMenu)

				if id == 1001 {
					openBrowser("http://localhost:8081")
				} else if id == 1002 {
					removeTrayIcon()
					os.Exit(0)
				}
			}
		}
	case 2: // WM_DESTROY
		postQuitMessage.Call(0)
	}
	ret, _, _ := defWindowProc.Call(uintptr(hwnd), uintptr(msg), wparam, lparam)
	return ret
}

func startTrayIcon() {
	runtime.LockOSThread()
	className, _ := syscall.UTF16PtrFromString("DevGateTrayClass")
	wc := WNDCLASSW{
		LpfnWndProc:   syscall.NewCallback(wndProc),
		LpszClassName: className,
	}
	registerClass.Call(uintptr(unsafe.Pointer(&wc)))

	hwnd, _, _ := createWindowEx.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(className)),
		0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	)
	if hwnd == 0 {
		log.Printf("[Warning] Windows Tray Window creation failed (running in headless mode).")
		select {} // block forever
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getModuleHandle := kernel32.NewProc("GetModuleHandleW")
	hInst, _, _ := getModuleHandle.Call(0)

	hIcon, _, _ := loadIcon.Call(hInst, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("APP"))))
	if hIcon == 0 {
		hIcon, _, _ = loadIcon.Call(0, uintptr(IDI_SHIELD))
	}
	if hIcon == 0 {
		hIcon, _, _ = loadIcon.Call(0, uintptr(IDI_APPLICATION))
	}

	globalNid.CbSize = uint32(unsafe.Sizeof(globalNid))
	globalNid.HWnd = syscall.Handle(hwnd)
	globalNid.UID = 1
	globalNid.UFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
	globalNid.UCallbackMessage = WM_TRAYICON
	globalNid.HIcon = syscall.Handle(hIcon)

	tipBytes, _ := syscall.UTF16FromString("DevGate - Zero-Trust Developer Proxy")
	copy(globalNid.SzTip[:], tipBytes)

	shellNotifyIcon.Call(NIM_ADD, uintptr(unsafe.Pointer(&globalNid)))

	var msg MSG
	for {
		ret, _, _ := getMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if ret == 0 {
			break
		}
		translateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		dispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func removeTrayIcon() {
	if globalNid.HWnd != 0 {
		shellNotifyIcon.Call(NIM_DELETE, uintptr(unsafe.Pointer(&globalNid)))
	}
}

func showNotification(title, msg string) {
	if globalNid.HWnd == 0 {
		return
	}

	nid := globalNid
	nid.UFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_INFO

	titleBytes, _ := syscall.UTF16FromString(title)
	copy(nid.SzInfoTitle[:], titleBytes)

	msgBytes, _ := syscall.UTF16FromString(msg)
	copy(nid.SzInfo[:], msgBytes)

	nid.DwInfoFlags = NIIF_WARNING

	shellNotifyIcon.Call(NIM_MODIFY, uintptr(unsafe.Pointer(&nid)))
}

func openBrowser(url string) {
	verbPtr := syscall.StringToUTF16Ptr("open")
	urlPtr := syscall.StringToUTF16Ptr(url)
	shellExecute.Call(0, uintptr(unsafe.Pointer(verbPtr)), uintptr(unsafe.Pointer(urlPtr)), 0, 0, 1)
}

func showPopup(title, msg string) {
	messageBox := user32.NewProc("MessageBoxW")
	textPtr, _ := syscall.UTF16PtrFromString(msg)
	captionPtr, _ := syscall.UTF16PtrFromString(title)
	// MB_OK = 0x00000000, MB_ICONWARNING = 0x00000030, MB_SETFOREGROUND = 0x00010000, MB_TOPMOST = 0x00040000
	messageBox.Call(0, uintptr(unsafe.Pointer(textPtr)), uintptr(unsafe.Pointer(captionPtr)), 0x00000030|0x00010000|0x00040000)
}
