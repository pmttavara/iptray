// SPDX-FileCopyrightText: © 2026 Phillip Trudeau-Tavara <pmttavara@protonmail.com>
// SPDX-License-Identifier: 0BSD

#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <shellapi.h>

#pragma comment(linker, "-subsystem:windows")


typedef unsigned char      u8;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef int                bool;
#define true  1
#define false 0

static void xmemset(void *dst, int c, int n) {
    u8 *d = (u8 *)dst;
    while (n--) *d++ = (u8)c;
}
static void xmemcpy(void *dst, const void *src, int n) {
    const u8 *s = (const u8 *)src;
    u8 *d = (u8 *)dst;
    while (n--) *d++ = *s++;
}
static int xmemcmp(const void *a, const void *b, int n) {
    const u8 *p = (const u8 *)a, *q = (const u8 *)b;
    while (n--) { if (*p != *q) return *p - *q; p++; q++; }
    return 0;
}

// MSVC inserts a call to this when it detects a potential buffer overrun at compile
// time (/sdl or /GS array checks); we never actually hit it, but the symbol must exist.
void __cdecl __report_rangecheckfailure(void) { ExitProcess(255); }

// Pack four octets into a network-order IPADDR/in_addr (first octet = low byte).
#define IP4(a, b, c, d) ((IPAddr)((u8)(a) | ((u8)(b) << 8) | ((u8)(c) << 16) | ((u32)(u8)(d) << 24)))

#define PING_TARGET      IP4(1, 1, 1, 1)
#define PING_TIMEOUT_MS  300
#define PING_INTERVAL_MS 400             // ~2.5x/sec
#define PING_PAYLOAD     32              // ICMP echo payload bytes

#define STUN_SERVER      "stun.l.google.com" // free public STUN server
#define STUN_PORT        "19302"
#define STUN_TIMEOUT_MS  800             // how long to wait for a STUN reply
#define STUN_REFRESH_MS  30000           // re-check public IP every 30s while online

#define TRAY_ADD_DELAY_MS 200            // gap between each icon's first add, to coax ordering

#define WM_TRAY      (WM_APP + 1) // tray icon callback message
#define WM_NET_STATE (WM_APP + 2) // posted by the ping thread: wParam=online, lParam=ip
#define ID_EXIT      1            // context-menu command id

#define ICON_FONT       "Segoe UI" // font face for the octet digits
#define ICON_TEXT_BLEED 2          // stretch "999" this many px past the icon so the ink reaches the edges

// The notification area gives no left-to-right ordering guarantee, and it
// persists each icon's slot by (exe path, uID). To keep a manual arrangement
// from drifting, we identify each octet by a fixed GUID instead -- so once you
// drag them into order, that order sticks across restarts. The catch: a GUID is
// bound to this exe's path, so if the exe moves (or a stale one is registered),
// NIM_ADD is rejected; we detect that and transparently fall back to uID.
static const GUID g_guids[4] = {
    { 0x7a9e1c40, 0x2b6d, 0x4f81, { 0xa3, 0x55, 0x10, 0x07, 0x12, 0x00, 0x00, 0x00 } },
    { 0x7a9e1c40, 0x2b6d, 0x4f81, { 0xa3, 0x55, 0x10, 0x07, 0x12, 0x00, 0x00, 0x01 } },
    { 0x7a9e1c40, 0x2b6d, 0x4f81, { 0xa3, 0x55, 0x10, 0x07, 0x12, 0x00, 0x00, 0x02 } },
    { 0x7a9e1c40, 0x2b6d, 0x4f81, { 0xa3, 0x55, 0x10, 0x07, 0x12, 0x00, 0x00, 0x03 } },
};

// All of these are touched only on the UI thread (WndProc), so no locking.
static UINT g_taskbar_created;  // RegisterWindowMessage("TaskbarCreated")
static bool g_added;            // have the four icons been NIM_ADD'd yet?
static bool g_use_guid = true;  // identify icons by GUID? falls to false if the shell rejects it
static HICON g_icons[4];        // currently-shown icons, kept alive until replaced
static bool g_online;           // last state we drew, for redraw on TaskbarCreated
static u32  g_ip;               // last IP we drew

// Largest size whose worst-case "999" fits in w x h, then stretched horizontally
// so "999" spans the full width with no side gutter. One size for all four icons.
static HFONT make_fitting_font(HDC dc, int w, int h) {
    for (int size = h; size >= 4; size -= 1) {
        HFONT probe = CreateFontA(-size, 0, 0, 0, FW_REGULAR, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  ANTIALIASED_QUALITY, DEFAULT_PITCH | FF_DONTCARE, ICON_FONT);
        HGDIOBJ old = SelectObject(dc, probe);
        SIZE sz = {0};
        TEXTMETRICA tm = {0};
        GetTextExtentPoint32A(dc, "999", 3, &sz);
        GetTextMetricsA(dc, &tm);
        SelectObject(dc, old);
        DeleteObject(probe);
        if (sz.cx > 0 && sz.cx <= w && sz.cy <= h) {
            // Stretch the average char width so "999" overshoots the icon by
            // ICON_TEXT_BLEED px; centered + NOCLIP, the ink lands in the corners.
            int target = w + ICON_TEXT_BLEED;
            int avg = (tm.tmAveCharWidth * target + sz.cx / 2) / sz.cx;
            return CreateFontA(-size, avg, 0, 0, FW_REGULAR, FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                               ANTIALIASED_QUALITY, DEFAULT_PITCH | FF_DONTCARE, ICON_FONT);
        }
    }
    return CreateFontA(-4, 0, 0, 0, FW_REGULAR, FALSE, FALSE, FALSE,
                       DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                       ANTIALIASED_QUALITY, DEFAULT_PITCH | FF_DONTCARE, ICON_FONT);
}

// Render one octet in bright green (online) or red (offline) onto a transparent
// icon. Caller must DestroyIcon().
static HICON make_icon(const char *text, bool online) {
    int w = GetSystemMetrics(SM_CXSMICON);
    int h = GetSystemMetrics(SM_CYSMICON);
    if (w <= 0) w = 16;
    if (h <= 0) h = 16;

    BITMAPINFO bi = {0};
    bi.bmiHeader.biSize        = sizeof(bi.bmiHeader);
    bi.bmiHeader.biWidth       = w;
    bi.bmiHeader.biHeight      = -h; // negative -> top-down
    bi.bmiHeader.biPlanes      = 1;
    bi.bmiHeader.biBitCount    = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    HDC screen = GetDC(NULL);
    void *pixels = NULL;
    HBITMAP color = CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &pixels, NULL, 0);
    HDC dc = CreateCompatibleDC(screen);
    ReleaseDC(NULL, screen);
    if (!color || !dc) {
        if (dc) DeleteDC(dc);
        if (color) DeleteObject(color);
        return NULL;
    }

    HGDIOBJ old_bmp = SelectObject(dc, color);

    // Draw the digits in WHITE on the zeroed (transparent) DIB so each pixel's
    // brightness is the antialiased glyph coverage; we recolour from it below.
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(255, 255, 255));
    HFONT font = make_fitting_font(dc, w, h);
    HGDIOBJ old_font = SelectObject(dc, font);
    RECT text_rc = {0, 0, w, h};
    DrawTextA(dc, text, -1, &text_rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOCLIP);
    SelectObject(dc, old_font);
    DeleteObject(font);

    GdiFlush();

    // AND mask for legacy shells: colour->mono BitBlt keyed on black -> bg = 1
    // (transparent), glyph = 0 (opaque). Modern shells honour the alpha instead.
    HBITMAP mask = CreateBitmap(w, h, 1, 1, NULL);
    {
        HDC mdc = CreateCompatibleDC(NULL);
        HGDIOBJ old_mask = SelectObject(mdc, mask);
        SetBkColor(dc, RGB(0, 0, 0));
        BitBlt(mdc, 0, 0, w, h, dc, 0, 0, SRCCOPY);
        SelectObject(mdc, old_mask);
        DeleteDC(mdc);
    }

    // Recolour the white coverage into premultiplied green/red with matching
    // alpha, so the digits blend smoothly onto the transparent tray.
    {
        COLORREF fg = online ? RGB(0, 255, 0) : RGB(255, 0, 0);
        u32 fr = GetRValue(fg), fgc = GetGValue(fg), fb = GetBValue(fg);
        u32 *p = (u32 *)pixels;
        for (int i = 0; i < w * h; i += 1) {
            u32 a = p[i] & 0xFF; // grey coverage (r=g=b)
            u32 r = fr  * a / 255;
            u32 g = fgc * a / 255;
            u32 b = fb  * a / 255;
            p[i] = (a << 24) | (r << 16) | (g << 8) | b;
        }
    }

    SelectObject(dc, old_bmp);
    DeleteDC(dc);

    ICONINFO ii = {0};
    ii.fIcon    = TRUE;
    ii.hbmColor = color;
    ii.hbmMask  = mask;
    HICON icon = CreateIconIndirect(&ii); // copies the bitmaps

    DeleteObject(color);
    DeleteObject(mask);
    return icon;
}

// Ask a public STUN server what our address looks like from the outside -- i.e.
// our real, post-NAT, global IPv4. We're behind NAT so we can't know this on our
// own; STUN (RFC 5389) exists for exactly this and answers in one UDP round-trip,
// no HTTP/TLS needed. Returns the IP (network order, low byte = first octet) or 0.
static u32 get_public_ipv4(void) {
    u32 result = 0;

    struct addrinfo hints = {0};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    struct addrinfo *res = NULL;
    if (getaddrinfo(STUN_SERVER, STUN_PORT, &hints, &res) != 0 || !res) {
        return 0;
    }

    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(res);
        return 0;
    }

    // Don't let an unreachable STUN server stall the connectivity loop for long.
    int timeout = STUN_TIMEOUT_MS;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));

    // Build a 20-byte STUN Binding Request: type, length, magic cookie, then a
    // 96-bit transaction id we'll require the reply to echo back.
    u8 req[20] = {0};
    req[0] = 0x00; req[1] = 0x01;                               // Binding Request
    req[2] = 0x00; req[3] = 0x00;                               // 0 attribute bytes
    req[4] = 0x21; req[5] = 0x12; req[6] = 0xA4; req[7] = 0x42; // magic cookie
    {
        static u64 n = 0; // unique-enough transaction id; no crypto needed here
        u64 t = GetTickCount64();
        xmemcpy(req +  8, &t, 8);
        xmemcpy(req + 16, &n, 4);
        n++;
    }

    u8 buf[512];
    if (sendto(s, (const char *)req, sizeof(req), 0, res->ai_addr, (int)res->ai_addrlen) == (int)sizeof(req)) {
        int n = recvfrom(s, (char *)buf, sizeof(buf), 0, NULL, NULL);
        if (n >= 20 &&
            buf[0] == 0x01 && buf[1] == 0x01 &&                                     // Binding Success Response
            buf[4] == 0x21 && buf[5] == 0x12 && buf[6] == 0xA4 && buf[7] == 0x42 && // magic cookie
            xmemcmp(buf + 8, req + 8, 12) == 0) {                                   // our transaction id

            int msg_len = (buf[2] << 8) | buf[3];
            int end = 20 + msg_len;
            if (end > n) end = n;

            // Walk the TLV attributes looking for our mapped address.
            int o = 20;
            while (o + 4 <= end) {
                int atype = (buf[o + 0] << 8) | buf[o + 1];
                int alen  = (buf[o + 2] << 8) | buf[o + 3];
                int aval  = o + 4;
                if (aval + alen > end) {
                    break;
                }
                // XOR-MAPPED-ADDRESS (0x0020), IPv4 (family 0x01): the address is
                // stored XORed with the magic cookie, so un-XOR it byte by byte.
                if (atype == 0x0020 && alen >= 8 && buf[aval + 1] == 0x01) {
                    u8 a0 = buf[aval + 4] ^ 0x21;
                    u8 a1 = buf[aval + 5] ^ 0x12;
                    u8 a2 = buf[aval + 6] ^ 0xA4;
                    u8 a3 = buf[aval + 7] ^ 0x42;
                    result = a0 | (a1 << 8) | (a2 << 16) | ((u32)a3 << 24);
                    break;
                }
                // Plain MAPPED-ADDRESS (0x0001) from older servers: address as-is.
                // Take it only as a fallback; prefer XOR-MAPPED if it shows up.
                if (atype == 0x0001 && alen >= 8 && buf[aval + 1] == 0x01 && result == 0) {
                    u8 a0 = buf[aval + 4];
                    u8 a1 = buf[aval + 5];
                    u8 a2 = buf[aval + 6];
                    u8 a3 = buf[aval + 7];
                    result = a0 | (a1 << 8) | (a2 << 16) | ((u32)a3 << 24);
                }
                o = aval + ((alen + 3) & ~3); // attributes are padded to 4 bytes
            }
        }
    }

    closesocket(s);
    freeaddrinfo(res);
    return result;
}

// One ICMP echo to 1.1.1.1. true = a reply came back in time.
static bool ping_once(HANDLE icmp) {
    if (icmp == NULL || icmp == INVALID_HANDLE_VALUE) {
        return false;
    }
    char payload[PING_PAYLOAD];
    char reply[sizeof(ICMP_ECHO_REPLY) + PING_PAYLOAD + 8]; // documented minimum
    xmemset(payload, 'p', sizeof(payload));
    if (IcmpSendEcho(icmp, PING_TARGET, payload, (WORD)sizeof(payload),
                     NULL, reply, sizeof(reply), PING_TIMEOUT_MS) == 0) {
        return false; // timed out / no route
    }
    ICMP_ECHO_REPLY *r = (ICMP_ECHO_REPLY *)reply;
    return r->Status == IP_SUCCESS;
}

// Rebuild and (re)install all four tray icons from the given state.
static void update_tray(HWND hwnd, bool online, u32 ip) {
    int a = (ip >>  0) & 0xFF;
    int b = (ip >>  8) & 0xFF;
    int c = (ip >> 16) & 0xFF;
    int d = (ip >> 24) & 0xFF;

    char tip[64];
    wsprintfA(tip, "%d.%d.%d.%d (%s)", a, b, c, d, online ? "online" : "OFFLINE");

    bool first = !g_added;
    for (int k = 0; k < 4; k += 1) {
        // On first install, add right-to-left with a gap between each: the shell
        // inserts new icons at the left end, so adding octet 3 first settles them
        // into 0..3 order, and the delay stops a rapid burst from being reordered.
        int i = first ? 3 - k : k;
        if (first && k > 0) {
            Sleep(TRAY_ADD_DELAY_MS);
        }

        int octet = (ip >> (8 * i)) & 0xFF;
        char text[8];
        wsprintfA(text, "%d", octet);
        HICON icon = make_icon(text, online);

        NOTIFYICONDATAA nid = {0};
        nid.cbSize           = sizeof(nid);
        nid.hWnd             = hwnd;
        nid.uID              = i;
        nid.uFlags           = NIF_ICON | NIF_TIP | NIF_MESSAGE;
        nid.uCallbackMessage = WM_TRAY;
        nid.hIcon            = icon;
        lstrcpynA(nid.szTip, tip, sizeof(nid.szTip));
        if (g_use_guid) {
            nid.uFlags  |= NIF_GUID;
            nid.guidItem = g_guids[i];
        }

        if (!first) {
            Shell_NotifyIconA(NIM_MODIFY, &nid);
        } else {
            // First install. Clear any stale registration left by a crashed or
            // force-killed instance, then add. If the GUID is rejected (e.g. the
            // exe moved and the shell thinks another path owns it), fall back to
            // plain uID-identified icons.
            if (g_use_guid) {
                NOTIFYICONDATAA del = {0};
                del.cbSize   = sizeof(del);
                del.hWnd     = hwnd;
                del.uFlags   = NIF_GUID;
                del.guidItem = g_guids[i];
                Shell_NotifyIconA(NIM_DELETE, &del); // ignore result
            }
            if (!Shell_NotifyIconA(NIM_ADD, &nid) && g_use_guid) {
                g_use_guid  = false;
                nid.uFlags &= ~NIF_GUID;
                Shell_NotifyIconA(NIM_ADD, &nid);
            }
        }

        // The shell references our icon until we replace it, so only now is it
        // safe to free the previous one for this slot.
        if (g_icons[i]) {
            DestroyIcon(g_icons[i]);
        }
        g_icons[i] = icon;
    }
    g_added  = true;
    g_online = online;
    g_ip     = ip;
}

static void remove_tray(HWND hwnd) {
    for (int i = 0; i < 4; i += 1) {
        NOTIFYICONDATAA nid = {0};
        nid.cbSize = sizeof(nid);
        nid.hWnd   = hwnd;
        nid.uID    = i;
        if (g_use_guid) {
            nid.uFlags   = NIF_GUID;
            nid.guidItem = g_guids[i];
        }
        Shell_NotifyIconA(NIM_DELETE, &nid);
        if (g_icons[i]) {
            DestroyIcon(g_icons[i]);
            g_icons[i] = NULL;
        }
    }
    g_added = false;
}

static void show_context_menu(HWND hwnd) {
    POINT pt;
    GetCursorPos(&pt);
    HMENU menu = CreatePopupMenu();
    AppendMenuA(menu, MF_STRING, ID_EXIT, "Exit IPtray");
    SetForegroundWindow(hwnd); // so the menu dismisses when you click elsewhere
    TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
    DestroyMenu(menu);
}

static DWORD WINAPI ping_thread(LPVOID param) {
    HWND hwnd = (HWND)param;
    HANDLE icmp = IcmpCreateFile();

    u32 public_ip = 0;     // last public IP we learned from STUN (cached)
    u32 last_ip_check = 0; // GetTickCount() of the last STUN query

    bool     have_last = false;
    bool     last_online = false;
    u32      last_ip = 0;
    for (;;) {
        int start = GetTickCount();

        bool online = ping_once(icmp);

        // The cheap ICMP ping drives green/red every loop. The public IP barely
        // ever changes, so only hit STUN on the first connect, right after we
        // come back online, or once every STUN_REFRESH_MS while online.
        if (online) {
            bool just_came_online = (!have_last || !last_online);
            if (public_ip == 0 || just_came_online || start - (int)last_ip_check >= STUN_REFRESH_MS) {
                u32 got = get_public_ipv4();
                if (got) {
                    public_ip = got; // keep the last good value if a single query fails
                }
                last_ip_check = (u32)start;
            }
        }
        u32 ip = public_ip;

        // Only bother the UI thread when something actually changed.
        if (!have_last || online != last_online || ip != last_ip) {
            PostMessageA(hwnd, WM_NET_STATE, (WPARAM)online, (LPARAM)ip);
            have_last   = true;
            last_online = online;
            last_ip     = ip;
        }

        // A failed ping already burned ~PING_TIMEOUT_MS, so this mostly paces
        // the successful case to PING_INTERVAL_MS between pings.
        int elapsed = GetTickCount() - start;
        if (elapsed < PING_INTERVAL_MS) {
            Sleep(PING_INTERVAL_MS - elapsed);
        }
    }
}

static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    // Explorer restarted -> the taskbar forgot our icons; add them back.
    if (msg == g_taskbar_created) {
        g_added = false;
        update_tray(hwnd, g_online, g_ip);
        return 0;
    }
    switch (msg) {
        case WM_NET_STATE: {
            update_tray(hwnd, (bool)wp, (u32)lp);
            return 0;
        }
        case WM_TRAY: {
            UINT ev = LOWORD(lp);
            if (ev == WM_RBUTTONUP || ev == WM_CONTEXTMENU || ev == WM_LBUTTONUP) {
                show_context_menu(hwnd);
            }
            return 0;
        }
        case WM_COMMAND: {
            if (LOWORD(wp) == ID_EXIT) {
                DestroyWindow(hwnd);
            }
            return 0;
        }
        case WM_DESTROY: {
            remove_tray(hwnd);
            PostQuitMessage(0);
            return 0;
        }
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

static int iptray_main(HINSTANCE hInstance) {
    // Without this the shell hands our 16px icons a blurry upscale on HiDPI;
    // being DPI-aware makes SM_CXSMICON report real pixels so we render crisp.
    SetProcessDPIAware();

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    g_taskbar_created = RegisterWindowMessageA("TaskbarCreated");

    WNDCLASSA wc = {0};
    wc.lpfnWndProc   = wnd_proc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = "iptray_wndclass";
    if (!RegisterClassA(&wc)) {
        return 1;
    }

    // A real (top-level) window so we still catch the TaskbarCreated broadcast,
    // but we never ShowWindow() it -- it stays invisible.
    HWND hwnd = CreateWindowExA(0, "iptray_wndclass", "iptray", WS_OVERLAPPED,
                                0, 0, 0, 0, NULL, NULL, hInstance, NULL);
    if (!hwnd) {
        return 1;
    }

    CreateThread(NULL, 0, ping_thread, hwnd, 0, NULL); // first ping does the NIM_ADD

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    WSACleanup();
    return 0;
}

void WinMainCRTStartup(void) {
    ExitProcess((UINT)iptray_main(GetModuleHandleA(NULL)));
}
