#include "common.hpp"
#include "connector.hpp"
#include "certs.hpp"

#include <commctrl.h>

#include <cstdio>
#include <string>
#include <thread>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

namespace {

constexpr UINT WM_APP_LOG = WM_APP + 1;
constexpr UINT WM_APP_DONE = WM_APP + 2;

enum {
    IDC_TAB = 100,
    IDC_HINT = 101,
    IDC_CONNECT = 104,
    IDC_STATUS = 105,
    IDC_LOGS = 106,
    IDC_CLEAR = 107,
};

HWND g_wnd = nullptr;
HWND g_tab = nullptr;
HWND g_hint = nullptr;
HWND g_connect = nullptr;
HWND g_status = nullptr;
HWND g_logs = nullptr;
HWND g_clear = nullptr;
HFONT g_font = nullptr;
bool g_busy = false;

void append_log(const char* line) {
    if (!g_wnd || !line) return;
    auto* heap = new std::string(line);
    if (!PostMessageW(g_wnd, WM_APP_LOG, 0, (LPARAM)heap)) delete heap;
}

void logger_thunk(const char* line) { append_log(line); }

std::wstring now_stamp() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    wchar_t buf[40];
    swprintf(buf, 40, L"%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
    return buf;
}

void ui_append_log(const std::string& line) {
    if (!g_logs) return;
    int len = GetWindowTextLengthW(g_logs);
    SendMessageW(g_logs, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    std::wstring w = now_stamp() + L"  " + oc::utf16(line) + L"\r\n";
    SendMessageW(g_logs, EM_REPLACESEL, FALSE, (LPARAM)w.c_str());
}

void refresh_connect_button() {
    const bool on = oc::is_connected();
    SetWindowTextW(g_connect, on ? L"Disconnect" : L"Connect");
    SetWindowTextW(g_status, on ? L"Status: connected" : L"Status: disconnected");
    EnableWindow(g_connect, g_busy ? FALSE : TRUE);
}

void show_tab(int i) {
    const BOOL conn = (i == 0) ? TRUE : FALSE;
    const BOOL logs = (i == 1) ? TRUE : FALSE;
    ShowWindow(g_hint, conn);
    ShowWindow(g_connect, conn);
    ShowWindow(g_status, conn);
    ShowWindow(g_logs, logs);
    ShowWindow(g_clear, logs);
}

void layout(HWND hwnd) {
    RECT rc{};
    GetClientRect(hwnd, &rc);
    MoveWindow(g_tab, 0, 0, rc.right, rc.bottom, TRUE);

    RECT inner = rc;
    TabCtrl_AdjustRect(g_tab, FALSE, &inner);
    const int x = inner.left + 12;
    const int y = inner.top + 12;
    const int w = inner.right - inner.left - 24;
    const int h = inner.bottom - inner.top - 24;
    if (w < 40 || h < 40) return;

    MoveWindow(g_hint, x, y, w, 48, TRUE);
    MoveWindow(g_connect, x, y + 60, 120, 28, TRUE);
    MoveWindow(g_status, x + 132, y + 64, w - 132, 20, TRUE);

    MoveWindow(g_logs, x, y, w, h - 36, TRUE);
    MoveWindow(g_clear, x, y + h - 28, 80, 24, TRUE);
}

void do_connect_async(HWND hwnd) {
    if (g_busy) return;
    if (oc::is_connected()) {
        g_busy = true;
        refresh_connect_button();
        std::thread([hwnd]() {
            oc::disconnect_now();
            PostMessageW(hwnd, WM_APP_DONE, 1, 0);
        }).detach();
        return;
    }
    g_busy = true;
    refresh_connect_button();
    std::thread([hwnd]() {
        std::string err;
        bool ok = oc::connect_now(err);
        auto* heap = ok ? nullptr : new std::string(err);
        PostMessageW(hwnd, WM_APP_DONE, ok ? 1 : 0, (LPARAM)heap);
    }).detach();
}

HWND make(HWND parent, const wchar_t* cls, const wchar_t* text, DWORD style, int id) {
    HWND h = CreateWindowExW(0, cls, text, WS_CHILD | style, 0, 0, 10, 10, parent, (HMENU)(INT_PTR)id,
                             GetModuleHandleW(nullptr), nullptr);
    SendMessageW(h, WM_SETFONT, (WPARAM)g_font, TRUE);
    return h;
}

LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE: {
            g_font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

            g_tab = CreateWindowExW(0, WC_TABCONTROLW, L"", WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                                    0, 0, 100, 100, hwnd, (HMENU)IDC_TAB, GetModuleHandleW(nullptr), nullptr);
            SendMessageW(g_tab, WM_SETFONT, (WPARAM)g_font, TRUE);
            TCITEMW item{};
            item.mask = TCIF_TEXT;
            item.pszText = const_cast<wchar_t*>(L"Connection");
            TabCtrl_InsertItem(g_tab, 0, &item);
            item.pszText = const_cast<wchar_t*>(L"Logs");
            TabCtrl_InsertItem(g_tab, 1, &item);

            g_hint = make(hwnd, L"STATIC",
                          L"Press Connect, then launch osu!lazer and sign in with your osudesu account.",
                          WS_VISIBLE | SS_LEFT, IDC_HINT);
            g_connect = make(hwnd, L"BUTTON", L"Connect", WS_VISIBLE | BS_DEFPUSHBUTTON, IDC_CONNECT);
            g_status = make(hwnd, L"STATIC", L"Status: disconnected", WS_VISIBLE | SS_LEFT, IDC_STATUS);

            g_logs = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                     WS_CHILD | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL |
                                         ES_WANTRETURN,
                                     0, 0, 10, 10, hwnd, (HMENU)IDC_LOGS, GetModuleHandleW(nullptr), nullptr);
            SendMessageW(g_logs, WM_SETFONT, (WPARAM)g_font, TRUE);
            SendMessageW(g_logs, EM_SETLIMITTEXT, 8 * 1024 * 1024, 0);
            g_clear = make(hwnd, L"BUTTON", L"Clear", BS_PUSHBUTTON, IDC_CLEAR);

            oc::set_logger(logger_thunk);
            oc::log_exe_identity();
            oc::log("Ready. Press Connect.");
            refresh_connect_button();
            show_tab(0);
            return 0;
        }
        case WM_SIZE:
            layout(hwnd);
            return 0;
        case WM_NOTIFY: {
            auto* hdr = (NMHDR*)lp;
            if (hdr->idFrom == IDC_TAB && hdr->code == TCN_SELCHANGE)
                show_tab(TabCtrl_GetCurSel(g_tab));
            return 0;
        }
        case WM_COMMAND: {
            if (HIWORD(wp) == BN_CLICKED || HIWORD(wp) == 0) {
                const int id = LOWORD(wp);
                if (id == IDC_CONNECT) do_connect_async(hwnd);
                if (id == IDC_CLEAR) SetWindowTextW(g_logs, L"");
            }
            return 0;
        }
        case WM_APP_LOG: {
            auto* s = (std::string*)lp;
            if (s) {
                ui_append_log(*s);
                delete s;
            }
            return 0;
        }
        case WM_APP_DONE: {
            g_busy = false;
            auto* err = (std::string*)lp;
            if (!wp && err) {
                oc::log("Connect failed: %s", err->c_str());
                MessageBoxW(hwnd, oc::utf16(*err).c_str(), oc::kAppTitle, MB_ICONERROR);
            }
            delete err;
            refresh_connect_button();
            return 0;
        }
        case WM_CLOSE:
            if (oc::is_connected()) oc::disconnect_now();
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            oc::set_logger(nullptr);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

}  // namespace

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR cmd, int show) {
    if (cmd && wcsstr(cmd, L"--self-test")) {
        if (!oc::is_admin()) return 2;
        std::string err;
        oc::Cert cert;
        bool ok = oc::ensure_trusted_cert(cert, err);
        std::wstring path = oc::data_dir() + L"\\self-test.txt";
        FILE* f = nullptr;
        if (_wfopen_s(&f, path.c_str(), L"w") == 0 && f) {
            fprintf(f, "%s\n%s\n", ok ? "OK" : "FAIL", ok ? "certificate ready" : err.c_str());
            fclose(f);
        }
        return ok ? 0 : 1;
    }
    if (!oc::is_admin()) {
        if (!oc::relaunch_as_admin()) {
            MessageBoxW(nullptr,
                        L"Administrator rights are required.",
                        oc::kAppTitle, MB_ICONWARNING);
        }
        return 0;
    }

    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_STANDARD_CLASSES | ICC_TAB_CLASSES};
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"DesuswitchWnd";
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, oc::kAppTitle,
                                WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT, 560, 380,
                                nullptr, nullptr, inst, nullptr);
    g_wnd = hwnd;
    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);
    layout(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    return (int)msg.wParam;
}
