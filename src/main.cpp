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

constexpr UINT WM_APP_DONE = WM_APP + 1;

enum {
    IDC_HINT = 101,
    IDC_CONNECT = 104,
    IDC_STATUS = 105,
};

HWND g_hint = nullptr;
HWND g_connect = nullptr;
HWND g_status = nullptr;
HFONT g_font = nullptr;
bool g_busy = false;

void refresh_connect_button() {
    const bool on = oc::is_connected();
    SetWindowTextW(g_connect, on ? L"Disconnect" : L"Connect");
    SetWindowTextW(g_status, on ? L"Status: connected" : L"Status: disconnected");
    EnableWindow(g_connect, g_busy ? FALSE : TRUE);
}

void layout(HWND hwnd) {
    RECT rc{};
    GetClientRect(hwnd, &rc);
    const int x = 16;
    const int y = 16;
    const int w = rc.right - 32;
    if (w < 40) return;

    MoveWindow(g_hint, x, y, w, 48, TRUE);
    MoveWindow(g_connect, x, y + 60, 120, 28, TRUE);
    MoveWindow(g_status, x + 132, y + 64, w - 132, 20, TRUE);
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

            g_hint = make(hwnd, L"STATIC",
                          L"Press Connect, then launch osu!lazer and sign in with your osudesu account.",
                          WS_VISIBLE | SS_LEFT, IDC_HINT);
            g_connect = make(hwnd, L"BUTTON", L"Connect", WS_VISIBLE | BS_DEFPUSHBUTTON, IDC_CONNECT);
            g_status = make(hwnd, L"STATIC", L"Status: disconnected", WS_VISIBLE | SS_LEFT, IDC_STATUS);

            refresh_connect_button();
            return 0;
        }
        case WM_SIZE:
            layout(hwnd);
            return 0;
        case WM_COMMAND: {
            if (HIWORD(wp) == BN_CLICKED || HIWORD(wp) == 0) {
                const int id = LOWORD(wp);
                if (id == IDC_CONNECT) do_connect_async(hwnd);
            }
            return 0;
        }
        case WM_APP_DONE: {
            g_busy = false;
            auto* err = (std::string*)lp;
            if (!wp && err)
                MessageBoxW(hwnd, oc::utf16(*err).c_str(), oc::kAppTitle, MB_ICONERROR);
            delete err;
            refresh_connect_button();
            return 0;
        }
        case WM_CLOSE:
            if (oc::is_connected()) oc::disconnect_now();
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
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
    oc::recover_hosts_on_startup();

    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_STANDARD_CLASSES};
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
                                WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT, 520, 180,
                                nullptr, nullptr, inst, nullptr);
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
