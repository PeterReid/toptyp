// totp.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "toptyp.h"
#include <commctrl.h>
#include <stdint.h>
#define MAX_LOADSTRING 100
#define MAX_PASSWORD_LENGTH 255

// Global Variables:
HINSTANCE hInst;								// current instance
TCHAR szTitle[MAX_LOADSTRING];					// The title bar text
TCHAR szWindowClass[MAX_LOADSTRING];			// the main window class name

wchar_t passwordWindowBuf[MAX_PASSWORD_LENGTH];

// Forward declarations of functions included in this code module:
ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	About(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	SetPasswordDlg(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	EnterPasswordDlg(HWND, UINT, WPARAM, LPARAM);

HWND mainWnd = NULL;

HWND accountSearchEdit = NULL;
HWND scroll = NULL;
int scrollBarIsForAccountCount = 0;

HFONT iconFont = NULL;
HFONT font = NULL;

int activeTab = 0;
int trackingMouseLeave = false;

UINT_PTR codeDrawingProgressTimer = 0;

#define COPIED_USING_KEYBOARD -2
int copiedFromItem = -1;
char copiedCodeUtf8[50] = { 0 };
uint32_t editingAccountIndex = 0;

extern "C" {
	uint32_t load_accounts();
	uint32_t accounts_len();
	uint32_t get_account_name(uint32_t index, uint8_t *dest, uint32_t dest_len);
	uint32_t get_account_qr_code(uint32_t index, uint8_t* dest, uint32_t dest_len, uint32_t* side_len);
	
	uint32_t unfiltered_accounts_len();
	uint32_t get_backup_needed();
	uint32_t dismiss_backup_reminder();
	uint32_t describe_error(uint32_t code, uint8_t* dest, uint32_t dest_len);

	uint32_t get_code(uint32_t index, uint8_t *dest, uint32_t dest_len, uint32_t *millis_per_code, uint32_t *millis_into_code);
	uint32_t add_account(uint8_t *name, uint8_t *code, uint32_t algorithm, uint32_t digits, uint32_t period);
	uint32_t delete_account(uint32_t index);
	uint32_t get_account(uint32_t index, uint32_t from_scan_results, uint8_t *name, uint32_t name_len, uint8_t *code, uint32_t code_len, uint32_t *algorithm, uint32_t *digits, uint32_t *period);
	uint32_t edit_account(uint32_t index, uint8_t *name, uint8_t *code, uint32_t algorithm, uint32_t digits, uint32_t period);
	uint32_t scan(uint8_t *brightness, uint32_t width, uint32_t height);
	uint32_t scan_result_count();
	//uint32_t get_scan_result_name(uint32_t index, uint8_t *dest, uint32_t dest_len);
	uint32_t add_scan_result(uint32_t index, uint8_t* name);
	uint32_t set_search_query(uint8_t* query);
	uint32_t export_to_file_on_windows(uint16_t* path);
	uint32_t export_to_clipboard();
	uint32_t export_encrypted_to_clipboard(uint8_t *password);
	uint32_t import_from_clipboard(uint8_t* password);
	uint32_t import_retry(uint8_t *password);
	uint32_t export_to_encrypted_file_on_windows(uint16_t* path, uint8_t *password);
	uint32_t import_on_windows(uint16_t* path, uint8_t* password);
}

HBITMAP CreateRoundedCorner(HDC dc, COLORREF inside, COLORREF border, COLORREF outside, int radius);

HCURSOR handCursor = NULL, arrowCursor = NULL;


RECT editArea;
RECT scrollRect;
bool showingBackupReminder = false;
int sizeBasis = 0;
int bottomButtonHeight = 0;
int textBoxHeight = 0;

void SetActiveTab(int idc, bool andShow);

int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	InitCommonControls();

	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

 	// TODO: Place code here.
	MSG msg;
	HACCEL hAccelTable;

	// Initialize global strings
	LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadString(hInstance, IDC_TOTP, szWindowClass, MAX_LOADSTRING);
	MyRegisterClass(hInstance);

	uint32_t ret = load_accounts();

	// Perform application initialization:
	if (!InitInstance (hInstance, nCmdShow))
	{
		return FALSE;
	}

	hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_TOTP));
	handCursor = LoadCursor(NULL, IDC_HAND);
	arrowCursor = LoadCursor(NULL, IDC_ARROW);

	// Main message loop:
	while (GetMessage(&msg, NULL, 0, 0))
	{
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
		{
			if (IsDialogMessage(mainWnd, &msg) == 0)
			{
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
		}
	}

	return (int) msg.wParam;
}

void InvalidateAboveToolbar()
{
	RECT r;
	GetClientRect(mainWnd, &r);
	r.bottom -= bottomButtonHeight;
	InvalidateRect(mainWnd, &r, TRUE);
}


//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
//  COMMENTS:
//
//    This function and its usage are only necessary if you want this code
//    to be compatible with Win32 systems prior to the 'RegisterClassEx'
//    function that was added to Windows 95. It is important to call this function
//    so that the application will get 'well formed' small icons associated
//    with it.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= WndProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInstance;
	wcex.hIcon			= LoadIcon(hInstance, MAKEINTRESOURCE(IDI_TOTP));
	wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);
	wcex.lpszMenuName	= MAKEINTRESOURCE(IDC_TOTP);
	wcex.hbrBackground	= (HBRUSH)(COLOR_WINDOW+1);
	wcex.lpszClassName	= szWindowClass;
	wcex.hIconSm		= LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_TOTP));

	return RegisterClassEx(&wcex);
}

int ButtonIconMiddle(int bottom) {
	return bottom*4/11;
}
int ButtonLineWeight(int bottom) {
	return bottom/12 & ~1;
}

void DrawButtonBackground(HDC hdc, RECT r, LPCTSTR text, COLORREF textColor, bool focused) {
	HBRUSH br = CreateSolidBrush(RGB(230,230,230));
	FillRect(hdc, &r, br);
			
	SetBkMode(hdc, TRANSPARENT);
	HGDIOBJ oldObj = SelectObject(hdc, iconFont);

	RECT textRect = r;
	textRect.bottom -= textRect.bottom/8;

	COLORREF oldColor = SetTextColor(hdc, textColor);
	DrawText(hdc, text, -1, &textRect, DT_SINGLELINE|DT_CENTER|DT_BOTTOM);
	SetTextColor(hdc, oldColor);


	if (focused) {
		RECT focusRect = r;
		InflateRect(&focusRect, -sizeBasis / 4, -sizeBasis / 4);
		DrawFocusRect(hdc, &focusRect);
	}

	HBRUSH topLineBrush = CreateSolidBrush(RGB(200,200,200));
	SelectObject(hdc, topLineBrush);
	r.bottom = r.top + 1;
	FillRect(hdc, &r, topLineBrush);


	SelectObject(hdc, oldObj);

	DeleteObject(br);
	DeleteObject(topLineBrush);
}

COLORREF TabForegroundColor(bool selected)
{
	return selected ? RGB(240,30,30) : RGB(0,0,0);
}

struct TabButtonData {
	ULONGLONG clickTickCount;
	ULONGLONG focusTickCount;
} scanButtonData = { 0 }, addButtonData = { 0 }, accountsButtonData = { 0 };

bool ShouldDrawFocus(HWND wnd, TabButtonData* data)
{
	// For a user tabbing through all the controls, it is important to show when the
	// buttons along the bottom have focus. But for a user clicking on the tab buttons,
	// focus moves to the when the mouse button goes down on the button and then moves
	// away when the mouse button comes back up and the new tab control gains focus.
	// This causes an unsightly flash of the focus indicator. To avoid that, I want to 
	// hide the focus indicator when the focus is gained through a click. During a click
	// to focus, there is a WM_LBUTTONDOWN immediately followed by a WM_SETFOCUS. By
	// tracking the timing of those, we can hide the focus indicator when appropriate.
	return wnd == GetFocus() && data->focusTickCount - data->clickTickCount > 100;
}

LRESULT CALLBACK ScanButtonProc(HWND hWnd, UINT uMsg, WPARAM wParam,
                               LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
	PAINTSTRUCT ps;
	HDC hdc;
    switch (uMsg)
    {
	case WM_ERASEBKGND:
		return TRUE;
	case WM_SETFOCUS:
		scanButtonData.focusTickCount = ::GetTickCount64();
		break;
	case WM_LBUTTONDOWN:
		scanButtonData.clickTickCount = ::GetTickCount64();
		break;
    case WM_PAINT:
		hdc = BeginPaint(hWnd, &ps);
		{
			COLORREF foreground = TabForegroundColor(activeTab == IDC_TAB_SCAN);

			RECT r;
			GetClientRect(hWnd, &r);
			
			int qrMiddle = ButtonIconMiddle(r.bottom);
			int qrHeight = r.bottom / 3;
			int qrScale = 1;
			while (qrHeight > 34) {
				qrHeight /= 2;
				qrScale *= 2;
			}

			int rng = 1234;

			HBITMAP bmp = CreateCompatibleBitmap(hdc, qrHeight, qrHeight);
			HDC bmpDc = CreateCompatibleDC(hdc);
			SelectObject(bmpDc, bmp);
			for (int x=0; x<qrHeight; x++) {
				for (int y=0; y<qrHeight; y++) {
					SetPixel(bmpDc, x, y, x==0 || y==0 || x+1==qrHeight||y+1==qrHeight || (rng&1) ? RGB(255,255,255) : foreground);
					rng = (75 * rng + 74) % 65537;
				}
			}

			for (int i=0; i<3; i++) {
				int baseX = (i&1) * (qrHeight - 9) + 4;
				int baseY = ((i&2)>>1) * (qrHeight - 9) + 4;

				for (int dx=-4; dx<=4; dx++) {
					for (int dy=-4; dy<=4; dy++) {
						int distance = max(abs(dx), abs(dy));
						SetPixel(bmpDc, baseX+dx, baseY+dy, distance%2 || distance==0 ? foreground : RGB(255,255,255));
					}
				}

			}

			DrawButtonBackground(hdc, r, L"Scan", foreground, ShouldDrawFocus(hWnd, &scanButtonData));
			StretchBlt(hdc, r.right/2 - qrScale * qrHeight / 2, qrMiddle - qrHeight*qrScale/2, qrScale*qrHeight, qrScale*qrHeight, bmpDc, 0,0, qrHeight, qrHeight, SRCCOPY);

			DeleteDC(bmpDc);
			DeleteObject(bmp);

			EndPaint(hWnd, &ps);
		}
        return TRUE;
    } 
    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}


LRESULT CALLBACK AddButtonProc(HWND hWnd, UINT uMsg, WPARAM wParam,
                               LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
	PAINTSTRUCT ps;
	HDC hdc;
    switch (uMsg)
    {
	case WM_SETFOCUS:
		addButtonData.focusTickCount = ::GetTickCount64();
		break;
	case WM_LBUTTONDOWN:
		addButtonData.clickTickCount = ::GetTickCount64();
		break;
	case WM_ERASEBKGND:
		return TRUE;
    case WM_PAINT:
		hdc = BeginPaint(hWnd, &ps);
		{
			COLORREF foreground = TabForegroundColor(activeTab == IDC_TAB_ADD);

			RECT r;
			GetClientRect(hWnd, &r);
			DrawButtonBackground(hdc, r, L"Add", foreground, ShouldDrawFocus(hWnd, &addButtonData));
			
			int thickness = ButtonLineWeight(r.bottom);
			int plusMiddleX = r.right / 2;
			int plusMiddleY = ButtonIconMiddle(r.bottom);
			int length = r.bottom / 7;

			HBITMAP corners = CreateRoundedCorner(hdc, RGB(255,255,255), foreground, RGB(230,230,230), thickness/2);

			HDC cornersDC = CreateCompatibleDC(hdc);
			SelectObject(cornersDC, corners);

			HBRUSH plusBrush = CreateSolidBrush(foreground);
			RECT horizontalBar;
			horizontalBar.top = plusMiddleY - thickness/2;
			horizontalBar.bottom = plusMiddleY + thickness/2;
			horizontalBar.left = plusMiddleX - length;
			horizontalBar.right = plusMiddleX + length;

			BitBlt(hdc, horizontalBar.left - thickness/2, horizontalBar.top, thickness/2, thickness, cornersDC, 0,0,SRCCOPY);
			BitBlt(hdc, horizontalBar.right, horizontalBar.top, thickness/2, thickness, cornersDC, thickness/2,0,SRCCOPY);

			RECT verticalBar;
			verticalBar.top = plusMiddleY - length;
			verticalBar.bottom = plusMiddleY + length;
			verticalBar.left = plusMiddleX - thickness/2;
			verticalBar.right = plusMiddleX + thickness/2;

			
			BitBlt(hdc, verticalBar.left, verticalBar.top-thickness/2, thickness, thickness/2, cornersDC, 0,0,SRCCOPY);
			BitBlt(hdc, verticalBar.left, verticalBar.bottom, thickness, thickness/2, cornersDC, 0,thickness/2,SRCCOPY);

			{ // Draw the four segments that are the horizontal lines outlining the horizontal crossbar of the plus.
				RECT horizontalBarLine = horizontalBar;
				horizontalBarLine.right = plusMiddleX - thickness/2;
				horizontalBarLine.bottom = horizontalBarLine.top + 1;
				FillRect(hdc, &horizontalBarLine, plusBrush);
				horizontalBarLine.top = plusMiddleY + thickness/2 - 1;
				horizontalBarLine.bottom = horizontalBarLine.top + 1;
				FillRect(hdc, &horizontalBarLine, plusBrush);
				horizontalBarLine.left = plusMiddleX + thickness/2;
				horizontalBarLine.right = plusMiddleX + length;
				FillRect(hdc, &horizontalBarLine, plusBrush);
				horizontalBarLine.top = plusMiddleY - thickness/2;
				horizontalBarLine.bottom = horizontalBarLine.top + 1;
				FillRect(hdc, &horizontalBarLine, plusBrush);
			}

			{ // Draw the four segments that are the vertical lines outlining the vertical crossbar of the plus.
				RECT verticalBarLine = verticalBar;
				verticalBarLine.bottom = plusMiddleY - thickness/2 + 1;
				verticalBarLine.right = verticalBarLine.left + 1;
				FillRect(hdc, &verticalBarLine, plusBrush);
				verticalBarLine.left = plusMiddleX + thickness/2 - 1;
				verticalBarLine.right = verticalBarLine.left + 1;
				FillRect(hdc, &verticalBarLine, plusBrush);
				verticalBarLine.top = plusMiddleY + thickness/2 - 1;
				verticalBarLine.bottom = plusMiddleY + length;
				FillRect(hdc, &verticalBarLine, plusBrush);
				verticalBarLine.left = plusMiddleX - thickness/2;
				verticalBarLine.right = verticalBarLine.left + 1;
				FillRect(hdc, &verticalBarLine, plusBrush);
			}

			HBRUSH whiteBrush = (HBRUSH)GetStockObject(WHITE_BRUSH);
			horizontalBar.top += 1;
			horizontalBar.bottom -= 1;
			FillRect(hdc, &horizontalBar, whiteBrush);

			verticalBar.left += 1;
			verticalBar.right -= 1;
			FillRect(hdc, &verticalBar, whiteBrush);

			DeleteDC(cornersDC);
			DeleteObject(corners);
			DeleteObject(plusBrush);

			EndPaint(hWnd, &ps);
		}
        return TRUE;
    } 
    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}



LRESULT CALLBACK AccountsButtonProc(HWND hWnd, UINT uMsg, WPARAM wParam,
                               LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
	PAINTSTRUCT ps;
	HDC hdc;
    switch (uMsg)
    {
	case WM_SETFOCUS:
		accountsButtonData.focusTickCount = ::GetTickCount64();
		break;
	case WM_LBUTTONDOWN:
		accountsButtonData.clickTickCount = ::GetTickCount64();
		break;
	case WM_ERASEBKGND:
		return TRUE;
    case WM_PAINT:
		hdc = BeginPaint(hWnd, &ps);
		{
			COLORREF foreground = TabForegroundColor(activeTab == IDC_TAB_ACCOUNTS);
			RECT r;
			GetClientRect(hWnd, &r);
			DrawButtonBackground(hdc, r, L"Accounts", foreground, ShouldDrawFocus(hWnd, &accountsButtonData));
			
			int itemHeight = ButtonLineWeight(r.bottom);
			int itemLeft = (r.right - r.left)/2 - (r.right - r.left) / 9;
			int itemRight = r.right - itemLeft;
			int itemListMiddle = ButtonIconMiddle(r.bottom);
			int itemSpacing = r.bottom / 8;


			HBRUSH fillBrush = CreateSolidBrush(foreground);
			HBRUSH whiteBrush = (HBRUSH)::GetStockObject(WHITE_BRUSH);
			HBITMAP corners = CreateRoundedCorner(hdc, RGB(255,255,255), foreground, RGB(230,230,230), itemHeight/2);

			HDC cornersDC = CreateCompatibleDC(hdc);
			SelectObject(cornersDC, corners);
			for (int itemIdx=-1; itemIdx<=1; itemIdx++) {
				int itemTop = itemListMiddle +itemSpacing*itemIdx - itemHeight/2;
				BitBlt(hdc, itemLeft, itemTop, itemHeight, itemHeight, cornersDC, 0,0,SRCCOPY);

				BitBlt(hdc, itemLeft + itemHeight*3/2, itemTop, itemHeight/2, itemHeight, cornersDC,0,0,SRCCOPY);
				BitBlt(hdc, itemRight - itemHeight/2, itemTop, itemHeight/2, itemHeight, cornersDC,itemHeight/2,0,SRCCOPY);
				RECT bodyRect;
				bodyRect.top = itemTop + 1;
				bodyRect.bottom = itemTop + itemHeight - 1;
				bodyRect.right = itemRight - itemHeight/2;
				bodyRect.left = itemLeft + itemHeight*4/2;
				FillRect(hdc, &bodyRect, whiteBrush);

				bodyRect.top = itemTop;
				bodyRect.bottom = itemTop + 1;
				FillRect(hdc, &bodyRect, fillBrush);
				bodyRect.top = itemTop + itemHeight - 1;
				bodyRect.bottom = bodyRect.top + 1;
				FillRect(hdc, &bodyRect, fillBrush);
			}

			DeleteDC(cornersDC);

			DeleteObject(corners);
			DeleteObject(fillBrush);

			EndPaint(hWnd, &ps);
		}
        return TRUE;
    } 
    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}


LRESULT CALLBACK SaveButtonProc(HWND hWnd, UINT uMsg, WPARAM wParam,
                               LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
	PAINTSTRUCT ps;
	HDC hdc;
    switch (uMsg)
    {
	case WM_ERASEBKGND:
		return TRUE;
    case WM_PAINT:
		hdc = BeginPaint(hWnd, &ps);
		{
			BOOL enabled = IsWindowEnabled(hWnd);

			COLORREF foreground = enabled ? RGB(255,255,255) : RGB(150, 150, 150);
			COLORREF background = enabled ? RGB(240, 30, 30) : RGB(200, 200, 200);
			COLORREF border = background;
			if (GetFocus() == hWnd) {
				border = enabled ? RGB(100, 0, 0) : RGB(150, 150, 150);
			}
			int radius = sizeBasis/3;


			HBITMAP corners = CreateRoundedCorner(hdc, background, border, RGB(255,255,255), radius);

			HDC cornersDC = CreateCompatibleDC(hdc);
			SelectObject(cornersDC, corners);
			HBRUSH b = CreateSolidBrush(background);

			RECT r;
			GetClientRect(hWnd, &r);
			
			FillRect(hdc, &r, b);
			BitBlt(hdc, r.left, r.top, radius, radius, cornersDC, 0,0,SRCCOPY);
			BitBlt(hdc, r.right - radius, r.top, radius, radius, cornersDC, radius,0,SRCCOPY);
			BitBlt(hdc, r.left, r.bottom - radius, radius, radius, cornersDC, 0,radius,SRCCOPY);
			BitBlt(hdc, r.right - radius, r.bottom - radius, radius, radius, cornersDC, radius,radius,SRCCOPY);

			HFONT oldFont = (HFONT)SelectObject(hdc, font);
			SetTextColor(hdc, foreground);
			SetBkMode(hdc, TRANSPARENT);
			WCHAR textBuf[256];
			GetWindowText(hWnd, textBuf, sizeof(textBuf)/sizeof(WCHAR));
			DrawText(hdc, textBuf, -1, &r, DT_SINGLELINE|DT_CENTER|DT_VCENTER);
			SelectObject(hdc, oldFont);

			if (GetFocus() == hWnd) {
				HBRUSH borderBrush = CreateSolidBrush(border);
				RECT borderLine = r;
				borderLine.left += radius;
				borderLine.right -= radius;
				borderLine.bottom = borderLine.top + 1;
				FillRect(hdc, &borderLine, borderBrush);

				borderLine.top = r.bottom - 1;
				borderLine.bottom = r.bottom;
				FillRect(hdc, &borderLine, borderBrush);

				borderLine = r;
				borderLine.top += radius;
				borderLine.bottom -= radius;
				borderLine.right = borderLine.left + 1;
				FillRect(hdc, &borderLine, borderBrush);

				borderLine.left = r.right - 1;
				borderLine.right = r.right;
				FillRect(hdc, &borderLine, borderBrush);
			}

			DeleteDC(cornersDC);
			DeleteObject(corners);

			EndPaint(hWnd, &ps);
		}
        return TRUE;
    } 
    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}


LRESULT CALLBACK AdvancedButtonProc(HWND hWnd, UINT uMsg, WPARAM wParam,
                               LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
	PAINTSTRUCT ps;
	HDC hdc;
    switch (uMsg)
    {
	case WM_ERASEBKGND:
		return TRUE;
    case WM_PAINT:
		hdc = BeginPaint(hWnd, &ps);
		{
			int radius = sizeBasis/3;

			RECT r;
			GetClientRect(hWnd, &r);
			
			HBRUSH b = (HBRUSH)::GetStockObject(WHITE_BRUSH);
			FillRect(hdc, &r, b);

			HFONT oldFont = (HFONT)SelectObject(hdc, font);
			SetTextColor(hdc, RGB(0,0,0));
			SetBkMode(hdc, TRANSPARENT);
			DrawText(hdc, L"Advanced...", -1, &r, DT_SINGLELINE|DT_RIGHT|DT_VCENTER);
			SelectObject(hdc, oldFont);

			EndPaint(hWnd, &ps);
		}
        return TRUE;
    } 
    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}
#include <windowsx.h>

LRESULT CALLBACK RadioButtonProc(HWND hWnd, UINT uMsg, WPARAM wParam,
                               LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
	PAINTSTRUCT ps;
	HDC paintDC;
	switch (uMsg)
	{
	case WM_ERASEBKGND:
		return TRUE;
	case WM_PAINT:
		paintDC = BeginPaint(hWnd, &ps);
		{
			RECT r;
			GetClientRect(hWnd, &r);

			HDC hdc = CreateCompatibleDC(paintDC);
			HBITMAP offscreenBmp = CreateCompatibleBitmap(paintDC, r.right, r.bottom);
			SelectObject(hdc, offscreenBmp);


			bool checked = (Button_GetState(hWnd) & BST_CHECKED) != 0;

			HWND next = GetWindow(hWnd, GW_HWNDNEXT);
			if (GetWindowStyle(next) & WS_GROUP) next = NULL;

			HWND prev = GetWindowStyle(hWnd) & WS_GROUP ? NULL : GetWindow(hWnd, GW_HWNDPREV);
			bool prevChecked = prev && (Button_GetState(prev) & BST_CHECKED) != 0;

			if (next) {
				bool wasChecked = GetWindowLong(hWnd, GWLP_USERDATA) != 0;
				if (wasChecked != checked) {
					WCHAR nextText[256];
					GetWindowText(next, nextText, 255);
					SetWindowLong(hWnd, GWLP_USERDATA, (LONG)checked);
					InvalidateRect(next, NULL, FALSE);
				}
			}
			COLORREF foreground = checked ? RGB(240,30,30): RGB(200,200,200);

			int radius = sizeBasis/3;
			HBITMAP corners = CreateRoundedCorner(hdc, RGB(255,255,255), foreground, RGB(255,255,255), radius);

			HDC cornersDC = CreateCompatibleDC(hdc);
			SelectObject(cornersDC, corners);
			HBRUSH selectedBrush = CreateSolidBrush(RGB(240,30,30));
			
			FillRect(hdc, &r, (HBRUSH)GetStockObject(WHITE_BRUSH));

			HBRUSH foregroundBrush = CreateSolidBrush(foreground);
			RECT lineRect;

			lineRect = r;
			lineRect.bottom = lineRect.top + 1;
			FillRect(hdc, &lineRect, foregroundBrush);

			lineRect = r;
			lineRect.top = lineRect.bottom - 1;
			FillRect(hdc, &lineRect, foregroundBrush);
			
			lineRect = r;
			lineRect.right = lineRect.left + 1;
			FillRect(hdc, &lineRect, prevChecked ? selectedBrush : foregroundBrush); // The left edge will show as selected if either of its neighbors is selected.
			
			if (!next) { // To avoid doubling up the line between adjacent choices, we don't draw the right edge (unless this button is the rightmost).
				lineRect = r;
				lineRect.left = lineRect.right - 1;
				FillRect(hdc, &lineRect, foregroundBrush);
			}

			if (!prev) { // If we are the first in this set of options, we need to round out the left corners.
				BitBlt(hdc, r.left, r.top, radius, radius, cornersDC, 0,0,SRCCOPY);
				BitBlt(hdc, r.left, r.bottom - radius, radius, radius, cornersDC, 0,radius,SRCCOPY);
			}
			if (!next) { // If we are the last in this set of options, we need to round out the right corners.
				BitBlt(hdc, r.right - radius, r.bottom - radius, radius, radius, cornersDC, radius,radius,SRCCOPY);
				BitBlt(hdc, r.right - radius, r.top, radius, radius, cornersDC, radius,0,SRCCOPY);
			}

			HFONT oldFont = (HFONT)SelectObject(hdc, font);
			SetTextColor(hdc, foreground);
			SetBkMode(hdc, TRANSPARENT);
			WCHAR labelText[256];
			GetWindowText(hWnd, labelText, sizeof(labelText)/ sizeof(WCHAR));
			DrawText(hdc, labelText, -1, &r, DT_SINGLELINE|DT_CENTER|DT_VCENTER);
			SelectObject(hdc, oldFont);

			DeleteDC(cornersDC);
			DeleteObject(corners);
			DeleteObject(foregroundBrush);
			DeleteObject(selectedBrush);

			BitBlt(paintDC, 0,0, r.right, r.bottom, hdc, 0,0, SRCCOPY);

			DeleteDC(hdc);
			DeleteObject(offscreenBmp);

			EndPaint(hWnd, &ps);
		}
        return TRUE;
    }
    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}

void ReportError(HWND parent, uint32_t err, WCHAR* message)
{
	if (err) {
		WCHAR errorBuf[256] = L"";
		uint8_t errorUtf8[512];
		if (0 == describe_error(err, errorUtf8, sizeof(errorUtf8))) {
			MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS | MB_USEGLYPHCHARS, (char*)errorUtf8, sizeof(errorUtf8), errorBuf, sizeof(errorBuf) / sizeof(*errorBuf));
		}
		MessageBoxW(parent, errorBuf, message, MB_ICONERROR);
	}
}

LRESULT CALLBACK StaticLabelProc(HWND hWnd, UINT uMsg, WPARAM wParam,
                               LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
	PAINTSTRUCT ps;
	HDC paintDC;
	switch (uMsg)
	{
	case WM_ERASEBKGND:
		return TRUE;
	case WM_PAINT:
		paintDC = BeginPaint(hWnd, &ps);
		{
			RECT r;
			GetClientRect(hWnd, &r);

			HDC hdc = CreateCompatibleDC(paintDC);
			HBITMAP offscreenBmp = CreateCompatibleBitmap(paintDC, r.right, r.bottom);
			SelectObject(hdc, offscreenBmp);

			FillRect(hdc, &r, (HBRUSH)GetStockObject(WHITE_BRUSH));
			
			HFONT oldFont = (HFONT)SelectObject(hdc, font);
			SetTextColor(hdc, RGB(240,30,30));
			SetBkMode(hdc, TRANSPARENT);
			WCHAR labelText[256];
			GetWindowText(hWnd, labelText, sizeof(labelText)/sizeof(WCHAR));
			DrawText(hdc, labelText, -1, &r, DT_WORDBREAK|DT_LEFT|DT_NOPREFIX);
			SelectObject(hdc, oldFont);

			BitBlt(paintDC, 0,0, r.right, r.bottom, hdc, 0,0, SRCCOPY);

			DeleteDC(hdc);
			DeleteObject(offscreenBmp);

			EndPaint(hWnd, &ps);
		}
        return TRUE;
    }
    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//

HWND CreateHintingEdit(RECT r, int idc, WCHAR *hintText)
{
	HWND edit = CreateWindow(_T("EDIT"), NULL, WS_CHILD|ES_AUTOHSCROLL|WS_TABSTOP, r.left,r.top, r.right - r.left,r.bottom - r.top, mainWnd, (HMENU)(UINT_PTR)idc, NULL, NULL);
	Edit_SetCueBannerTextFocused(edit, hintText, TRUE);
	SendMessage(edit, WM_SETFONT, (WPARAM)font, FALSE);
	return edit;
}

void InitAccountsTab()
{
	set_search_query((uint8_t *)"");

	RECT clientRect;
	GetClientRect(mainWnd, &clientRect);

	int editMargin = sizeBasis * 3 / 2;

	editArea.left = editMargin;
	editArea.top = editMargin;
	editArea.right = clientRect.right - editMargin;
	editArea.bottom = editArea.top + textBoxHeight;

	showingBackupReminder = get_backup_needed();

	scrollRect = clientRect;
	scrollRect.left = scrollRect.right - GetSystemMetrics(SM_CYVSCROLL);
	scrollRect.top = editArea.bottom + editMargin;
	scrollRect.bottom -= bottomButtonHeight + (showingBackupReminder ? sizeBasis*2 : 0);

	accountSearchEdit = CreateHintingEdit(editArea, IDC_SEARCH, L"Search...");
   
	scroll = CreateWindowEx( 0, // no extended styles 
		L"SCROLLBAR",           // scroll bar control class 
		(PTSTR) NULL,           // no window text 
		WS_CHILD   // window styles  
			| SBS_VERT,         // vertical scroll bar style 
		scrollRect.left,              // horizontal position 
		scrollRect.top, // vertical position 
		scrollRect.right - scrollRect.left,             // width of the scroll bar 
		scrollRect.bottom - scrollRect.top,               // height of the scroll bar
		mainWnd,             // handle to main window 
		(HMENU) NULL,           // no menu 
		hInst,                // instance owning this window 
		(PVOID) NULL            // pointer not needed 
		);

	scrollBarIsForAccountCount = accounts_len();

	SCROLLINFO info = { 0 };
	info.cbSize = sizeof(info);
	info.fMask = SIF_RANGE | SIF_PAGE;
	info.nMax = scrollBarIsForAccountCount * sizeBasis*4;
	info.nPage = scrollRect.bottom - scrollRect.top;

	bool scrollBarShowing = info.nMax > (int)info.nPage;
	if (scrollBarShowing) {
		SetScrollInfo(scroll, SB_CTL, &info, FALSE);
	}
	else {
		scrollRect.left = scrollRect.right;
	}

	HWND wnds[] = {
		accountSearchEdit, 
		scroll // should be last
	};

	HDWP defer = BeginDeferWindowPos(sizeof(wnds) / sizeof(HWND));
	for (size_t i = 0; i < sizeof(wnds) / sizeof(HWND) - (scrollBarShowing ? 0 : 1); i++) {
		if (wnds[i]) {
			DeferWindowPos(defer, wnds[i], NULL, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOREPOSITION | SWP_NOZORDER | SWP_NOSIZE | SWP_SHOWWINDOW);
		}
	}
	EndDeferWindowPos(defer);

	SetFocus(accountSearchEdit);
}

void DestroyAccountsTab()
{
	DestroyWindow(accountSearchEdit);
	DestroyWindow(scroll);
}


struct {
	HWND nameEdit;
	RECT nameEditArea;
	HWND codeEdit;
	RECT codeEditArea;
	HWND saveButton;
	HWND tokenLength6, tokenLength8, tokenLength10;
	HWND algorithmSha1, algorithmSha256, algorithmSha512;
	HWND period15, period30, period60;
	HWND labels[5];
	HWND advancedButton;
	bool advancedMode;
} addAccountTab = { 0 };

struct TabParam {
	HWND *wnd;
	int idc;
	const WCHAR *text;
};

void InitAddTab()
{
	RECT mainRect;
	GetClientRect(mainWnd, &mainRect);

	int margin = sizeBasis;

	int componentTop = mainRect.top + margin;
	int componentBottom = mainRect.bottom - bottomButtonHeight - margin - sizeBasis*3;
	int componentPlacementFromTop = sizeBasis*3/2;
	int textBoxMargin = sizeBasis*2/3;

	addAccountTab.nameEditArea.left = margin + textBoxMargin;
	addAccountTab.nameEditArea.top = componentTop + (componentBottom - componentTop) * 0 / 5 + componentPlacementFromTop + textBoxMargin;
	addAccountTab.nameEditArea.right = mainRect.right - margin - textBoxMargin;
	addAccountTab.nameEditArea.bottom = addAccountTab.nameEditArea.top + textBoxHeight;

	addAccountTab.nameEdit = CreateHintingEdit(addAccountTab.nameEditArea, IDC_NAME, L"e.g. example.com");

	addAccountTab.codeEditArea = addAccountTab.nameEditArea;
	addAccountTab.codeEditArea.top = componentTop + (componentBottom - componentTop) * 1 / 5 + componentPlacementFromTop + textBoxMargin;
	addAccountTab.codeEditArea.bottom = addAccountTab.codeEditArea.top + textBoxHeight;
	addAccountTab.codeEdit = CreateHintingEdit(addAccountTab.codeEditArea, IDC_CODE, L"e.g. L9WPBRYZLHALSNMW");

	addAccountTab.advancedMode = false;

	RECT advancedButtonRect;
	advancedButtonRect.right = mainRect.right / 2 + sizeBasis * 7;
	advancedButtonRect.left = mainRect.right / 2 - sizeBasis * 7;
	advancedButtonRect.top = componentTop + (componentBottom - componentTop) * 2 / 5 + componentPlacementFromTop;
	advancedButtonRect.bottom = advancedButtonRect.top + sizeBasis * 5 / 2;

	addAccountTab.advancedButton = CreateWindow(_T("BUTTON"), L"Show Advanced Options", WS_CHILD | ES_AUTOHSCROLL | WS_TABSTOP | WS_GROUP, advancedButtonRect.left, advancedButtonRect.top, advancedButtonRect.right - advancedButtonRect.left, advancedButtonRect.bottom - advancedButtonRect.top, mainWnd, (HMENU)IDC_ADVANCED, NULL, NULL);
	SetWindowSubclass(addAccountTab.advancedButton, SaveButtonProc, 0, 0);

	
	int saveButtonWidth = sizeBasis * 8;
	RECT saveButtonRect = addAccountTab.codeEditArea;
	saveButtonRect.left = (mainRect.left + mainRect.right - saveButtonWidth)/2;
	saveButtonRect.right = saveButtonRect.left + saveButtonWidth;
	saveButtonRect.top = mainRect.bottom - bottomButtonHeight - sizeBasis*4;
	saveButtonRect.bottom = saveButtonRect.top + sizeBasis*5/2;
	addAccountTab.saveButton = CreateWindow(_T("BUTTON"), L"Save", WS_CHILD | ES_AUTOHSCROLL | WS_TABSTOP | WS_GROUP, saveButtonRect.left, saveButtonRect.top, saveButtonRect.right - saveButtonRect.left, saveButtonRect.bottom - saveButtonRect.top, mainWnd, (HMENU)IDC_SAVE, NULL, NULL);
	SetWindowSubclass(addAccountTab.saveButton, SaveButtonProc, 0, 0);

	WCHAR *labels[] = {
		L"Account Name",
		L"Secret Code",
	};
	for (int i=0; i<2; i++) {
		addAccountTab.labels[i] = CreateWindowW(L"STATIC", labels[i], WS_CHILD, 
			addAccountTab.nameEditArea.left, 
			componentTop + (componentBottom - componentTop) * i / 5,//addAccountTab.nameEditArea.top - sizeBasis*2/3 - textBoxHeight, 
			addAccountTab.nameEditArea.right - addAccountTab.nameEditArea.left, 
			textBoxHeight, mainWnd, (HMENU)NULL, hInst, 0);
		SetWindowSubclass(addAccountTab.labels[i], StaticLabelProc, 0, 0);
	}
}

void ShowAdvancedAddOptions(uint32_t algorithm, uint32_t digits, uint32_t period, DWORD buttonFlags) {
	DestroyWindow(addAccountTab.advancedButton);
	addAccountTab.advancedButton = NULL;
	RECT mainRect;
	GetClientRect(mainWnd, &mainRect);

	int margin = sizeBasis;

	int componentTop = mainRect.top + margin;
	int componentBottom = mainRect.bottom - bottomButtonHeight - margin - sizeBasis*3;
	int componentPlacementFromTop = sizeBasis*3/2;
	int textBoxMargin = sizeBasis*2/3;
	addAccountTab.nameEditArea.left = margin + textBoxMargin;
	addAccountTab.nameEditArea.top = componentTop + (componentBottom - componentTop) * 0 / 5 + componentPlacementFromTop + textBoxMargin;
	addAccountTab.nameEditArea.right = mainRect.right - margin - textBoxMargin;
	addAccountTab.nameEditArea.bottom = addAccountTab.nameEditArea.top + textBoxHeight;
	MoveWindow(addAccountTab.nameEdit, addAccountTab.nameEditArea.left, addAccountTab.nameEditArea.top, addAccountTab.nameEditArea.right - addAccountTab.codeEditArea.left, addAccountTab.nameEditArea.bottom - addAccountTab.nameEditArea.top, FALSE);


	addAccountTab.codeEditArea = addAccountTab.nameEditArea;
	addAccountTab.codeEditArea.top = componentTop + (componentBottom - componentTop) * 1 / 5 + componentPlacementFromTop + textBoxMargin;
	addAccountTab.codeEditArea.bottom = addAccountTab.codeEditArea.top + textBoxHeight;
	MoveWindow(addAccountTab.codeEdit, addAccountTab.codeEditArea.left, addAccountTab.codeEditArea.top, addAccountTab.codeEditArea.right - addAccountTab.codeEditArea.left, addAccountTab.codeEditArea.bottom - addAccountTab.codeEditArea.top, FALSE);

	addAccountTab.advancedMode = true;

	TabParam wnds[3][3] = {
		{
			{ &addAccountTab.tokenLength6, 0, L"6" },
			{ &addAccountTab.tokenLength8, 0, L"8" },
			{ &addAccountTab.tokenLength10, 0, L"10" },
		},
		{
			{ &addAccountTab.algorithmSha1, 0, L"SHA-1" },
			{ &addAccountTab.algorithmSha256, 0, L"SHA-256" },
			{ &addAccountTab.algorithmSha512, 0, L"SHA-512" },
		},
		{
			{ &addAccountTab.period15, 0, L"15 seconds" },
			{ &addAccountTab.period30, 0, L"30 seconds" },
			{ &addAccountTab.period60, 0, L"60 seconds" },
		}
	};

	RECT radioArea;
	int radioButtonHeight = textBoxHeight + sizeBasis;
	for (int buttonSet=0; buttonSet<3; buttonSet++) {
		radioArea.top = componentTop + (componentBottom - componentTop) * (buttonSet+2) / 5 + componentPlacementFromTop;
		radioArea.bottom = radioArea.top + radioButtonHeight;
		for (int i=0; i<3; i++) {
			radioArea.left = margin + (mainRect.right - margin - margin) * i / 3;
			radioArea.right = margin + (mainRect.right - margin - margin) * (i+1) / 3;

			TabParam tabParam = wnds[buttonSet][i];
			*tabParam.wnd = CreateWindow(_T("BUTTON"), tabParam.text, buttonFlags|WS_CHILD|WS_TABSTOP|BS_AUTORADIOBUTTON|(i==0 ? WS_GROUP : 0), radioArea.left,radioArea.top, radioArea.right - radioArea.left,radioArea.bottom - radioArea.top, mainWnd, (HMENU)(UINT_PTR)tabParam.idc, NULL, NULL);
			SetWindowSubclass(*tabParam.wnd, RadioButtonProc, 0, 0);
		}
	}

	WCHAR *labels[] = {
		L"Account Name",
		L"Secret Code",
		L"Token Length",
		L"Algorithm",
		L"Token Rotates Every..."
	};
	for (int i=0; i<5; i++) {
		if  (addAccountTab.labels[i]) continue;
		addAccountTab.labels[i] = CreateWindowW(L"STATIC", labels[i], WS_CHILD, 
			addAccountTab.nameEditArea.left, 
			componentTop + (componentBottom - componentTop) * i / 5,//addAccountTab.nameEditArea.top - sizeBasis*2/3 - textBoxHeight, 
			addAccountTab.nameEditArea.right - addAccountTab.nameEditArea.left, 
			textBoxHeight, mainWnd, (HMENU)NULL, hInst, 0);
		SetWindowSubclass(addAccountTab.labels[i], StaticLabelProc, 0, 0);
	}

	SetWindowPos(addAccountTab.saveButton, addAccountTab.period60, 0,0,0,0, SWP_NOSIZE|SWP_NOMOVE|SWP_NOACTIVATE);

	Button_SetCheck(algorithm==1 ? addAccountTab.algorithmSha1 : algorithm==256 ? addAccountTab.algorithmSha256 : addAccountTab.algorithmSha512, BST_CHECKED);
	Button_SetCheck(digits==6 ? addAccountTab.tokenLength6 : digits==8 ? addAccountTab.tokenLength8 : addAccountTab.tokenLength10, BST_CHECKED);
	Button_SetCheck(period==15 ? addAccountTab.period15 : period==30 ? addAccountTab.period30 : addAccountTab.period60, BST_CHECKED);
}

void ShowCreatedAddControls()
{
	HWND wnds[] = {
		addAccountTab.nameEdit, addAccountTab.codeEdit, addAccountTab.saveButton, addAccountTab.advancedButton,
		addAccountTab.tokenLength6, addAccountTab.tokenLength8, addAccountTab.tokenLength10,
		addAccountTab.algorithmSha1, addAccountTab.algorithmSha256, addAccountTab.algorithmSha512,
		addAccountTab.period15, addAccountTab.period30, addAccountTab.period60,
		addAccountTab.labels[0], addAccountTab.labels[1], addAccountTab.labels[2], addAccountTab.labels[3], addAccountTab.labels[4]
	};

	HDWP defer = BeginDeferWindowPos(sizeof(wnds)/sizeof(HWND));
	for (size_t i=0; i<sizeof(wnds)/sizeof(HWND); i++) {
		if (wnds[i]) {
			DeferWindowPos(defer, wnds[i], NULL, 0, 0, 0, 0, SWP_NOMOVE|SWP_NOREPOSITION|SWP_NOZORDER|SWP_NOSIZE|SWP_SHOWWINDOW);
		}
	}
	EndDeferWindowPos(defer);

	SetFocus(addAccountTab.nameEdit);
}

void DestroyAddTab()
{
	HWND wnds[] = {
		addAccountTab.nameEdit, addAccountTab.codeEdit, addAccountTab.saveButton, addAccountTab.advancedButton,
		addAccountTab.tokenLength6, addAccountTab.tokenLength8, addAccountTab.tokenLength10,
		addAccountTab.algorithmSha1, addAccountTab.algorithmSha256, addAccountTab.algorithmSha512,
		addAccountTab.period15, addAccountTab.period30, addAccountTab.period60,
		addAccountTab.labels[0], addAccountTab.labels[1], addAccountTab.labels[2], addAccountTab.labels[3], addAccountTab.labels[4]
	};
	size_t wndCount = sizeof(wnds) / sizeof(HWND);
	HDWP defer  = BeginDeferWindowPos((int)wndCount);
	for (size_t i = 0; i < wndCount; i++) {
		if (wnds[i]) {
			DeferWindowPos(defer, wnds[i], NULL, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOREPOSITION | SWP_NOZORDER | SWP_NOSIZE | SWP_HIDEWINDOW);
		}
	}
	EndDeferWindowPos(defer);

	for (size_t i=0; i<wndCount; i++) {
		if (wnds[i]) {
			DestroyWindow(wnds[i]);
		}
	}
	
	ZeroMemory(&addAccountTab, sizeof(addAccountTab));
}
void SaveAccount()
{
	WCHAR nameBuffer[255];
	WCHAR codeBuffer[255];

	GetWindowTextW(addAccountTab.nameEdit, nameBuffer, sizeof(nameBuffer)/sizeof(WCHAR));
	GetWindowTextW(addAccountTab.codeEdit, codeBuffer, sizeof(codeBuffer)/sizeof(WCHAR));
	int tokenLength = addAccountTab.tokenLength10 && (Button_GetState(addAccountTab.tokenLength10) & BST_CHECKED) ? 10
		: addAccountTab.tokenLength8 && (Button_GetState(addAccountTab.tokenLength8) & BST_CHECKED) ? 8
		: 6;
	int period = addAccountTab.period60 && (Button_GetState(addAccountTab.period60) & BST_CHECKED) ? 60
		: addAccountTab.period15 && (Button_GetState(addAccountTab.period15) & BST_CHECKED) ? 15
		: 30;
	int algorithm = addAccountTab.algorithmSha512 && (Button_GetState(addAccountTab.algorithmSha512) & BST_CHECKED) ? 512
		: addAccountTab.algorithmSha256 && (Button_GetState(addAccountTab.algorithmSha256) & BST_CHECKED) ? 256
		: 1;

	uint8_t nameUtf8[512];
	uint8_t codeUtf8[512];
	WideCharToMultiByte(CP_UTF8, 0, nameBuffer, -1, (char *)nameUtf8, sizeof(nameUtf8), 0, 0);
	WideCharToMultiByte(CP_UTF8, 0, codeBuffer, -1, (char *)codeUtf8, sizeof(codeUtf8), 0, 0);

	int err = activeTab == IDC_TAB_ADD
		? add_account(nameUtf8, codeUtf8, algorithm, tokenLength, period)
		: edit_account(editingAccountIndex, nameUtf8, codeUtf8, algorithm, tokenLength, period);
	if (err) {
		ReportError(mainWnd, err, activeTab == IDC_TAB_ADD ? L"Add failed" : L"Edit failed");
		return;
	}

	SetActiveTab(IDC_TAB_ACCOUNTS, true);
}

struct {
	HWND instructions;
	HWND scan;
	HWND status;
} scanTab;

void InitScanTab()
{
	RECT mainRect;
	GetClientRect(mainWnd, &mainRect);

	int margin = sizeBasis;

	scanTab.instructions = CreateWindowW(L"STATIC", L"Please make sure the QR code is visible on your screen and then click...", WS_CHILD|WS_VISIBLE, 
		margin, 
		margin, 
		mainRect.right - margin*2, 
		textBoxHeight*2, mainWnd, (HMENU)NULL, hInst, 0);
	SetWindowSubclass(scanTab.instructions, StaticLabelProc, 0, 0);

	int scanButtonTop = margin + textBoxHeight*2 + margin;
	scanTab.scan = CreateWindow(_T("BUTTON"), L"Scan", WS_VISIBLE|WS_CHILD|ES_AUTOHSCROLL|WS_TABSTOP|WS_GROUP, margin, scanButtonTop, mainRect.right-margin*2, sizeBasis*5/2, mainWnd, (HMENU)IDC_SCAN, NULL, NULL);
	SetWindowSubclass(scanTab.scan, SaveButtonProc, 0, 0);

	int statusTop = scanButtonTop + textBoxHeight + margin * 2;
	scanTab.status = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
		margin,
		statusTop,
		mainRect.right - margin * 2,
		textBoxHeight * 2, mainWnd, (HMENU)NULL, hInst, 0);
	SetWindowSubclass(scanTab.status, StaticLabelProc, 0, 0);

	SetFocus(scanTab.scan);
}

void DestroyScanTab()
{
	HWND wnds[] = {
		scanTab.instructions, scanTab.scan, scanTab.status
	};
	for (size_t i=0; i<sizeof(wnds)/sizeof(HWND); i++) {
		DestroyWindow(wnds[i]);
	}

	ZeroMemory(&scanTab, sizeof(scanTab));
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   HWND hWnd;

   hInst = hInstance; // Store instance handle in our global variable

   sizeBasis = GetSystemMetrics(SM_CYVSCROLL);
   int width = sizeBasis*24;
   int height = (int)(width * 1.618);
   
   const POINT ptZero = { 0, 0 };
   HMONITOR hMon = MonitorFromPoint(ptZero, MONITOR_DEFAULTTOPRIMARY);
   MONITORINFO mi = { sizeof(mi) };
   GetMonitorInfo(hMon, &mi);
   
   hWnd = mainWnd = CreateWindowEx(0, szWindowClass, szTitle, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
      mi.rcWork.left + (mi.rcWork.right - mi.rcWork.left - width) / 2,
	  mi.rcWork.top + (mi.rcWork.bottom - mi.rcWork.top - height) / 2, width, height, NULL, NULL, hInstance, NULL);

   if (!hWnd)
   {
      return FALSE;
   }

   RECT clientRect;
   GetClientRect(hWnd, &clientRect);

   font = CreateFont(sizeBasis*6/4, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FF_MODERN, L"Segoe UI");
   iconFont = CreateFont(sizeBasis, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FF_MODERN, L"Segoe UI");

   
   HDC dc = GetDC(hWnd);
   HGDIOBJ oldObj = SelectObject(dc, font);
   TEXTMETRIC tm = {0};
   GetTextMetrics (dc, &tm);
   SelectObject(dc, oldObj);
   textBoxHeight = tm.tmHeight;
	
   int bottomCornerButtonSize = (clientRect.right - clientRect.left) / 3;
   bottomButtonHeight = (int)(bottomCornerButtonSize / 1.618);

   
   
   HWND accountsTabWnd = CreateWindowEx( 0,
	   L"BUTTON",
	   L"Accounts",
	   WS_CHILD | WS_VISIBLE | WS_TABSTOP,
	   clientRect.left,clientRect.bottom - bottomButtonHeight,bottomCornerButtonSize,bottomButtonHeight, hWnd, (HMENU)IDC_TAB_ACCOUNTS, hInstance, (PVOID)NULL);
   HWND addTabWnd = CreateWindowEx( 0,
	   L"BUTTON",
	   L"Add",
	   WS_CHILD | WS_VISIBLE | WS_TABSTOP,
	   clientRect.left + bottomCornerButtonSize,clientRect.bottom - bottomButtonHeight,clientRect.right-clientRect.left - bottomCornerButtonSize*2,bottomButtonHeight, hWnd, (HMENU)IDC_TAB_ADD, hInstance, (PVOID)NULL);
	HWND scanTabWnd = CreateWindowEx( 0,
	   L"BUTTON",
	   L"Scan",
	   WS_CHILD | WS_VISIBLE | WS_TABSTOP,
	   clientRect.right - bottomCornerButtonSize,clientRect.bottom - bottomButtonHeight, bottomCornerButtonSize,bottomButtonHeight, hWnd, (HMENU)IDC_TAB_SCAN, hInstance, (PVOID)NULL);
 
   
   SetWindowSubclass(scanTabWnd, ScanButtonProc, 0, 0);
   SetWindowSubclass(addTabWnd, AddButtonProc, 0, 0);
   SetWindowSubclass(accountsTabWnd, AccountsButtonProc, 0, 0);

   SetActiveTab(IDC_TAB_ACCOUNTS, true);

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

#include <math.h>
#include <commdlg.h>

HBITMAP CreateRoundedCorner(HDC dc, COLORREF inside, COLORREF border, COLORREF outside, int radius) {
	HDC dc2 = CreateCompatibleDC(dc);
	HBITMAP bmp = CreateCompatibleBitmap(dc, radius*2, radius*2);
	HGDIOBJ oldObj = SelectObject(dc2, bmp);

	int curveMiddle = radius-1;
	int distanceMin = (curveMiddle-1)*(curveMiddle-1);
	int distanceMax = (curveMiddle+1)*(curveMiddle+1);
	for (int x=0; x<radius; x++) {
		for (int y=0; y<radius; y++) {
			COLORREF pixelColor = RGB(255,255,255);
			int distanceSq = x*x + y*y;
			if (distanceSq <= distanceMin) {
				pixelColor = inside;
			} else if (distanceSq >= distanceMax) {
				pixelColor = outside;
			} else {
				float distance = (float)sqrt((float)distanceSq);
				float distanceWrongness = distance - curveMiddle;

				if (distanceWrongness > 0) {
					int fade = (int)(distanceWrongness * 256);
					pixelColor = RGB( (GetRValue(outside)*fade + GetRValue(border)*(256-fade))/256, (GetGValue(outside)*fade + GetGValue(border)*(256-fade))/256, (GetBValue(outside)*fade + GetBValue(border)*(256-fade))/256 );
				} else {
					int fade = (int)(-distanceWrongness * 256);
					pixelColor = RGB( (GetRValue(inside)*fade + GetRValue(border)*(256-fade))/256, (GetGValue(inside)*fade + GetGValue(border)*(256-fade))/256, (GetBValue(inside)*fade + GetBValue(border)*(256-fade))/256 );
				}
			}
			
			SetPixel(dc2, radius - 1 - x, radius - 1 - y, pixelColor);
			SetPixel(dc2, radius + x, radius + y, pixelColor);
			SetPixel(dc2, radius - 1 - x, radius + y, pixelColor);
			SetPixel(dc2, radius + x, radius - 1 - y, pixelColor);
		}
	}

	SelectObject(dc2, oldObj);
	DeleteDC(dc2);

	return bmp;
}

void SetActiveTab(int idc, bool andShow)
{
	if (activeTab == idc) return;

	switch (activeTab) {
	case IDC_TAB_ACCOUNTS: 
		DestroyAccountsTab(); 
		break;
	case IDC_TAB_ADD: 
	case IDC_TAB_EDIT: 
		DestroyAddTab(); 
		break;
	case IDC_TAB_SCAN: 
		DestroyScanTab(); 
		break;
	}

	HWND oldTabButton = GetDlgItem(mainWnd, activeTab);
	if (oldTabButton) InvalidateRect(oldTabButton, NULL, FALSE);
	activeTab = idc;
	HWND newTabButton = GetDlgItem(mainWnd, activeTab);
	if (newTabButton) InvalidateRect(newTabButton, NULL, FALSE);
	
	switch (activeTab) {
	case IDC_TAB_ACCOUNTS: 
		InitAccountsTab();
		break;
	case IDC_TAB_ADD: 
	case IDC_TAB_EDIT: 
		{
			InitAddTab();
			if (andShow) {
				ShowCreatedAddControls();
			}
			break;
		}
	case IDC_TAB_SCAN: 
		InitScanTab(); 
		break;
	}

	if (andShow) InvalidateAboveToolbar();

}

void InvalidateAccountList() {
	RECT invalidateArea = scrollRect;
	invalidateArea.right = invalidateArea.left - 1;
	invalidateArea.left = 0;
	InvalidateRect(mainWnd, &invalidateArea, FALSE);
}

int selectedItem = -1;
void SetSelectedItem(int item) {
	if (item == selectedItem) return;

	selectedItem = item;
	InvalidateAccountList();
}

static int ListItemHeight() {
	return sizeBasis * 4;
}

RECT codeHitArea = { 0 };
POINT mousePoint = { 0 };

bool UpdateMouseCursor() {
	if (activeTab == IDC_TAB_ACCOUNTS) {
		GetCursorPos(&mousePoint);
		ScreenToClient(mainWnd, &mousePoint);
		if (PtInRect(&editArea, mousePoint)) {
			return false;
		}

		HCURSOR targetCursor = selectedItem >= 0 && PtInRect(&codeHitArea, mousePoint) ? handCursor : arrowCursor;
		SetCursor(targetCursor);
		return true;
	}
	return false;
}

void PaintEdits(HDC hdc, RECT *rects, int nRects)
{
	int radius = sizeBasis/3;
	int margin = 2*radius;
	HBITMAP textBoxCorners = CreateRoundedCorner(hdc, RGB(255,255,255), RGB(200,200,200), RGB(255,255,255), radius);
	HBRUSH br = CreateSolidBrush(RGB(200,200,200));
	HDC src = CreateCompatibleDC(hdc);

	int marginOnly = margin-radius;
	SelectObject(src, textBoxCorners);
	for (int i=0; i<nRects; i++) {
		RECT rect = rects[i];
		BitBlt(hdc, rect.left-margin,rect.top-margin,radius,radius,src,0,0,SRCCOPY);
		BitBlt(hdc, rect.right+margin-radius,rect.top-margin,radius,radius,src,radius,0,SRCCOPY);
		BitBlt(hdc, rect.left-margin,rect.bottom+margin-radius,radius,radius,src,0,radius,SRCCOPY);
		BitBlt(hdc, rect.right+margin-radius,rect.bottom+margin-radius,radius,radius,src,radius,radius,SRCCOPY);

		RECT r;
			
		r = rect; r.top = rect.top-margin; r.bottom = r.top + 1; r.left -= marginOnly; r.right += marginOnly;
		FillRect(hdc, &r, br);

		r.bottom = rect.bottom+margin; r.top = r.bottom - 1;
		FillRect(hdc, &r, br);
			
		r = rect; r.left = rect.left-margin; r.right = r.left + 1; r.top -= marginOnly; r.bottom += marginOnly;
		FillRect(hdc, &r, br);

		r.right = rect.right + margin; r.left = r.right - 1;
		FillRect(hdc, &r, br);
	}

	DeleteDC(src);
	DeleteObject(textBoxCorners);
}

int GetTextHeight(HDC hdc)
{
	RECT measureRect = {0};
	DrawText(hdc, L"O", 1, &measureRect, DT_SINGLELINE|DT_CALCRECT);
	return measureRect.bottom - measureRect.top;
}

void PaintAccounts(HDC hdc)
{
	PaintEdits(hdc, &editArea, 1);

	RECT area;
	GetClientRect(mainWnd, &area);
	int listTop = scrollRect.top;
	int listBottom = area.bottom - bottomButtonHeight;
	int listItemHeight = ListItemHeight();
	int dividerHeight = sizeBasis/6;

	bool showBackupReminder = get_backup_needed();
	if (showBackupReminder) {
		listBottom -= sizeBasis * 2;
	}
	
	int account_count = accounts_len();

	bool resizingScroll = scrollRect.bottom != listBottom;
	if (resizingScroll) {
		scrollRect.bottom = listBottom;
		SetWindowPos(scroll, NULL, scrollRect.left, scrollRect.top, scrollRect.right - scrollRect.left, scrollRect.bottom - scrollRect.top, SWP_NOZORDER | SWP_NOACTIVATE);
	}
	if (account_count != scrollBarIsForAccountCount || resizingScroll) {
		scrollBarIsForAccountCount = account_count;

		SCROLLINFO info = { 0 };
		info.cbSize = sizeof(info);
		info.fMask = SIF_RANGE | SIF_PAGE;
		info.nMax = scrollBarIsForAccountCount * sizeBasis * 4;
		info.nPage = scrollRect.bottom - scrollRect.top;
		if (info.nMax > (int)info.nPage) {
			if (scrollRect.left == scrollRect.right) {
				ShowWindow(scroll, SW_SHOW);
				scrollRect.left = scrollRect.right - GetSystemMetrics(SM_CYVSCROLL);
			}
		}
		else {
			if (scrollRect.left != scrollRect.right) {
				ShowWindow(scroll, SW_HIDE);
				scrollRect.left = scrollRect.right;
			}
		}
		SetScrollInfo(scroll, SB_CTL, &info, TRUE);
	}


	HRGN listRegion = CreateRectRgn(area.left, listTop, scrollRect.left, listBottom); 
	SelectClipRgn (hdc, listRegion);

	HBRUSH dividerBrush = CreateSolidBrush(RGB(230,230,230));
	HBRUSH backgroundBrush = (HBRUSH)GetStockObject(WHITE_BRUSH);
			
	HBITMAP itemBmp = CreateCompatibleBitmap(hdc, scrollRect.left, listItemHeight);
	HDC itemDC = CreateCompatibleDC(hdc);
	SelectObject(itemDC, itemBmp);

	SelectObject(itemDC, font);

	int textHeight = GetTextHeight(itemDC);

	// Draw the actual list of accounts
	int pos = GetScrollPos(scroll, SB_CTL);

	bool drewKeyboardCopyiedCode = false;

	int i, listY;
	for (i=0, listY = listTop - pos; i<account_count; i++, listY += listItemHeight) {
		if (listY + listItemHeight < listTop) continue;
		if (listY > listBottom) break;
		RECT divider;
		divider.left = 0;
		divider.right = scrollRect.left;
		divider.top = listItemHeight - dividerHeight;
		divider.bottom = listItemHeight;

		RECT itemArea = divider;
		itemArea.top = 0;
		itemArea.bottom = listItemHeight - dividerHeight;
		FillRect(itemDC, &itemArea, backgroundBrush);

		bool keyboardCopyCandidate = (selectedItem == COPIED_USING_KEYBOARD && copiedFromItem == COPIED_USING_KEYBOARD && i == 0);

		if (i == selectedItem || keyboardCopyCandidate) {
			uint32_t millisPerCode = 1, millisIntoCode = 0;

			WCHAR ch[50];
			char codeUtf8[50];
			if (get_code(i, (uint8_t *)codeUtf8, sizeof(codeUtf8), &millisPerCode, &millisIntoCode) != 0) {
				continue;
			}

			bool copiedThisCode = (copiedFromItem == i || ((selectedItem==COPIED_USING_KEYBOARD||selectedItem==0) && copiedFromItem==COPIED_USING_KEYBOARD && i==0)) && strcmp(copiedCodeUtf8, codeUtf8) == 0;
			
			if (i == selectedItem || copiedThisCode) {
				if (keyboardCopyCandidate) drewKeyboardCopyiedCode = true;

				size_t codeLength = strlen(codeUtf8);
				if (codeLength == 6) { // XXX XXX
					codeUtf8[7] = 0;
					codeUtf8[6] = codeUtf8[5];
					codeUtf8[5] = codeUtf8[4];
					codeUtf8[4] = codeUtf8[3];
					codeUtf8[3] = ' ';
				}
				else if (codeLength == 8) { // XXXX XXXX
					codeUtf8[9] = 0;
					codeUtf8[8] = codeUtf8[7];
					codeUtf8[7] = codeUtf8[6];
					codeUtf8[6] = codeUtf8[5];
					codeUtf8[5] = codeUtf8[4];
					codeUtf8[4] = ' ';
				}
				else if (codeLength == 10) { // XXX XXX XXXX
					codeUtf8[12] = 0;
					codeUtf8[11] = codeUtf8[9];
					codeUtf8[10] = codeUtf8[8];
					codeUtf8[9] = codeUtf8[7];
					codeUtf8[8] = codeUtf8[6];
					codeUtf8[7] = ' ';
					codeUtf8[6] = codeUtf8[5];
					codeUtf8[5] = codeUtf8[4];
					codeUtf8[4] = codeUtf8[3];
					codeUtf8[3] = ' ';
				}
				MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS | MB_USEGLYPHCHARS, (char*)codeUtf8, sizeof(codeUtf8), ch, sizeof(ch) / sizeof(*ch));

				RECT codeRect = divider;
				codeRect.top = (listItemHeight - textHeight) / 2;
				codeRect.right -= sizeBasis;
				RECT codeMeasureRect = codeRect;
				DrawText(itemDC, ch, -1, &codeMeasureRect, DT_SINGLELINE | DT_CALCRECT);
				int codeWidth = codeMeasureRect.right - codeMeasureRect.left;


				DrawText(itemDC, ch, -1, &codeRect, DT_SINGLELINE | DT_RIGHT);
				codeHitArea = codeRect;
				codeHitArea.top += listY;
				codeHitArea.left = codeHitArea.right - codeWidth;
				codeHitArea.bottom = codeMeasureRect.bottom + listY;
				UpdateMouseCursor();

				int pixelProgress = (int)(codeWidth * (double)millisIntoCode / millisPerCode);

				HRGN redCode = CreateRectRgn(codeRect.right - codeWidth, codeRect.top, codeRect.right - codeWidth + pixelProgress, codeRect.bottom);
				SelectClipRgn(itemDC, redCode);
				COLORREF oldColor = SetTextColor(itemDC, TabForegroundColor(true));
				DrawText(itemDC, ch, -1, &codeRect, DT_SINGLELINE | DT_RIGHT);
				SetTextColor(itemDC, oldColor);
				SelectClipRgn(itemDC, NULL);
				DeleteObject(redCode);

				if (copiedThisCode) {
					SelectObject(itemDC, iconFont);
					RECT copiedRect = codeRect;
					copiedRect.bottom = codeRect.top;
					copiedRect.top = copiedRect.bottom - textHeight;
					copiedRect.left = copiedRect.right - codeWidth;
					DrawText(itemDC, L"Copied", -1, &copiedRect, DT_SINGLELINE | DT_CENTER | DT_BOTTOM | DT_NOCLIP);

					copiedRect.top = codeRect.top + textHeight;
					copiedRect.bottom = copiedRect.top + textHeight;
					DrawText(itemDC, L"to clipboard", -1, &copiedRect, DT_SINGLELINE | DT_CENTER | DT_TOP | DT_NOCLIP);
					SelectObject(itemDC, font);
				}

				// Time a redraw for when the above clipping region grows by a pixel.
				if (codeDrawingProgressTimer) {
					KillTimer(mainWnd, codeDrawingProgressTimer);
				}
				int nextPixelMillis = (pixelProgress + 1) * millisPerCode / codeWidth;
				codeDrawingProgressTimer = SetTimer(mainWnd, ID_CODE_DRAWING_PROGRESS, nextPixelMillis - millisIntoCode + 10, NULL); // 10ms is an unnoticable slop, in case the WM_TIMER timing is not very accurate
			}
		}

		RECT textRect = divider;
		textRect.left = sizeBasis;
		textRect.top = (listItemHeight - textHeight)/2;

		char utf8AccountName[100] = "";
		WCHAR ch[100] = L"";
		get_account_name(i, (uint8_t *)utf8AccountName, sizeof(utf8AccountName));
		MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS|MB_USEGLYPHCHARS, utf8AccountName, 100, ch, 100);
		DrawText(itemDC, ch, -1, &textRect, DT_SINGLELINE);

		FillRect(itemDC, &divider, dividerBrush);

		BitBlt(hdc, 0, listY, scrollRect.left, listItemHeight, itemDC, 0,0, SRCCOPY);
	}

	if (copiedFromItem == COPIED_USING_KEYBOARD && !drewKeyboardCopyiedCode) {
		// This state should not linger if the list is changed such that the copied code
		// no longer shows. That could cause the Copied to Clipboard notification to 
		// jump around as the search results change, which is technically correct but
		// not really the intention of showing it. We just want to show that the Enter
		// press did something.
		copiedFromItem = -1;
	}

	if (listY < listBottom) {
		RECT belowList;
		SetRect(&belowList, 0, listY, scrollRect.left, listBottom);
		FillRect(hdc, &belowList, backgroundBrush);
	}

	if (account_count == 0) {
		RECT listRect;
		SetRect(&listRect, area.left, listTop, scrollRect.left, listBottom);
		SelectObject(hdc, font);
		SetTextColor(hdc, RGB(100, 100, 100));
		DrawText(hdc, unfiltered_accounts_len()==0 ? L"No Accounts" : L"No Matches", -1, & listRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
	}

	SelectClipRgn(hdc, NULL);

	if (showBackupReminder) {
		HBRUSH reminderBackgroundBrush = CreateSolidBrush(RGB(240, 30, 30));
		RECT reminderRect = area;
		reminderRect.top = listBottom;
		reminderRect.bottom = listBottom + sizeBasis*2;
		FillRect(hdc, &reminderRect, reminderBackgroundBrush);
		SetTextColor(hdc, RGB(0, 0, 0));
		SelectObject(hdc, iconFont);
		SetBkMode(hdc, TRANSPARENT);
		DrawText(hdc, L"You have made changes since making a backup.", -1, &reminderRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
		DeleteObject(reminderBackgroundBrush);
	}

	DeleteObject(itemDC);
	DeleteObject(itemBmp);

	DeleteObject(dividerBrush);
	DeleteObject(listRegion);
}

void PaintAddTab(HDC hdc)
{
	RECT edits[2] = { addAccountTab.nameEditArea, addAccountTab.codeEditArea };
	PaintEdits(hdc, edits, 2);
}

void CopyAsciiToClipboard(const char *ascii)
{
	if (!OpenClipboard(mainWnd)) return;
	EmptyClipboard();

	size_t len = strlen(ascii);
	HGLOBAL textHandle = GlobalAlloc(GMEM_MOVEABLE, len + 1); 
	if (textHandle) {
		uint8_t *dest = (uint8_t *)GlobalLock(textHandle); 
        memcpy(dest, ascii, len+1); 
        GlobalUnlock(textHandle); 

		SetClipboardData(CF_TEXT, textHandle); // transfers ownership of textHandle to Windows
	}
	CloseClipboard();
}

void EditAccount(int idx, bool fromScanResults)
{
	uint8_t nameUtf8[256];
	uint8_t codeUtf8[256];
	WCHAR nameBuf[256];
	WCHAR codeBuf[256];

	uint32_t algorithm, digits, period;
	uint32_t err = get_account(idx, (uint32_t)fromScanResults, nameUtf8, sizeof(nameUtf8), codeUtf8, sizeof(codeUtf8), &algorithm, &digits, &period);
	if (err) {
		ReportError(mainWnd, err, L"Failed to load account details");
		return;
	}

	MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS|MB_USEGLYPHCHARS, (const char *)nameUtf8, sizeof(nameUtf8)/sizeof(*nameUtf8), nameBuf, sizeof(nameBuf)/sizeof(*nameBuf));
	MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS|MB_USEGLYPHCHARS, (const char *)codeUtf8, sizeof(codeUtf8)/sizeof(*codeUtf8), codeBuf, sizeof(codeBuf)/sizeof(*codeBuf));

	SetActiveTab(fromScanResults ? IDC_TAB_ADD : IDC_TAB_EDIT, false);
	SetWindowText(addAccountTab.nameEdit, nameBuf);
	SetWindowText(addAccountTab.codeEdit, codeBuf);
	if (fromScanResults) {
		SendMessage(addAccountTab.codeEdit, EM_SETREADONLY, TRUE, 0);
	}

	if (algorithm != 1 || digits != 6 || period != 30) {
		ShowAdvancedAddOptions(algorithm, digits, period, fromScanResults ? WS_DISABLED : 0);
	} else {
		if (fromScanResults) {
			DestroyWindow(addAccountTab.advancedButton);
			addAccountTab.advancedButton = NULL;
		}
	}
	InvalidateAboveToolbar();
	ShowCreatedAddControls();
	editingAccountIndex = idx;
}

void DeleteAccount(int idx)
{
	if (delete_account(idx)) {
		MessageBox(mainWnd, L"Deleting failed", L"Error", MB_ICONERROR);
	}
	InvalidateRect(mainWnd, NULL, FALSE);
}

void RunScan()
{
	HDC hScreenDC = GetDC(nullptr); // CreateDC("DISPLAY",nullptr,nullptr,nullptr);
	HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
	int width = GetDeviceCaps(hScreenDC, HORZRES);
	int height = GetDeviceCaps(hScreenDC, VERTRES);
	HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC,width,height);
	HBITMAP hOldBitmap = static_cast<HBITMAP>(SelectObject(hMemoryDC,hBitmap));

	SelectObject(hMemoryDC, hBitmap);
	BitBlt(hMemoryDC,0,0,width,height,hScreenDC,0,0,SRCCOPY|CAPTUREBLT);

	BITMAPINFO info = {0};
	info.bmiHeader.biSize = sizeof(info.bmiHeader);
	GetDIBits(hMemoryDC, hBitmap, 0, height, NULL, &info, DIB_RGB_COLORS);
	int pixels = info.bmiHeader.biWidth * info.bmiHeader.biHeight;
	if (info.bmiHeader.biBitCount != 32 || pixels*4 != info.bmiHeader.biSizeImage) {
		return;
	}
	
	uint32_t* rgbs = (uint32_t*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, info.bmiHeader.biSizeImage);
	uint8_t *grays = (uint8_t *)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, pixels);
	if (!rgbs || !grays) {
		GlobalFree(rgbs);
		GlobalFree(grays);
		return;
	}

	info.bmiHeader.biCompression = BI_RGB;
	int dibitsrets = GetDIBits(hMemoryDC, hBitmap, 0, info.bmiHeader.biHeight, rgbs, &info, DIB_RGB_COLORS);
	
	for (int y = 0; y<height; y++) {
		for (int x = 0; x < width; x++) {
			uint32_t rgb = rgbs[x + (height - y - 1) * width];
			grays[x + y*width] = ((rgb & 0xff) + ((rgb >> 8) & 0xff) + ((rgb >> 16) & 0xff)) / 3;
		}
	}
	int err = scan(grays, info.bmiHeader.biWidth, info.bmiHeader.biHeight);
	if (err) {
		ReportError(mainWnd, err, L"Scan failed");
		return;
	}
	SelectObject(hMemoryDC, hOldBitmap);
	DeleteDC(hMemoryDC);
	DeleteDC(hScreenDC);
	GlobalFree(rgbs);
	GlobalFree(grays);
	DeleteObject(hBitmap);

	uint32_t results = scan_result_count();

	WCHAR status[256];
	if (results == 0) {
		wcscpy_s(status, L"No QR codes found.");
	} else if (results == 1) {
		EditAccount(0, true);
		return;
	} else {
		wcscpy_s(status, L"Multiple QR codes found. Please make sure just one is on your screen.");
	}
	SetWindowTextW(scanTab.status, status);
	InvalidateRect(scanTab.status, NULL, FALSE);
}

bool GetFilePath(bool save, WCHAR szPath[MAX_PATH])
{
	OPENFILENAME ofn = { sizeof(ofn) };
	ofn.hwndOwner = mainWnd;
	ofn.lpstrFilter = L"Text Files\0*.txt\0All Files\0*.*\0";
	ofn.lpstrFile = szPath;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrTitle = save ? L"Export As" : L"Import From";
	ofn.lpstrDefExt = L"txt";
	return !!(save ? GetSaveFileName(&ofn) : GetOpenFileName(&ofn));
}

void ExportUnencryptedToFile()
{
	WCHAR szPath[MAX_PATH] = L"";
	if (!GetFilePath(true, szPath)) return;
	ReportError(mainWnd, export_to_file_on_windows((uint16_t*)szPath), L"Export failed.");

	if (activeTab == IDC_TAB_ACCOUNTS) InvalidateAboveToolbar();
}

void ExportEncryptedToFile()
{
	if (DialogBox(hInst, MAKEINTRESOURCE(IDD_SET_PASSWORD), mainWnd, SetPasswordDlg) != IDOK) return;
	
	WCHAR szPath[MAX_PATH] = L"";
	if (!GetFilePath(true, szPath)) return;

	uint8_t passwordUtf8[512];
	WideCharToMultiByte(CP_UTF8, 0, passwordWindowBuf, -1, (char*)passwordUtf8, sizeof(passwordUtf8), 0, 0);

	ReportError(mainWnd, export_to_encrypted_file_on_windows((uint16_t*)szPath, passwordUtf8), L"Export failed.");
	ZeroMemory(passwordWindowBuf, sizeof(passwordWindowBuf));
	
	if (activeTab == IDC_TAB_ACCOUNTS) InvalidateAboveToolbar();
}

void ExportEncryptedToClipboard()
{
	if (DialogBox(hInst, MAKEINTRESOURCE(IDD_SET_PASSWORD), mainWnd, SetPasswordDlg) != IDOK) return;

	uint8_t passwordUtf8[512];
	WideCharToMultiByte(CP_UTF8, 0, passwordWindowBuf, -1, (char*)passwordUtf8, sizeof(passwordUtf8), 0, 0);

	ReportError(mainWnd, export_encrypted_to_clipboard(passwordUtf8), L"Export failed.");
	ZeroMemory(passwordWindowBuf, sizeof(passwordWindowBuf));

	if (activeTab == IDC_TAB_ACCOUNTS) InvalidateAboveToolbar();
}

void ImportFromClipboard()
{
	uint32_t err = import_from_clipboard(NULL);
	if (err == 0) {

	}
	else if (err == 19) {
		if (DialogBox(hInst, MAKEINTRESOURCE(IDD_ENTER_PASSWORD), mainWnd, EnterPasswordDlg) != IDOK) return;
	}
	else {
		ReportError(mainWnd, err, L"Import failed");
	}
	InvalidateAboveToolbar();
}

void ImportFromFile()
{
	WCHAR szPath[MAX_PATH] = L"";
	if (!GetFilePath(false, szPath)) return;


	uint32_t err = import_on_windows((uint16_t*)szPath, NULL);
	if (err == 0) {

	}
	else if (err == 19) {
		if (DialogBox(hInst, MAKEINTRESOURCE(IDD_ENTER_PASSWORD), mainWnd, EnterPasswordDlg) != IDOK) return;
	}
	else {
		ReportError(mainWnd, err, L"Import failed.");
	}
	InvalidateAboveToolbar();
}

void UpdateSelectionForMousePoint()
{
	int y = mousePoint.y;
	int x = mousePoint.x;
	if (y >= scrollRect.top && y <= scrollRect.bottom && x <= scrollRect.left) {
		int pos = GetScrollPos(scroll, SB_CTL);
		int listItemHeight = ListItemHeight();
		int itemIdx = (y - scrollRect.top + pos) / listItemHeight;
		if (itemIdx >= scrollBarIsForAccountCount) {
			itemIdx = -1;
		}
		SetSelectedItem(itemIdx);

		// We need to know when the mouse leaves the window, so we can remove the hover effect then.
		// TrackMouseEvent needs to be called once to start listening for that.
		if (!trackingMouseLeave) {
			TRACKMOUSEEVENT tme = { 0 };
			tme.cbSize = sizeof(tme);
			tme.hwndTrack = mainWnd;
			tme.dwFlags = TME_LEAVE;
			TrackMouseEvent(&tme);
			trackingMouseLeave = true;
		}

	}
	else {
		SetSelectedItem(-1);
	}
}

void Print()
{
	PRINTDLG pd;

	// Initialize PRINTDLG
	ZeroMemory(&pd, sizeof(pd));
	pd.lStructSize = sizeof(pd);
	pd.hwndOwner = mainWnd;
	pd.hDevMode = NULL;     // Don't forget to free or store hDevMode.
	pd.hDevNames = NULL;     // Don't forget to free or store hDevNames.
	pd.Flags = PD_USEDEVMODECOPIESANDCOLLATE | PD_RETURNDC | PD_NOSELECTION | PD_NOPAGENUMS;
	pd.nCopies = 1;
	pd.nFromPage = 0xFFFF;
	pd.nToPage = 0xFFFF;
	pd.nMinPage = 1;
	pd.nMaxPage = 0xFFFF;

	if (!PrintDlg(&pd)) return;

	DOCINFO di = { sizeof(DOCINFO), L"Toptyp Secrets" };

	HDC dc = pd.hDC;


	int pageWidth = GetDeviceCaps(pd.hDC, PHYSICALWIDTH);
	int dpiX = GetDeviceCaps(pd.hDC, LOGPIXELSX);
	int pageHeight = GetDeviceCaps(pd.hDC, PHYSICALHEIGHT);
	int dpiY = GetDeviceCaps(pd.hDC, LOGPIXELSY);

	int qrDotWidth = dpiX * 2;
	int	qrDotHeight = dpiY * 2;

	int pageXMargin = dpiX;
	int pageYMargin = dpiY;

	int qrXMargin = dpiX / 2;
	int qrYMargin = dpiY / 2;
	int textBelowQr = dpiY / 8;

	int columns = (pageWidth - pageXMargin*2) / (qrDotWidth + qrXMargin * 2);
	int rows = (pageHeight - pageYMargin * 2) / (qrDotHeight + qrYMargin * 2);

	HFONT font = CreateFont(dpiY/4, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FF_MODERN, L"Segoe UI");
	SelectObject(dc, font);

	uint8_t qrBuf[80 * 80];

	int row = 0;
	int col = 0;
	if (StartDoc(pd.hDC, &di) > 0) {
		bool pageNeeded = true;
		uint32_t nAccounts = accounts_len();
		for (uint32_t accountIdx = 0; accountIdx < nAccounts; accountIdx++) {
			if (pageNeeded) {
				if (accountIdx) {
					EndPage(dc);
				}
				StartPage(pd.hDC);
				pageNeeded = false;
			}
			
			WCHAR accountNameBuf[256];
			uint8_t accountNameUtf8[256];
			if (get_account_name(accountIdx, accountNameUtf8, sizeof(accountNameUtf8))) break;

			MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS | MB_USEGLYPHCHARS, (const char*)accountNameUtf8, sizeof(accountNameUtf8) / sizeof(*accountNameUtf8), accountNameBuf, sizeof(accountNameBuf) / sizeof(*accountNameBuf));


			HBRUSH whiteBrush = (HBRUSH)GetStockObject(WHITE_BRUSH);
			HBRUSH blackBrush = (HBRUSH)GetStockObject(BLACK_BRUSH);

			SelectObject(dc, blackBrush);
			uint32_t qrSize = 0;
			uint32_t ret = get_account_qr_code(accountIdx, qrBuf, sizeof(qrBuf), &qrSize);
			if (ret == 0) {
				int qrTop = pageYMargin + qrYMargin + row * (qrDotHeight + qrYMargin * 2);
				int qrLeft = pageXMargin + qrXMargin + col * (qrDotWidth + qrXMargin * 2);
				int qrBottom = qrTop + qrDotHeight;
				int qrRight = qrLeft + qrDotWidth;

				RECT r;
				SetRect(&r, qrLeft - qrXMargin, qrBottom + textBelowQr, qrRight + qrXMargin, qrBottom + dpiY);
				DrawText(dc, accountNameBuf, -1, &r, DT_NOPREFIX | DT_CENTER | DT_TOP | DT_SINGLELINE);
				
				// Drawing lots of squares leads to little visible gaps between them.
				// To avoid that, we draw horizontal and vertical stripes along columns
				// and then rows.
				for (uint32_t qrX = 0; qrX < qrSize; qrX++) {
					int pixelX = qrLeft + qrDotWidth * qrX / qrSize;
					int nextPixelX = qrLeft + qrDotWidth * (qrX + 1) / qrSize;

					int filledStartY = -1;
					for (uint32_t qrY = 0; qrY < qrSize+1; qrY++) {
						bool filled = qrY < qrSize && qrBuf[qrX + qrY * qrSize];

						if (filled) {
							if (filledStartY == -1) filledStartY = qrY;
						}
						else if (filledStartY != -1) {
							RECT r;
							int pixelY = qrTop + qrDotHeight * filledStartY / qrSize;
							int nextPixelY = qrTop + qrDotHeight * qrY / qrSize;

							SetRect(&r, pixelX, pixelY, nextPixelX, nextPixelY);

							FillRect(dc, &r, blackBrush);
							
							filledStartY = -1;
						}
					}
				}

				for (uint32_t qrY = 0; qrY < qrSize; qrY++) {
					int pixelY = qrTop + qrDotHeight * qrY / qrSize;
					int nextPixelY = qrTop + qrDotHeight * (qrY + 1) / qrSize;

					int filledStartX = -1;
					for (uint32_t qrX = 0; qrX < qrSize + 1; qrX++) {
						bool filled = qrX < qrSize && qrBuf[qrX + qrY * qrSize];

						if (filled) {
							if (filledStartX == -1) filledStartX = qrX;
						}
						else if (filledStartX != -1) {
							RECT r;
							int pixelX = qrLeft + qrDotWidth * filledStartX / qrSize;
							int nextPixelX = qrLeft + qrDotWidth * qrX / qrSize;

							SetRect(&r, pixelX, pixelY, nextPixelX, nextPixelY);

							FillRect(dc, &r, blackBrush);

							filledStartX = -1;
						}
					}
				}


				col++;
				if (col == columns) {
					col = 0;
					row++;
					if (row == rows) {
						row = 0;
						pageNeeded = true;
					}
				}
			}
		}

		EndPage(pd.hDC);
		EndDoc(pd.hDC);

	}
	// Delete DC when done.
	DeleteDC(pd.hDC);
	
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_COMMAND	- process the application menu
//  WM_PAINT	- Paint the main window
//  WM_DESTROY	- post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	PAINTSTRUCT ps;
	HDC hdc;

	switch (message)
	{
	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		// Parse the menu selections:
		switch (wmId)
		{
		case IDM_ABOUT:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
			break;
		case IDM_EXIT:
			DestroyWindow(hWnd);
			break;
		case IDM_PRINT:
			Print();
			break;
		case IDM_EXPORT_ENCRYPTED_TO_FILE:
			ExportEncryptedToFile();
			break;
		case IDM_EXPORT_UNENCRYPTED_TO_FILE:
			ExportUnencryptedToFile();
			break;
		case IDM_EXPORT_UNENCRYPTED_TO_CLIPBOARD:
			export_to_clipboard();
			if (activeTab == IDC_TAB_ACCOUNTS) InvalidateAboveToolbar();
			break;
		case IDM_EXPORT_ENCRYPTED_TO_CLIPBOARD:
			ExportEncryptedToClipboard();
			break;
		case IDM_IMPORT_FROM_CLIPBOARD:
			ImportFromClipboard();
			InvalidateAboveToolbar();
			break;
		case IDM_IMPORT_FROM_FILE:
			ImportFromFile();
			break;
		case IDC_SEARCH:
			if (HIWORD(wParam) == EN_CHANGE) {
				int foo = 0;
				WCHAR search[255] = L"";
				uint8_t searchUtf8[512] = { 0 };
				GetWindowText(accountSearchEdit, search, sizeof(search) / sizeof(WCHAR));
				WideCharToMultiByte(CP_UTF8, 0, search, -1, (char*)searchUtf8, sizeof(searchUtf8), 0, 0);
				set_search_query(searchUtf8);
				InvalidateAccountList();
			}
			break;

		case IDC_TAB_ACCOUNTS:
		case IDC_TAB_ADD:
		case IDC_TAB_SCAN:
			SetActiveTab(wmId, true);
			break;
		case IDC_ADVANCED:
			ShowAdvancedAddOptions(1, 6, 30, 0);
			ShowCreatedAddControls();
			break;
		case IDC_SAVE:
			SaveAccount();
			break;
		case IDC_SCAN:
			RunScan();
			break;
		case IDOK:
			if (activeTab == IDC_TAB_ACCOUNTS && GetFocus() == accountSearchEdit) {
				char codeUtf8[50] = { 0 };
				uint32_t millisPerCode, millisIntoCode;
				get_code(0, (uint8_t*)codeUtf8, sizeof(codeUtf8), &millisPerCode, &millisIntoCode);

				CopyAsciiToClipboard(codeUtf8);
				memcpy(copiedCodeUtf8, codeUtf8, sizeof(copiedCodeUtf8));
				copiedFromItem = COPIED_USING_KEYBOARD;
				selectedItem = COPIED_USING_KEYBOARD;
				InvalidateRect(mainWnd, NULL, FALSE);
			}
			break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
		break;
	case WM_MOUSEWHEEL:
		{
			int dScroll = ((int16_t)HIWORD(wParam));
			dScroll /= -10;
			if (dScroll) {
				SetScrollPos(scroll, SB_CTL, GetScrollPos(scroll, SB_CTL) + dScroll, TRUE);
			}
			RECT r;
			r.left = 0;
			r.right = scrollRect.left;
			r.bottom = scrollRect.bottom;
			r.top = scrollRect.top;
			InvalidateRect(hWnd, &r, FALSE);
			UpdateSelectionForMousePoint();
			break;
		}
	case WM_VSCROLL:
		{
			int type = LOWORD(wParam);
			int dScroll = 0;
			if (type == SB_THUMBPOSITION || type == SB_THUMBTRACK) {
				int pos = HIWORD(wParam);
				SetScrollPos(scroll, SB_CTL, pos, FALSE);
			} else if (type == SB_PAGEUP) {
				dScroll = -(scrollRect.bottom - scrollRect.top);
			} else if (type == SB_PAGEDOWN) {
				dScroll =  scrollRect.bottom - scrollRect.top;
			} else if (type == SB_LINEDOWN) {
				dScroll = sizeBasis*4;
			} else if (type == SB_LINEUP) {
				dScroll = -sizeBasis*4;
			} else {
				break;
			}
			if (dScroll) {
				SetScrollPos(scroll, SB_CTL, GetScrollPos(scroll, SB_CTL) + dScroll, FALSE);
			}
			RECT r;
			r.left = 0;
			r.right = scrollRect.left;
			r.bottom = scrollRect.bottom;
			r.top = scrollRect.top;
			InvalidateRect(hWnd, &r, FALSE);
		}
		break;
	case WM_PAINT:
		{
			hdc = BeginPaint(hWnd, &ps);

			if (activeTab == IDC_TAB_ACCOUNTS) {
				PaintAccounts(hdc);
			} else if (activeTab == IDC_TAB_ADD || activeTab == IDC_TAB_EDIT) {
				PaintAddTab(hdc);
			}

			EndPaint(hWnd, &ps);
		}
		break;
	case WM_TIMER:
		{
			InvalidateAccountList();

			// This was intended as a one-shot timer. Kill it, or else it will repeat.
			KillTimer(mainWnd, codeDrawingProgressTimer);
			codeDrawingProgressTimer = 0;
		}
		break;
	case WM_MOUSEMOVE:
		{
			int x = LOWORD(lParam);
			int y = HIWORD(lParam);

			mousePoint.x = x;
			mousePoint.y = y;

			if (activeTab == IDC_TAB_ACCOUNTS) {
				UpdateSelectionForMousePoint();
			}
		}
		break;
	case WM_SETCURSOR:
		if (UpdateMouseCursor()) {
			break;
		} else {
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
	case WM_LBUTTONDOWN:
		{
			if (activeTab == IDC_TAB_ACCOUNTS) {
				if( selectedItem>=0 && PtInRect(&codeHitArea, mousePoint) ) {
					char codeUtf8[50] = { 0 };
					uint32_t millisPerCode, millisIntoCode;
					get_code(selectedItem, (uint8_t *)codeUtf8, sizeof(codeUtf8), &millisPerCode, &millisIntoCode);

					CopyAsciiToClipboard(codeUtf8);
					memcpy(copiedCodeUtf8, codeUtf8, sizeof(copiedCodeUtf8));
					copiedFromItem = selectedItem;
					InvalidateRect(mainWnd, NULL, FALSE);
				}
				return true;
			}
		}
	case WM_RBUTTONDOWN:
	case WM_LBUTTONUP:
	case WM_RBUTTONUP:
		UpdateMouseCursor();
		return DefWindowProc(hWnd, message, wParam, lParam);
	case WM_CONTEXTMENU:
		{

			if (activeTab == IDC_TAB_ACCOUNTS && selectedItem >= 0) {
				int clickedItem = selectedItem;
				WCHAR accountNameBuf[256];
				uint8_t accountNameUtf8[256];
				if (get_account_name(clickedItem, accountNameUtf8, sizeof(accountNameUtf8))) break;

				MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS|MB_USEGLYPHCHARS, (const char *)accountNameUtf8, sizeof(accountNameUtf8)/sizeof(*accountNameUtf8), accountNameBuf, sizeof(accountNameBuf)/sizeof(*accountNameBuf));

				WCHAR editMessage[300] = L"Edit ";
				WCHAR deleteMessage[300] = L"Delete ";
				wcscat_s(editMessage, accountNameBuf);
				wcscat_s(deleteMessage, accountNameBuf);

				HMENU menu = CreatePopupMenu();
				AppendMenu(menu, MF_STRING|MF_ENABLED, 1, editMessage);
				AppendMenu(menu, MF_STRING|MF_ENABLED, 2, deleteMessage);
				POINT cursor;
				::GetCursorPos(&cursor);
				int ret = TrackPopupMenu(menu, TPM_RETURNCMD|TPM_NONOTIFY, cursor.x, cursor.y, 0, mainWnd, NULL);
				if (ret == 1) {
					EditAccount(clickedItem, false);
				} else if (ret == 2) {
					WCHAR deleteMessageBuf[512] = L"Are you sure you want to delete ";
					wcscat_s(deleteMessageBuf, accountNameBuf);
					wcscat_s(deleteMessageBuf, L"?");
					
					if (MessageBox(mainWnd, deleteMessageBuf, L"Confirm Account Deletion", MB_ICONWARNING|MB_YESNO)==IDYES) {
						DeleteAccount(clickedItem);
					}
				}
				
			}
			else if (activeTab == IDC_TAB_ACCOUNTS && showingBackupReminder) {
				RECT clientRect;
				GetClientRect(mainWnd, &clientRect);
				POINT cursor;
				::GetCursorPos(&cursor);

				POINT clientCursor = cursor;
				ScreenToClient(mainWnd, &clientCursor);

				if (clientCursor.y < clientRect.bottom - bottomButtonHeight && clientCursor.y > clientRect.bottom - bottomButtonHeight - sizeBasis * 2) {
					HMENU menu = CreatePopupMenu();
					AppendMenu(menu, MF_STRING | MF_ENABLED, 1, L"Dismiss");
					int ret = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY, cursor.x, cursor.y, 0, mainWnd, NULL);
					if (ret == 1) {
						dismiss_backup_reminder();
						InvalidateAboveToolbar();
					}
				}
			}
		}
		break;
	case WM_CTLCOLOREDIT:
		{
			LRESULT ret = DefWindowProc(hWnd, message, wParam, lParam);
			HDC hdc = (HDC)wParam;
			HWND wnd = (HWND)lParam;

			SetBkColor((HDC)wParam, RGB(255, 255, 255));
			return ret;
		}
		break;
	case WM_CTLCOLORSTATIC:
		// Forcing white background here avoids having the read-only text fields look odd with a gray center and white trim.
		SetBkColor((HDC)wParam, RGB(255, 255, 255));
		break;
	case WM_MOUSELEAVE:
		SetSelectedItem(-1);
		trackingMouseLeave = false;
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}


// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

// Shrink so that the rounded border will occupy the original space of this edit
void ShrinkEditHorizontally(HWND ctrl) {
	int radius = sizeBasis / 3;
	int margin = 2 * radius;

	WINDOWPLACEMENT wndpl = { 0 };
	GetWindowPlacement(ctrl, &wndpl);
	wndpl.rcNormalPosition.left += margin;
	wndpl.rcNormalPosition.right -= margin;
	SetWindowPlacement(ctrl, &wndpl);
}

// Message handler for about box.
INT_PTR CALLBACK SetPasswordDlg(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		{
		EnableWindow(GetDlgItem(hDlg, IDOK), FALSE);
		SetWindowSubclass(GetDlgItem(hDlg, IDOK), SaveButtonProc, 0, 0);
		SetWindowSubclass(GetDlgItem(hDlg, IDCANCEL), SaveButtonProc, 0, 0);
		ShrinkEditHorizontally(GetDlgItem(hDlg, IDC_PASSWORD_1));
		ShrinkEditHorizontally(GetDlgItem(hDlg, IDC_PASSWORD_2));
		}
		return (INT_PTR)TRUE;
	case WM_CTLCOLORDLG:
		return (INT_PTR)GetStockBrush(WHITE_BRUSH);
	case WM_PAINT:
	{
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hDlg, &ps);

		WINDOWPLACEMENT p = { 0 };
		RECT editAreas[2];
		for (int i = 0; i < 2; i++) {
			HWND edit = GetDlgItem(hDlg, IDC_PASSWORD_1 + i);
			GetWindowPlacement(edit, &p);
			editAreas[i] = p.rcNormalPosition;
		}

		PaintEdits(hdc, editAreas, 2);
		EndPaint(hDlg, &ps);
	}
	case WM_CTLCOLORSTATIC:
		// Forcing white background here avoids having the read-only text fields look odd with a gray center and white trim.
		SetBkColor((HDC)wParam, RGB(255, 255, 255));
		SetTextColor((HDC)wParam, RGB(240, 30, 30));
		return (INT_PTR)GetStockBrush(WHITE_BRUSH);
	case WM_COMMAND:
		if (HIWORD(wParam) == EN_CHANGE) {
			WCHAR password1[MAX_PASSWORD_LENGTH+1];
			WCHAR password2[MAX_PASSWORD_LENGTH+1];
			GetWindowText(GetDlgItem(hDlg, IDC_PASSWORD_1), password1, MAX_PASSWORD_LENGTH);
			GetWindowText(GetDlgItem(hDlg, IDC_PASSWORD_2), password2, MAX_PASSWORD_LENGTH);
			size_t len = wcslen(password1);
			BOOL passwordsGood = len > 0 && len < MAX_PASSWORD_LENGTH && wcscmp(password1, password2) == 0;
			HWND okButton = GetDlgItem(hDlg, IDOK);
			if (passwordsGood != IsWindowEnabled(okButton)) {
				EnableWindow(okButton, passwordsGood);
				InvalidateRect(okButton, NULL, FALSE);
			}
		}
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			if (LOWORD(wParam) == IDOK) {
				GetWindowText(GetDlgItem(hDlg, IDC_PASSWORD_1), passwordWindowBuf, MAX_PASSWORD_LENGTH);
			}
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

// Message handler for about box.
INT_PTR CALLBACK EnterPasswordDlg(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
	{
		SetWindowSubclass(GetDlgItem(hDlg, IDOK), SaveButtonProc, 0, 0);
		SetWindowSubclass(GetDlgItem(hDlg, IDCANCEL), SaveButtonProc, 0, 0);
		ShrinkEditHorizontally(GetDlgItem(hDlg, IDC_PASSWORD_1));
	}
	return (INT_PTR)TRUE;
	case WM_CTLCOLORDLG:
		return (INT_PTR)GetStockBrush(WHITE_BRUSH);
	case WM_PAINT:
	{
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hDlg, &ps);

		WINDOWPLACEMENT p = { 0 };
		HWND edit = GetDlgItem(hDlg, IDC_PASSWORD_1);
		GetWindowPlacement(edit, &p);

		PaintEdits(hdc, &p.rcNormalPosition, 1);
		EndPaint(hDlg, &ps);
	}
	case WM_CTLCOLORSTATIC:
		// Forcing white background here avoids having the read-only text fields look odd with a gray center and white trim.
		SetBkColor((HDC)wParam, RGB(255, 255, 255));
		SetTextColor((HDC)wParam, RGB(240, 30, 30));
		return (INT_PTR)GetStockBrush(WHITE_BRUSH);
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			if (LOWORD(wParam) == IDOK) {
				GetWindowText(GetDlgItem(hDlg, IDC_PASSWORD_1), passwordWindowBuf, MAX_PASSWORD_LENGTH);
				uint8_t passwordUtf8[512];
				WideCharToMultiByte(CP_UTF8, 0, passwordWindowBuf, -1, (char*)passwordUtf8, sizeof(passwordUtf8), 0, 0);

				uint32_t err = import_retry(passwordUtf8);
				if (err != 0) {
					ReportError(hDlg, err, L"Import failed");
					SetFocus(GetDlgItem(hDlg, IDC_PASSWORD_1));
					return (INT_PTR)TRUE;
				}
			}
			
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}
