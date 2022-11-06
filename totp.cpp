// totp.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "totp.h"
#include <commctrl.h>

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;								// current instance
TCHAR szTitle[MAX_LOADSTRING];					// The title bar text
TCHAR szWindowClass[MAX_LOADSTRING];			// the main window class name

// Forward declarations of functions included in this code module:
ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	About(HWND, UINT, WPARAM, LPARAM);

HWND mainWnd = NULL;

HWND scroll = NULL;

HFONT iconFont = NULL;
HFONT font = NULL;

int activeTab = IDC_TAB_ACCOUNTS;

HBITMAP CreateRoundedCorner(HDC dc, COLORREF inside, COLORREF border, COLORREF outside, int radius);

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

	// Perform application initialization:
	if (!InitInstance (hInstance, nCmdShow))
	{
		return FALSE;
	}

	hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_TOTP));

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
	wcex.hbrBackground	= (HBRUSH)(COLOR_WINDOW+1);
	wcex.lpszMenuName	= MAKEINTRESOURCE(IDC_TOTP);
	wcex.lpszClassName	= szWindowClass;
	wcex.hIconSm		= LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

	return RegisterClassEx(&wcex);
}

int ButtonIconMiddle(int bottom) {
	return bottom*4/11;
}
int ButtonLineWeight(int bottom) {
	return bottom/12 & ~1;
}

void DrawButtonBackground(HDC hdc, RECT r, LPCTSTR text, COLORREF textColor) {
	HBRUSH br = CreateSolidBrush(RGB(230,230,230));
	FillRect(hdc, &r, br);
			
	SetBkMode(hdc, TRANSPARENT);
	HGDIOBJ oldObj = SelectObject(hdc, iconFont);

	RECT textRect = r;
	textRect.bottom -= textRect.bottom/8;

	COLORREF oldColor = SetTextColor(hdc, textColor);
	DrawText(hdc, text, -1, &textRect, DT_SINGLELINE|DT_CENTER|DT_BOTTOM);
	SetTextColor(hdc, oldColor);

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

LRESULT CALLBACK ScanButtonProc(HWND hWnd, UINT uMsg, WPARAM wParam,
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

			DrawButtonBackground(hdc, r, L"Scan", foreground);
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
	case WM_ERASEBKGND:
		return TRUE;
    case WM_PAINT:
		hdc = BeginPaint(hWnd, &ps);
		{
			COLORREF foreground = TabForegroundColor(activeTab == IDC_TAB_ADD);

			RECT r;
			GetClientRect(hWnd, &r);
			DrawButtonBackground(hdc, r, L"Add", foreground);
			
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
	case WM_ERASEBKGND:
		return TRUE;
    case WM_PAINT:
		hdc = BeginPaint(hWnd, &ps);
		{
			COLORREF foreground = TabForegroundColor(activeTab == IDC_TAB_ACCOUNTS);
			RECT r;
			GetClientRect(hWnd, &r);
			DrawButtonBackground(hdc, r, L"Accounts", foreground);
			
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


struct HintingEditData {
	BOOL showingHint;
	BOOL hasFocus;
	LPCTSTR hintText;
};

HintingEditData searchHintingEditData = { TRUE, FALSE, L"Search..." };

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
RECT editArea;
RECT scrollRect;
int sizeBasis = 0;
int bottomButtonHeight = 0;

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   HWND hWnd;

   hInst = hInstance; // Store instance handle in our global variable

   sizeBasis = GetSystemMetrics(SM_CYVSCROLL);
   int width = sizeBasis*24;
   int height = (int)(width * 1.618);
   
   hWnd = mainWnd= CreateWindow(szWindowClass, szTitle, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
      CW_USEDEFAULT, 0, width, height, NULL, NULL, hInstance, NULL);

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

   int editMargin = sizeBasis*3/2;
   
   int bottomCornerButtonSize = (clientRect.right - clientRect.left) / 3;
   bottomButtonHeight = (int)(bottomCornerButtonSize / 1.618);

   editArea.left = editMargin;
   editArea.top = editMargin;
   editArea.right = clientRect.right - editMargin;
   editArea.bottom = editArea.top + tm.tmHeight;

   scrollRect = clientRect;
   scrollRect.left = scrollRect.right - GetSystemMetrics(SM_CYVSCROLL);
   scrollRect.top = editArea.bottom + editMargin;
   scrollRect.bottom -= bottomButtonHeight;

   HWND edit = CreateWindow(_T("EDIT"), NULL, WS_VISIBLE|WS_CHILD|ES_AUTOHSCROLL|WS_TABSTOP, editArea.left,editArea.top, editArea.right - editArea.left,editArea.bottom - editArea.top, hWnd, (HMENU)IDC_SEARCH, NULL, NULL);
   SetWindowLongPtr(edit, GWLP_USERDATA, (LONG)&searchHintingEditData);
   SetWindowText(edit, searchHintingEditData.hintText);

   
   SendMessage(edit, WM_SETFONT, (WPARAM)font, FALSE);
   

   scroll = CreateWindowEx( 0, // no extended styles 
            L"SCROLLBAR",           // scroll bar control class 
            (PTSTR) NULL,           // no window text 
            WS_CHILD | WS_VISIBLE   // window styles  
                | SBS_VERT,         // vertical scroll bar style 
            scrollRect.left,              // horizontal position 
            scrollRect.top, // vertical position 
			scrollRect.right - scrollRect.left,             // width of the scroll bar 
			scrollRect.bottom - scrollRect.top,               // height of the scroll bar
            hWnd,             // handle to main window 
            (HMENU) NULL,           // no menu 
            hInstance,                // instance owning this window 
            (PVOID) NULL            // pointer not needed 
			);

   SCROLLINFO info = { 0 };
   info.cbSize = sizeof(info);
   info.fMask = SIF_RANGE | SIF_PAGE;
   info.nMax = 20 * sizeBasis*4;
   info.nPage = sizeBasis*4*10;
   SetScrollInfo(scroll, SB_CTL, &info, FALSE);

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

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

#include <math.h>

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
				float distance = sqrt((float)distanceSq);
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

void SetActiveTab(int idc)
{
	InvalidateRect(GetDlgItem(mainWnd, activeTab), NULL, FALSE);
	activeTab = idc;
	InvalidateRect(GetDlgItem(mainWnd, activeTab), NULL, FALSE);
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
		case IDC_SEARCH:
			{
				switch (wmEvent) {
				case EN_SETFOCUS:
					{
						HintingEditData *hintingEditData = (HintingEditData *)GetWindowLongPtr((HWND)lParam, GWLP_USERDATA);
						if (hintingEditData->showingHint) {
							SetWindowText((HWND)lParam, L"");
							hintingEditData->showingHint = FALSE;
						}
						hintingEditData->hasFocus = TRUE;
					}
					break;
				case EN_KILLFOCUS:
					{
						HintingEditData *hintingEditData = (HintingEditData *)GetWindowLongPtr((HWND)lParam, GWLP_USERDATA);
						if (!hintingEditData->showingHint && GetWindowTextLength((HWND)lParam)==0) {
							SetWindowText((HWND)lParam, hintingEditData->hintText);
							hintingEditData->showingHint = TRUE;
						}
						hintingEditData->hasFocus = FALSE;
					}
					break;
				}

			}
			break;
		case IDC_TAB_ACCOUNTS:
		case IDC_TAB_ADD:
		case IDC_TAB_SCAN:
			SetActiveTab(wmId);
			break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
		break;
	case WM_VSCROLL:
		{
			int type = LOWORD(wParam);
			if (type == SB_THUMBPOSITION || type == SB_THUMBTRACK) {


				int pos = HIWORD(wParam);
				SetScrollPos(scroll, SB_CTL, pos, FALSE);
				RECT r;
				r.left = 0;
				r.right = scrollRect.left;
				r.bottom = scrollRect.bottom;
				r.top = scrollRect.top;
				InvalidateRect(hWnd, &r, FALSE);
			}
		}
		break;
	case WM_ERASEBKGND:
		break;
	case WM_PAINT:
		{
			hdc = BeginPaint(hWnd, &ps);

			{
				int radius = 5;
				int margin = radius + 5;
				HBITMAP textBoxCorners = CreateRoundedCorner(hdc, RGB(255,255,255), RGB(200,200,200), RGB(255,255,255), radius);
				HDC src = CreateCompatibleDC(hdc);

				SelectObject(src, textBoxCorners);
				BitBlt(hdc, editArea.left-margin,editArea.top-margin,radius,radius,src,0,0,SRCCOPY);
				BitBlt(hdc, editArea.right+margin-radius,editArea.top-margin,radius,radius,src,radius,0,SRCCOPY);
				BitBlt(hdc, editArea.left-margin,editArea.bottom+margin-radius,radius,radius,src,0,radius,SRCCOPY);
				BitBlt(hdc, editArea.right+margin-radius,editArea.bottom+margin-radius,radius,radius,src,radius,radius,SRCCOPY);

				DeleteDC(src);
				DeleteObject(textBoxCorners);

				HBRUSH br = CreateSolidBrush(RGB(200,200,200));

				int marginOnly = margin-radius;

				RECT r;
			
				r = editArea; r.top = editArea.top-margin; r.bottom = r.top + 1; r.left -= marginOnly; r.right += marginOnly;
				FillRect(hdc, &r, br);

				r.bottom = editArea.bottom+margin; r.top = r.bottom - 1;
				FillRect(hdc, &r, br);
			
				r = editArea; r.left = editArea.left-margin; r.right = r.left + 1; r.top -= marginOnly; r.bottom += marginOnly;
				FillRect(hdc, &r, br);

				r.right = editArea.right + margin; r.left = r.right - 1;
				FillRect(hdc, &r, br);
			}



			RECT area;
			GetClientRect(hWnd, &area);
			int listTop = editArea.bottom + sizeBasis;
			int listBottom = area.bottom - bottomButtonHeight;
			HRGN listRegion = CreateRectRgn(area.left, listTop + sizeBasis, scrollRect.left, listBottom); 
			SelectClipRgn (hdc, listRegion);
			

			HBRUSH dividerBrush = CreateSolidBrush(RGB(230,230,230));
			HBRUSH backgroundBrush = CreateSolidBrush(RGB(255,255,255));
			
			int listItemHeight = sizeBasis*4;
			int dividerHeight = sizeBasis/6;
			SelectObject(hdc, font);

			int textHeight;
			{
				RECT measureRect = area;
				DrawText(hdc, L"O", 1, &measureRect, DT_SINGLELINE|DT_CALCRECT);
				textHeight = measureRect.bottom - measureRect.top;
			}

			// Draw the actual list of accounts
			int pos = GetScrollPos(scroll, SB_CTL);
			for (int i=0, listY = listTop - pos; i<20; i++, listY += listItemHeight) {
				if (listY + listItemHeight < listTop) continue;
				if (listY > listBottom) break;
				RECT divider;
				divider.left = 0;
				divider.right = scrollRect.left;
				divider.top = listY + listItemHeight - dividerHeight;
				divider.bottom = divider.top + dividerHeight;

				RECT itemArea = divider;
				itemArea.top = listY;
				itemArea.bottom = listY + listItemHeight;
				FillRect(hdc, &itemArea, backgroundBrush);

				RECT textRect = divider;
				textRect.left = sizeBasis;
				textRect.top = listY + (listItemHeight - textHeight)/2;
				WCHAR ch[50];
				wsprintf(ch, L"Option %d", i+1);
				DrawText(hdc, ch, -1, &textRect, DT_SINGLELINE);


				FillRect(hdc, &divider, dividerBrush);
			}

			SelectClipRgn(hdc, NULL);
			EndPaint(hWnd, &ps);

			DeleteObject(dividerBrush);
			DeleteObject(backgroundBrush);
		}
		break;
	case WM_CTLCOLOREDIT:
		{
			LRESULT ret = DefWindowProc(hWnd, message, wParam, lParam);
			HDC hdc = (HDC)wParam;
			HWND wnd = (HWND)lParam;

			HintingEditData *hintingEditData = (HintingEditData *)GetWindowLongPtr(wnd, GWLP_USERDATA);
			if (hintingEditData && hintingEditData->showingHint) {
				SetTextColor(hdc, RGB(200,200,200));
			}
			return ret;
		}
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
