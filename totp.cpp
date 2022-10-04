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
			TranslateMessage(&msg);
			DispatchMessage(&msg);
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
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   HWND hWnd;

   hInst = hInstance; // Store instance handle in our global variable

   int sizeBasis = GetSystemMetrics(SM_CYVSCROLL);
   int width = sizeBasis*24;
   int height = (int)(width * 1.618);
   
   hWnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
      CW_USEDEFAULT, 0, width, height, NULL, NULL, hInstance, NULL);

   if (!hWnd)
   {
      return FALSE;
   }
   
   RECT scrollRect;
   GetClientRect(hWnd, &scrollRect);
   scrollRect.left = scrollRect.right - GetSystemMetrics(SM_CYVSCROLL);

   HFONT font = CreateFont(sizeBasis*6/4, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FF_MODERN, L"Segoe UI");
   
   HDC dc = GetDC(hWnd);
   HGDIOBJ oldObj = SelectObject(dc, font);
   TEXTMETRIC tm = {0};
   GetTextMetrics (dc, &tm);
   SelectObject(dc, oldObj);

   int editMargin = sizeBasis*3/2;
   
   editArea.left = editMargin;
   editArea.top = editMargin;
   editArea.right = scrollRect.left - editMargin;
   editArea.bottom = editArea.top + tm.tmHeight;

   HWND edit = CreateWindow(_T("EDIT"), NULL, WS_VISIBLE|WS_CHILD|ES_AUTOHSCROLL, editArea.left,editArea.top, editArea.right - editArea.left,editArea.bottom - editArea.top, hWnd, NULL, NULL, NULL);
   SetWindowText(edit, _T("TExt content"));
   
   SendMessage(edit, WM_SETFONT, (WPARAM)font, FALSE);

   HWND scroll = CreateWindowEx( 0, // no extended styles 
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
   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

#include <math.h>

#define ROUNDED_CORNER_BOTTOM_RIGHT 0
#define ROUNDED_CORNER_BOTTOM_LEFT 1
#define ROUNDED_CORNER_TOP_RIGHT 2
#define ROUNDED_CORNER_TOP_LEFT 3

HBITMAP CreateRoundedCorner(HDC dc, COLORREF color, int radius, int corner) {
	HDC dc2 = CreateCompatibleDC(dc);
	HBITMAP bmp = CreateCompatibleBitmap(dc, radius, radius);
	HGDIOBJ oldObj = SelectObject(dc2, bmp);

	bool flipHorizontal = (corner&1)!=0;
	bool flipVertical = (corner&2)!=0;

	int curveMiddle = radius-1;
	int distanceMin = (curveMiddle-1)*(curveMiddle-1);
	int distanceMax = (curveMiddle+1)*(curveMiddle+1);
	for (int x=0; x<radius; x++) {
		for (int y=0; y<radius; y++) {
			COLORREF pixelColor = RGB(255,255,255);
			int distanceSq = x*x + y*y;
			if (distanceSq >= distanceMin && distanceSq <= distanceMax) {
				float distance = sqrt((float)distanceSq);
				float distanceWrongness = fabs(distance - curveMiddle);
				if (distanceWrongness <= 1) {
					int intensity = 200 + (int)((distanceWrongness)*55);
					pixelColor = RGB(intensity, intensity, intensity);
				}
			}
			
			SetPixel(dc2, flipHorizontal ? radius-1-x : x, flipVertical ? radius-1-y : y, pixelColor);
		}
	}

	SelectObject(dc2, oldObj);
	DeleteDC(dc2);

	return bmp;
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
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
		break;
	case WM_PAINT:
		{
			hdc = BeginPaint(hWnd, &ps);
			// TODO: Add any drawing code here...

			int radius = 5;
			int margin = radius + 5;
			HBITMAP topLeft = CreateRoundedCorner(hdc, RGB(255,0,0), radius, ROUNDED_CORNER_TOP_LEFT);
			HBITMAP topRight = CreateRoundedCorner(hdc, RGB(255,0,0), radius, ROUNDED_CORNER_TOP_RIGHT);
			HBITMAP bottomLeft = CreateRoundedCorner(hdc, RGB(255,0,0), radius, ROUNDED_CORNER_BOTTOM_LEFT);
			HBITMAP bottomRight = CreateRoundedCorner(hdc, RGB(255,0,0), radius, ROUNDED_CORNER_BOTTOM_RIGHT);
			HDC src = CreateCompatibleDC(hdc);

			SelectObject(src, topLeft); BitBlt(hdc, editArea.left-margin,editArea.top-margin,radius,radius,src,0,0,SRCCOPY);
			SelectObject(src, topRight); BitBlt(hdc, editArea.right+margin-radius,editArea.top-margin,radius,radius,src,0,0,SRCCOPY);
			SelectObject(src, bottomLeft); BitBlt(hdc, editArea.left-margin,editArea.bottom+margin-radius,radius,radius,src,0,0,SRCCOPY);
			SelectObject(src, bottomRight); BitBlt(hdc, editArea.right+margin-radius,editArea.bottom+margin-radius,radius,radius,src,0,0,SRCCOPY);

			DeleteDC(src);

			
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

			EndPaint(hWnd, &ps);
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
