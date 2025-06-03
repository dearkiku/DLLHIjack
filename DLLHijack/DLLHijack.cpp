// DLLHijack.cpp : 定义应用程序的入口点。
//

// Windows 头文件
// #include "framework.h"
#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
#include <windows.h>
#include "DLLHijack.h"
#include <fstream>			// 输出 .def/.h 文件（std::wofstream）
#include <shlobj.h>			// SHBrowseForFolder 和 SHGetPathFromIDList
#include "CommCtrl.h"		// ListView 样式与函数需要
#include "shellapi.h"		// 拖放Drag & Drop（DragAcceptFiles、DragQueryFile）  
#include "commdlg.h"		// GetOpenFileName 文件选择框  
#include "filesystem"		// std::filesystem::path 路径处理  

#define MAX_LOADSTRING 100
// 简洁的数据类型
struct ExportedFunction {
	WORD ordinal;        // 序号
	std::string name;    // 函数名（ANSI字符串）
};
// 全局变量:
HINSTANCE hInst;                                // 当前实例
WCHAR szTitle[MAX_LOADSTRING];                  // 标题栏文本
WCHAR szWindowClass[MAX_LOADSTRING];            // 主窗口类名
HWND hMain, hStatic[3], hEdit[2], hButton[3], hCheckBox, hListView;	// 组件句柄
WNDPROC oldEditProc = nullptr;	// 旧的编辑框窗口过程
std::vector<ExportedFunction> function;	// 存储函数数据的集合
// 此代码模块中包含的函数的前向声明:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	// TODO: 在此处放置代码。

	// 初始化全局字符串
	LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadStringW(hInstance, IDC_DLLHIJACK, szWindowClass, MAX_LOADSTRING);
	MyRegisterClass(hInstance);

	// 执行应用程序初始化:
	if (!InitInstance(hInstance, nCmdShow))
	{
		return FALSE;
	}

	HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_DLLHIJACK));

	MSG msg;

	// 主消息循环:
	while (GetMessage(&msg, nullptr, 0, 0))
	{
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return (int)msg.wParam;
}

// 获取编辑框中的文本
static std::wstring GetEditText(HWND hwndEdit) {
	// 获取编辑框中的文本长度
	int length = GetWindowTextLength(hwndEdit);
	if (length == 0) {
		return L"";
	}

	// 分配缓冲区，额外加1用于存储字符串的结束符'\0'
	std::wstring buffer(length + 1, L'\0');

	// 获取编辑框中的文本
	GetWindowText(hwndEdit, &buffer[0], length + 1);

	// 调整wstring的大小，去掉多余的空字符
	buffer.resize(length);

	return buffer;
}

// 获取DLL架构 导出函数数量
static void ParseExportTableOffline(const std::wstring& filePath) {
	function.clear();
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hMapping = nullptr;
	LPVOID lpBase = nullptr;
	do
	{
		hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hFile == INVALID_HANDLE_VALUE) {
			MessageBox(hMain, L"无法打开filePath文件", L"错误", MB_OK);
			break;
		}

		hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
		if (!hMapping) {
			MessageBox(hMain, L"无法创建文件映射", L"错误", MB_OK);
			break;
		}

		lpBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
		if (!lpBase) {
			MessageBox(hMain, L"无法映射文件视图", L"错误", MB_OK);
			break;
		}

		BYTE* base = reinterpret_cast<BYTE*>(lpBase);
		PIMAGE_DOS_HEADER pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
		if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
			MessageBox(hMain, L"DOS 头无效", L"错误", MB_OK);
			break;
		}

		PIMAGE_NT_HEADERS pNT = reinterpret_cast<PIMAGE_NT_HEADERS>(base + pDos->e_lfanew);
		if (pNT->Signature != IMAGE_NT_SIGNATURE) {
			MessageBox(hMain, L"NT 头无效", L"错误", MB_OK);
			break;
		}

		bool is64 = (pNT->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
		DWORD exportDirRVA = is64
			? reinterpret_cast<PIMAGE_NT_HEADERS64>(pNT)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
			: reinterpret_cast<PIMAGE_NT_HEADERS32>(pNT)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		// std::wcout << L"架构: " << (is64 ? L"64位" : L"32位") << std::endl;

		if (exportDirRVA == 0) {
			MessageBox(hMain, L"该 DLL 没有导出表", L"错误", MB_OK);
			break;
		}

		auto RvaToFoa = [&](DWORD rva) -> DWORD {
			PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNT);
			for (int i = 0; i < pNT->FileHeader.NumberOfSections; ++i, ++section) {
				DWORD start = section->VirtualAddress;
				DWORD size = section->Misc.VirtualSize;
				if (rva >= start && rva < start + size) {
					return section->PointerToRawData + (rva - start);
				}
			}
			return 0;
			};

		DWORD exportDirOffset = RvaToFoa(exportDirRVA);
		if (exportDirOffset == 0) {
			MessageBox(hMain, L"找不到导出表的文件偏移", L"错误", MB_OK);
			break;
		}

		PIMAGE_EXPORT_DIRECTORY pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + exportDirOffset);

		DWORD nameCount = pExportDir->NumberOfNames;
		DWORD namesRVA = pExportDir->AddressOfNames;
		DWORD ordinalsRVA = pExportDir->AddressOfNameOrdinals;
		DWORD functionsRVA = pExportDir->AddressOfFunctions;

		DWORD namesOffset = RvaToFoa(namesRVA);
		DWORD ordinalsOffset = RvaToFoa(ordinalsRVA);
		DWORD functionsOffset = RvaToFoa(functionsRVA);

		if (!namesOffset || !ordinalsOffset || !functionsOffset) {
			MessageBox(hMain, L"导出表信息无效", L"错误", MB_OK);
			break;
		}

		auto names = reinterpret_cast<DWORD*>(base + namesOffset);
		auto ordinals = reinterpret_cast<WORD*>(base + ordinalsOffset);

		std::wstring tips = GetEditText(hEdit[1]);

		if (is64)
		{
			tips += L":[x64]-";
		}
		else
		{
			tips += L":[x32]-";
		}
		tips += L"导出函数总数:";// （有名）
		tips += std::to_wstring(nameCount);
		// 设置提示到标签
		SetWindowTextW(hStatic[2], tips.c_str());

		for (DWORD i = 0; i < nameCount; ++i) {
			DWORD nameRVA = names[i];
			DWORD nameOffset = RvaToFoa(nameRVA);
			if (nameOffset == 0) continue;

			const char* funcName = reinterpret_cast<const char*>(base + nameOffset);
			// WORD ordinal = ordinals[i] ;
			WORD ordinal = ordinals[i] + 1;
			function.push_back({ ordinal, std::string(funcName) });
			//DWORD funcRVA = funcs[ordinal];

			//std::wcout << L"[序号: " << (ordinal + pExportDir->Base)
			//	<< L"] 函数名: " << funcName
			//	<< L" RVA: 0x" << std::hex << funcRVA << std::dec << std::endl;
		}

	} while (false);

	// 清理资源
	if (lpBase) UnmapViewOfFile(lpBase);
	if (hMapping) CloseHandle(hMapping);
	if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
}

// 写出DEF文件
static void WriteDefFile(const std::vector<ExportedFunction>& funcs, const std::wstring& outputPath)
{
	std::wofstream ofs(outputPath);
	if (!ofs.is_open()) {
		MessageBox(hMain, L"无法写入DEF文件", L"错误", MB_OK);
		return;
	}
	// 设置流的本地化环境以支持宽字符
	ofs.imbue(std::locale("en_US.utf8"));

	ofs << L"// 需要将此文件添加到>>>项目(P)->属性(ALT+F7)->链接器->输入->模块定义文件<<<中(平台选择和编译需一致)" << std::endl;
	
	ofs << L"LIBRARY" << std::endl;
	ofs << L"EXPORTS" << std::endl;

	for (const auto& func : funcs) {
		ofs << std::wstring(func.name.begin(), func.name.end())
			<< L"=" << PREFIX_REDIRECT << std::wstring(func.name.begin(), func.name.end())
			<< L" @" << func.ordinal << std::endl;
	}

	ofs.close();
}

// 写出H文件
static void WriteHeaderFile(const std::vector<ExportedFunction>& funcs, const std::wstring& outputPath, const std::wstring& dllName)
{
	OutputDebugString(outputPath.c_str());
	std::wofstream ofs(outputPath);
	if (!ofs.is_open()) {
		std::wstring tips = L"无法写出到该目录：" + outputPath;
		MessageBox(hMain, tips.c_str(), L"错误", MB_OK);
		return;
	}
	// 设置流的本地化环境以支持宽字符
	ofs.imbue(std::locale("en_US.utf8"));

	ofs << L"#pragma once\n";
	ofs << L"// 从 Windows 头文件中排除极少使用的内容\n";
	ofs << L"#define WIN32_LEAN_AND_MEAN\n";
	ofs << L"#include <Windows.h>\n\n";

	// 声明原始模块句柄
	ofs << L"HMODULE " << PREFIX_REAL << "Module = NULL;\n\n";

	// 声明 FARPROC 变量
	for (const auto& f : funcs) {
		ofs << L"FARPROC " << PREFIX_REAL << std::wstring(f.name.begin(), f.name.end()) << L" = NULL;\n";
	}

	ofs << L"\nFARPROC WINAPI GetAddress(LPCSTR lpProcName)\n{\n";
	ofs << L"    FARPROC pAddress = GetProcAddress(" << PREFIX_REAL << "Module, lpProcName);\n";
	ofs << L"    if (!pAddress)\n";
	ofs << L"    {\n";
	ofs << L"        MessageBoxW(NULL, L\"Get address failed\", L\"" << dllName << L".dll\", MB_OK);\n";
	ofs << L"        ExitProcess(1);\n";
	ofs << L"    }\n";
	ofs << L"    return pAddress;\n";
	ofs << L"}\n\n";

	// Init
	ofs << L"VOID WINAPI " << FUNCATION_INIT << "()\n{\n";
	// 系统路径
	if (IsDlgButtonChecked(hMain, IDC_CHECKBOX_SYSTEM) == BST_CHECKED)
	{
		ofs << L"    WCHAR real_dll_path[MAX_PATH];\n";
		ofs << L"    GetSystemDirectoryW(real_dll_path, MAX_PATH);\n";
		ofs << L"    lstrcatW(real_dll_path, L\"\\\\" << dllName << L".dll\");\n\n";
	}
	else // 根目录 .\*.DLL 
	{
		ofs << L"    WCHAR real_dll_path[] = L\".\\\\" << dllName << L".dll\";\n\n";
	}

	// 载入原始DLL
	ofs << L"    " << PREFIX_REAL << "Module = LoadLibraryW(real_dll_path);\n";
	ofs << L"    if (!" << PREFIX_REAL << "Module)\n";
	ofs << L"    {\n";
	ofs << L"        MessageBoxW(NULL, L\"Load original dll failed\", L\"" << dllName << L".dll\", MB_OK);\n";
	ofs << L"        ExitProcess(1);\n";
	ofs << L"    }\n\n";

	// 获取函数地址
	for (const auto& f : funcs) {
		ofs << L"    " << PREFIX_REAL << std::wstring(f.name.begin(), f.name.end()) << L" = GetAddress(\"" << std::wstring(f.name.begin(), f.name.end()) << L"\");\n";
	}
	ofs << L"}\n\n";

	// Free
	ofs << L"VOID WINAPI " << FUNCATION_FREE << "()\n{\n";
	ofs << L"    if (" << PREFIX_REAL << "Module) FreeLibrary(" << PREFIX_REAL << "Module);\n";
	ofs << L"}\n\n";

	// Redirect函数
	for (const auto& f : funcs) {
		ofs << L"void " << PREFIX_REDIRECT << std::wstring(f.name.begin(), f.name.end()) << L"() { " << PREFIX_REAL << std::wstring(f.name.begin(), f.name.end()) << L"(); }\n";
	}
	// 清理
	ofs.close();
}

//
//  函数: MyRegisterClass()
//
//  目标: 注册窗口类。
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEXW wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = WndProc;
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0;
	wcex.hInstance = hInstance;
	wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_DLLHIJACK));
	wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszMenuName = MAKEINTRESOURCEW(IDC_DLLHIJACK);
	wcex.lpszClassName = szWindowClass;
	wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

	return RegisterClassExW(&wcex);
}

//
//   函数: InitInstance(HINSTANCE, int)
//
//   目标: 保存实例句柄并创建主窗口
//
//   注释:
//
//        在此函数中，我们在全局变量中保存实例句柄并
//        创建和显示主程序窗口。
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
	hInst = hInstance; // 将实例句柄存储在全局变量中

	HWND hWnd = CreateWindowEx(
		0,// WS_EX_TOPMOST | WS_EX_CONTEXTHELP, 
		szWindowClass, szTitle,
		WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
		CW_USEDEFAULT, 0, 434, 528,
		nullptr, nullptr, hInstance, nullptr);
	if (!hWnd)
	{
		return FALSE;
	}

	ShowWindow(hWnd, nCmdShow);
	UpdateWindow(hWnd);

	return TRUE;
}

// 更新列表视图
static void UpdateListView(const std::vector<ExportedFunction>& funcs, const std::wstring& filePath)
{
	// 将文件路径转成filesystem path类型
	std::filesystem::path file_path(filePath);
	// 获取不带后缀的文件名
	// 将文件名显示到名称编辑框
	SetWindowTextW(hEdit[1], file_path.stem().wstring().c_str());
	// 清空旧项目
	ListView_DeleteAllItems(hListView);
	// 获取新的DLL函数
	ParseExportTableOffline(filePath);
	// 提前分配项目空间
	ListView_SetItemCount(hListView, funcs.size());
	for (size_t i = 0; i < funcs.size(); ++i)
	{
		const ExportedFunction& func = funcs[i];

		// 插入序号列
		LVITEM lvi = { 0 };
		lvi.mask = LVIF_TEXT;
		lvi.iItem = static_cast<int>(i);
		lvi.iSubItem = 0;

		WCHAR szOrdinal[16];
		swprintf_s(szOrdinal, L"%d", func.ordinal);
		lvi.pszText = szOrdinal;

		ListView_InsertItem(hListView, &lvi);

		// 设置函数名列（从 std::string 转换为 std::wstring）
		std::wstring wName(func.name.begin(), func.name.end());
		ListView_SetItemText(hListView, static_cast<int>(i), 1, const_cast<LPWSTR>(wName.c_str()));
	}
}

// 处理目录输入框回车事件
LRESULT CALLBACK EditSubclassProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	if (msg == WM_KEYDOWN && wParam == VK_RETURN)
	{
		std::wstring path = GetEditText(hWnd);
		if (!path.empty() && std::filesystem::exists(path))
		{
			LPCWSTR ext = wcsrchr(path.c_str(), L'.');
			if (ext && (_wcsicmp(ext, L".dll") == 0)) // 匹配 .dll 不区分大小写
			{
				UpdateListView(function, path);
			}
		}
		return 0;
	}
	return CallWindowProc(oldEditProc, hWnd, msg, wParam, lParam);
}

// 初始化窗口组件
static void InitControls(HWND hWnd) {
	hStatic[0] = CreateWindowEx(
		WS_EX_WINDOWEDGE,
		WC_STATIC, L"输入DLL",
		WS_CHILD | WS_VISIBLE | SS_CENTER | SS_CENTERIMAGE,
		16, 15, 64, 32,
		hWnd, (HMENU)IDC_STATIC_INPUT, hInst, NULL);
	hStatic[1] = CreateWindowEx(
		WS_EX_WINDOWEDGE,
		WC_STATIC, L"原始DLL",
		WS_CHILD | WS_VISIBLE | SS_CENTER | SS_CENTERIMAGE,
		16, 55, 64, 32,
		hWnd, (HMENU)IDC_STATIC_OUTPUT, hInst, NULL);
	hStatic[2] = CreateWindowEx(
		WS_EX_WINDOWEDGE,
		WC_STATIC, L"拖入1个DLL | 浏览选择 |  输入路径按回车",// 提示架构和函数数量的标签
		WS_CHILD | WS_VISIBLE | SS_CENTER | SS_CENTERIMAGE,
		16, 96, 395, 32,
		hWnd, (HMENU)IDC_STATIC_OUTPUT, hInst, NULL);
	// 按钮
	hButton[0] = CreateWindowEx(
		0,
		WC_BUTTON, L"...",// 输入DLL浏览
		WS_CHILD | WS_VISIBLE | WS_TABSTOP,
		363, 15, 48, 32,
		hWnd, (HMENU)IDC_BUTTON_BROWSE_INPUT, hInst, NULL);
	hButton[1] = CreateWindowEx(
		0,
		WC_BUTTON, L"生成.def",
		WS_CHILD | WS_VISIBLE | WS_TABSTOP,
		232, 448, 83, 32,
		hWnd, (HMENU)IDC_BUTTON_OUTPUT_DEF, hInst, NULL);
	hButton[2] = CreateWindowEx(
		0,
		WC_BUTTON, L"生成.h",
		WS_CHILD | WS_VISIBLE | WS_TABSTOP,
		328, 448, 83, 32,
		hWnd, (HMENU)IDC_BUTTON_OUTPUT_H, hInst, NULL);

	// 复选框
	hCheckBox = CreateWindowEx(0,
		WC_BUTTON, L"系统路径",
		WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
		331, 55, 80, 32,
		hWnd, (HMENU)IDC_CHECKBOX_SYSTEM, hInst, NULL);
	SendMessage(hCheckBox, BM_SETCHECK, BST_CHECKED, NULL);

	// 目录输入框
	hEdit[0] = CreateWindowEx(
		WS_EX_STATICEDGE,
		WC_EDIT, L"",
		WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_WANTRETURN,
		80, 15, 280, 32,
		hWnd, (HMENU)IDC_EDIT_INPUT, hInst, NULL);
	oldEditProc = (WNDPROC)SetWindowLongPtr(hEdit[0], GWLP_WNDPROC, (LONG_PTR)EditSubclassProc);
	// DLL名称框
	hEdit[1] = CreateWindowEx(
		WS_EX_STATICEDGE,
		WC_EDIT, L"",
		WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
		80, 55, 240, 32,
		hWnd, (HMENU)IDC_EDIT_NAME, hInst, NULL);

	// 创建报表列表框
	hListView = CreateWindowEx(
		NULL, WC_LISTVIEW, NULL,
		WS_CHILD | WS_VISIBLE | WS_BORDER
		// 列表 | 指定只能有一个列表项被选中。默认时可以多项选择 | 即使控件失去输入焦点，仍显示出项的选择状态
		| LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
		16, 138, 395, 296,
		hWnd, (HMENU)IDC_LISTVIEW_SHOW, hInst, NULL);
	ListView_SetExtendedListViewStyle(hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_ONECLICKACTIVATE | LVS_EX_UNDERLINEHOT | LVS_EX_AUTOCHECKSELECT);
	TCHAR achTemp[50];
	// 列设置
	LVCOLUMN lvc = { LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM | LVCF_FMT };
	lvc.fmt = LVCFMT_CENTER;
	lvc.cxIdeal = 50;

	lvc.cx = 60; //列宽
	wsprintf(achTemp, L"序数"); lvc.pszText = achTemp;
	ListView_InsertColumn(hListView, 0, &lvc);

	lvc.cx = 315;
	wsprintf(achTemp, L"函数名"); lvc.pszText = achTemp;
	ListView_InsertColumn(hListView, 1, &lvc);
}

// 浏览文件夹
std::wstring BrowseForFolder(HWND hWnd)
{
	BROWSEINFO bi = { 0 };
	bi.lpszTitle = L"请选择保存文件的文件夹";
	bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
	bi.hwndOwner = hWnd;

	LPITEMIDLIST pidl = SHBrowseForFolder(&bi);
	if (pidl != nullptr)
	{
		WCHAR szPath[MAX_PATH];
		if (SHGetPathFromIDList(pidl, szPath))
		{
			CoTaskMemFree(pidl);
			return szPath;
		}
		CoTaskMemFree(pidl);
	}
	return L"";
}

//
//  函数: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  目标: 处理主窗口的消息。
//
//  WM_COMMAND  - 处理应用程序菜单
//  WM_PAINT    - 绘制主窗口
//  WM_DESTROY  - 发送退出消息并返回
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	static HBRUSH hbrBackground;  // 用于保存背景色的画刷
	switch (message)
	{
	case WM_CREATE:
	{
		hMain = hWnd;
		hbrBackground = CreateSolidBrush(GetSysColor(COLOR_WINDOW));  // 获取系统背景颜色
		DragAcceptFiles(hWnd, TRUE); // 支持文件拖拽
		InitControls(hWnd);
	}
	break;
	case WM_DROPFILES:
	{
		HDROP hDrop = (HDROP)wParam;
		WCHAR szFileName[MAX_PATH] = { 0 };
		DragQueryFile(hDrop, 0, szFileName, MAX_PATH);
		// 获取文件扩展名并转换为小写
		LPCWSTR ext = wcsrchr(szFileName, L'.');
		if (ext && (_wcsicmp(ext, L".dll") == 0)) // 匹配 .dll 不区分大小写
		{
			SetWindowTextW(hEdit[0], szFileName);

			UpdateListView(function, szFileName);
		}
		DragFinish(hDrop); // 释放资源
	}
	break;
	case WM_COMMAND:
	{
		int wmId = LOWORD(wParam);
		// 分析菜单选择:
		switch (wmId)
		{
		case IDC_BUTTON_BROWSE_INPUT:
		{
			WCHAR szFile[MAX_PATH] = { 0 };
			OPENFILENAME ofn = { 0 };
			ofn.lStructSize = sizeof(ofn);
			ofn.hwndOwner = hWnd;
			ofn.lpstrFilter = L"DLL 文件 (*.dll)\0*.dll";// \0所有文件 (*.*)\0*.*\0
			ofn.lpstrFile = szFile;
			ofn.nMaxFile = MAX_PATH;
			ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
			ofn.lpstrTitle = L"选择 DLL 文件";
			if (GetOpenFileName(&ofn)) {
				// 设置路径到编辑框
				SetWindowTextW(hEdit[0], szFile);

				UpdateListView(function, szFile);
			}
		}
		break;
		case IDC_BUTTON_OUTPUT_DEF:
		{
			std::wstring folder = BrowseForFolder(hWnd);
			if (!folder.empty())
			{
				std::wstring hPath = folder + L"\\" + GetEditText(hEdit[1]) + L".def";
				WriteDefFile(function, hPath);
			}
		}
		break;
		case IDC_BUTTON_OUTPUT_H:
		{
			std::wstring folder = BrowseForFolder(hWnd);
			if (!folder.empty())
			{
				std::wstring dllName = GetEditText(hEdit[1]);
				std::wstring hPath = folder + L"\\" + dllName + L".h";
				WriteHeaderFile(function, hPath, dllName);
			}
		}
		break;
		//case IDM_EXIT:
		//    DestroyWindow(hWnd);
		//    break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
	}
	break;
	case WM_PAINT:
	{
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hWnd, &ps);
		// TODO: 在此处添加使用 hdc 的任何绘图代码...
		EndPaint(hWnd, &ps);
	}
	break;
	case WM_CTLCOLORSTATIC:
	{
		HDC hdcStatic = (HDC)wParam;
		SetBkMode(hdcStatic, TRANSPARENT);  // 透明背景
		SetTextColor(hdcStatic, RGB(0, 0, 0));  // 黑色文本
		return (LRESULT)hbrBackground;  // 设置标签控件的背景色
	}
	break;
	case WM_CTLCOLORBTN:
	{
		HDC hdcButton = (HDC)wParam;
		SetBkMode(hdcButton, TRANSPARENT);  // 透明背景
		SetTextColor(hdcButton, RGB(0, 0, 0));  // 黑色文本
		return (LRESULT)hbrBackground;  // 设置按钮控件的背景色
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
