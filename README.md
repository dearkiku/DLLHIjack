# 如何使用DLLHijack进行快速的DLL劫持
- 1.在DLLHijack的界面将你需要劫持的DLL 输入/浏览/拖入 到程序中
- 2.确认目录&函数名&架构之后，点击生成DEF和H文件
- 3.将文件添加到你创建的DLL中
- 4.在DLL_PROCESS_ATTACH添加InitHijack() 在DLL_PROCESS_DETACH添加FreeHijack()
- 5.编译后放入目标程序根目录即可
# 注意事项
- 如果你的DLL是在软件根目录的，只需要取消勾选[×]系统路径，然后更改原始DLL输入框的名字（例如debug->debug_m），然后更改原DLL(debug.dll->debug_m.dll)，再将生成的DLL放入目录即可在程序访问debug.dll的时候转发到当前目录下的debug.dll
- 不是所有的程序都能通过此种方法劫持，其他方法可以看看[[这里]](https://learn.microsoft.com/zh-cn/windows/win32/dlls/secure-boot-and-appinit-dlls)

![image](https://github.com/dearkiku/DLLHIjack/blob/main/temp/%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20250509100824.png)
![image](https://github.com/dearkiku/DLLHIjack/blob/main/temp/%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20250509100719.png)
