# EAC Bypass + CR3 Ready IOCTL
This is my EAC Bypass (Setup) Driver that offers an undetected communication and callback handler/hooking system through IOCTL. Its not fully done/made because anything further with Handles & UserMode Hiding is up to the user & if publicized will become blacklisted or detected But I'll list some things you have to do yourself to make this work. This is just an undetected Base you can do to control CR3 & IOCTL Communication with Driver -> Usermode.
# 简单反作弊驱动绕过
这是我的EAC Bypass（安装）驱动程序，通过IOCTL提供未被检测到的通信和回调处理/挂钩系统。由于任何进一步处理句柄和用户模式隐藏的工作都取决于用户，如果公开将被列入黑名单或被检测到，因此它尚未完全完成/制作。但我会列出一些你需要自己做的事情，以使其正常工作。这只是一个未被检测到的基础，你可以用它来控制CR3和驱动程序 -> 用户模式的IOCTL通信。
# Things to add
- EPROCESS Bypass & DKOM Eprocess Bypass for Usermode.
- CR3 R/W Implementation (Just use my other source)
- Handle ID Randomization for KM->UM Communication
- Get a mapper (Use my DSE Exploit)
# Contact
If you want all of this done or want to hire me for more professional work (I do bypasses for BE,EAC,VGK) My contact discord is -> `_ambitza`
