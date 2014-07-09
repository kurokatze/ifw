ifw
===
ifw source code is located in frameworks/base/services/java/com/android/server/firewall/ under AOSP
IntentFirewall.java contains main code of ifw.

xml files provide seandroid ifw policy. These will not be compiled during AOSP compilation.
Put them under /data/system/ifw/ directory on your device to work, all xml files will be loaded during next boot.

hook contains modified codes for ifw checking in AMS. These files belongs to Android framework layer.
Corresponding files can be found in frameworks/base.
