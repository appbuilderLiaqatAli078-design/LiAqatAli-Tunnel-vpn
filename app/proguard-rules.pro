# Custom Tunnel Pro — Security & Obfuscation Rules

# Hide original source file names and strip debug attributes
-renamesourcefileattribute SourceFile
-overloadaggressively
-repackageclasses 'o.ctp'

# Keep Native JNI Bridges (Xray Core & HEV SOCKS5 Tunnel)
-keep class hev.socks5.tunnel.** { *; }
-keep class libv2ray.** { *; }
-keep class go.** { *; }

# Keep JSch SSH reflection classes
-keep class com.jcraft.jsch.** { *; }
-dontwarn com.jcraft.jsch.**
-dontwarn org.bouncycastle.**
-dontwarn org.newsclub.net.unix.**

# Strip verbose debug logs in release builds
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}
