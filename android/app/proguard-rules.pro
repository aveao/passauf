# The native library looks these up by name, so R8 must not touch them.
-keep class zone.ave.passauf.PassaufNative { *; }
-keep interface zone.ave.passauf.PassaufNative$Transceiver { *; }
-keep interface zone.ave.passauf.PassaufNative$ProgressListener { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}
