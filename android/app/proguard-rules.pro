# The native library looks these up by name, so R8 must not touch them.
-keep class io.github.aveao.passauf.PassaufNative { *; }
-keep interface io.github.aveao.passauf.PassaufNative$Transceiver { *; }
-keep interface io.github.aveao.passauf.PassaufNative$ProgressListener { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}
