# Called from native code and by name, so shrinking must not rename or remove them.
-keep class io.github.plutopro.ripsec.vpn.** { *; }
