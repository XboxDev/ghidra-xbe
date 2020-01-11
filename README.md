ghidra-xbe ![CI Status](https://github.com/mborgerson/ghidra-xbe/workflows/Build/badge.svg?branch=master)
==========

This is an extension for the Ghidra SRE framework to support loading Xbox Executable Format (XBE) files.

How to Build
------------
To build this extension on Ubuntu, you can simply run the `build.sh` script in this repository. It will download the JDK, Gradle 5.0, and Ghidra release package, then build the extension and output to the `dist` directory.

How to Install
--------------
Copy the extension package `dist/ghidra_*_ghidra-xbe.zip` to your Ghidra installation directory `<path to Ghidra root>/Extensions/Ghidra`. When starting Ghidra, in the main window navigate to <kbd>File</kbd>&rarr;<kbd>Install Extensions...</kbd>, and select **XboxExecutableLoader**. You can now import and analyze XBE files!
