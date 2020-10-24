#!/bin/bash -e
pushd /tmp

echo "[*] Downloading files..."
cat <<EOF > urls.txt
https://corretto.aws/downloads/latest/amazon-corretto-11-x64-linux-jdk.tar.gz
https://services.gradle.org/distributions/gradle-5.0-bin.zip
https://ghidra-sre.org/ghidra_9.1.2_PUBLIC_20200212.zip
https://github.com/mborgerson/XbSymbolDatabase/releases/download/cli-tool-0.1/XbSymbolDatabaseTool.zip
EOF
cat urls.txt | xargs -n 1 -P 10 wget --no-verbose

echo "[*] Extracting JDK..."
mkdir -p jdk
tar --strip-components=1 -C jdk --extract -f amazon-corretto-11-x64-linux-jdk.tar.gz
export JAVA_HOME=$PWD/jdk
export PATH=$JAVA_HOME/bin:$PATH

echo "[*] Extracting Gradle..."
unzip -q gradle-5.0-bin.zip
export PATH=$PWD/gradle-5.0/bin:$PATH

echo "[*] Extracting Ghidra..."
unzip -q ghidra_9.1.2_PUBLIC_20200212.zip
export GHIDRA_INSTALL_DIR=$PWD/ghidra_9.1.2_PUBLIC

echo "[*] Extracting XbSymbolDatabase..."
unzip -q XbSymbolDatabaseTool.zip
export XBSYMBOLDATABASE=$PWD/XbSymbolDatabaseTool

popd # Back to source root

# Copy XbSymbolDatabase into this source tree for redist
cp $XBSYMBOLDATABASE/XbSymbolDatabaseTool.linux64.Release   os/linux64/XbSymbolDatabaseTool
cp $XBSYMBOLDATABASE/LICENSE                                os/linux64/XbSymbolDatabaseTool.LICENSE
cp $XBSYMBOLDATABASE/XbSymbolDatabaseTool.macos64.Release   os/osx64/XbSymbolDatabaseTool
cp $XBSYMBOLDATABASE/LICENSE                                os/osx64/XbSymbolDatabaseTool.LICENSE
cp $XBSYMBOLDATABASE/XbSymbolDatabaseTool.win64.Release.exe os/win64/XbSymbolDatabaseTool.exe
cp $XBSYMBOLDATABASE/LICENSE                                os/win64/XbSymbolDatabaseTool.LICENSE

echo "[*] Building..."
gradle -b build.gradle

if [[ "$RUNTESTS" == "1" ]]; then
	echo "[*] Installing Extension..."
	cp ./dist/*ghidra-xbe.zip $GHIDRA_INSTALL_DIR/Ghidra/Extensions
	pushd $GHIDRA_INSTALL_DIR/Ghidra/Extensions
	unzip *ghidra-xbe.zip
	popd

	echo "[*] Running tests..."
	pushd tests
	$GHIDRA_INSTALL_DIR/support/analyzeHeadless . test_project -import xbefiles/triangle.xbe -postScript ./test_load.py
	if [[ -e TEST_PASS ]]; then
		echo "[+] Test PASSED"
	else
		echo "[-] Test FAILED"
		exit 1
	fi
fi

echo "[*] Done!"
