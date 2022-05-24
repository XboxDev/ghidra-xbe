#!/bin/bash -e

export CORRETTO_ARCHIVE=amazon-corretto-15-x64-linux-jdk.tar.gz
export CORRETTO_URL=https://corretto.aws/downloads/latest/${CORRETTO_ARCHIVE}
export GHIDRA_VER_CORE=10.1.4
export GHIDRA_VER=${GHIDRA_VER_CORE}_PUBLIC
export GHIDRA_DATE=20220519
export GHIDRA_ARCHIVE=ghidra_${GHIDRA_VER}_${GHIDRA_DATE}.zip
export GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VER_CORE}_build/${GHIDRA_ARCHIVE}
export GRADLE_VER=6.8.2
export GRADLE_ARCHIVE=gradle-${GRADLE_VER}-bin.zip
export GRADLE_URL=https://services.gradle.org/distributions/${GRADLE_ARCHIVE}
export XBSYMBOLDATABASE_ARCHIVE=XbSymbolDatabase.zip
export XBSYMBOLDATABASE_URL=https://github.com/Cxbx-Reloaded/XbSymbolDatabase/releases/latest/download/${XBSYMBOLDATABASE_ARCHIVE}
declare -a URLS=(
	$CORRETTO_URL
	$GHIDRA_URL
	$GRADLE_URL
	$XBSYMBOLDATABASE_URL
)

pushd /tmp

echo "[*] Downloading files..."
echo ${URLS[@]} | xargs -n 1 -P ${#URLS[@]} wget -N -nv

echo "[*] Extracting JDK..."
tar --strip-components=1 --one-top-level=jdk -xf ${CORRETTO_ARCHIVE}
export JAVA_HOME=$PWD/jdk
export PATH=$JAVA_HOME/bin:$PATH

echo "[*] Extracting Gradle..."
unzip -q ${GRADLE_ARCHIVE}
export PATH=$PWD/gradle-${GRADLE_VER}/bin:$PATH

echo "[*] Extracting Ghidra..."
unzip -q ${GHIDRA_ARCHIVE}
export GHIDRA_INSTALL_DIR=$PWD/ghidra_${GHIDRA_VER}

echo "[*] Extracting XbSymbolDatabase..."
unzip -qd XbSymbolDatabase ${XBSYMBOLDATABASE_ARCHIVE}
export XBSYMBOLDATABASE=$PWD/XbSymbolDatabase

popd # Back to source root

# Copy XbSymbolDatabase into this source tree for redist
cp $XBSYMBOLDATABASE/linux_x64/bin/XbSymbolDatabaseCLI	os/linux_x86_64/XbSymbolDatabaseTool
cp $XBSYMBOLDATABASE/LICENSE					os/linux_x86_64/XbSymbolDatabaseTool.LICENSE
cp $XBSYMBOLDATABASE/macos_x64/bin/XbSymbolDatabaseCLI	os/mac_x86_64/XbSymbolDatabaseTool
cp $XBSYMBOLDATABASE/LICENSE					os/mac_x86_64/XbSymbolDatabaseTool.LICENSE
cp $XBSYMBOLDATABASE/win_x64/bin/XbSymbolDatabaseCLI.exe	os/win_x86_64/XbSymbolDatabaseTool.exe
cp $XBSYMBOLDATABASE/LICENSE					os/win_x86_64/XbSymbolDatabaseTool.LICENSE

# Add execute permissions to Linux and macOS XbSymbolDatabase binaries
chmod +x os/linux_x86_64/XbSymbolDatabaseTool
chmod +x os/mac_x86_64/XbSymbolDatabaseTool

echo "[*] Building..."
gradle -b build.gradle

if [[ "$RUNTESTS" == "1" || "$CI" == "true" ]]; then
	echo "[*] Installing Extension..."
	cp dist/*ghidra-xbe.zip $GHIDRA_INSTALL_DIR/Ghidra/Extensions
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
	popd
fi

if [[ "$CI" == "true" ]]; then
	export BUILD_TAG=build-$(date -u +'%Y%m%d%H%M')
	mkdir -p dist
	echo -n $BUILD_TAG > dist/tag
fi

if [[ "$GITHUB_ACTIONS" == "true" ]]; then
	echo "::set-output name=BUILD_TAG::$BUILD_TAG"
	echo "::set-output name=GHIDRA_VER::$GHIDRA_VER"
	echo "::set-output name=GHIDRA_ARCHIVE::$GHIDRA_ARCHIVE"
	echo "::set-output name=GHIDRA_URL::$GHIDRA_URL"
fi

echo "[*] Done!"
