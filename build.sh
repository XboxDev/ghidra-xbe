#!/bin/bash -e
pushd /tmp

echo "[*] Downloading files..."
cat <<EOF > urls.txt
https://corretto.aws/downloads/latest/amazon-corretto-11-x64-linux-jdk.tar.gz
https://services.gradle.org/distributions/gradle-5.0-bin.zip
https://ghidra-sre.org/ghidra_9.1.1_PUBLIC_20191218.zip
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
unzip -q ghidra_9.1.1_PUBLIC_20191218.zip
export GHIDRA_INSTALL_DIR=$PWD/ghidra_9.1.1_PUBLIC

popd

echo "[*] Building..."
gradle

echo "[*] Done!"
