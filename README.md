# Blockchain, Quantum Cryptography and E-Payment/ E-Commerce Security Project      

## Description

This project contains a Java Card applet that implements Crystals-Dilithium Signature Algorithm with Keccak/SHA-3 for signing files. The project includes the source code for both the Java Card applet and the host application (See the `src` folder). Also, this project can be run as an `Intellij Idea Project` for ease of use.

## Requirements

Create a Java Card applet using `JavaCard 3.2.0+ API` for the following requirements:

- Create the PQC signature of the file with ML-DSA or NIST PQC round 4 algorithm and Keccak/SHA-3.
- The Java Card application exchanges message and is selected by a host stand-alone application (C/C++/Java/JavaScript), or a browser plugin / WASM – Web Assembly.
- The source code for the Java card applet and for the host application must be provided.
- Also the files with the compilation and run phases must be provided. 

## Repository Structure

```bash
.
├───.idea
│   └───libraries
├───classes                     <-- folder for compiled applet class and .CAP file
│   └───main
├───jars
├───jcdk                        <-- folder for CAP file converter
│   ├───bin
│   └───lib
├───lib
├───src                         <-- folder for the source code
│   ├───net                     <-- folder for the PQC implementation of the Crystals-Dilithium Signature Algorithm
│   │   └───thiim
│   │       └───dilithium
│   │           ├───impl
│   │           ├───interfaces
│   │           └───provider
│   └───pqc                     <-- folder for the main applet class and the host application
│       └───javacard
│           └───implementation
└───testFiles

```

## Scripts

- `create_cap.bat` / `create_cap.sh`: Script to create the CAP file from the Java Card applet source code.
  (NOTE: Due to the PQC Signature Algorithm Implementation, the compilation of the Applet fails due to the limitations of the JavaCard).
- `test_host.bat` / `test_host.sh`: Script to run the host application and test the Java Card applet.

> [!WARNING]
> The scripts are provided for Windows and Linux. Make sure to use the appropriate script for your operating system. You need to have installed a JDK that can compile with the flag --release 8. For instance, you can use the OpenJDK 8 or 11. If any derivative code is made upon this one using Maven, JDK 11 will need to be used, since JDK 8 is deprecated for it.

## Test files

For the demonstration of the functionality of the applet, the Host program works with files from the `test_files` folder. These files show the signing and SHA3-256 hashing functionalities of the Java Card applet. The files are in various formats (`.pdf`, `.docx`, `.txt`) to test the applet with different types of files. Any file can be provided beside the ones in this project, since the program works with the file bytes.

## Compilation and Execution

You can either generate the CAP file and install it on a Java Card simulator or a real Java Card or you can use the provided host application to test the applet. The host application communicates with the applet using APDU commands and allows you to encrypt and decrypt files.

Use the `create_cap.bat` or `create_cap.sh` script to create the CAP file from the Java Card applet source code. The script will compile the applet and generate the CAP file in the `classes` folder.

Use the `test_host.bat` or `test_host.sh` script to run the host application and test the Java Card applet. The script will compile the host application and run it, allowing you to encrypt and decrypt the test files using the applet.

Otherwise, you can simply open this project in an `Intellij Idea Client` and run the `Host.java` file. This is a much simpler way of checking out the functionality, especially for those not adept at working with `javac.exe` and `converter.bat`.

> [!IMPORTANT]
> Make sure to set the environment variables (`JAVA_HOME`) according to your own setup.
