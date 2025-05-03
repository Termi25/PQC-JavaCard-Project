package pqc.javacard.implementation;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.*;


public class Main {

    private static final byte SIGN = 0x00;
    private static final byte HASH_ONLY = 0x10;
    private static final int BYTE_LENGTH = 32;

    public static void main(String[] args) throws IOException {
        CardSimulator simulator = new CardSimulator();

        AID appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, PQC_Applet.class);

        simulator.selectApplet(appletAID);

        File folder = new File("testFiles");
        if(!folder.isDirectory()){
            System.out.println("Test folder does not exists. Add a test folder with this name in project root: testFiles");
            return;
        }

        for (File file : folder.listFiles()) {
            if (file.isDirectory()) {
                continue;
            }
            if (file.getName().endsWith(".enc") || file.getName().endsWith(".sha3")) {
                continue;
            }

            File encFile = new File(folder, file.getName().split("\\.")[0] + ".enc");
            boolean isOnlySHA3=false;
            signFile(simulator, file, encFile, isOnlySHA3);

            encFile = new File(folder, file.getName().split("\\.")[0] + ".sha3");
            isOnlySHA3=true;
            signFile(simulator, file, encFile, isOnlySHA3);
        }
    }

    public static void signFile(CardSimulator simulator, File inputFile, File outputFile, boolean isOnlySHA3) throws IOException {
        if (inputFile.exists()) {

            byte appletMode = SIGN;
            if(isOnlySHA3){
                appletMode = HASH_ONLY;
            }

            FileInputStream fis = new FileInputStream(inputFile);
            BufferedInputStream bis = new BufferedInputStream(fis);

            FileOutputStream fos = new FileOutputStream(outputFile);
            BufferedOutputStream bos = new BufferedOutputStream(fos);

            byte[] buffer = new byte[BYTE_LENGTH];
            while (true) {
                int noBytes=bis.read(buffer);
                if(noBytes == -1){
                    break;
                }

                if(noBytes < BYTE_LENGTH){
                    byte[] dataBlock = new byte[noBytes];
                    System.arraycopy(buffer, 0, dataBlock, 0, noBytes);
                    ResponseAPDU response = simulator.transmitCommand(new CommandAPDU(0x00,0x20,appletMode,0x00,dataBlock));
                    bos.write(response.getData());
                }else{
                    ResponseAPDU response = simulator.transmitCommand(new CommandAPDU(0x00,0x10,0x00,0x00,buffer));
                }
            }

            fis.close();
            bos.close();
        }
    }
}
