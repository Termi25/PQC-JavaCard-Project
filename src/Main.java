import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.*;


public class Main {
    public static final byte ENCRYPT = 0x00;
    public static final byte DECRYPT = 0x10;

    public static void main(String[] args) throws IOException {
        CardSimulator simulator = new CardSimulator();

        AID appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, AES_Applet.class);

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
            if (file.getName().endsWith(".enc") || file.getName().startsWith("Decrypted_")) {
                continue;
            }

            File encFile = new File(folder, file.getName().split("\\.")[0] + ".enc");
            encryptFile(simulator, file, encFile, true);

            File decFile = new File(folder, "Decrypted_" + file.getName());
            encryptFile(simulator, encFile, decFile, false);
        }
    }

    public static void encryptFile(CardSimulator simulator, File inputFile, File outputFile, boolean isEncrypting) throws IOException {
        if (inputFile.exists()) {

            byte claAESMode = ENCRYPT;
            if (isEncrypting) {
                claAESMode = DECRYPT;
            }

            FileInputStream fis = new FileInputStream(inputFile);

            FileOutputStream fos = new FileOutputStream(outputFile);
            BufferedOutputStream bos = new BufferedOutputStream(fos);

            byte[] buffer = fis.readAllBytes();
            int offset = 0;
            while (offset < buffer.length) {
                int remainingBytes = buffer.length - offset;
                boolean lastBlock = (remainingBytes <= 16);

                ResponseAPDU response = null;
                if (lastBlock) {
                    byte[] lastDataBlock = new byte[16];
                    System.arraycopy(buffer, offset, lastDataBlock, 0, remainingBytes);

                    if (isEncrypting) {
                        int padding = 16 - remainingBytes;
                        if (padding > 0 && padding < 16) {
                            for (int i = remainingBytes; i < 16; i++) {
                                lastDataBlock[i] = (byte) padding;
                            }
                        }
                        response = simulator.transmitCommand(new CommandAPDU(claAESMode,0x20,0x00,0x00,lastDataBlock));
                        bos.write(response.getData());

                    } else {
                        response = simulator.transmitCommand(new CommandAPDU(claAESMode,0x20,0x00,0x00,lastDataBlock));

                        lastDataBlock = response.getData();

                        int padding = lastDataBlock[15];
                        if(padding > 0 && padding < 16){
                            bos.write(lastDataBlock, 0, 16 - padding);
                        }else{
                            bos.write(lastDataBlock);
                        }
                    }
                } else {
                    byte[] dataBlock = new byte[16];
                    System.arraycopy(buffer, offset, dataBlock, 0, 16);
                    response = simulator.transmitCommand(new CommandAPDU(claAESMode,0x10,0x00,0x00,dataBlock));
                    bos.write(response.getData());
                }
                offset += 16;
            }

            fis.close();
            bos.close();
        }
    }
}
