import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.stream.Collectors;

/**
 * @description: 主程序工具类
 * @author：Favor
 * @date: 2024/5/31
 */
public class MainUtil {

    /**
     * 生成授权序列号
     * @throws Exception
     */
    public static void generateSerials() throws Exception {
        File hashFile = new File(SerializeUtil.TARGET_PATH + File.separator + "Hash");
        if (!hashFile.exists()) {
            throw new RuntimeException("客户Hash文件不存在: " + hashFile.getAbsolutePath());
        }
        String hash2 = SerializeUtil.deserializeObjectFromFile(String.valueOf(hashFile));
        //给hash2进行RSA数字签名产生序列号
        RSAPrivateKey rsaPrivateKey = SignatureUtil.init();
        SignatureUtil.rsaSign(hash2, rsaPrivateKey);
        System.out.println("请将序列号认证码文件PublicKey和保序列号文件SN发送给客户！");
    }

    /**
     * 对受保护的内容进行加密
     */
    public static void encrypt() {
        Scanner scanner = new Scanner(System.in);
        File sourceFile;
        File encFile;
        SecureRandom secureRandom = new SecureRandom();
        String key = new BigInteger(1024, secureRandom).toString(16);
        File keyFile = new File(SerializeUtil.TARGET_PATH + File.separator + "KEY");
        if (keyFile.exists()) {
            keyFile.delete();
        }
        System.out.println("密钥文件KEY保存地址：" + keyFile.getAbsolutePath());
        System.out.println("请将密钥文件KEY发送给客户！");
        SerializeUtil.serializeObjectToFile(key, String.valueOf(keyFile));
        System.out.println("请输入需要加密文件的绝对路径: ");
        String absolutePath = scanner.nextLine().replace("\"", "");
        sourceFile = new File(absolutePath);
        String fileName = sourceFile.getName();
        if (!sourceFile.exists()) {
            throw new RuntimeException("文件不存在: " + sourceFile.getAbsolutePath());
        }
        encFile = new File(SerializeUtil.TARGET_PATH + File.separator + "enc_" + fileName);
        System.out.println("加密后文件路径为: " + encFile.getAbsolutePath());
        if (encFile.exists()) {
            encFile.delete();
        }
        // 加密
        try (FileInputStream fis = new FileInputStream(sourceFile);
             FileOutputStream fos = new FileOutputStream(encFile, true)) {
            FileCryptoUtil.encryptFile(fis, fos, key);
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException |
                 InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }


    public static void embedWaterMark() throws Exception {
        File sourceFile;
        File embedFile;
        Scanner scanner = new Scanner(System.in);
        System.out.println("请输入需要添加数字水印文件的绝对路径: ");
        String absolutePath = scanner.nextLine().replace("\"", "");
        sourceFile = new File(absolutePath);

        String fileName = sourceFile.getName();
        if (!sourceFile.exists()) {
            throw new RuntimeException("文件不存在: " + sourceFile.getAbsolutePath());
        }
        embedFile = new File(SerializeUtil.TARGET_PATH + File.separator + "embed_" + fileName);
        System.out.println("添加数字水印后文件路径为: " + embedFile.getAbsolutePath());
        if (embedFile.exists()) {
            embedFile.delete();
        }
        WaterMarkUtil.embedWaterMark(sourceFile, embedFile, "DRMS");
    }

    /**
     * 获取当前计算机上所有网络接口的MAC地址列表
     *
     * @return
     * @throws Exception
     */
    public static List<String> getMacList() throws Exception {
        java.util.Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
        StringBuilder sb = new StringBuilder();
        ArrayList<String> tmpMacList = new ArrayList<>();
        while (en.hasMoreElements()) {
            NetworkInterface iface = en.nextElement();
            List<InterfaceAddress> addrs = iface.getInterfaceAddresses();
            for (InterfaceAddress addr : addrs) {
                InetAddress ip = addr.getAddress();
                NetworkInterface network = NetworkInterface.getByInetAddress(ip);
                if (network == null) {
                    continue;
                }
                byte[] mac = network.getHardwareAddress();
                if (mac == null) {
                    continue;
                }
                sb.delete(0, sb.length());
                for (int i = 0; i < mac.length; i++) {
                    sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
                }
                tmpMacList.add(sb.toString());
            }
        }
        if (tmpMacList.size() <= 0) {
            return tmpMacList;
        }
        return tmpMacList.stream().distinct().collect(Collectors.toList());
    }
}
