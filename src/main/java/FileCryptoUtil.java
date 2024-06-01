import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

/**
 * @description: 文件加密工具类
 * @author：Favor
 * @date: 2024/5/31
 */
public class FileCryptoUtil {
    private static final int IV_LENGTH = 16;
    private static final int KEY_LENGTH = 16;

    /**
     * 文件加密
     *
     * @param fis
     * @param fos
     * @param encKey
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     */
    public static void encryptFile(FileInputStream fis, FileOutputStream fos, String encKey) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        byte[] encKeyBytes = getEncKeyBytes(encKey);
        final byte[] encKeySha256 = sha256(encKeyBytes);
        fos.write(encKeySha256);
        byte[] ivBytes = getRandomIv();
        fos.write(ivBytes);
        Cipher cipher = getCipher(encKeyBytes, ivBytes, Cipher.ENCRYPT_MODE);
        // 构造加密流并输出
        try (CipherInputStream cis = new CipherInputStream(fis, cipher)) {
            byte[] buffer = new byte[1024];
            int n;
            while ((n = cis.read(buffer)) != -1) {
                fos.write(buffer, 0, n);
            }
        }
    }

    /**
     * 获取系统时间作为初始向量IV
     *
     * @return
     */
    private static byte[] getRandomIv() {
        byte[] ivBytes = new byte[IV_LENGTH];
        Random random = new Random(System.currentTimeMillis());
        random.nextBytes(ivBytes);
        return ivBytes;
    }

    /**
     * 提取16位加密密钥
     *
     * @param encKey
     * @return
     */
    private static byte[] getEncKeyBytes(String encKey) {
        if (encKey == null || encKey.length() < KEY_LENGTH) {
            throw new IllegalArgumentException("非法密钥！");
        }
        return encKey.substring(0, KEY_LENGTH).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * 构造加密/解密算法
     *
     * @param encKeyBytes
     * @param ivBytes
     * @param encryptMode
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     */
    private static Cipher getCipher(byte[] encKeyBytes, byte[] ivBytes, int encryptMode) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");//AES/CFB/PKCS5Padding 密码反馈模式
        SecretKeySpec secretKeySpec = new SecretKeySpec(encKeyBytes, "AES");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        cipher.init(encryptMode, secretKeySpec, iv);
        return cipher;
    }

    /**
     * sha256，接受字节数组作为输入
     *
     * @param bytes
     * @return
     * @throws NoSuchAlgorithmException
     */
    private static byte[] sha256(byte[] bytes) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(bytes);
    }
}
