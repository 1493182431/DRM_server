import java.io.File;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * @description: RSA数字签名工具类
 * @author：Favor
 * @date: 2024/5/31
 */
public class SignatureUtil {

    /**
     * 初始化密钥
     *
     * @return
     * @throws Exception
     */
    public static RSAPrivateKey init() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(512);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        File sourceFile = new File(SerializeUtil.TARGET_PATH + File.separator + "PublicKey");
        if (sourceFile.exists()) {
            sourceFile.delete();
        }
        System.out.println("序列号认证码保存地址：" + sourceFile.getAbsolutePath());
        SerializeUtil.serializeObjectToFile(rsaPublicKey, String.valueOf(sourceFile));
        return rsaPrivateKey;
    }

    /**
     * 执行签名
     *
     * @param src
     * @param rsaPrivateKey
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static void rsaSign(String src, RSAPrivateKey rsaPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(src.getBytes());
        byte[] result = signature.sign();
        File sourceFile = new File(SerializeUtil.TARGET_PATH + File.separator + "SN");
        if (sourceFile.exists()) {
            sourceFile.delete();
        }
        System.out.println("序列号保存地址：" + sourceFile.getAbsolutePath());
        SerializeUtil.serializeObjectToFile(byteArrayToHexString(result), String.valueOf(sourceFile));
    }

    /**
     * 将字节数组转换为十六进制字符串
     *
     * @param bytes
     * @return
     */
    public static String byteArrayToHexString(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}