package com.dosuv.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.net.ssl.SSLContext;

import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wechat.pay.contrib.apache.httpclient.WechatPayHttpClientBuilder;
import com.wechat.pay.contrib.apache.httpclient.auth.AutoUpdateCertificatesVerifier;
import com.wechat.pay.contrib.apache.httpclient.auth.PrivateKeySigner;
import com.wechat.pay.contrib.apache.httpclient.auth.WechatPay2Credentials;
import com.wechat.pay.contrib.apache.httpclient.auth.WechatPay2Validator;
import com.wechat.pay.contrib.apache.httpclient.util.AesUtil;
import com.wechat.pay.contrib.apache.httpclient.util.PemUtil;

public class WeixinPayUtils {
	private static final Logger logger = LoggerFactory.getLogger(WeixinPayUtils.class);
	public String defaultApiKey;//apiV3key 
	public String defaultMerchantId;//商户id
	private String defaultMerchantSerialNumber;//商户编号
	private PrivateKey defaultmerchantPrivateKey;//给微信发送请求签名使用
	private PublicKey defaultPubicKey;//用来对微信返回的数据进行校验签名使用
	private KeyStore defaultKeyStore;//给用户付款等接口用到
	/**
	 * @param apiKey apiV3Key
	 * @param merchantId 商户id
	 * @param merchantSerialNumber 商户编号
	 * <li>微信证书文件</li>
	 * @param merchantPrivateKey 给微信发送请求签名使用   --微信下载的三个文件中的 apiclient_key.pem
	 * @param pubicKey 用来对微信返回的数据进行校验签名使用   --配置好其它参数后手动调用getCer方法获得
	 * @param keyStore 给用户付款等接口用到   --微信下载三个文件中的p12文件
	 */
	public WeixinPayUtils(String apiKey,String merchantId,String merchantSerialNumber,PrivateKey merchantPrivateKey,PublicKey pubicKey,KeyStore keyStore){
		defaultApiKey = apiKey;
		defaultMerchantId =merchantId;
		defaultMerchantSerialNumber = merchantSerialNumber;
		defaultmerchantPrivateKey = merchantPrivateKey;
		defaultPubicKey = pubicKey;
		defaultKeyStore = keyStore;
	}
	public HttpClient createDefaultHttpClient() {
		return createHttpClient(defaultApiKey,defaultmerchantPrivateKey, defaultMerchantId, defaultMerchantSerialNumber);
	}
	/**
	 * 微信支付 文档见 https://pay.weixin.qq.com/wiki/doc/apiv3/open/pay/chapter2_5_2.shtml
	 * 创建v3请求客户端
	 * 
	 * @param apiKey
	 *            平台设置的请求接口v3key
	 * @param merchantPrivateKey
	 *            商户私钥
	 * @param merchantId
	 *            商户号
	 * @param merchantSerialNumber
	 *            商户证书序列号
	 * @return
	 */
	public static HttpClient createHttpClient(String apiKey, PrivateKey merchantPrivateKey, String merchantId,
			String merchantSerialNumber) {
		try {
			// 加载平台证书（mchId：商户号,mchSerialNo：商户证书序列号,apiV3Key：V3密钥）
			// 初始化httpClient
			return WechatPayHttpClientBuilder.create()
					.withMerchant(merchantId, merchantSerialNumber, merchantPrivateKey)
					.withValidator(new WechatPay2Validator(new AutoUpdateCertificatesVerifier(
							new WechatPay2Credentials(merchantId,
									new PrivateKeySigner(merchantSerialNumber, merchantPrivateKey)),
							apiKey.getBytes("utf-8"))))
					.build();
		} catch (Exception e) {
			logger.error(e.toString());
			return null;
		}
	}
	public HttpClient createSSLDefaultHttpClient() {
		try {
			return createSSLHttpClient(defaultKeyStore, defaultMerchantId);
		} catch (NoSuchAlgorithmException | CertificateException | KeyStoreException | KeyManagementException|IOException | UnrecoverableKeyException e) {return null;} 
	}
	public static HttpClient createSSLHttpClient(KeyStore keyStore,String password) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException, KeyManagementException, UnrecoverableKeyException {
			SSLContext sslcontext = SSLContexts.custom().loadKeyMaterial(keyStore,password.toCharArray()
			          ).build();
			       SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext);
					return HttpClients.custom().setSSLSocketFactory(sslsf).build(); 
	}
	/**
	 * https://pay.weixin.qq.com/wiki/doc/apiv3/apis/chapter3_2_4.shtml
	 *
	 * @param appId 应用id
	 * @param time 时间戳
	 * @param randomStr 随机字符串
	 * @param extendStr 扩展字段
	 * @return 签名
	 */
	public String createSign(String appId,String time,String randomStr,String extendStr) {
		try {
			return createSign(defaultmerchantPrivateKey,appId, time, randomStr, extendStr);
		} catch (Exception e) {return null;}
	}
	
	public static String createSign(PrivateKey merchantPrivateKey,String appId,String time,String randomStr,String extendStr) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {
		String message = appId+"\n"+time+"\n"+randomStr+"\n"+extendStr+"\n";
		return createSign(merchantPrivateKey, message);
	}
	public static String createSign(PrivateKey merchantPrivateKey,String message) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException{
		Signature sign = Signature.getInstance("SHA1withRSA");
		sign.initSign(merchantPrivateKey);
		sign.update(message.getBytes("UTF-8"));
		return new String(Base64.getEncoder().encodeToString(sign.sign()));
	}
	public boolean verifySign(String message,String sign) throws SignatureException, IOException {
		try {
			return verifySign(defaultPubicKey,message, sign);
		} catch (InvalidKeyException e) {e.printStackTrace();return false;}
	}
	public static boolean verifySign(PublicKey publicKey,String message,String sign) throws InvalidKeyException, SignatureException{
		try {
			Signature signature = Signature.getInstance("SHA256withRSA");
			signature.initVerify(publicKey);
			signature.update(message.getBytes("UTF-8"));
			return signature.verify(Base64.getDecoder().decode(sign.getBytes("UTF-8")));
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {return false;}
		
	}
	public static X509Certificate parseCertificate(String certificate) throws IOException, CertificateException{
		return PemUtil.loadCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(certificate.getBytes("UTF-8"))));
	}
	public static KeyStore readKeyStore(InputStream keyStoreInputStream,String passwd) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(keyStoreInputStream,passwd.toCharArray());
		return keyStore;
	}
	public String decryptToString(String associatedData, String nonce, String ciphertext) throws GeneralSecurityException, IOException {
		return decryptToString(defaultApiKey, associatedData, nonce, ciphertext);
	}
	public static String decryptToString(String apiKey,String associatedData, String nonce, String ciphertext) throws GeneralSecurityException, IOException {
		return new AesUtil(apiKey.getBytes()).decryptToString(associatedData.getBytes(), nonce.getBytes(), ciphertext);
	}
	/**
	 * 获取证书接口 暂时不被调用
	 * @throws ClientProtocolException
	 * @throws IOException
	 */
	public String getCer() throws ClientProtocolException, IOException {
		HttpClient httpClient = createDefaultHttpClient();
		HttpGet httpGet = new HttpGet("https://api.mch.weixin.qq.com/v3/certificates");
		httpGet.addHeader("Accept", "application/json");
		httpGet.addHeader("Content-type","application/json; charset=utf-8");
		CloseableHttpResponse response = (CloseableHttpResponse) httpClient.execute(httpGet);
		String bodyAsString = EntityUtils.toString(response.getEntity());
		ObjectMapper objectMapper = new ObjectMapper();
		JsonNode json = objectMapper.reader().readTree(bodyAsString).get("data").get(0).get("encrypt_certificate");
		try {
			return decryptToString(json.get("associated_data").textValue(), json.get("nonce").textValue(), json.get("ciphertext").textValue());
		}catch (Exception e) {}
		return bodyAsString;
	}
}
