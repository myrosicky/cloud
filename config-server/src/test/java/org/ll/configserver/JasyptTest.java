package org.ll.configserver;
import org.jasypt.encryption.StringEncryptor;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.RestTemplate;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment=WebEnvironment.NONE)
public class JasyptTest {

	    @Autowired
	    private StringEncryptor jasyptStringEncryptor;

	    @Test
	    public void encrypt() {
	        String encryptStr = jasyptStringEncryptor.encrypt("config-server");
	        System.out.println("encrypted Str:" + encryptStr);
	    }

	    @Test
	    public void decrypt() {
	        String encryptStr = jasyptStringEncryptor.decrypt("TqrnYZn55aFVwnSo2TrbFA==");
	        System.out.println(encryptStr);
	    }
	    
	    @Test
	    public void testEncrypt() {
	        RestTemplate restTemplate = new RestTemplate();
	        System.out.println(restTemplate.postForObject("http://localhost:8888/encrypt", "q", String.class));
	    }
}
