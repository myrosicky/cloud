package org.ll.configserver;
import org.jasypt.encryption.StringEncryptor;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
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

}
