package org.AuthenticateServer;

import org.AuthenticateServer.config.TestConfig;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
public class startAuthServerTest extends TestConfig {

	@Test
	public final void testMain() {
			try {
				Thread.sleep(99999999l);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
	}

}
