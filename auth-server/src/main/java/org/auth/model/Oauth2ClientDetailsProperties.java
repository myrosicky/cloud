package org.auth.model;

import java.util.List;

import lombok.Data;

import org.springframework.security.oauth2.provider.client.BaseClientDetails;

@Data
public class Oauth2ClientDetailsProperties {

	List<BaseClientDetails> clients;
}
