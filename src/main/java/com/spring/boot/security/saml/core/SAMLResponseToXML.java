package com.spring.boot.security.saml.core;

import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLAuthenticationToken;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.util.SAMLUtil;

public class SAMLResponseToXML extends SAMLAuthenticationProvider  {

	public Authentication authenticate(Authentication authentication) {
		
		SAMLAuthenticationToken token = (SAMLAuthenticationToken) authentication;
		SAMLMessageContext context = token.getCredentials();
		 try {
            String assertion = XMLHelper.nodeToString(SAMLUtil.marshallMessage(context.getInboundMessage()));
            System.out.println("=========================================");
            System.out.println(assertion);
        } catch (MessageEncodingException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
		return token;
 
	}
	
}
