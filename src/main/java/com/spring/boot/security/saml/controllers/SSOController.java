package com.spring.boot.security.saml.controllers;

import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SAMLAuthenticationToken;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import java.util.Set;

@Controller
@RequestMapping("/saml")
public class SSOController {

    // Logger
    private static final Logger LOG = LoggerFactory.getLogger(SSOController.class);

    @Autowired
    private MetadataManager metadata;

    @GetMapping("/discovery")
    public String idpSelection(HttpServletRequest request, Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
       
        if (auth == null)
            LOG.debug("Current authentication instance from security context is null");
        else
            LOG.debug("Current authentication instance from security context: {}", this.getClass().getSimpleName());
        if (auth == null || (auth instanceof AnonymousAuthenticationToken)) {
            Set<String> idps = metadata.getIDPEntityNames();
            for (String idp : idps)
                LOG.info("Configured Identity Provider for SSO: {}", idp);
            model.addAttribute("idps", idps);
            return "pages/discovery";
        } else {
            LOG.warn("The current user is already logged.");
            
            SAMLAuthenticationToken token = (SAMLAuthenticationToken) auth;
            SAMLMessageContext context = token.getCredentials();
            try {
               String assertion = XMLHelper.nodeToString(SAMLUtil.marshallMessage(context.getInboundMessage()));
               System.out.println("==============================================================");
               System.out.println(assertion);
           } catch (MessageEncodingException e1) {
               // TODO Auto-generated catch block
               e1.printStackTrace();
           }

            return "redirect:/landing";
        }
    }

}
