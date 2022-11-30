package com.spring.boot.security.saml.core;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.XML;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.saml.SAMLAuthenticationToken;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.Attributes;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

@Service
public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService {

    // Logger
    private static final Logger LOG = LoggerFactory.getLogger(SAMLUserDetailsServiceImpl.class);

    public Object loadUserBySAML(SAMLCredential credential) {

        // The method is supposed to identify local account of user referenced by
        // data in the SAML assertion and return UserDetails object describing the user.
    	
    	System.out.println(credential.getAuthenticationAssertion().getParent());

    	LOG.info("credential==========: {}", credential.getAuthenticationAssertion().getParent() );
    	
    	try {  
    		XMLObject xml = credential.getAuthenticationAssertion().getParent();
    		JSONObject json = XML.toJSONObject(xml.toString());   
	        String jsonString = json.toString(4);  
	        System.out.println(jsonString);  
    		  
    		}catch (JSONException e) {  
    		// TODO: handle exception  
    		System.out.println(e.toString());  
    		} 
    	
    	
        String userID = credential.getNameID().getValue();
        
        for(Attribute attribute : credential.getAttributes()) {
        	System.out.println(getString(attribute));
        	String[] xml = credential.getAttributeAsStringArray(attribute.getName());
        	System.out.println(xml);
        }
        //Principal's SAML Attributes

        LOG.info("{} is logged in", userID);
        List<GrantedAuthority> authorities = new ArrayList<>();
        GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
        authorities.add(authority);
        
        //Method which uses JAXB to convert object to XML
        //jaxbObjectToXML(credential);
        String xml;
		try {
			xml = toXML(credential);
		} catch (JAXBException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
		UserDetails userDetails = new User(
				userID, "<abc123>", true, true, true, true, authorities);
        // In a real scenario, this implementation has to locate user in a arbitrary
        // dataStore based on information present in the SAMLCredential and
        // returns such a date in a form of application specific UserDetails object.
        return userDetails;
    }
    
    private String getString(XMLObject xmlValue) {
        if (xmlValue instanceof XSString) {
            return ((XSString) xmlValue).getValue();
        } else if (xmlValue instanceof XSAny) {
            return ((XSAny) xmlValue).getTextContent();
        } else {
            return null;
        }
    }

    public static String toXML(SAMLCredential car) throws JAXBException {
        StringWriter stringWriter = new StringWriter();

        JAXBContext jaxbContext = JAXBContext.newInstance(SAMLCredential.class);
        Marshaller jaxbMarshaller = jaxbContext.createMarshaller();

        // format the XML output
        jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT,
            true);

        QName qName = new QName("com.codenotfound.jaxb.model", "car");
        JAXBElement<SAMLCredential> root = new JAXBElement<>(qName, SAMLCredential.class, car);

        jaxbMarshaller.marshal(root, stringWriter);

        String result = stringWriter.toString();
        System.out.println(result);
        return result;
      }
    
    private static void jaxbObjectToXML(SAMLCredential employee) 
    {
        try
        {
          //Create JAXB Context
            JAXBContext jaxbContext = JAXBContext.newInstance(SAMLCredential.class);
             
            //Create Marshaller
            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
   
            //Required formatting??
            jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
   
           //Store XML to File
            File file = new File("SAMLCredential.xml");
             
            //Writes XML file to file-system
            jaxbMarshaller.marshal(employee, file); 
        } 
        catch (JAXBException e) 
        {
            e.printStackTrace();
        }
    }
    
    private static String jaxbObjectToXMLA(SAMLCredential customer) {
        String xmlString = "";
        try {
            JAXBContext context = JAXBContext.newInstance(SAMLCredential.class);
            Marshaller m = context.createMarshaller();

            m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE); // To format XML

            StringWriter sw = new StringWriter();
            m.marshal(customer, sw);
            xmlString = sw.toString();

        } catch (JAXBException e) {
            e.printStackTrace();
        }

        return xmlString;
    }
    
  //This function is called recursively
    private static void visitChildNodes(NodeList nList)
    {
       for (int temp = 0; temp < nList.getLength(); temp++)
       {
          Node node = nList.item(temp);
          if (node.getNodeType() == Node.ELEMENT_NODE)
          {
             System.out.println("Node Name = " + node.getNodeName() + "; Value = " + node.getTextContent());
             //Check all attributes
             if (node.hasAttributes()) {
                // get attributes names and values
                NamedNodeMap nodeMap = node.getAttributes();
                for (int i = 0; i < nodeMap.getLength(); i++)
                {
                    Node tempNode = nodeMap.item(i);
                    System.out.println("Attr name : " + tempNode.getNodeName()+ "; Value = " + tempNode.getNodeValue());
                }
                if (node.hasChildNodes()) {
                   //We got more childs; Let's visit them as well
                   visitChildNodes(node.getChildNodes());
                }
            }
          }
       }
    }

}
