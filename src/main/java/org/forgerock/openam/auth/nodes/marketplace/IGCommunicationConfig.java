/*
 * This code is to be used exclusively in connection with ForgeRock’s software or services. 
 * ForgeRock only offers ForgeRock software or services to legal entities who have entered 
 * into a binding license agreement with ForgeRock.  
 */

package org.forgerock.openam.auth.nodes.marketplace;

import java.util.Map;

import org.forgerock.am.config.ChoiceValues;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.annotations.sm.Id;

import com.google.common.collect.ImmutableMap;
import com.sun.identity.sm.RequiredValueValidator;

public interface IGCommunicationConfig {

	@Id
	String id();

	@Attribute(order = 100, validators = { RequiredValueValidator.class })
	default String igURL() {
		return "https://YourIGServer";
	};

	@Attribute(order = 200, validators = { RequiredValueValidator.class })
	default String signPublicKey() {
		return "";
	};

	@Attribute(order = 300, validators = { RequiredValueValidator.class })
	default String decryptPrivateKey() {
		return "";
	};
	
    @Attribute(order = 400)
    default ToIGSecurity sendToIGSecurity() {
        return ToIGSecurity.Signed;
    };

	@Attribute(order = 500, validators = { RequiredValueValidator.class })
	default String returningJWTName() {
		return "";
	};
	
	@Attribute(order = 600, validators = { RequiredValueValidator.class })
	default long jwtExpiration() {
		return 10000;
	};
	
	
    public enum ToIGSecurity {

        /**
         * Signed.
         */
        Signed,
        /**
         * Signed and Encrypted.
         */
        SignAndEncrypt;
    	

        @Override
        public String toString() {
            switch(this) {
                case Signed: return "Signed";
                case SignAndEncrypt: return "Sign And Encrypt";
                default: throw new IllegalArgumentException();
            }
        }
    }
    
    
    class ToIGSecurityChoice implements ChoiceValues {
        @Override
        public Map<String, String> getChoiceValues() {
            return ImmutableMap.<String, String>builder()
                    .put("signed", "SIGNED")
                    .put("encsign", "ENCRYPTANDSIGN")
                    .build();
        }
    }
}
