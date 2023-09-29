/*
 * This code is to be used exclusively in connection with ForgeRock’s software or services. 
 * ForgeRock only offers ForgeRock software or services to legal entities who have entered 
 * into a binding license agreement with ForgeRock.  
 */

package org.forgerock.openam.auth.nodes.marketplace;

import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.UUID;

import javax.inject.Inject;

import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.builders.EncryptedThenSignedJwtBuilder;
import org.forgerock.json.jose.builders.JwtBuilderFactory;
import org.forgerock.json.jose.builders.SignedJwtBuilderImpl;
import org.forgerock.json.jose.jwe.EncryptionMethod;
import org.forgerock.json.jose.jwe.JweAlgorithm;
import org.forgerock.json.jose.jwk.RsaJWK;
import org.forgerock.json.jose.jws.EncryptedThenSignedJwt;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jws.handlers.SecretRSASigningHandler;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.sm.AnnotatedServiceRegistry;
import org.forgerock.secrets.SecretBuilder;
import org.forgerock.secrets.SecretsProvider;
import org.forgerock.secrets.keys.KeyEncryptionKey;
import org.forgerock.secrets.keys.SigningKey;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.spi.RedirectCallback;
import com.sun.identity.sm.RequiredValueValidator;


@Node.Metadata(outcomeProvider = IGCommunication.IGCommunicationOutcomeProvider.class, configClass = IGCommunication.Config.class, tags = { "marketplace", "trustnetwork", "Kerberos" })
public class IGCommunication extends AbstractDecisionNode {
	private final Logger logger = LoggerFactory.getLogger(IGCommunication.class);
	private String loggerPrefix = "[Secure IG Communication]" + IGCommunicationPlugin.logAppender;

	private final Config config;
	private IGCommunicationConfig igCommConfig;
	private static final String BUNDLE = IGCommunication.class.getName();

	private static final String SUCCESS = "SUCCESS";
	private static final String ERROR = "ERROR";
	private static final String NONCE = "igCommNonce";

	/**
	 * Configuration for the node.
	 */
	public interface Config {
		/**
		 * The Configured service
		 */
		@Attribute(order = 100, choiceValuesClass = IGCommunicationConfigChoiceValues.class)
		default String igCommConfigName() {
			return IGCommunicationConfigChoiceValues.createIGCommConfigName("Global Default");
		};

		/**
		 * The IG Route
		 */
		@Attribute(order = 200, validators = { RequiredValueValidator.class })
		String route();
		
		
		
		/**
		 * The config mapping to IG JWT payload from sharedState attributes
		 */
		@Attribute(order = 300)
		Map<String, String> cfgAccountMapperConfigurationToIG();	
		

		/**
		 * The config mapping from IG JWT payload to sharedState attributes
		 */
		@Attribute(order = 400)
		Map<String, String> cfgAccountMapperConfiguration();
	}

	/**
	 * Create the node using Guice injection. Just-in-time bindings can be used to
	 * obtain instances of other classes from the plugin.
	 *
	 * @param config The service config.
	 * @param realm  The realm the node is in.
	 */
	@Inject
	public IGCommunication(@Assisted Config config, @Assisted Realm realm, AnnotatedServiceRegistry serviceRegistry) {
		this.config = config;
		igCommConfig = IGCommunicationConfigChoiceValues.getIGCommConfig(config.igCommConfigName());
	}

	@Override
	public Action process(TreeContext context) {
		try {
			//does the JWT exist in the returning session
			if (context.request.parameters.get(igCommConfig.returningJWTName())!=null) {
				//it does... lets get to work... check signature, decrypt and map to sharedstate
				
				JwtClaimsSet theClaimSet = verifyAndDecryptFromIG(context, context.request.parameters.get(igCommConfig.returningJWTName()).get(0));
				
				//TODO Map the attributes in the claims to the shared state and exit success outcome
				logger.error(loggerPrefix + "Here are all the claims " + theClaimSet.build());
				
				return Action.goTo(SUCCESS).build();
			}
			else {
				//it doesn't, so setup a nonce and redirect to IG
				String sendString = "";
				switch(this.igCommConfig.sendToIGSecurity().name()) {
				case "None":
					sendString = getSetNonce(context);
					if (config.cfgAccountMapperConfigurationToIG()!=null && config.cfgAccountMapperConfigurationToIG().keySet()!=null && config.cfgAccountMapperConfigurationToIG().keySet().size()>0)
						throw new Exception("Cannot set Send to Gateway Security to None, and configure a mapping to send data to Identity Gateway");
					break;
				case "Signed":
					sendString = getSignedJWT(context);
					break;
				case "EncryptAndSign":
					sendString = getEncryptedThenSignedJWT(context);
				}
				
				//redirect the user
				RedirectCallback rcb = getRDCallback(context, sendString);
				return Action.send(rcb).build();
			}
			
		} catch (Exception ex) {
			String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(ex);
			logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
			context.getStateFor(this).putShared(loggerPrefix + "Exception", new Date() + ": " + ex.getMessage());
			context.getStateFor(this).putShared(loggerPrefix + "StackTrace", new Date() + ": " + stackTrace);			
			return Action.
					goTo(ERROR).
					withHeader("Error occurred").
					withErrorMessage(ex.getMessage()).
					build();
		}
	}
	
	private JwtClaimsSet verifyAndDecryptFromIG(TreeContext context, String jwt) throws Exception {
		String nonce = context.getStateFor(this).get(NONCE).asString();
		context.getStateFor(this).remove(NONCE);
		
		JwtBuilderFactory jwtBuilderFactory = new JwtBuilderFactory();
		EncryptedThenSignedJwt readMe = jwtBuilderFactory.reconstruct(jwt, EncryptedThenSignedJwt.class);
		RsaJWK publicRSAJWK = RsaJWK.parse(this.igCommConfig.signPublicKey());
		SigningHandler verificationHandler = new SigningManager(new SecretsProvider(Clock.systemDefaultZone())).newVerificationHandler(publicRSAJWK);
		boolean valid = readMe.verify(verificationHandler);
		
		if (!valid) {
			throw new Exception("Signature check fail for returning JWT from Gateway. Here is the JWT: " + jwt);
		}

		RsaJWK privateRSAJWK = RsaJWK.parse(this.igCommConfig.decryptPrivateKey());	
		//TODO need to figure out to use the supported decrypt
		readMe.decrypt(privateRSAJWK.toRSAPrivateKey());
		JwtClaimsSet jcs = readMe.getClaimsSet();
		Date now = new Date();
		if (jcs.getExpirationTime().after(now) && jcs.getNotBeforeTime().before(now) && jcs.getSubject().equalsIgnoreCase(nonce))
			return jcs;
		else 
			throw new Exception("After sign check pass and decrypt of JWT coming back from IG, the expiration date was off, or the not before date failed or the nonce did not match what was stored in this session.  Heres the nonce: " + nonce + ".  Here are the claims returned: " + jcs.build());
	}
	
	private RedirectCallback getRDCallback(TreeContext context, String sendString) throws Exception{
		String redirectUrl = this.igCommConfig.igURL() + config.route() + "/?" + sendString;
		RedirectCallback redirect = new RedirectCallback(redirectUrl, null, "GET");
		redirect.setTrackingCookie(true);	
		return redirect;
	}
	
	private String getEncryptedThenSignedJWT(TreeContext context) throws Exception{
		SecureRandom sr = new SecureRandom();
		long randomLong = Math.abs(sr.nextLong());
		
		RsaJWK privateRSAJWK = RsaJWK.parse(this.igCommConfig.decryptPrivateKey());		
		RsaJWK publicRSAJWK = RsaJWK.parse(this.igCommConfig.signPublicKey());
		
		// sign setup
		SecretBuilder ssb = new SecretBuilder();
		ssb.expiresAt(Instant.now().plusMillis(this.igCommConfig.jwtExpiration()));
		ssb.stableId(Long.toString(randomLong));
		ssb.secretKey(privateRSAJWK.toRSAPrivateKey());
		SigningKey sk = new SigningKey(ssb);
		SecretRSASigningHandler srsh = new SecretRSASigningHandler(sk);

		
		//Encryption setup
		SecretBuilder sb = new SecretBuilder();
		sb.expiresAt(Instant.now().plusMillis(this.igCommConfig.jwtExpiration()));
		sb.stableId(Long.toString(randomLong));
		RSAPublicKey rpk = publicRSAJWK.toRSAPublicKey();
		sb.publicKey(rpk);
		KeyEncryptionKey kek = new KeyEncryptionKey(sb);

		JweAlgorithm jweAlgorithm = JweAlgorithm.RSA_OAEP_256;
		EncryptionMethod encryptionMethod = EncryptionMethod.A256GCM;

		JwtBuilderFactory jwtBuilderFactory = new JwtBuilderFactory();
		
		EncryptedThenSignedJwtBuilder jwtBuilder = jwtBuilderFactory
				.jwe(kek)
				.headers()
				.alg(jweAlgorithm)
				.enc(encryptionMethod).done()
				.claims(getClaimSetToIG(context, getSetNonce(context)))
				.signedWith(srsh, JwsAlgorithm.RS256);

		String ets = jwtBuilder.build();
		return ets;
	}
	
	private String getSignedJWT(TreeContext context) throws Exception{
		SecureRandom sr = new SecureRandom();
		long randomLong = Math.abs(sr.nextLong());
		
		RsaJWK privateRSAJWK = RsaJWK.parse(this.igCommConfig.decryptPrivateKey());		
		
		// sign setup
		SecretBuilder ssb = new SecretBuilder();
		ssb.expiresAt(Instant.now().plusMillis(this.igCommConfig.jwtExpiration()));
		ssb.stableId(Long.toString(randomLong));
		ssb.secretKey(privateRSAJWK.toRSAPrivateKey());
		SigningKey sk = new SigningKey(ssb);
		SecretRSASigningHandler srsh = new SecretRSASigningHandler(sk);
		
		SignedJwtBuilderImpl jwtBuilder = new SignedJwtBuilderImpl(srsh)
				.headers().alg(JwsAlgorithm.RS256).done()
				.claims(getClaimSetToIG(context, getSetNonce(context)));

		String ets = jwtBuilder.build();
		return ets;
	}
		
	private JwtClaimsSet getClaimSetToIG(TreeContext context, String nonce)throws Exception{
		Date now = new Date();
		Date expireDate = new Date(now.getTime() + this.igCommConfig.jwtExpiration());
		String theID = UUID.randomUUID().toString();
		JwtClaimsSet jwtClaims = new JwtClaimsSet();	
		NodeState ns = context.getStateFor(this);
		
		Map<String, String> toIGMap = config.cfgAccountMapperConfigurationToIG();
		
		if (toIGMap!=null && toIGMap.keySet()!=null)
			for(Iterator<String> i = toIGMap.keySet().iterator(); i.hasNext();) {
				String thisKey = i.next();
				String igKey = toIGMap.get(thisKey);
				String thisVal = ns.get(thisKey).asString();
				jwtClaims.put(igKey, thisVal);
				
			}	
		jwtClaims.put("referer", context.request.headers.get("referer").get(0));
		jwtClaims.setIssuer(context.request.hostName);
		jwtClaims.setSubject(nonce);
		jwtClaims.addAudience(this.igCommConfig.igURL());
		jwtClaims.setExpirationTime(expireDate);
		jwtClaims.setNotBeforeTime(now);
		jwtClaims.setIssuedAtTime(now);
		jwtClaims.setJwtId(theID);
		
		return jwtClaims;
	}
	
	private String getSetNonce(TreeContext context)throws Exception{
		SecureRandom random = new SecureRandom();
		long randomLong = random.nextLong();
		String nonce = Long.toString(Math.abs(randomLong));
		
		context.getStateFor(this).putShared(NONCE, nonce);
		return nonce;
	
	}
	
	/**
	 * Defines the possible outcomes from this node.
	 */
	public static class IGCommunicationOutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, IGCommunicationOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(new Outcome(SUCCESS, bundle.getString("SuccessOutcome")), new Outcome(ERROR, bundle.getString("ErrorOutcome")));
		}
	}

}
