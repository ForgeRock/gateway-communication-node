/*
 * This code is to be used exclusively in connection with ForgeRock’s software or services. 
 * ForgeRock only offers ForgeRock software or services to legal entities who have entered 
 * into a binding license agreement with ForgeRock.  
 */

package org.forgerock.openam.auth.nodes.marketplace;

import static org.forgerock.openam.utils.StringUtils.isBlank;

import java.util.Collections;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.core.realms.RealmLookupException;
import org.forgerock.openam.core.realms.Realms;
import org.forgerock.openam.sm.AnnotatedServiceRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.iplanet.sso.SSOException;
import com.sun.identity.shared.Constants;
import com.sun.identity.sm.ChoiceValues;
import com.sun.identity.sm.SMSEntry;
import com.sun.identity.sm.SMSException;

public class IGCommunicationConfigChoiceValues extends ChoiceValues {
	
	
    private static final Logger logger = LoggerFactory.getLogger(IGCommunicationConfigChoiceValues.class);
	private static String loggerPrefix = "[IGCommunicationConfigChoiceValues]" + IGCommunicationPlugin.logAppender;

	public static String createIGCommConfigName(String id) {
		return id;
	}

	public static String createIGCommConfigName(String id, String realm) {
		return id + " [" + realm + "]";
	}

	public static String createIGCommConfigName(String id, Realm realm) {
		return id + " [" + realm.asPath() + "]";
	}

	public static boolean isGlobalIGCommConfig(String igCommConfigName) {
		return !igCommConfigName.endsWith("]");
	}

	public static String getRealmString(String igCommConfigName) {
		if (isGlobalIGCommConfig(igCommConfigName))
			return null;
		return igCommConfigName.substring(igCommConfigName.lastIndexOf('[') + 1, igCommConfigName.length() - 1);
	}

	public static Realm getRealm(String igCommConfigName) throws RealmLookupException {
		if (isGlobalIGCommConfig(igCommConfigName))
			return null;
		return Realms.of(getRealmString(igCommConfigName));
	}

	public static String getId(String igCommConfigName) {
		if (isGlobalIGCommConfig(igCommConfigName))
			return igCommConfigName;
		return igCommConfigName.substring(0, igCommConfigName.lastIndexOf('[') - 1);
	}

	public static IGCommunicationConfig getIGCommConfig(String igCommConfigName) {
		AnnotatedServiceRegistry serviceRegistry = InjectorHolder.getInstance(AnnotatedServiceRegistry.class);
		try {
			IGCommunicationService igCommService;
			if (isGlobalIGCommConfig(igCommConfigName)) {
				igCommService = serviceRegistry.getGlobalSingleton(IGCommunicationService.class);
			} else {
				igCommService = serviceRegistry
						.getRealmSingleton(IGCommunicationService.class, getRealm(igCommConfigName)).get();
			}
			return igCommService.commConfigs().get(getId(igCommConfigName));
		} catch (SSOException | SMSException | RealmLookupException e) {
			logger.error(loggerPrefix + "Couldn't load igComm configs", e);
			throw new IllegalStateException(loggerPrefix + "Couldn't load IG Comm configs", e);
		}
	}

	public static boolean isIGCommServiceEnabled(String igCommConfigName) {
		AnnotatedServiceRegistry serviceRegistry = InjectorHolder.getInstance(AnnotatedServiceRegistry.class);
		try {
			IGCommunicationService igCommService;
			if (isGlobalIGCommConfig(igCommConfigName)) {
				igCommService = serviceRegistry.getGlobalSingleton(IGCommunicationService.class);
			} else {
				igCommService = serviceRegistry
						.getRealmSingleton(IGCommunicationService.class, getRealm(igCommConfigName)).get();
			}
			return igCommService.enable();
		} catch (SSOException | SMSException | RealmLookupException e) {
			logger.error(loggerPrefix + "Couldn't load igComm configs", e);
			throw new IllegalStateException(loggerPrefix + "Couldn't load igComm configs", e);
		}
	}

	@Override
	public Map getChoiceValues(Map envParams) throws IllegalStateException {
		String realm = null;
		if (envParams != null) {
			realm = (String) envParams.get(Constants.ORGANIZATION_NAME);
		}
		if (isBlank(realm)) {
			realm = SMSEntry.getRootSuffix();
		}
		AnnotatedServiceRegistry serviceRegistry = InjectorHolder.getInstance(AnnotatedServiceRegistry.class);
		try {
			Map<String, String> configs = new TreeMap<String, String>();
			IGCommunicationService globalIGCommService = serviceRegistry
					.getGlobalSingleton(IGCommunicationService.class);
			Iterator<String> globalConfigIterator = globalIGCommService.commConfigs().idSet().iterator();
			while (globalConfigIterator.hasNext()) {
				String id = globalConfigIterator.next();
				configs.put(IGCommunicationConfigChoiceValues.createIGCommConfigName(id), "");
			}
			if (serviceRegistry.getRealmSingleton(IGCommunicationService.class, Realms.of(realm)).isPresent()) {
				IGCommunicationService realmIGCommService = serviceRegistry
						.getRealmSingleton(IGCommunicationService.class, Realms.of(realm)).get();
				Iterator<String> realmConfigIterator = realmIGCommService.commConfigs().idSet().iterator();
				while (realmConfigIterator.hasNext()) {
					String id = realmConfigIterator.next();
					configs.put(IGCommunicationConfigChoiceValues.createIGCommConfigName(id, Realms.of(realm)), "");
				}
			}
			return configs;
		} catch (SSOException | SMSException | RealmLookupException e) {
			logger.error(loggerPrefix + "Couldn't load igComm configs", e);
			throw new IllegalStateException(loggerPrefix + "Couldn't load igComm configs", e);
		}
	}

	@Override
	public Map<String, String> getChoiceValues() {
		return getChoiceValues(Collections.EMPTY_MAP);
	}

}
