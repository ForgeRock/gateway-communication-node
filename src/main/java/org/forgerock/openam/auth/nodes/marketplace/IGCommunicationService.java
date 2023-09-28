/*
 * This code is to be used exclusively in connection with ForgeRock’s software or services. 
 * ForgeRock only offers ForgeRock software or services to legal entities who have entered 
 * into a binding license agreement with ForgeRock.  
 */

package org.forgerock.openam.auth.nodes.marketplace;

import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.annotations.sm.Config;
import org.forgerock.openam.annotations.sm.SubConfig;
import org.forgerock.openam.sm.annotations.subconfigs.Multiple;

import com.sun.identity.sm.RequiredValueValidator;

@Config(scope = Config.Scope.REALM_AND_GLOBAL)
public interface IGCommunicationService {

	@SubConfig
	Multiple<IGCommunicationConfig> commConfigs();

    @Attribute(order = 90, validators = {RequiredValueValidator.class})
    default boolean enable() { return true; }
}
