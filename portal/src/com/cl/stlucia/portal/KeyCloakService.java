package com.cl.stlucia.portal;

import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.springsecurity.client.KeycloakRestTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class KeyCloakService {
	@Autowired
	private AdapterDeploymentContext adapterDeploymentContext;

	// for restful API call, but most case Client API would be sufficient
    @Autowired
    private KeycloakRestTemplate keycloakRestTemplate;

}
