package com.cl.stlucia.portal;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;

import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.json.JSONObject;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.OidcKeycloakAccount;
import org.keycloak.adapters.springsecurity.client.KeycloakRestTemplate;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class HomeController {
	@Autowired
	private AdapterDeploymentContext adapterDeploymentContext;

    @Autowired
    private KeycloakRestTemplate keycloakRestTemplate;
	
	@RequestMapping({"/", "/home"})
	public String index() {
		return "index";
	}

	private String getLoginId(Principal principal) {
		OidcKeycloakAccount account = (OidcKeycloakAccount)((KeycloakAuthenticationToken)principal).getAccount();
		KeycloakSecurityContext context = account.getKeycloakSecurityContext();
		IDToken idToken = context.getIdToken();

		return idToken.getPreferredUsername();
	}
	
	@RequestMapping("/main")
	public ModelAndView main(Model model, Principal principal) {
		OidcKeycloakAccount account = (OidcKeycloakAccount)((KeycloakAuthenticationToken)principal).getAccount();
		KeycloakSecurityContext context = account.getKeycloakSecurityContext();
		IDToken idToken = context.getIdToken();

		model.addAttribute("loginId", idToken.getName()+" ("+idToken.getPreferredUsername()+")");
		
		ModelAndView mv = new ModelAndView("main");
		return mv;
	}

	@GetMapping("/changePassword")
	public String showChangePassword(HttpServletRequest request, HttpServletResponse response) {
		return "changePassword";
	}
    
	@PostMapping("/changePassword") 
	public String changePassword(HttpServletRequest request, HttpServletResponse response, Principal principal) throws ServletException {
		String username = getLoginId(principal);
		String currentPassword = request.getParameter("currentPassword");
		String newPassword = request.getParameter("newPassword");
		
		HttpHeaders headers = null;
		String access_token = null;
		String url = null;

		// change password
		headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		headers.set("Authorization", "Bearer " + access_token);
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("currentPassword", currentPassword);
		jsonObject.put("newPassword", newPassword);
		jsonObject.put("confirmation", newPassword);
		HttpEntity<String> entity = new HttpEntity<String>(jsonObject.toString(), headers);
		
		url = "http://localhost:8180/auth/realms/public/account/credentials/password";
	    try {
	    	// keycloakRestTemplate will get access token and put in authorization header
		    ResponseEntity<String> strResponse = keycloakRestTemplate.postForEntity(url, entity, String.class);
			if (strResponse.getStatusCodeValue()==200) {
				System.out.println("Update password success!!!");
			}
	    } catch (HttpClientErrorException httpClientErrorException) {
	    	System.out.println("Error: "+httpClientErrorException.getResponseBodyAsString());
	    } catch (HttpServerErrorException httpServerErrorException) {
	    	System.out.println("Error: "+httpServerErrorException.getResponseBodyAsString());
	    } catch (Exception e) {
	    	System.out.println(e.getMessage());
	    }

		return "main";
	}
	
	private String getAccessToken(String username, String currentPassword) {
		String access_token = null;
		
		RestTemplate restTemplate = new RestTemplate();
		
		// get access token
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		
		MultiValueMap<String, String> params= new LinkedMultiValueMap<String, String>();
		params.add("client_id", "portal");
		params.add("username", username);
		params.add("password", currentPassword);
		params.add("grant_type", "password");

		HttpEntity<MultiValueMap<String, String>> req = new HttpEntity<MultiValueMap<String, String>>(params, headers);
		
		String url = "http://localhost:8180/auth/realms/public/protocol/openid-connect/token";
		ResponseEntity<Object> kcResponse = restTemplate.postForEntity(url, req, Object.class);
		if (kcResponse.getStatusCodeValue()==200) {
			LinkedHashMap<String, String> json = (LinkedHashMap<String, String>)kcResponse.getBody();
			access_token = json.get("access_token");
		}
		return access_token;
	}
	
	private Keycloak getKeycloak() {
		KeycloakDeployment deployment = adapterDeploymentContext.resolveDeployment(null);
// use admin user account to invoke service 
// User needs at least "manage-users, view-clients, view-realm, view-users" roles for "realm-management"
//		Keycloak keycloak = KeycloakBuilder.builder() //
//				.serverUrl(deployment.getAuthServerBaseUrl()) //
//				.realm("master") //
//				.grantType(OAuth2Constants.PASSWORD) //
//				.clientId("admin-cli") //
//				.username("api") //
//				.password("api") //
//				.build();
		// use service account to invoke service
		// user service account needs at least "manage-users, view-clients, view-realm, view-users" roles for "realm-management"
		Keycloak keycloak = KeycloakBuilder.builder() //
				.serverUrl(deployment.getAuthServerBaseUrl()) //
				.realm(deployment.getRealm()) //
				.grantType(OAuth2Constants.CLIENT_CREDENTIALS) //
				.clientId(deployment.getResourceName()) //
				.clientSecret((String) deployment. getResourceCredentials().get("secret")) //
				//.resteasyClient(new ResteasyClientBuilder().connectionPoolSize(10).build()) //
				.build();

		return keycloak;
	}
	
	@GetMapping("/register")
	public String showRegister(HttpServletRequest request, HttpServletResponse response) {
		return "register";
	}
	
	@PostMapping("/register")
	public String register(HttpServletRequest request, HttpServletResponse response) throws ServletException {
		String username = request.getParameter("username");
		String password = "Test!1234";
		String firstName = request.getParameter("firstName");
		String lastName = request.getParameter("lastName");
		String email = request.getParameter("email");

		KeycloakDeployment deployment = adapterDeploymentContext.resolveDeployment(null);
		try (Keycloak keycloak = this.getKeycloak()) {
			RealmResource realm = keycloak.realm(deployment.getRealm());
			
	        CredentialRepresentation credential = new CredentialRepresentation();
	        credential.setType(CredentialRepresentation.PASSWORD);
	        credential.setValue(password);
	        
	        UserRepresentation user = new UserRepresentation();
	        user.setUsername(username);
	        user.setFirstName(firstName);
	        user.setLastName(lastName);
	        user.setEmail(email);
	        user.setCredentials(Arrays.asList(credential));
	        user.setEnabled(true);
	        //user.setRealmRoles(Arrays.asList("applicant"));

            List<String> requiredActionList = new ArrayList<>();
            requiredActionList.add("UPDATE_PASSWORD");
            user.setRequiredActions(requiredActionList);	        
	        
	        Response kcResponse = realm.users().create(user);
	        final int status = kcResponse.getStatus();
	        if (status != HttpStatus.CREATED.value()) {
	        	if (status == HttpStatus.CONFLICT.value()) {
	                throw new ServletException("Error: User already exists");
	        	}
	            throw new ServletException("Failed to create user, status code: "+status);
	        }

	        String userId = getCreatedId(kcResponse);
	        RoleRepresentation savedRoleRepresentation = realm.roles().get("APPLICANT").toRepresentation();
	        realm.users().get(userId).roles().realmLevel().add(Arrays.asList(savedRoleRepresentation));
		}
        
		return "redirect:/main";
	}

	private String getCreatedId(Response response) {
	    URI location = response.getLocation();
	    if (location == null) {
	        return null;
	    }
	    String path = location.getPath();
	    return path.substring(path.lastIndexOf('/') + 1);
	}
	
	@GetMapping("/updateProfile")
	public String showUpdateProfile(Model model, HttpServletRequest request, HttpServletResponse response, Principal principal) {
		OidcKeycloakAccount account = (OidcKeycloakAccount)((KeycloakAuthenticationToken)principal).getAccount();
		KeycloakSecurityContext context = account.getKeycloakSecurityContext();
		IDToken idToken = context.getIdToken();
		
		model.addAttribute("username", idToken.getPreferredUsername());
		model.addAttribute("firstName", idToken.getFamilyName());
		model.addAttribute("lastName", idToken.getGivenName());
		model.addAttribute("email", idToken.getEmail());
		return "updateProfile";
	}

	@PostMapping("/updateProfile")
	public String updateProfile(HttpServletRequest request, HttpServletResponse response, Principal principal) throws ServletException {
		String firstName = request.getParameter("firstName");
		String lastName = request.getParameter("lastName");
		String email = request.getParameter("email");

		// User "idm-admin" needs at least "manage-users, view-clients, view-realm, view-users" roles for "realm-management"
		KeycloakDeployment deployment = adapterDeploymentContext.resolveDeployment(null);
		try (Keycloak keycloak = this.getKeycloak()) {
			RealmResource realm = keycloak.realm(deployment.getRealm());
			
			OidcKeycloakAccount account = (OidcKeycloakAccount)((KeycloakAuthenticationToken)principal).getAccount();
			KeycloakSecurityContext context = account.getKeycloakSecurityContext();
			IDToken idToken = context.getIdToken();
			
	        UserResource userResource =  realm.users().get(idToken.getSubject());
	        UserRepresentation user = userResource.toRepresentation();
	        user.setFirstName(firstName);
	        user.setLastName(lastName);
	        user.setEmail(email);
	        userResource.update(user);
		}
        
		return "redirect:/main";
	}

	@GetMapping("/resetPassword")
	public String showResetPassword(HttpServletRequest request, HttpServletResponse response) {
		return "resetPassword";
	}
	
	@PostMapping("/resetPassword") 
	public String resetPassword(HttpServletRequest request, HttpServletResponse response) {
		String username = request.getParameter("username");
		String newPassword = request.getParameter("newPassword");

		KeycloakDeployment deployment = adapterDeploymentContext.resolveDeployment(null);
		try (Keycloak keycloak = this.getKeycloak()) {
			List<UserRepresentation> users = keycloak.realm(deployment.getRealm()).users().search(username);
			UserRepresentation user = users.get(0);
			
			UserResource resource = keycloak.realm(deployment.getRealm()).users().get(user.getId());
			CredentialRepresentation newCredential = new CredentialRepresentation();
			newCredential.setValue(newPassword);
			newCredential.setType(CredentialRepresentation.PASSWORD);
			newCredential.setTemporary(false);
			resource.resetPassword(newCredential);
		}

		return "main";
	}

	@GetMapping("/unlockUser")
	public String showUnlockUser(HttpServletRequest request, HttpServletResponse response) {
		return "unlockUser";
	}

	@PostMapping("/unlockUser")
	public String unlockUser(HttpServletRequest request, HttpServletResponse response, Principal principal) throws ServletException {
		String username = request.getParameter("username");

		// User "idm-admin" needs at least "manage-users, view-clients, view-realm, view-users" roles for "realm-management"
		KeycloakDeployment deployment = adapterDeploymentContext.resolveDeployment(null);
		try (Keycloak keycloak = this.getKeycloak()) {
			List<UserRepresentation> users = keycloak.realm(deployment.getRealm()).users().search(username);
			UserRepresentation user = users.get(0);
			
			Map<String, Object> userStatus = keycloak.realm(deployment.getRealm()).attackDetection().bruteForceUserStatus(user.getId());
			if ((Boolean)userStatus.get("disabled")) {
				System.out.println("User "+username+" is locked!!!");
				keycloak.realm(deployment.getRealm()).attackDetection().clearBruteForceForUser(user.getId());
			}
		}
        
		return "redirect:/main";
	}

	@PostMapping("/enableUser")
	public String enableUser(HttpServletRequest request, HttpServletResponse response, Principal principal) throws ServletException {
		String username = request.getParameter("username");

		// User "idm-admin" needs at least "manage-users, view-clients, view-realm, view-users" roles for "realm-management"
		KeycloakDeployment deployment = adapterDeploymentContext.resolveDeployment(null);
		try (Keycloak keycloak = this.getKeycloak()) {
			List<UserRepresentation> users = keycloak.realm(deployment.getRealm()).users().search(username);
			UserRepresentation user = users.get(0);
	        user.setEnabled(true);
			
			UserResource userResource = keycloak.realm(deployment.getRealm()).users().get(user.getId());
	        userResource.update(user);
		}
        
		return "redirect:/main";
	}

	@RequestMapping("/ssoLogin")
	public void redirectToLogin(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		KeycloakDeployment deployment = adapterDeploymentContext.resolveDeployment(null);
		System.out.println("AuthServerBaseUrl: "+deployment.getAuthServerBaseUrl());
		System.out.println("AuthUrl: "+deployment.getAuthUrl().clone().build());
		System.out.println("LogoutUrl: "+deployment.getLogoutUrl().clone().build());
		
		String redirectUri = "http://localhost:8080/"+request.getServletContext().getContextPath()+"/main";
		String frontendUri = "http://localhost:8180/auth";
		String uri = frontendUri+"/realms/public/protocol/openid-connect/auth?client_id=portal&response_mode=fragment&response_type=code&login=true&redirect_uri="+URLEncoder.encode(redirectUri, "UTF-8");
	    response.sendRedirect(uri);
	}

	@RequestMapping("/ssoChangePassword")
	public void redirectToChangePassword(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		KeycloakDeployment deployment = adapterDeploymentContext.resolveDeployment(null);
		String redirectUri = "http://localhost:8080/"+request.getServletContext().getContextPath()+"/main";
		//String uri = deployment.getAccountUrl()+"/password"+"?referrer=Home&referrer_uri="+encodedRedirectUri;
		String uri = deployment.getAccountUrl()+"/password"+"?referrer="+deployment.getResourceName()+"&referrer_uri="+URLEncoder.encode(redirectUri, "UTF-8");
	    response.sendRedirect(uri);
	}

	// Keycloak Logout is handle by keycloakLogoutHandler defined in security config
	// keycloakLogoutHandler will invoke keycloak server (endpoint: deployment.getLogoutUrl(), i.e. OIDC_Config.end_session_endpoint ) to logout
	// but in case of frontendUrl different to backendUrl, the frontendUrl are not accessible for application server
	@GetMapping("/ssoLogout")
	public void ssoLogout(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		KeycloakDeployment deployment = adapterDeploymentContext.resolveDeployment(null);
		String redirectUri = "http://localhost:8080/"+request.getServletContext().getContextPath()+"/logout";
		// http://auth-server/auth/realms/{realm-name}/protocol/openid-connect/logout?redirect_uri=encodedRedirectUri
		String logoutUrl = deployment.getLogoutUrl().clone().build().toString()+"?redirect_uri="+URLEncoder.encode(redirectUri, "UTF-8");
	    response.sendRedirect(logoutUrl);
	}
}
