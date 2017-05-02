/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.instagram;

import org.apache.commons.collections.functors.OnePredicate;
import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityIOStreamUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.util.*;

import static org.apache.oltu.oauth2.common.OAuth.ContentType.JSON;

/**
 * Authenticator for Instagram
 */
public class InstagramAuthenticator extends OpenIDConnectAuthenticator implements FederatedApplicationAuthenticator {

	private static Log log = LogFactory.getLog(InstagramAuthenticator.class);

	/**
	 * Get Instagram authorization endpoint
	 */
	@Override
	protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {
		return InstagramAuthenticatorConstants.INSTAGRAM_OAUTH_ENDPOINT;
	}

	/**
	 * Get Instagram access token endpoint
	 */
	@Override
	protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {
		return InstagramAuthenticatorConstants.INSTAGRAM_TOKEN_ENDPOINT;
	}

	/**
	 * Get Instagram user info endpoint
	 */
	@Override
	protected String getUserInfoEndpoint(OAuthClientResponse token, Map<String, String> authenticatorProperties) {
		return InstagramAuthenticatorConstants.INSTAGRAM_USERINFO_ENDPOINT;
	}

	/**
	 * Always return false as there is no ID token in Instagram OAuth.
	 *
	 * @param authenticatorProperties Authenticator properties.
	 * @return False
	 */
	@Override
	protected boolean requiredIDToken(Map<String, String> authenticatorProperties) {
		return false;
	}

	/**
	 * Get friendly name of the Authenticator
	 */
	@Override
	public String getFriendlyName() {
		return InstagramAuthenticatorConstants.INSTAGRAM_CONNECTOR_FRIENDLY_NAME;
	}

	/**
	 * Get name of the Authenticator
	 */
	@Override
	public String getName() {
		return InstagramAuthenticatorConstants.INSTAGRAM_CONNECTOR_NAME;
	}

	/**
	 * Get OAuth2 Scope
	 *
	 * @param scope                   Scope
	 * @param authenticatorProperties Authentication properties.
	 * @return OAuth2 Scope
	 */
	@Override
	protected String getScope(String scope, Map<String, String> authenticatorProperties) {

		return InstagramAuthenticatorConstants.INSTAGRAM_BASIC_SCOPE;
	}

	/**
	 * Get the Instagram specific claim dialect URI.
	 *
	 * @return Claim dialect URI.
	 */
	@Override
	public String getClaimDialectURI() {
		return InstagramAuthenticatorConstants.CLAIM_DIALECT_URI;
	}

	/**
	 * Get the configuration properties of UI
	 */
	@Override
	public List<Property> getConfigurationProperties() {
		List<Property> configProperties = new ArrayList<Property>();

		Property clientId = new Property();
		clientId.setName(OIDCAuthenticatorConstants.CLIENT_ID);
		clientId.setDisplayName("Client Id");
		clientId.setRequired(true);
		clientId.setDescription("Enter Instagram client identifier value");
		clientId.setDisplayOrder(0);
		configProperties.add(clientId);

		Property clientSecret = new Property();
		clientSecret.setName(OIDCAuthenticatorConstants.CLIENT_SECRET);
		clientSecret.setDisplayName("Client Secret");
		clientSecret.setRequired(true);
		clientSecret.setConfidential(true);
		clientSecret.setDescription("Enter Instagram client secret value");
		clientSecret.setDisplayOrder(1);
		configProperties.add(clientSecret);

		Property callbackUrl = new Property();
		callbackUrl.setDisplayName("Callback URL");
		callbackUrl.setName(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
		callbackUrl.setDescription("Enter the callback URL");
		callbackUrl.setDisplayOrder(2);
		configProperties.add(callbackUrl);

		return configProperties;
	}

	/**
	 * This method are overridden for extra claim request to Instagram end-point.
	 *
	 * @param request  the http request
	 * @param response the http response
	 * @param context  the authentication context
	 * @throws AuthenticationFailedException
	 */
	@Override
	protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
	                                             AuthenticationContext context) throws AuthenticationFailedException {
		try {
			Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
			String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
			String clientSecret = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_SECRET);
			String tokenEndPoint = getTokenEndpoint(authenticatorProperties);
			String callbackUrl = getCallbackUrl(authenticatorProperties);
			OAuthAuthzResponse authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
			String code = authzResponse.getCode();
			OAuthClientRequest accessRequest;
			try {
				accessRequest =
						OAuthClientRequest.tokenLocation(tokenEndPoint).setGrantType(GrantType.AUTHORIZATION_CODE)
						                  .setClientId(clientId).setClientSecret(clientSecret)
						                  .setRedirectURI(callbackUrl).setCode(code).buildBodyMessage();
				// create OAuth client that uses custom http client under the hood
				OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
				OAuthClientResponse oAuthResponse;
				oAuthResponse = oAuthClient.accessToken(accessRequest);
				String accessToken = oAuthResponse.getParam(InstagramAuthenticatorConstants.ACCESS_TOKEN);
				if (StringUtils.isNotEmpty(accessToken)) {
					Map<ClaimMapping, String> claims = buildClaims(oAuthResponse, authenticatorProperties);
					if (claims != null && !claims.isEmpty()) {
						//Find the subject from the IDP claim mapping, subject Claim URI.
						String subjectFromClaims = FrameworkUtils
								.getFederatedSubjectFromClaims(context.getExternalIdP().getIdentityProvider(), claims);
						associateSubjectFromClaims(context, subjectFromClaims, claims);
					} else {
						throw new AuthenticationFailedException(
								"Claims for the user not found for access Token : " + accessToken);
					}
				} else {
					throw new AuthenticationFailedException("Could not receive a valid access token from Instagram");
				}
			} catch (OAuthSystemException e) {
				throw new AuthenticationFailedException("Exception while building access token request", e);
			} catch (ApplicationAuthenticatorException e) {
				throw new AuthenticationFailedException("Exception while building the claim mapping", e);
			}
		} catch (OAuthProblemException e) {
			throw new AuthenticationFailedException("Exception while getting the access token form the response", e);
		}
	}

	/**
	 * This method is to get the Instagram user details.
	 *
	 * @param url         user info endpoint.
	 * @param accessToken access token.
	 * @return user info
	 * @throws ApplicationAuthenticatorException
	 */
	private JSONObject fetchUserInfo(String url, String accessToken) throws ApplicationAuthenticatorException {
		if (log.isDebugEnabled()) {
			log.debug("Sending the request for getting the user info");
		}
		StringBuilder jsonResponseCollector = new StringBuilder();
		BufferedReader bufferedReader = null;
		HttpURLConnection httpConnection = null;
		JSONObject jsonObj = null;
		try {
			URL obj = new URL(url + "?" + InstagramAuthenticatorConstants.ACCESS_TOKEN + "=" + accessToken);
			URLConnection connection = obj.openConnection();
			// Cast to a HttpURLConnection
			if (connection instanceof HttpURLConnection) {
				httpConnection = (HttpURLConnection) connection;
				httpConnection.setConnectTimeout(InstagramAuthenticatorConstants.CONNECTION_TIMEOUT_VALUE);
				httpConnection.setReadTimeout(InstagramAuthenticatorConstants.READ_TIMEOUT_VALUE);
				httpConnection.setRequestMethod(InstagramAuthenticatorConstants.HTTP_GET_METHOD);
				bufferedReader = new BufferedReader(new InputStreamReader(httpConnection.getInputStream()));
			} else {
				throw new ApplicationAuthenticatorException("Exception while casting the HttpURLConnection");
			}
			String inputLine = bufferedReader.readLine();
			while (inputLine != null) {
				jsonResponseCollector.append(inputLine).append("\n");
				inputLine = bufferedReader.readLine();
			}
			jsonObj = new JSONObject(jsonResponseCollector.toString());
		} catch (MalformedURLException e) {
			throw new ApplicationAuthenticatorException(
					"MalformedURLException while generating the user info URL: " + url, e);
		} catch (ProtocolException e) {
			throw new ApplicationAuthenticatorException("ProtocolException while setting the request method: " +
			                                            InstagramAuthenticatorConstants.HTTP_GET_METHOD +
			                                            " for the URL: " + url, e);
		} catch (IOException e) {
			throw new ApplicationAuthenticatorException("Error when reading the response from " + url +
			                                            "to update user claims", e);
		} finally {
			IdentityIOStreamUtils.closeReader(bufferedReader);
			if (httpConnection != null) {
				httpConnection.disconnect();
			}
		}
		if (log.isDebugEnabled()) {
			log.debug("Receiving the response for the User info: " + jsonResponseCollector.toString());
		}
		return jsonObj;
	}

	/**
	 * This method is to build the claims for the user info.
	 *
	 * @param token                   token
	 * @param authenticatorProperties authenticatorProperties
	 * @return claims
	 */
	private Map<ClaimMapping, String> buildClaims(OAuthClientResponse token,
	                                              Map<String, String> authenticatorProperties)
			throws ApplicationAuthenticatorException {
		Map<ClaimMapping, String> claims = new HashMap<>();
		String accessToken = token.getParam("access_token");
		String url = getUserInfoEndpoint(token, authenticatorProperties);
		JSONObject json;
		try {
			json = fetchUserInfo(url, accessToken);
			if (json.length() == 0) {
				if (log.isDebugEnabled()) {
					log.debug("Unable to fetch user claims. Proceeding without user claims");
				}
				return claims;
			}
			JSONObject userData = json.getJSONObject(InstagramAuthenticatorConstants.ROOT_ELEMENT);
			Iterator<?> keys = userData.keys();
			while (keys.hasNext()) {
				String key = (String) keys.next();
				String value;
				if (userData.get(key) instanceof JSONObject) {
					value = userData.get(key).toString();
				} else {

					value = userData.getString(key);
				}
				String claimUri = InstagramAuthenticatorConstants.CLAIM_DIALECT_URI + "/" + key;
				ClaimMapping claimMapping = new ClaimMapping();
				Claim claim = new Claim();
				claim.setClaimUri(claimUri);
				claimMapping.setRemoteClaim(claim);
				claimMapping.setLocalClaim(claim);
				claims.put(claimMapping, value);

			}
		} catch (ApplicationAuthenticatorException e) {
			throw new ApplicationAuthenticatorException("Exception while fetching the user info from " + url, e);
		}
		return claims;
	}

	/**
	 * This method is to configure the subject identifier from the claims.
	 *
	 * @param context           AuthenticationContext
	 * @param subjectFromClaims subject identifier claim
	 * @param claims            claims
	 */
	private void associateSubjectFromClaims(AuthenticationContext context, String subjectFromClaims,
	                                        Map<ClaimMapping, String> claims) {
		//Use default claim URI on the Authenticator if claim mapping is not defined by the admin
		if (StringUtils.isBlank(subjectFromClaims)) {
			String userId =
					InstagramAuthenticatorConstants.CLAIM_DIALECT_URI + "/" + InstagramAuthenticatorConstants.USERNAME;
			ClaimMapping claimMapping = new ClaimMapping();
			Claim claim = new Claim();
			claim.setClaimUri(userId);
			claimMapping.setRemoteClaim(claim);
			claimMapping.setLocalClaim(claim);
			subjectFromClaims = claims.get(claimMapping);
		}
		AuthenticatedUser authenticatedUserObj =
				AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(subjectFromClaims);
		context.setSubject(authenticatedUserObj);
		authenticatedUserObj.setUserAttributes(claims);
	}
}