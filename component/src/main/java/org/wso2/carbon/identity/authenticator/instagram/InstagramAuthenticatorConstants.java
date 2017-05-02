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

public class InstagramAuthenticatorConstants {

    /*
	* Private Constructor will prevent the instantiation of this class directly
	*/
    private InstagramAuthenticatorConstants() {
    }

    //Instagram authorize endpoint URL.
    public static final String INSTAGRAM_OAUTH_ENDPOINT = "https://api.instagram.com/oauth/authorize/";
    //Instagram token  endpoint URL.
    public static final String INSTAGRAM_TOKEN_ENDPOINT = "https://api.instagram.com/oauth/access_token";
    //Instagram user info endpoint URL.
    public static final String INSTAGRAM_USERINFO_ENDPOINT = "https://api.instagram.com/v1/users/self";
    //The authorization code that the application requested.
    public static final String OAUTH2_GRANT_TYPE_CODE = "code";
    //Instagram connector friendly name.
    public static final String INSTAGRAM_CONNECTOR_FRIENDLY_NAME = "Instagram ";
    //Instagram connector name.
    public static final String INSTAGRAM_CONNECTOR_NAME = "Instagram";
    //The access token.
    public static final String ACCESS_TOKEN = "access_token";
    //The user name.
    public static final String USERNAME = "username";
    //The user.
    public static final String INSTAGRAM_USER = "user";
    //permission scope.
    public static final String INSTAGRAM_BASIC_SCOPE = "basic";
    //The claim dialect URI.
    public static final String CLAIM_DIALECT_URI = "http://wso2.org/instagram/claims";
    //The Http get method
    public static final String HTTP_GET_METHOD = "GET";
    //Root element of the json response
    public static final String ROOT_ELEMENT = "data";
    //Constant for connection time out
    public static final int CONNECTION_TIMEOUT_VALUE = 15000;
    //Constant for read time out
    public static final int READ_TIMEOUT_VALUE = 15000;
}