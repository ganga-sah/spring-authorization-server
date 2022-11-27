/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.web;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.Getter;
import org.apache.http.client.utils.URIBuilder;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.http.MediaType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;
import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

/**
 * @author Joe Grandja
 * @since 0.0.1
 */
@Controller
public class AuthorizationController {
	private final WebClient webClient;
	private final String messagesBaseUri;
	private @Value("${token-uri}") String tokenUri;
	private @Value("${client-id}") String clientId;
	private @Value("${client-secret}") String clientSecret;

	public AuthorizationController(WebClient webClient,
			@Value("${messages.base-uri}") String messagesBaseUri) {
		this.webClient = webClient;
		this.messagesBaseUri = messagesBaseUri;
	}

	@GetMapping(value = "/authorize", params = "grant_type=authorization_code")
	public String authorizationCodeGrant(Model model,
			@RegisteredOAuth2AuthorizedClient("safeguard-client-authorization-code")
					OAuth2AuthorizedClient authorizedClient) {

		MultiValueMap<String, String> bodyValues = new LinkedMultiValueMap<>();
		bodyValues.add("settingGroup", "SERVER_PROPERTIES");
		bodyValues.add("settingType", "APWG_ECX_API_ACCESS_TOKEN");
		String messages = this.webClient
				.post()
				.uri(this.messagesBaseUri)
				.bodyValue(getEcrimeXSettingsRequestBody())
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.retrieve()
				.bodyToMono(String.class)
				.block();
		System.out.println("****** messages="+messages);
		model.addAttribute("messages", messages);
		return "index";
	}

	// '/authorized' is the registered 'redirect_uri' for authorization_code
	@GetMapping(value = "/authorized", params = OAuth2ParameterNames.ERROR)
	public String authorizationFailed(Model model, HttpServletRequest request) {
		String errorCode = request.getParameter(OAuth2ParameterNames.ERROR);
		if (StringUtils.hasText(errorCode)) {
			model.addAttribute("error",
					new OAuth2Error(
							errorCode,
							request.getParameter(OAuth2ParameterNames.ERROR_DESCRIPTION),
							request.getParameter(OAuth2ParameterNames.ERROR_URI))
			);
		}

		return "index";
	}

	@GetMapping(value = "/authorize", params = "grant_type=client_credentials")
	public String clientCredentialsGrant(Model model) {
		MultiValueMap<String, String> bodyValues = new LinkedMultiValueMap<>();
		bodyValues.add("settingGroup", "SERVER_PROPERTIES");
		bodyValues.add("settingType", "APWG_ECX_API_ACCESS_TOKEN");
		System.out.println("****** tokenUri = " + tokenUri);
		String messages;
		if (this.tokenUri.isEmpty()) {
			// For empty value of token-uri, token will be implicitely created via .attributes() call below
			messages = this.webClient
					.post()
					.uri(this.messagesBaseUri)
					.bodyValue(getEcrimeXSettingsRequestBody())
					.attributes(clientRegistrationId("safeguard-client-client-credentials"))
					.retrieve()
					.bodyToMono(String.class)
					.block();
		} else {
			// For empty value of token-uri, token will be explicitely created without use of .attributes() call webClient seuence below
			// This token doesn't have scope for Spring AS, so API call fails for Spring AS,
			String token = getToken(this.tokenUri, this.clientId, this.clientSecret);
			System.out.println("***** token="+token);
			messages = this.webClient
					.post()
					.uri(buildUri(token, "http://localhost:8080", "/safeguard/api/v1/settings/global"))
					.bodyValue(getEcrimeXSettingsRequestBody())
					.retrieve()
					.bodyToMono(String.class)
					.block();
		}
		System.out.println("****** messages="+messages);
		model.addAttribute("messages", messages);

		return "index";
	}


	private URI buildUri(String token, String baseUri, String apiPath) {
		try {
			URIBuilder b = new URIBuilder(baseUri);
			b.setPath(apiPath);
			b.addParameter("access_token", token);
			return b.build();
		} catch (Exception e) {
			//throw new RuntimeException(e);
			return null;
		}
	}

	private String getToken(String tokenUri, String clientId, String clientSecret) {
		return this.webClient.post()
				.uri(buildGetTokenUri(tokenUri, clientId, clientSecret))
				.retrieve()
				.bodyToMono(GetTokenResponse.class)
				.map(GetTokenResponse::getAccessToken)
				//.retryWhen(RETRY_SPEC)
				.block();
	}

	private URI buildGetTokenUri(String tokenUri, String clientId, String clientSecret) {
		try {
			URIBuilder b = new URIBuilder(tokenUri);
			b.addParameter("grant_type", "client_credentials");
			b.addParameter("client_id", clientId);
			b.addParameter("client_secret", clientSecret);
			return b.build();
		} catch (Exception e) {
			//throw new RuntimeException(e);
			return null;
		}
	}

	//[{"settingGroup":"SERVER_PROPERTIES","settingType":"APWG_ECX_API_ACCESS_TOKEN"}]
	private List<GetSettingRequestDto> getEcrimeXSettingsRequestBody() {
		return List.of(
				//new GetSettingRequestDto(SettingGroup.SERVER_PROPERTIES, SettingType.APWG_ECX_API_BASE_URL),
				new GetSettingRequestDto(SettingGroup.SERVER_PROPERTIES, SettingType.APWG_ECX_API_ACCESS_TOKEN)
		);
	}

	public class GetSettingRequestDto {
		SettingGroup settingGroup;
		SettingType settingType;
		GetSettingRequestDto(SettingGroup settingGroup, SettingType settingType) {
			this.settingGroup = settingGroup;
			this.settingType = settingType;
		}
		public SettingGroup getSettingGroup() {
			return this.settingGroup;
		}
		public SettingType getSettingType() {
			return this.settingType;
		}
	}

	public enum SettingGroup {
		SERVER_PROPERTIES
	}

	public enum SettingType {
		APWG_ECX_API_BASE_URL,
		APWG_ECX_API_ACCESS_TOKEN
	}

}
