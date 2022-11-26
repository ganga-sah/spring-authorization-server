package sample.web;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class GetTokenResponse {
	@JsonProperty("access_token")
	private String accessToken;
	public String getAccessToken() {
		return accessToken;
	}
}
