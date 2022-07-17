package com.common.resourceserver.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class Token {

    @Schema(description = "Access token", required = true, example = "4cyw2rFfzHWd83xz6Kj02w63IK0", accessMode = Schema.AccessMode.READ_ONLY)
    @JsonProperty("access_token")
    private String accessToken;

    @Schema(description = "Type of token", required = true, example = "bearer", accessMode = Schema.AccessMode.READ_ONLY)
    @JsonProperty("token_type")
    private String tokenType;

    @Schema(description = "Refresh token", required = true, example = "bjJAjafRpobV7CygniQntsFq8Vk", accessMode = Schema.AccessMode.READ_ONLY)
    @JsonProperty("refresh_token")
    private String refreshToken;

    @Schema(description = "Time expires in", required = true, example = "60", accessMode = Schema.AccessMode.READ_ONLY)
    @JsonProperty("expires_in")
    private Integer expiresIn;

    @Schema(description = "scope", required = true, example = "read write", accessMode = Schema.AccessMode.READ_ONLY)
    @JsonProperty("scope")
    private String scope;
}
