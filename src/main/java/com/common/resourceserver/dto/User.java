package com.common.resourceserver.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Schema(description = "User name", required = true, example = "admin", accessMode = Schema.AccessMode.WRITE_ONLY)
    private String username;

    @Schema(description = "Password", required = true, example = "123456", accessMode = Schema.AccessMode.WRITE_ONLY)
    private String password;
}
