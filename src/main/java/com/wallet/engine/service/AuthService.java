package com.wallet.engine.service;

import com.wallet.engine.dto.AuthResponse;
import com.wallet.engine.dto.LoginRequest;
import com.wallet.engine.dto.RegisterRequest;

public interface AuthService {
    AuthResponse register(RegisterRequest request);
    AuthResponse login(LoginRequest request);
}