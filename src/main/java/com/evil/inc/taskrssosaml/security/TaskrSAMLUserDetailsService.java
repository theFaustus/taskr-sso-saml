package com.evil.inc.taskrssosaml.security;

import com.evil.inc.taskrssosaml.domain.User;
import com.evil.inc.taskrssosaml.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class TaskrSAMLUserDetailsService implements SAMLUserDetailsService {

    private final UserRepository repository;

    @Override
    @Transactional
    public Object loadUserBySAML(SAMLCredential samlCredential) {
        try {
            String username = samlCredential.getAttributeAsString("UserID");
            return repository.findByUsername(username);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("User is not registered in [taskr]", e);
        }
    }

}