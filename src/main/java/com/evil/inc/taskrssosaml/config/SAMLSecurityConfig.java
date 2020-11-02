package com.evil.inc.taskrssosaml.config;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.context.SAMLContextProviderLB;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.storage.EmptyStorageFactory;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;

@Configuration
@EnableWebSecurity
@ComponentScan(basePackages = {"org.springframework.security.saml", "com.evil.inc.taskrssosaml"})
public class SAMLSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${taskr.entityId}")
    private String entityId;

    @Value("${taskr.entityBaseUrl}")
    private String entityBaseUrl;

    private final String idpMetadataUrl = "https://idp.ssocircle.com/idp-meta.xml";


    @Bean
    public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
        return new PropertySourcesPlaceholderConfigurer();
    }

    /**
     * Initialization of OpenSAML library
     *
     * @return SAMLBootstrap
     */
    @Bean
    public static SAMLBootstrap samlBootstrap() {
        return new CustomSAMLBootstrap();
    }

    @Bean
    public SAMLContextProviderImpl contextProvider() {
        return new SAMLContextProviderImpl();
    }

    /**
     * Secured pages with SAML as entry point
     *
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .antMatchers("/saml/**").permitAll()
                .anyRequest()
                .authenticated();
        http.csrf().disable();

        http.exceptionHandling().authenticationEntryPoint(samlEntryPoint());

        http.addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class);
        http.addFilterAfter(samlFilter(), BasicAuthenticationFilter.class);
    }

    /**
     * Unsecured pages
     *
     * @param web
     * @throws Exception
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers("/templates/**")
                .antMatchers("/static/**");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(samlAuthenticationProvider());
    }

    /**
     * Filters for processing of SAML messages
     * Filters of the SAML module need to be enabled as part of the Spring Security settings.
     *
     * @return FilterChainProxy
     * @throws Exception
     */
    @Bean
    public FilterChainProxy samlFilter() throws Exception {
        List<SecurityFilterChain> chains = new ArrayList<>();
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"), samlEntryPoint()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout/**"), samlLogoutFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"), metadataDisplayFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"), samlWebSSOProcessingFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout/**"), samlLogoutProcessingFilter()));
        return new FilterChainProxy(chains);
    }

    /**
     * Filter processing incoming logout messages -->
     * First argument determines URL user will be redirected to after successful global logout
     *
     * @return SAMLLogoutProcessingFilter
     */
    @Bean
    public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
        return new SAMLLogoutProcessingFilter(successLogoutHandler(), logoutHandler());
    }

    /**
     * Successful authentication using SAML token results in creation of an Authentication object by the SAMLAuthenticationProvider.
     * By default instance of org.springframework.security.providers.ExpiringUsernameAuthenticationToken is created.
     * <p>
     * When forcePrincipalAsString = false AND userDetail = null (default) - NameID object included in the SAML Assertion (credential.getNameID() of type org.opensaml.saml2.core.NameID)
     * When forcePrincipalAsString = false AND userDetail != null - UserDetail object returned from the SAMLUserDetailsService
     *
     * @return SAMLAuthenticationProvider
     */
    @Bean
    public SAMLAuthenticationProvider samlAuthenticationProvider() {
        SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
        samlAuthenticationProvider.setForcePrincipalAsString(false);
        return samlAuthenticationProvider;
    }

    /**
     * Entry point to initialize authentication, default values taken from properties file
     *
     * @return SAMLEntryPoint
     */
    @Bean
    public SAMLEntryPoint samlEntryPoint() {
        SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
        samlEntryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions());
        return samlEntryPoint;
    }

    /**
     * After identification of IDP to use for authentication (for details see Section 9.1, “IDP selection and discovery”),
     * SAML Extension creates an AuthnRequest SAML message and sends it to the selected IDP. Both construction of the
     * AuthnRequest and binding used to send it can be customized using WebSSOProfileOptions object. SAMLEntryPoint determines
     * WebSSOProfileOptions configuration to use by calling method getProfileOptions. The default implementation returns the
     * value specified in property defaultOptions. The method can be overridden to provide custom logic for SSO initialization
     *
     * @return WebSSOProfileOptions
     */
    @Bean
    public WebSSOProfileOptions defaultWebSSOProfileOptions() {
        WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
        webSSOProfileOptions.setIncludeScoping(false);
        return webSSOProfileOptions;
    }

    /**
     * Processing filter for WebSSO profile messages
     *
     * @return SAMLProcessingFilter
     * @throws Exception
     */
    @Bean
    public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
        SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
        samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
        samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
        samlWebSSOProcessingFilter.setAuthenticationFailureHandler(failureRedirectHandler());
        return samlWebSSOProcessingFilter;
    }

    /**
     * Handler deciding where to redirect user after successful login
     *
     * @return SavedRequestAwareAuthenticationSuccessHandler
     */
    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successRedirectHandler.setDefaultTargetUrl("/");
        return successRedirectHandler;
    }

    /**
     * Handler deciding where to redirect user after failed login
     *
     * @return SimpleUrlAuthenticationFailureHandler
     */
    @Bean
    public SimpleUrlAuthenticationFailureHandler failureRedirectHandler() {
        SimpleUrlAuthenticationFailureHandler simpleUrlAuthenticationFailureHandler = new SimpleUrlAuthenticationFailureHandler();
        simpleUrlAuthenticationFailureHandler.setUseForward(true);
        simpleUrlAuthenticationFailureHandler.setDefaultFailureUrl("/error.html");
        return simpleUrlAuthenticationFailureHandler;
    }

    /**
     * Override default logout processing filter with the one processing SAML messages
     *
     * @return SAMLLogoutFilter
     */
    @Bean
    public SAMLLogoutFilter samlLogoutFilter() {
        return new SAMLLogoutFilter(successLogoutHandler(), new LogoutHandler[]{logoutHandler()}, new LogoutHandler[]{logoutHandler()});
    }

    /**
     * Handler for successful logout
     *
     * @return SimpleUrlLogoutSuccessHandler
     */
    @Bean
    public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
        SimpleUrlLogoutSuccessHandler simpleUrlLogoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
        simpleUrlLogoutSuccessHandler.setDefaultTargetUrl("/");
        simpleUrlLogoutSuccessHandler.setAlwaysUseDefaultTargetUrl(true);
        return simpleUrlLogoutSuccessHandler;
    }

    /**
     * Logout handler terminating local session
     *
     * @return SecurityContextLogoutHandler
     */
    @Bean
    public SecurityContextLogoutHandler logoutHandler() {
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.setInvalidateHttpSession(true);
        logoutHandler.setClearAuthentication(true);
        return logoutHandler;
    }

    /**
     * The filter is waiting for connections on URL suffixed with filterSuffix and presents SP metadata there
     *
     * @return MetadataDisplayFilter
     */
    @Bean
    public MetadataDisplayFilter metadataDisplayFilter() {
        return new MetadataDisplayFilter();
    }

    /**
     * Central storage of cryptographic keys
     *
     * @return JKSKeyManager
     */
    @Bean
    public KeyManager keyManager() {
        ClassPathResource storeFile = new ClassPathResource("/security/taskrSamlKeystore.jks");
        String storePass = "123456";
        Map<String, String> passwords = new HashMap<>();
        passwords.put("taskrsaml", "123456");
        return new JKSKeyManager(storeFile, storePass, passwords, "taskrsaml");
    }

    /**
     * Class loading incoming SAML messages from httpRequest stream
     *
     * @return SAMLProcessor
     */
    @Bean
    public SAMLProcessor processor() {
        return new SAMLProcessorImpl(Arrays.asList(httpPostBinding(), httpRedirectDeflateBinding()));
    }

    /**
     * Logger for SAML messages and events
     *
     * @return SAMLDefaultLogger
     */
    @Bean
    public SAMLDefaultLogger samlLogger() {
        SAMLDefaultLogger samlDefaultLogger = new SAMLDefaultLogger();
        samlDefaultLogger.setLogMessages(true);
        return samlDefaultLogger;
    }

    @Bean
    public EmptyStorageFactory emptyStorageFactory() {
        return new EmptyStorageFactory();
    }

    /**
     * SAML 2.0 Web SSO profile
     *
     * @return WebSSOProfile
     */
    @Bean
    public WebSSOProfile webSSOprofile() {
        return new WebSSOProfileImpl();
    }

    /**
     * SAML 2.0 Holder-of-Key Web SSO profile
     *
     * @return WebSSOProfileConsumerHoKImpl
     */
    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOProfile() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    /**
     * SAML 2.0 WebSSO Assertion Consumer
     *
     * @return WebSSOProfileConsumer
     */
    @Bean
    public WebSSOProfileConsumer webSSOprofileConsumer() {
        return new WebSSOProfileConsumerImpl();
    }

    /**
     * SAML 2.0 Holder-of-Key WebSSO Assertion Consumer
     *
     * @return WebSSOProfileConsumerHoKImpl
     */
    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    /**
     * SAML 2.0 Logout Profile
     *
     * @return SingleLogoutProfile
     */
    @Bean
    public SingleLogoutProfile logoutprofile() {
        return new SingleLogoutProfileImpl();
    }

    /**
     * Filter automatically generates default SP metadata
     *
     * @return MetadataGeneratorFilter
     */
    @Bean
    public MetadataGeneratorFilter metadataGeneratorFilter() {
        return new MetadataGeneratorFilter(metadataGenerator());
    }

    @Bean
    public MetadataGenerator metadataGenerator() {
        MetadataGenerator metadataGenerator = new MetadataGenerator();
        metadataGenerator.setEntityId(entityId);
        metadataGenerator.setExtendedMetadata(extendedMetadata());
        metadataGenerator.setIncludeDiscoveryExtension(false);
        metadataGenerator.setEntityBaseURL(entityBaseUrl);
        metadataGenerator.setKeyManager(keyManager());
        return metadataGenerator;
    }

    @Bean
    public ExtendedMetadata extendedMetadata() {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setIdpDiscoveryEnabled(false);
        extendedMetadata.setSignMetadata(false);
        return extendedMetadata;
    }

    /**
     * IDP Metadata configuration - paths to metadata of IDPs in circle of trust is here
     *
     * @return CachingMetadataManager
     * @throws MetadataProviderException
     */
    @Bean
    @Qualifier("metadata")
    public CachingMetadataManager metadata() throws MetadataProviderException {
        List<MetadataProvider> providers = new ArrayList<MetadataProvider>();
        providers.add(idpExtendedMetadataProvider());
        return new CachingMetadataManager(providers);
    }

    /**
     * Example of classpath metadata with Extended Metadata
     *
     * @return ExtendedMetadataDelegate
     * @throws MetadataProviderException
     */
    @Bean
    public ExtendedMetadataDelegate idpExtendedMetadataProvider() throws MetadataProviderException {
        HTTPMetadataProvider httpMetadataProvider = new HTTPMetadataProvider(backgroundTimer(), httpClient(), idpMetadataUrl);
        httpMetadataProvider.setParserPool(parserPool());
        ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(httpMetadataProvider, extendedMetadata());
        extendedMetadataDelegate.setMetadataTrustCheck(true);
        extendedMetadataDelegate.setMetadataRequireSignature(false);
        return extendedMetadataDelegate;
    }

    @Bean
    public Timer backgroundTimer() {
        return new Timer(true);
    }

    @Bean
    public HttpClient httpClient() {
        return new HttpClient(multiThreadedHttpConnectionManager());
    }

    @Bean
    public MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager() {
        return new MultiThreadedHttpConnectionManager();
    }


    @Bean(initMethod = "initialize")
    public StaticBasicParserPool parserPool() {
        return new StaticBasicParserPool();
    }


    @Bean(name = "parserPoolHolder")
    public ParserPoolHolder parserPoolHolder() {
        return new ParserPoolHolder();
    }

    /**
     * Bindings, encoders and decoders used for creating and parsing messages
     *
     * @return HTTPPostBinding
     */
    @Bean
    public HTTPPostBinding httpPostBinding() {
        return new HTTPPostBinding(parserPool(), VelocityFactory.getEngine());
    }


    @Bean
    public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
        return new HTTPRedirectDeflateBinding(parserPool());
    }
}
