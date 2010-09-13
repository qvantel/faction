require 'openssl'
require 'savon'

module Faction #:nodoc:

  # Exception base for Faction
  class Exception < ::Exception; end
  # Any sort of Exception from Crowd
  class AuthenticationException < Exception; end

  # See http://docs.atlassian.com/crowd/current/com/atlassian/crowd/integration/service/soap/server/SecurityServer.html
  # for Crowd SOAP API documentation.
  #
  # The <tt>validation_factors</tt> parameter is a <tt>Hash</tt> that can contain the following keys:
  # * <tt>:user_agent</tt> - <tt>ValidationFactor.USER_AGENT</tt>
  # * <tt>:remote_address</tt> - <tt>ValidationFactor.REMOTE_ADDRESS</tt>
  # * <tt>:remote_host</tt> - <tt>ValidationFactor.REMOTE_HOST</tt>
  # * <tt>:forwarded_for</tt> - <tt>ValidationFactor.X_FORWARDED_FOR</tt>
  # * <tt>:random_number</tt> - <tt>ValidationFactor.RANDOM_NUMBER</tt>
  # * <tt>:name</tt> - <tt>ValidationFactor.NAME</tt>
  class Client
    @@debug = false

    # Sets the global debugging for Client
    def self.debug=(value)
      @@debug = value
    end

    # True if Faction is in debug mode
    def self.debug?
      @@debug
    end

    # Url of the Crowd SecurityServer
    attr_reader :crowd_url
    # Application name
    attr_reader :app_name
    # Appliction password
    attr_reader :app_password

    # Instantiates a new client using a "standard" <tt>crowd.properties</tt> file.
    def self.from_properties(properties_file)
      props = Hash[*open(properties_file).readlines.map {|line|
                     line.split(/=/, 2).map(&:strip)}.flatten]
      self.new(props['crowd.server.url'] + '/SecurityServer',
               props['application.name'],
               props['application.password'],
               :verify_cert => ['yes', 'true'].include?(props['ssl.verify']))
    end

    # Creates a new Crowd client.
    #
    # Parameters:
    # * <tt>crowd_url</tt> - The URL to Crowd SecurityServer.
    # * <tt>app_name</tt> - Application name.
    # * <tt>app_password</tt> - Application password.
    # * <tt>options</tt> - A Hash of options (described below).
    #
    # Options
    # * <tt>:verify_cert</tt> - If <tt>false</tt> the peer SSL certificate is not verified.
    #
    # Example:
    #   Faction::Client.new('http://localhost:8085/crowd/services/SecurityServer', 'application', 'password')
    #
    def initialize(crowd_url, app_name, app_password, options = {})
      @crowd_url = crowd_url
      @crowd = Savon::Client.new(@crowd_url + (Client.debug? ? '?wsdl' : ''))
      if options[:verify_cert] == false
        @crowd.request.http.ssl_client_auth(:verify_mode => OpenSSL::SSL::VERIFY_NONE)
      end
      @app_name = app_name
      @app_password = app_password
      @app_token = nil
    end

    # See <tt>SecurityServerClient.authenticatePrincipal</tt>
    def authenticate_principal(name, password, validation_factors = nil)
      authenticated_crowd_call(:authenticate_principal,
                                { 'auth:application' => app_name,
                                  'auth:name' => name,
                                  'auth:credential' => {'auth:credential' => password},
                                  'auth:validationFactors' => convert_validation_factors(validation_factors)})
    end

    # See <tt>SecurityServerClient.invalidatePrincipalToken</tt>
    def invalidate_principal_token(token)
      authenticated_crowd_call(:invalidate_principal_token, token) && nil
    end

    # See <tt>SecurityServerClient.getCookieInfo</tt>
    def get_cookie_info
      authenticated_crowd_call(:get_cookie_info)
    end

    # See <tt>SecurityServerClient.isValidPrincipalToken</tt>
    def valid_principal_token?(token, validation_factors = nil)
      authenticated_crowd_call(:is_valid_principal_token,
                               token,
                               {'auth:validationFactors' => convert_validation_factors(validation_factors)})
    end

    # See <tt>SecurityServer.updatePrincipalCredential</tt>
    def update_principal_credential(name, new_password)
      authenticated_crowd_call(:update_principal_credential,
                               name,
                               {'auth:credential' => new_password, 'auth:encryptedCredential' => false})
    end

    def find_principal_by_token(token)
      fix_principal_attributes(authenticated_crowd_call(:find_principal_by_token, token))
    end

    def find_principal_by_name(name)
      fix_principal_attributes(authenticated_crowd_call(:find_principal_by_name, name))
    end

    def add_principal_to_group(principal, group)
      authenticated_crowd_call(:add_principal_to_group, principal, group) && nil
    end

    private

    CROWD_NAMESPACES = {
      'xmlns:wsdl' => 'urn:SecurityServer',
      'xmlns:auth' => 'http://authentication.integration.crowd.atlassian.com',
      'xmlns:xsd'  => 'http://www.w3.org/2001/XMLSchema',
      'xmlns:xsi'  => 'http://www.w3.org/2001/XMLSchema-instance'
    }

    USER_AGENT      = "User-Agent" #:nodoc:
    REMOTE_ADDRESS  = "remote_address" #:nodoc:
    REMOTE_HOST     = "remote_host" #:nodoc:
    X_FORWARDED_FOR = "X-Forwarded-For" #:nodoc:
    RANDOM_NUMBER   = "Random-Number" #:nodoc:
    NAME            = "NAME" #:nodoc:

    VALIDATION_FACTOR_MAPPING = {
      :user_agent     => USER_AGENT,
      :remote_address => REMOTE_ADDRESS,
      :remote_host    => REMOTE_HOST,
      :forwarded_for  => X_FORWARDED_FOR,
      :random_number  => RANDOM_NUMBER,
      :name           => NAME
    }

    def convert_validation_factors(in_validation_factors)
      return nil if in_validation_factors.nil?
      result = in_validation_factors.map do |name, value|
        raise Faction::Exception, "Invalid validation factor #{name}" if !VALIDATION_FACTOR_MAPPING.include?(name)
        {'auth:name'  => VALIDATION_FACTOR_MAPPING[name], 'auth:value' => value}
      end
      {'auth:ValidationFactor' => result}
    end

    def app_authentication
      Hash['auth:name'  => app_name,
           'auth:token' => app_token]
    end

    def ensure_app_token!
      app_token
    end

    def app_token
      @app_token ||= authenticate_application
    end

    def authenticate_application
      response = crowd_call(:authenticate_application) do |soap|
        soap.body.merge!('wsdl:in0' => {
                           'auth:name' => app_name,
                           'auth:credential' => {
                             'auth:credential' => app_password,
                           }})
      end
      response[:token]
    end

    def crowd_call(name, &block)
      method = (Client.debug? ? name : "#{name}!").to_sym
      response = @crowd.call(method) do |soap|
        soap.namespaces.merge!(CROWD_NAMESPACES)
        soap.body = {}
        yield soap if block_given?
      end
      response.to_hash[:"#{name}_response"][:out]
    end

    def real_authenticated_crowd_call(name, *args)
      ensure_app_token!
      crowd_call(name) do |soap|
        soap.body = {'wsdl:in0' => app_authentication}
        order = ['wsdl:in0']
        args.each_with_index do |arg, index|
          soap.body["wsdl:in#{index + 1}"] = arg
          order << "wsdl:in#{index + 1}"
        end
        soap.body[:order!] = order
      end
    end

    def authenticated_crowd_call(name, *args)
      begin
        real_authenticated_crowd_call(name, *args)
      rescue Savon::SOAPFault => f
        # retry once
        @app_token = nil
        begin
          real_authenticated_crowd_call(name, *args)
        rescue Savon::SOAPFault => f
          raise AuthenticationException, f.message
        end
      end
    end
    
    def fix_principal_attributes(result)
      attributes = result[:attributes][:soap_attribute].inject({}) do |hash, item|
        hash[item[:name].to_sym] = item[:values][:string]
        hash
      end
      result.merge(:attributes => attributes)
    end
  end
end
