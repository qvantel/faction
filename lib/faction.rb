require 'openssl'
require 'savon'

module Faction
  class Exception < ::Exception; end
  class AuthenticationException < Exception; end

  class Client
    @@debug = false

    def self.debug=(value)
      @@debug = value
    end

    def self.debug?
      @@debug
    end

    CROWD_NAMESPACES = {
      'xmlns:wsdl' => 'urn:SecurityServer',
      'xmlns:auth' => 'http://authentication.integration.crowd.atlassian.com',
      'xmlns:xsd'  => 'http://www.w3.org/2001/XMLSchema',
      'xmlns:xsi'  => 'http://www.w3.org/2001/XMLSchema-instance'
    }

    attr_reader :crowd_url
    attr_reader :app_name
    attr_reader :app_password

    def self.from_properties(properties_file)
      props = Hash[*open(properties_file).readlines.map {|line|
                     line.split(/=/, 2).map(&:strip)}.flatten]
      self.new(props['crowd.server.url'] + '/SecurityServer',
               props['application.name'],
               props['application.password'],
               :verify_cert => ['yes', 'true'].include?(props['ssl.verify']))
    end

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

    def authenticate_principal(name, password, validation_factors = nil)
      authenticated_crowd_call(:authenticate_principal,
                                { 'auth:application' => app_name,
                                  'auth:name' => name,
                                  'auth:credential' => {'auth:credential' => password},
                                  'auth:validationFactors' => convert_validation_factors(validation_factors)})
    end

    def invalidate_principal_token(token)
      authenticated_crowd_call(:invalidate_principal_token, token) && nil
    end

    def get_cookie_info
      authenticated_crowd_call(:get_cookie_info)
    end

    def valid_principal_token?(token, validation_factors = nil)
      authenticated_crowd_call(:is_valid_principal_token,
                               token,
                               {'auth:validationFactors' => convert_validation_factors(validation_factors)})
    end

    private

    USER_AGENT      = "User-Agent"
    REMOTE_ADDRESS  = "remote_address"
    REMOTE_HOST     = "remote_host"
    X_FORWARDED_FOR = "X-Forwarded-For"
    RANDOM_NUMBER   = "Random-Number"
    NAME            = "NAME"

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
        args.each_with_index do |arg, index|
          soap.body["wsdl:in#{index + 1}"] = arg
        end
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
  end
end
