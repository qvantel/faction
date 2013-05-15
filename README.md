# Faction

Faction is a client for Atlassian Crowd's SOAP API.

## Installation

Add this line to your application's Gemfile:

    gem 'faction', github: 'onesto/faction'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install faction

## Usage

### User authentication

```ruby
token = begin
  crowd = Faction::Client.new('http://localhost:8050/crowd/services/SecurityServer', 'myapp', 'secret')
  validation_factors = {:user_agent     => "Some web browser",
                        :remote_address => "127.0.0.1"}
  crowd.authenticate_principal('test-user', 'secret-password', validation_factors)
rescue Faction::AuthenticationException => e
  puts "Authentication failed: #{e}"
end
# .. do something with token ..
```

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

## License

Ruby on Rails is released under the ![MIT License](http://opensource.org/licenses/MIT).
