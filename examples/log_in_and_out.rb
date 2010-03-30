require 'faction'

CROWD_URL     = 'http://localhost:8085/crowd/services/SecurityServer'
APP_NAME      = 'application'
APP_PASSWORD  = 'password'

TEST_USERNAME = 'test'
TEST_PASSWORD = 'test'

crowd = Faction::Client.new(CROWD_URL, APP_NAME, APP_PASSWORD, :verify_cert => false)
token = crowd.authenticate_principal(TEST_USERNAME, TEST_PASSWORD)
puts("#{TEST_USERNAME} logged in, token = #{token}")
crowd.invalidate_principal_token(token)
