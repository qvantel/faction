require 'rake'

Gem::Specification.new do |s|
  s.name = 'faction'
  s.description = 'A simple Savon-based client for Atlassian Crowd'
  s.summary = <<EOF
A simple Savon-based client for Atlassian Crowd
EOF
  s.version = '2010.13'
  s.date = '2010-03-30'

  s.authors = ['Olli Helenius']
  s.email = ['olli.helenius@onesto.fi']

  s.require_paths = ['lib']
  s.files = FileList["#{s.name}.gemspec", 'lib/**/*.rb', 'lib/**/*.yml'].to_a

  s.add_dependency('savon')
end
