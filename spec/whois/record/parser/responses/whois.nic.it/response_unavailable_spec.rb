# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/whois/record/parser/responses/whois.nic.it/response_unavailable_spec.rb
#
# and regenerate the tests with the following rake task
#
#   $ rake genspec:parsers
#

require 'spec_helper'
require 'whois/record/parser/whois.nic.it.rb'

describe Whois::Record::Parser::WhoisNicIt, "response_unavailable.expected" do

  before(:each) do
    file = fixture("responses", "whois.nic.it/response_unavailable.txt")
    part = Whois::Record::Part.new(:body => File.read(file))
    @parser = klass.new(part)
  end

  context "#response_unavailable?" do
    it do
      @parser.response_unavailable?.should == true
    end
  end
end