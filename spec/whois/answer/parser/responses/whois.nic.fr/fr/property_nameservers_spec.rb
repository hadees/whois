# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/whois/answer/parser/responses/whois.nic.fr/fr/property_nameservers_spec.rb
#
# and regenerate the tests with the following rake task
#
#   $ rake genspec:parsers
#

require 'spec_helper'
require 'whois/answer/parser/whois.nic.fr'

describe Whois::Answer::Parser::WhoisNicFr, "property_nameservers.expected" do

  before(:each) do
    file = fixture("responses", "whois.nic.fr/fr/property_nameservers.txt")
    part = Whois::Answer::Part.new(:body => File.read(file))
    @parser = klass.new(part)
  end

  context "#nameservers" do
    it do
      @parser.nameservers.should be_a(Array)
    end
    it do
      @parser.nameservers.should have(4).items
    end
    it do
      @parser.nameservers[0].should be_a(_nameserver)
    end
    it do
      @parser.nameservers[0].should == _nameserver.new(:name => "ns1.google.com")
    end
    it do
      @parser.nameservers[1].should be_a(_nameserver)
    end
    it do
      @parser.nameservers[1].should == _nameserver.new(:name => "ns2.google.com")
    end
    it do
      @parser.nameservers[2].should be_a(_nameserver)
    end
    it do
      @parser.nameservers[2].should == _nameserver.new(:name => "ns3.google.com")
    end
    it do
      @parser.nameservers[3].should be_a(_nameserver)
    end
    it do
      @parser.nameservers[3].should == _nameserver.new(:name => "ns4.google.com")
    end
  end
end