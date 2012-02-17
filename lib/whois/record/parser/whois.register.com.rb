#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2012 Simone Carletti <weppos@weppos.net>
#++


require 'whois/record/parser/base'


module Whois
  class Record
    class Parser

      # Parser for the whois.register.com server.
      #
      # @note This parser is just a stub and provides only a few basic methods
      #   to check for domain availability and get domain status.
      #   Please consider to contribute implementing missing methods.
      # 
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      # @author Evan Alter
      # @since  2.1.0
      class WhoisRegisterCom < Base

        property_not_supported :status

        # The server seems to provide only linesrmation for registered domains
        property_supported :available? do
          false
        end

        property_supported :registered? do
          !available?
        end


        property_supported :created_on do
          unless rcomexpress?
            if content_for_scanner =~ /Created on\.+:(.*)\n/
              return Time.parse($1)
            end
          else
            if content_for_scanner =~ /Creation date:(.*)\n/
              return Time.parse($1)
            end
          end
        end
        
        property_supported :expires_on do
          unless rcomexpress?
            if content_for_scanner =~ /Expires on\.+:(.*)\n/
              return Time.parse($1)
            end
          else
            if content_for_scanner =~ /Expiration date:(.*)\n/
              return Time.parse($1)
            end
          end
        end
        
        # 
        # property_supported :updated_on do
        #   if content_for_scanner =~ /Last Updated on: (.+)\n/
        #     Time.parse($1)
        #   end
        # end
        # 
        # property_supported :expires_on do
        #   if content_for_scanner =~ /Expires on: (.+)\n/
        #     Time.parse($1)
        #   end
        # end


        property_supported :registrar do
          unless rcomexpress?
            Record::Registrar.new(
              :name => content_for_scanner[/Registrar Name.+:(.+)\n/, 1].strip,
              :url => content_for_scanner[/Registrar Homepage:(.+)\n/, 1].strip
            )
          end
        end

        property_supported :registrant_contacts do
          unless rcomexpress?
            return build_register_contact('Registrant:', Record::Contact::TYPE_REGISTRANT)
          else
            return build_rcomexpress_contact('Registrant Contact:', Record::Contact::TYPE_REGISTRANT)
          end
        end

        property_supported :admin_contacts do
          unless rcomexpress?
            return build_register_contact('Administrative Contact:', Record::Contact::TYPE_ADMIN)
          else
            return build_rcomexpress_contact('Administrative Contact:', Record::Contact::TYPE_ADMIN)
          end
        end

        property_supported :technical_contacts do
          unless rcomexpress?
            return build_register_contact('Technical  Contact:', Record::Contact::TYPE_TECHNICAL)
          else
            return build_rcomexpress_contact('Technical Contact:', Record::Contact::TYPE_TECHNICAL)
          end
        end


        property_supported :nameservers do
          unless rcomexpress?
            if content_for_scanner =~ /DNS Servers:\n((.+\n)+)\n/
              $1.split("\n").map do |line|
                Record::Nameserver.new(line.strip)
              end
            end
          else
            if content_for_scanner =~ /Name Servers:\n((.+\n)+)\n/
               $1.split("\n").map do |line|
                 Record::Nameserver.new(line.strip)
               end
             end
          end
        end


      private

        def build_register_contact(element, type)
        	match = content_for_scanner.slice(/#{element}\n((.+\n)+)\n/, 1)
          return unless match

          lines = $1.split("\n").map(&:strip)

          Record::Contact.new(
            :type         => type,
            :id           => nil,
            :name         => lines[1].strip,
            :organization => lines[0].strip,
            :address      => lines[2].strip,
            :city         => lines[3].to_s.partition(",")[0].strip,
            :zip          => lines[3].to_s.rpartition(" ")[2].strip,
            :state        => lines[3].to_s.partition(",")[2].rpartition(" ")[0].to_s.strip,
            :country      => lines[4].strip,
            :phone        => lines[5].to_s.slice(/Phone:(.+)/,1).strip,
            :email        => lines[6].to_s.slice(/Email:(.+)/,1).strip
          )
        end
        
        def build_rcomexpress_contact(element, type)
          match = content_for_scanner.slice(/#{element}\n(.*\n.+\(.*\)\n.*\n(.+\n)+)\n/, 1)
          return unless match

          lines = $1.split("\n").map(&:strip)
          
          name_and_email = lines[1].match(/(.+)\((.*)\)/)
          
          fields = {
            :type         => type,
            :id           => nil,
            :name         => name_and_email[1].strip,
            :organization => lines[0].strip,
            :address      => lines[4].strip,
            :city         => lines[5].to_s.partition(",")[0].strip,
            :zip          => lines[5].to_s.rpartition(" ")[2].strip,
            :state        => lines[5].to_s.partition(",")[2].rpartition(" ")[0].to_s.strip,
            :country      => lines[6].strip,
            :phone        => lines[2].strip,
            :fax          => lines[3].to_s.slice(/Fax:(.*)/,1).strip,
            :email        => name_and_email[2].strip
          }
          
          #Convert any blank fields to nil
          fields.each { |k, v| fields[k] = v.to_s.empty? ? nil : v }

          Record::Contact.new(fields)
        end
        
        def rcomexpress?
          content_for_scanner =~ /\n=-=-=-=\n/
        end

      end

    end
  end
end